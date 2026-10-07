"""
Q-Trail Multi-Bank Forensic Reconciliation & Network Matching Engine
=============================================================================
Core reconciliation and network-matching logic to detect direct and 1-hop
intermediate transactions between two individuals (Person A and Person B)
using their HDFC and ICICI bank statements.

Features:
1. Data Normalization & Extraction (Regex Engine):
   - UTR extraction (12-digit numeric UPI/IMPS and alphanumeric NEFT/RTGS codes)
   - Counterparty VPA extraction with delimiter boundary isolation
   - Counterparty Account/Mask/IFSC extraction
   - Counterparty Name extraction isolated from banking noise tokens
2. Match Rule 1: Direct Transactions (A -> B and B -> A):
   - Exact join on UTR
   - Fallback fuzzy match on Date, Amount, and Narration cross-check
3. Match Rule 2: Intermediate Transactions (A -> X -> B):
   - Network counterparty intersection (Candidate X)
   - Temporal constraints (0 <= Inflow Date - Outflow Date <= time_window_days)
   - Value constraints (Inflow Amount <= Outflow Amount)
   - Grouping by identified intermediary entity
=============================================================================
"""

from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd
from loguru import logger

# =============================================================================
# 1. Regex Engine & Parsing Constants for Indian Banking Formats
# =============================================================================

# UTR Regex Pattern:
# Indian banking systems generate two primary classes of transaction references:
# 1. UPI & IMPS RRN (Retrieval Reference Number): Exactly 12 numeric digits (e.g., '412345678901').
# 2. NEFT & RTGS Alphanumeric References:
#    - NEFT references typically start with bank acronym + 'N' (e.g., 'HDFCN00123456789', 'AXISN0412345')
#      or standard RBI 'N' prefix + 15 digits (e.g., 'N123456789012345').
#    - RTGS references typically start with bank acronym + 'R' (e.g., 'HDFCR520260201001', 'ICICR2026...').
#    - Lookbehind/lookahead ensure we don't accidentally truncate 16-digit account numbers or mobile numbers.
REGEX_UTR = re.compile(r"(?i)\b([A-Z]{3,4}[NR][A-Z0-9]{6,18}|[NR]\d{8,18}|(?<!\d)\d{12}(?!\d))\b")

# Counterparty VPA (Virtual Payment Address) Regex Pattern:
# NPCI UPI specification defines VPAs as username@psp_handle (e.g., 'username@okhdfcbank', 'biz.parts@icici').
# In HDFC statements, hyphens '-' are used as token delimiters (e.g. 'UPI-NAME-VPA-IFSC-UTR').
# If a hyphen is present between the counterparty name and the VPA, naive matching might capture
# 'NAME-username@bank'. We enforce boundary checks so leading delimiter hyphens are discarded.
REGEX_VPA_DELIMITED = re.compile(r"(?i)[-/]([a-zA-Z0-9.\-_]+@[a-zA-Z]+)")
REGEX_VPA_GENERAL = re.compile(r"([a-zA-Z0-9.\-_]+@[a-zA-Z]+)")

# Counterparty Account / Mask / IFSC Regex Pattern:
# Indian bank narrations obscure counterparty accounts as XXXXXX1234 or **123456,
# or provide the recipient bank's 11-character RBI IFSC code (e.g., 'HDFC0000123', 'ICIC0000456').
REGEX_ACCOUNT = re.compile(r"(?i)\b([X*]{2,12}\d{4,6}|[A-Z]{4}0[A-Z0-9]{6})\b")

# Counterparty Name Regex Pattern:
# In HDFC and ICICI narrations, the counterparty name appears after the transaction mode prefix
# (UPI, IMPS, NEFT, RTGS, MMT/IMPS, BIL/IN/UPI, INF/NEFT) and before the UTR, VPA, IFSC, or account mask.
REGEX_NAME = re.compile(
    r"(?i)"
    r"(?:^|[\s/_-])"
    r"(?:MMT[-/ ]+IMPS|INF[-/ ]+NEFT|BIL[-/ ]+IN[-/ ]+UPI|BIL[-/ ]+UPI|UPI|IMPS|NEFT|RTGS)"
    r"(?:[\s/_-]+(?:P2A|P2M|DR|CR|IN|OUT))?"
    r"(?:[\s/_-]+(?:[A-Z]{3,4}[NR][A-Z0-9]+|[NR]?\d{10,18}))?"
    r"[-/]"
    r"([A-Za-z][A-Za-z\s.]{1,35}?)"
    r"(?=[-/](?:[a-zA-Z0-9.\-_]+@|[A-Z]{4}0|\d{10,18}|[X*]{2,}\d*|PAYMENT|ICICI|HDFC|AXIS|SBIN|$)|$)"
)

# Clutter prefix cleaner for entity names
REGEX_NAME_NOISE_PREFIX = re.compile(
    r"(?i)^(?:SENT TO MR|SENT TO MS|SENT TO|PAY TO|PAYMENT TO|TRANSFER TO)\s+"
)


# =============================================================================
# 2. Data Normalization & Feature Extraction Engine
# =============================================================================


def _detect_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Helper to detect standard column names case-insensitively."""
    lower_map = {c.lower().strip(): c for c in df.columns}
    for cand in candidates:
        if cand.lower().strip() in lower_map:
            return lower_map[cand.lower().strip()]
    return None


def extract_banking_features(
    df: pd.DataFrame,
    narration_col: str | None = None,
    *,
    output_prefix: str = "",
) -> pd.DataFrame:
    """
    Extracts structured forensic banking features from transaction narrations using vectorized regex.

    Extracted Columns:
    - UTR: 12-digit numeric RRN (UPI/IMPS) or alphanumeric NEFT/RTGS reference.
    - Counterparty_VPA: Clean UPI handle (e.g., 'username@okhdfcbank').
    - Counterparty_Account: Trailing numeric mask (e.g., 'XXXXXX1234') or counterparty IFSC code.
    - Counterparty_Name: Alphabetical entity/person name isolated from banking clutter.

    Args:
        df: Input DataFrame (e.g. HDFC or ICICI bank statement).
        narration_col: Column name containing the raw narration. If None, auto-detected.
        output_prefix: Optional prefix for the newly created extraction columns.

    Returns:
        pd.DataFrame: Copy of input DataFrame enriched with extraction features.
    """
    if df.empty:
        df_out = df.copy()
        for col in ["UTR", "Counterparty_VPA", "Counterparty_Account", "Counterparty_Name"]:
            df_out[f"{output_prefix}{col}"] = pd.Series(dtype="object")
        return df_out

    df_out = df.copy()

    # Auto-detect narration column if not provided
    if not narration_col:
        narration_col = _detect_column(
            df_out, ["Narration", "Description", "Transaction Remarks", "Particulars", "Remarks"]
        )

    if not narration_col or narration_col not in df_out.columns:
        logger.warning("No valid narration column identified for feature extraction.")
        for col in ["UTR", "Counterparty_VPA", "Counterparty_Account", "Counterparty_Name"]:
            df_out[f"{output_prefix}{col}"] = None
        return df_out

    # Vectorized string series
    narr = df_out[narration_col].fillna("").astype(str).str.strip()

    # 1. Extract UTR (UPI 12-digit numeric or NEFT/RTGS alphanumeric)
    utr_series = narr.str.extract(REGEX_UTR)[0].str.upper()
    df_out[f"{output_prefix}UTR"] = utr_series.replace({"": None})

    # 2. Extract Counterparty VPA (with delimiter isolation to avoid hyphen bleed)
    vpa_delim = narr.str.extract(REGEX_VPA_DELIMITED)[0]
    vpa_general = narr.str.extract(REGEX_VPA_GENERAL)[0]
    clean_vpa = vpa_delim.fillna(vpa_general).str.lower().str.strip()
    df_out[f"{output_prefix}Counterparty_VPA"] = clean_vpa.replace({"": None})

    # 3. Extract Counterparty Account Mask / IFSC
    acc_series = narr.str.extract(REGEX_ACCOUNT)[0].str.upper()
    df_out[f"{output_prefix}Counterparty_Account"] = acc_series.replace({"": None})

    # 4. Extract Counterparty Name
    raw_name_series = narr.str.extract(REGEX_NAME)[0]
    cleaned_name_series = raw_name_series.str.replace(
        REGEX_NAME_NOISE_PREFIX, "", regex=True
    ).str.strip()
    # Strip any trailing isolated noise words
    cleaned_name_series = cleaned_name_series.replace(
        r"(?i)\b(?:PAYMENT|PAY|TRF|TRANSFER|NA)\b", "", regex=True
    ).str.strip()
    df_out[f"{output_prefix}Counterparty_Name"] = cleaned_name_series.replace({"": None})

    return df_out


def _prepare_statement_dataframe(
    df: pd.DataFrame,
    *,
    date_col: str | None = None,
    debit_col: str | None = None,
    credit_col: str | None = None,
    narration_col: str | None = None,
) -> pd.DataFrame:
    """
    Standardizes statement column names, parses dates, and formats debit/credit amounts.
    """
    if df.empty:
        return pd.DataFrame(
            columns=[
                "Date",
                "Date_dt",
                "Narration",
                "Debit",
                "Credit",
                "UTR",
                "Counterparty_VPA",
                "Counterparty_Account",
                "Counterparty_Name",
            ]
        )

    # Resolve column names
    resolved_date = date_col or _detect_column(
        df, ["Date", "Value Date", "Txn Date", "Transaction Date"]
    )
    resolved_narr = narration_col or _detect_column(
        df, ["Narration", "Description", "Particulars", "Remarks"]
    )
    resolved_debit = debit_col or _detect_column(
        df, ["Debit", "Debit Amount", "Withdrawal", "Withdrawal Amount", "DR"]
    )
    resolved_credit = credit_col or _detect_column(
        df, ["Credit", "Credit Amount", "Deposit", "Deposit Amount", "CR"]
    )

    std = pd.DataFrame(index=df.index)

    # Date normalization
    if resolved_date and resolved_date in df.columns:
        std["Date"] = df[resolved_date].astype(str)
        try:
            std["Date_dt"] = pd.to_datetime(df[resolved_date], errors="coerce", format="mixed")
        except Exception:
            std["Date_dt"] = pd.to_datetime(df[resolved_date], errors="coerce")
    else:
        std["Date"] = ""
        std["Date_dt"] = pd.NaT

    # Narration normalization
    if resolved_narr and resolved_narr in df.columns:
        std["Narration"] = df[resolved_narr].fillna("").astype(str).str.strip()
    else:
        std["Narration"] = ""

    # Debit & Credit amounts normalization
    if resolved_debit and resolved_debit in df.columns:
        std["Debit"] = pd.to_numeric(
            df[resolved_debit].astype(str).str.replace(",", "").str.strip(), errors="coerce"
        ).fillna(0.0)
    else:
        std["Debit"] = 0.0

    if resolved_credit and resolved_credit in df.columns:
        std["Credit"] = pd.to_numeric(
            df[resolved_credit].astype(str).str.replace(",", "").str.strip(), errors="coerce"
        ).fillna(0.0)
    else:
        std["Credit"] = 0.0

    # Retain original index for provenance
    std["orig_idx"] = df.index

    # Perform feature extraction
    enriched = extract_banking_features(std, narration_col="Narration")
    return enriched


# =============================================================================
# 3. Match Rule 1: Direct Transactions (A -> B or B -> A)
# =============================================================================


def match_direct_transactions(
    statement_a: pd.DataFrame,
    statement_b: pd.DataFrame,
    *,
    person_a_name: str = "Person A",
    person_b_name: str = "Person B",
    person_a_vpa: str = "",
    person_b_vpa: str = "",
    date_col: str | None = None,
    debit_col: str | None = None,
    credit_col: str | None = None,
    narration_col: str | None = None,
) -> pd.DataFrame:
    """
    Executes Match Rule 1: Identifies explicit 1-to-1 direct transfers between Person A and Person B.

    Logic:
    1. Primary Tier: Merges Statement A's Debits with Statement B's Credits (A -> B) and vice versa (B -> A)
       on the extracted 'UTR' column.
    2. Fallback Tier: For transactions with missing or unmatched UTRs, executes fuzzy matching where:
       Debit Date == Credit Date AND Debit Amount == Credit Amount AND
       (A's Narration contains B's VPA/Name OR B's Narration contains A's VPA/Name).

    Returns:
        pd.DataFrame: Matched direct transfers labeled as 'Direct_Transfer'.
    """
    df_a = _prepare_statement_dataframe(
        statement_a,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )
    df_b = _prepare_statement_dataframe(
        statement_b,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )

    if df_a.empty or df_b.empty:
        return pd.DataFrame(
            columns=[
                "Transfer_Type",
                "Direction",
                "Match_Method",
                "UTR",
                "Amount",
                "Transfer_Date",
                "Sender_Person",
                "Recipient_Person",
                "Sender_Narration",
                "Recipient_Narration",
                "Sender_VPA",
                "Recipient_VPA",
                "Sender_Account",
                "Recipient_Account",
            ]
        )

    matched_records: list[dict[str, Any]] = []

    # Evaluate both directional transfers: A -> B and B -> A
    transfer_scenarios = [
        ("A_TO_B", df_a, df_b, person_a_name, person_b_name, person_a_vpa, person_b_vpa),
        ("B_TO_A", df_b, df_a, person_b_name, person_a_name, person_b_vpa, person_a_vpa),
    ]

    for direction, src_df, dst_df, src_person, dst_person, src_vpa, dst_vpa in transfer_scenarios:
        # Filter source debits and destination credits
        debits = src_df[src_df["Debit"] > 0].copy()
        credits = dst_df[dst_df["Credit"] > 0].copy()

        if debits.empty or credits.empty:
            continue

        matched_debit_indices: set[Any] = set()
        matched_credit_indices: set[Any] = set()

        # ---------------------------------------------------------------------
        # Tier 1: Exact UTR Match
        # ---------------------------------------------------------------------
        utr_debits = debits[debits["UTR"].notna() & (debits["UTR"].str.strip() != "")].copy()
        utr_credits = credits[credits["UTR"].notna() & (credits["UTR"].str.strip() != "")].copy()

        if not utr_debits.empty and not utr_credits.empty:
            merged_utr = pd.merge(
                utr_debits,
                utr_credits,
                on="UTR",
                suffixes=("_debit", "_credit"),
            )

            for _, row in merged_utr.iterrows():
                matched_debit_indices.add(row["orig_idx_debit"])
                matched_credit_indices.add(row["orig_idx_credit"])
                amount_val = float(row.get("Debit_debit", row.get("Debit", 0.0)))
                matched_records.append(
                    {
                        "Transfer_Type": "Direct_Transfer",
                        "Direction": direction,
                        "Match_Method": "UTR_EXACT",
                        "UTR": row["UTR"],
                        "Amount": amount_val,
                        "Transfer_Date": str(row["Date_debit"] or row["Date_credit"]),
                        "Sender_Person": src_person,
                        "Recipient_Person": dst_person,
                        "Sender_Narration": row["Narration_debit"],
                        "Recipient_Narration": row["Narration_credit"],
                        "Sender_VPA": row.get("Counterparty_VPA_debit"),
                        "Recipient_VPA": row.get("Counterparty_VPA_credit"),
                        "Sender_Account": row.get("Counterparty_Account_debit"),
                        "Recipient_Account": row.get("Counterparty_Account_credit"),
                    }
                )

        # ---------------------------------------------------------------------
        # Tier 2: Fallback Fuzzy Match (Missing/Null UTR)
        # ---------------------------------------------------------------------
        rem_debits = debits[~debits["orig_idx"].isin(matched_debit_indices)].copy()
        rem_credits = credits[~credits["orig_idx"].isin(matched_credit_indices)].copy()

        if rem_debits.empty or rem_credits.empty:
            continue

        # Match on Date equality and Amount equality
        merged_fallback = pd.merge(
            rem_debits,
            rem_credits,
            left_on=["Date", "Debit"],
            right_on=["Date", "Credit"],
            suffixes=("_debit", "_credit"),
        )

        if merged_fallback.empty:
            continue

        # Narration cross-check:
        # A's narration contains B's VPA/Name OR B's narration contains A's VPA/Name
        dst_name_clean = dst_person.lower().strip()
        src_name_clean = src_person.lower().strip()
        dst_vpa_clean = dst_vpa.lower().strip()
        src_vpa_clean = src_vpa.lower().strip()

        for _, row in merged_fallback.iterrows():
            narr_d = str(row["Narration_debit"]).lower()
            narr_c = str(row["Narration_credit"]).lower()
            vpa_d = str(row.get("Counterparty_VPA_debit") or "").lower()
            vpa_c = str(row.get("Counterparty_VPA_credit") or "").lower()
            name_d = str(row.get("Counterparty_Name_debit") or "").lower()
            name_c = str(row.get("Counterparty_Name_credit") or "").lower()

            is_direct_narr_match = False

            # Check if Sender narration references Recipient
            if dst_name_clean and (dst_name_clean in narr_d or dst_name_clean in name_d):
                is_direct_narr_match = True
            elif dst_vpa_clean and (dst_vpa_clean in narr_d or dst_vpa_clean in vpa_d):
                is_direct_narr_match = True

            # Check if Recipient narration references Sender
            if src_name_clean and (src_name_clean in narr_c or src_name_clean in name_c):
                is_direct_narr_match = True
            elif src_vpa_clean and (src_vpa_clean in narr_c or src_vpa_clean in vpa_c):
                is_direct_narr_match = True

            if is_direct_narr_match:
                matched_records.append(
                    {
                        "Transfer_Type": "Direct_Transfer",
                        "Direction": direction,
                        "Match_Method": "FALLBACK_FUZZY",
                        "UTR": row.get("UTR_debit") or row.get("UTR_credit") or "N/A",
                        "Amount": float(row.get("Debit_debit", row.get("Debit", 0.0))),
                        "Transfer_Date": str(row.get("Date_debit") or row.get("Date")),
                        "Sender_Person": src_person,
                        "Recipient_Person": dst_person,
                        "Sender_Narration": row["Narration_debit"],
                        "Recipient_Narration": row["Narration_credit"],
                        "Sender_VPA": row.get("Counterparty_VPA_debit"),
                        "Recipient_VPA": row.get("Counterparty_VPA_credit"),
                        "Sender_Account": row.get("Counterparty_Account_debit"),
                        "Recipient_Account": row.get("Counterparty_Account_credit"),
                    }
                )

    if not matched_records:
        return pd.DataFrame(
            columns=[
                "Transfer_Type",
                "Direction",
                "Match_Method",
                "UTR",
                "Amount",
                "Transfer_Date",
                "Sender_Person",
                "Recipient_Person",
                "Sender_Narration",
                "Recipient_Narration",
                "Sender_VPA",
                "Recipient_VPA",
                "Sender_Account",
                "Recipient_Account",
            ]
        )

    return pd.DataFrame(matched_records)


# =============================================================================
# 4. Match Rule 2: Intermediate Transactions (A -> X -> B)
# =============================================================================


def match_intermediate_transactions(
    statement_a: pd.DataFrame,
    statement_b: pd.DataFrame,
    *,
    person_a_name: str = "Person A",
    person_b_name: str = "Person B",
    bidirectional: bool = True,
    time_window_days: int = 0,
    direct_matched_utrs: set[str] | None = None,
    date_col: str | None = None,
    debit_col: str | None = None,
    credit_col: str | None = None,
    narration_col: str | None = None,
) -> pd.DataFrame:
    """
    Executes Match Rule 2: Network Overlap Analysis to identify 1-hop suspected intermediaries (Person X).

    Evaluates intermediate pass-through conduits:
    - Direction A -> B: Person A debits to X, Person B credits from X.
    - Direction B -> A (if bidirectional=True): Person B debits to X, Person A credits from X.

    Applies Tiered Temporal Flagging:
    - delta_hours <= 24: High Risk (Rapid Layering)
    - 24 < delta_hours <= 72: Medium Risk (Delayed Pass-Through)
    """
    df_a = _prepare_statement_dataframe(
        statement_a,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )
    df_b = _prepare_statement_dataframe(
        statement_b,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )

    empty_cols = [
        "Transfer_Type",
        "Direction",
        "Sender_Person",
        "Recipient_Person",
        "Intermediary_Entity",
        "Outflow_Date",
        "Inflow_Date",
        "Time_Delta_Days",
        "Time_Delta_Hours",
        "Risk_Level",
        "Layering_Type",
        "Outflow_Amount",
        "Inflow_Amount",
        "Retention_Amount",
        "Retention_Pct",
        "Outflow_UTR",
        "Inflow_UTR",
        "Outflow_Narration",
        "Inflow_Narration",
        "Outflow_VPA",
        "Inflow_VPA",
        "Outflow_Account",
        "Inflow_Account",
    ]

    if df_a.empty or df_b.empty:
        return pd.DataFrame(columns=empty_cols)

    direct_matched_utrs = {
        str(u).strip().upper() for u in (direct_matched_utrs or set()) if str(u).strip()
    }

    # Evaluate directions
    transfer_scenarios = [
        ("A_TO_B", df_a, df_b, person_a_name, person_b_name),
    ]
    if bidirectional:
        transfer_scenarios.append(("B_TO_A", df_b, df_a, person_b_name, person_a_name))

    def derive_counterparty_key(row: pd.Series) -> str | None:
        vpa = str(row.get("Counterparty_VPA") or "").strip().lower()
        if vpa and vpa != "none" and vpa != "nan" and "@" in vpa:
            return vpa
        name = str(row.get("Counterparty_Name") or "").strip().upper()
        if name and name != "NONE" and name != "NAN" and len(name) >= 3:
            return name
        return None

    matched_dfs: list[pd.DataFrame] = []

    for direction, src_df, dst_df, src_person, dst_person in transfer_scenarios:
        # Step 1: Subsets of Source Debits (src -> X) and Destination Credits (X -> dst)
        src_debits = src_df[src_df["Debit"] > 0].copy()
        dst_credits = dst_df[dst_df["Credit"] > 0].copy()

        # Exclude direct transfers already identified
        if direct_matched_utrs:
            src_debits = src_debits[~src_debits["UTR"].isin(direct_matched_utrs)]
            dst_credits = dst_credits[~dst_credits["UTR"].isin(direct_matched_utrs)]

        if src_debits.empty or dst_credits.empty:
            continue

        # Step 2: Establish robust Intermediary Identifier Key
        src_debits["Intermediary_Key"] = src_debits.apply(derive_counterparty_key, axis=1)
        dst_credits["Intermediary_Key"] = dst_credits.apply(derive_counterparty_key, axis=1)

        src_valid = src_debits[src_debits["Intermediary_Key"].notna()].copy()
        dst_valid = dst_credits[dst_credits["Intermediary_Key"].notna()].copy()

        if src_valid.empty or dst_valid.empty:
            continue

        # Step 3: Find intersection of counterparties present in both sets
        counterparties_src = set(src_valid["Intermediary_Key"].unique())
        counterparties_dst = set(dst_valid["Intermediary_Key"].unique())
        candidate_x_set = counterparties_src.intersection(counterparties_dst)

        if not candidate_x_set:
            continue

        logger.info(
            f"Direction {direction}: Identified {len(candidate_x_set)} candidate intermediary entities: {candidate_x_set}"
        )

        src_candidates = src_valid[src_valid["Intermediary_Key"].isin(candidate_x_set)].copy()
        dst_candidates = dst_valid[dst_valid["Intermediary_Key"].isin(candidate_x_set)].copy()

        # Step 4: Vectorized Temporal & Value Constraint Matching
        merged = pd.merge(
            src_candidates,
            dst_candidates,
            on="Intermediary_Key",
            suffixes=("_outflow", "_inflow"),
        )

        if merged.empty:
            continue

        # Inflow to dst must occur on or after Outflow from src
        time_delta = (
            merged["Date_dt_inflow"] - merged["Date_dt_outflow"]
        ).dt.total_seconds() / 86400.0

        if time_window_days and time_window_days > 0:
            valid_mask = (
                (time_delta >= 0.0)
                & (time_delta <= float(time_window_days))
                & (merged["Credit_inflow"] <= merged["Debit_outflow"])
            )
        else:
            valid_mask = (time_delta >= 0.0) & (merged["Credit_inflow"] <= merged["Debit_outflow"])

        matched = merged[valid_mask].copy()
        if matched.empty:
            continue

        # Build standardized output schema with tiered temporal flags
        matched["Transfer_Type"] = "Intermediate_Transfer"
        matched["Direction"] = direction
        matched["Sender_Person"] = src_person
        matched["Recipient_Person"] = dst_person
        matched["Intermediary_Entity"] = matched["Intermediary_Key"]
        matched["Outflow_Date"] = matched["Date_outflow"]
        matched["Inflow_Date"] = matched["Date_inflow"]
        matched["Time_Delta_Days"] = time_delta[valid_mask].round(2)
        delta_hours = (time_delta[valid_mask] * 24.0).round(1)
        matched["Time_Delta_Hours"] = delta_hours
        matched["Risk_Level"] = np.where(delta_hours <= 24.0, "HIGH", "MEDIUM")
        matched["Layering_Type"] = np.where(
            delta_hours <= 24.0, "RAPID_LAYERING", "DELAYED_PASS_THROUGH"
        )
        matched["Outflow_Amount"] = matched["Debit_outflow"].astype(float)
        matched["Inflow_Amount"] = matched["Credit_inflow"].astype(float)
        matched["Retention_Amount"] = (matched["Outflow_Amount"] - matched["Inflow_Amount"]).round(
            2
        )
        matched["Retention_Pct"] = (
            np.where(
                matched["Outflow_Amount"] > 0,
                (matched["Retention_Amount"] / matched["Outflow_Amount"]) * 100.0,
                0.0,
            )
        ).round(2)

        matched["Outflow_UTR"] = matched["UTR_outflow"].fillna("N/A")
        matched["Inflow_UTR"] = matched["UTR_inflow"].fillna("N/A")
        matched["Outflow_Narration"] = matched["Narration_outflow"]
        matched["Inflow_Narration"] = matched["Narration_inflow"]
        matched["Outflow_VPA"] = matched["Counterparty_VPA_outflow"]
        matched["Inflow_VPA"] = matched["Counterparty_VPA_inflow"]
        matched["Outflow_Account"] = matched["Counterparty_Account_outflow"]
        matched["Inflow_Account"] = matched["Counterparty_Account_inflow"]

        matched_dfs.append(matched[empty_cols])

    if not matched_dfs:
        return pd.DataFrame(columns=empty_cols)

    final_df = pd.concat(matched_dfs, ignore_index=True)
    final_df = final_df.sort_values(
        by=["Intermediary_Entity", "Outflow_Date", "Inflow_Date"]
    ).reset_index(drop=True)
    return final_df


def group_intermediate_transfers_by_intermediary(
    intermediate_df: pd.DataFrame,
) -> dict[str, list[dict[str, Any]]]:
    """
    Groups matched intermediate transfer records by the identified candidate intermediary (Person X).

    Args:
        intermediate_df: Output DataFrame from match_intermediate_transactions.

    Returns:
        dict[str, list[dict]]: Dictionary keyed by intermediary entity name/VPA.
    """
    if intermediate_df.empty or "Intermediary_Entity" not in intermediate_df.columns:
        return {}

    grouped_dict: dict[str, list[dict[str, Any]]] = {}
    for intermediary, group in intermediate_df.groupby("Intermediary_Entity"):
        grouped_dict[str(intermediary)] = group.to_dict(orient="records")

    return grouped_dict


# =============================================================================
# 5. Master Orchestrator: Comprehensive Reconciliation & Network Matching
# =============================================================================


def reconcile_and_match_network(
    statement_a: pd.DataFrame,
    statement_b: pd.DataFrame,
    *,
    person_a_name: str = "Person A",
    person_b_name: str = "Person B",
    person_a_vpa: str = "",
    person_b_vpa: str = "",
    time_window_days: int = 0,
    date_col: str | None = None,
    debit_col: str | None = None,
    credit_col: str | None = None,
    narration_col: str | None = None,
) -> dict[str, Any]:
    """
    Master pipeline orchestrating Match Rule 1 (Direct) and Match Rule 2 (Intermediate) transfers.

    Returns comprehensive forensic dossier:
    - direct_transfers: DataFrame of direct 1-to-1 transactions (A -> B and B -> A)
    - intermediate_transfers: DataFrame of 1-hop pass-through paths (A -> X -> B)
    - grouped_intermediaries: Dictionary of matched pairs grouped by Candidate X
    - metrics: Statistical summary of fund flows, retention, and network hops
    """
    # 1. Match Direct Transactions (Rule 1)
    direct_df = match_direct_transactions(
        statement_a,
        statement_b,
        person_a_name=person_a_name,
        person_b_name=person_b_name,
        person_a_vpa=person_a_vpa,
        person_b_vpa=person_b_vpa,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )

    # Collect matched UTRs so they are excluded from intermediate hops
    direct_utrs = set()
    if not direct_df.empty and "UTR" in direct_df.columns:
        direct_utrs = {
            str(u).strip().upper() for u in direct_df["UTR"] if str(u).strip() and str(u) != "N/A"
        }

    # 2. Match Intermediate Transactions (Rule 2 - Bidirectional)
    intermediate_df = match_intermediate_transactions(
        statement_a,
        statement_b,
        person_a_name=person_a_name,
        person_b_name=person_b_name,
        bidirectional=True,
        time_window_days=time_window_days,
        direct_matched_utrs=direct_utrs,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )

    # 3. Group intermediate transfers by intermediary
    grouped_intermediaries = group_intermediate_transfers_by_intermediary(intermediate_df)

    # 4. Compile Forensic Summary Metrics
    total_direct_vol = float(direct_df["Amount"].sum()) if not direct_df.empty else 0.0
    total_outflow_inter = (
        float(intermediate_df["Outflow_Amount"].sum()) if not intermediate_df.empty else 0.0
    )
    total_inflow_inter = (
        float(intermediate_df["Inflow_Amount"].sum()) if not intermediate_df.empty else 0.0
    )
    total_retained_inter = (
        float(intermediate_df["Retention_Amount"].sum()) if not intermediate_df.empty else 0.0
    )

    metrics = {
        "total_direct_transfers_count": len(direct_df),
        "total_direct_volume_inr": round(total_direct_vol, 2),
        "total_intermediate_hops_count": len(intermediate_df),
        "total_outflow_to_intermediaries_inr": round(total_outflow_inter, 2),
        "total_inflow_from_intermediaries_inr": round(total_inflow_inter, 2),
        "total_retained_by_intermediaries_inr": round(total_retained_inter, 2),
        "unique_intermediaries_count": len(grouped_intermediaries),
        "unique_intermediaries_list": sorted(grouped_intermediaries.keys()),
    }

    return {
        "status": "success",
        "direct_transfers": direct_df,
        "intermediate_transfers": intermediate_df,
        "grouped_intermediaries": grouped_intermediaries,
        "metrics": metrics,
    }


def detect_rapid_layering_for_profile(
    statement: pd.DataFrame,
    *,
    account_holder_name: str = "Account Holder",
    time_window_days: int = 1,
    date_col: str | None = None,
    debit_col: str | None = None,
    credit_col: str | None = None,
    narration_col: str | None = None,
) -> pd.DataFrame:
    """
    Detects Rapid Layering (Immediate Hop Pass-Through):
    Identifies transactions where an inflow (Credit > 0) is followed within hours or the same day
    (<= time_window_days) by rapid outflows (Debit > 0) to third-party counterparties.
    """
    df = _prepare_statement_dataframe(
        statement,
        date_col=date_col,
        debit_col=debit_col,
        credit_col=credit_col,
        narration_col=narration_col,
    )
    if df.empty:
        return pd.DataFrame()

    inflows = df[df["Credit"] > 0].copy()
    outflows = df[df["Debit"] > 0].copy()

    if inflows.empty or outflows.empty:
        return pd.DataFrame()

    def _clean_party(name_val, vpa_val, narr_val):
        for candidate in [name_val, vpa_val]:
            cand_str = str(candidate or "").strip()
            if cand_str and cand_str.upper() not in ("UNKNOWN", "NONE", "NAN", ""):
                return cand_str
        # Fallback to narration extraction
        n = str(narr_val or "").strip()
        if "/" in n:
            tokens = [t.strip() for t in n.split("/") if t.strip()]
            for tok in tokens:
                if "@" in tok:
                    return tok
                if (
                    len(tok) > 3
                    and not tok.isdigit()
                    and tok.upper() not in ("UPI", "IN", "OUT", "TFR")
                ):
                    return tok
        return "Unknown Counterparty"

    records = []
    for _, in_row in inflows.iterrows():
        in_amt = float(in_row["Credit"])
        in_date_str = str(in_row.get("Date", ""))
        in_date_dt = in_row.get("Date_dt")
        in_party = _clean_party(
            in_row.get("Counterparty_Name"),
            in_row.get("Counterparty_VPA"),
            in_row.get("Narration"),
        )

        for _, out_row in outflows.iterrows():
            out_amt = float(out_row["Debit"])
            out_date_str = str(out_row.get("Date", ""))
            out_date_dt = out_row.get("Date_dt")
            out_party = _clean_party(
                out_row.get("Counterparty_Name"),
                out_row.get("Counterparty_VPA"),
                out_row.get("Narration"),
            )

            if (
                in_party.lower() == out_party.lower()
                or out_party.lower() == account_holder_name.lower()
            ):
                continue

            # Temporal match: same date string or within time_window_days
            is_temporal_match = False
            delta_hours = 0.0

            if pd.notna(in_date_dt) and pd.notna(out_date_dt):
                delta_sec = (out_date_dt - in_date_dt).total_seconds()
                if time_window_days and time_window_days > 0:
                    if 0 <= delta_sec <= (time_window_days * 86400):
                        is_temporal_match = True
                        delta_hours = round(max(0.1, delta_sec / 3600.0), 1)
                else:
                    if delta_sec >= 0:
                        is_temporal_match = True
                        delta_hours = round(max(0.1, delta_sec / 3600.0), 1)
            elif in_date_str and out_date_str and in_date_str == out_date_str:
                is_temporal_match = True
                delta_hours = 0.5

            if is_temporal_match:
                retention_amt = max(0.0, in_amt - out_amt)
                retention_pct = round((retention_amt / in_amt * 100.0) if in_amt > 0 else 0.0, 1)

                records.append(
                    {
                        "Transfer_Type": "Rapid_Layering",
                        "Match_Method": "TEMPORAL_RAPID_LAYERING",
                        "Sender_Person": in_party,
                        "Intermediary_Entity": account_holder_name,
                        "Recipient_Person": out_party,
                        "Inflow_Date": in_date_str,
                        "Outflow_Date": out_date_str,
                        "Inflow_Amount": in_amt,
                        "Outflow_Amount": out_amt,
                        "Retention_Amount": retention_amt,
                        "Retention_Pct": retention_pct,
                        "Time_Delta_Hours": delta_hours,
                        "Inflow_Narration": in_row.get("Narration", ""),
                        "Outflow_Narration": out_row.get("Narration", ""),
                        "Inflow_UTR": in_row.get("UTR", "N/A"),
                        "Outflow_UTR": out_row.get("UTR", "N/A"),
                        "Inflow_VPA": in_row.get("Counterparty_VPA", ""),
                        "Outflow_VPA": out_row.get("Counterparty_VPA", ""),
                    }
                )

    if not records:
        return pd.DataFrame()

    res_df = pd.DataFrame(records)
    return res_df.drop_duplicates(
        subset=[
            "Sender_Person",
            "Recipient_Person",
            "Inflow_Date",
            "Outflow_Date",
            "Outflow_Amount",
        ]
    ).reset_index(drop=True)

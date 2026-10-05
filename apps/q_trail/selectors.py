"""
Q-Trail Selectors (Read-Only Analytical Queries)
=============================================================================
Provides read-only database queries, profile statement extraction,
N+1 query elimination, and interactive Plotly Dark Sankey diagram generators.
Strictly adheres to agentic-django guidelines: no mutations, pure read functions.
=============================================================================
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any

import pandas as pd
import plotly.graph_objects as go
from django.db.models import Count, QuerySet
from loguru import logger
from q_bank.models import AuditedPerson, BankTransaction

from core.models import InvestigationProfile

from .models import CaseDossier, FundTrailPath


def get_available_profiles_for_trail(
    audit_id: str | uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    """
    Retrieves investigation auditees and profiles available for money trail mapping,
    annotating each with bank account counts, transaction counts, and financial institutions.
    If audit_id is provided, scopes exclusively to profiles mapped to that audit.
    """
    mapped_profile_names: set[str] = set()
    mapped_profile_ids: set[str] = set()
    if audit_id:
        from core.audits import get_audit_by_id

        audit = get_audit_by_id(audit_id)
        if audit:
            mapped_profile_names = {p.full_name.strip().lower() for p in audit.profiles.all()}
            mapped_profile_ids = {str(p.id) for p in audit.profiles.all()}

    persons = (
        AuditedPerson.objects.prefetch_related("bank_accounts__transactions")
        .annotate(
            total_accounts_count=Count("bank_accounts", distinct=True),
        )
        .order_by("full_name")
    )

    profiles_data: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for person in persons:
        if audit_id and person.full_name.strip().lower() not in mapped_profile_names:
            continue

        accounts = list(person.bank_accounts.all())
        txns_count = sum(a.transactions.count() for a in accounts)
        banks = sorted({a.bank_name for a in accounts if a.bank_name})
        tot_debit = sum((a.total_debit for a in accounts), Decimal("0.00"))
        tot_credit = sum((a.total_credit for a in accounts), Decimal("0.00"))

        seen_ids.add(str(person.id))
        profiles_data.append(
            {
                "id": str(person.id),
                "person_id": str(person.id),
                "name": person.full_name,
                "department": person.department or "General Audit",
                "designation": person.designation or "Auditee",
                "employee_id": person.employee_id or "-",
                "accounts_count": len(accounts),
                "transactions_count": txns_count,
                "banks": banks,
                "total_debit": float(tot_debit),
                "total_credit": float(tot_credit),
                "has_data": txns_count > 0,
            }
        )

    # Cross-reference with core InvestigationProfile in case some profiles don't yet have an AuditedPerson
    core_profiles = InvestigationProfile.objects.all().order_by("full_name")
    if audit_id:
        core_profiles = core_profiles.filter(id__in=mapped_profile_ids)
    for cp in core_profiles:
        # Check if already added via matching name or ID
        if not any(p["name"].lower() == cp.full_name.lower() for p in profiles_data):
            profiles_data.append(
                {
                    "id": str(cp.id),
                    "person_id": str(cp.id),
                    "name": cp.full_name,
                    "department": cp.department or "Investigation",
                    "designation": cp.designation or "Subject",
                    "employee_id": cp.employee_id or "-",
                    "accounts_count": 0,
                    "transactions_count": 0,
                    "banks": [],
                    "total_debit": 0.0,
                    "total_credit": 0.0,
                    "has_data": False,
                }
            )

    return profiles_data


def get_transactions_df_for_profile(
    person_id: str | uuid.UUID | None,
    *,
    limit: int = 10000,
) -> pd.DataFrame:
    """
    Fetches all bank statement transactions for a specific profile / auditee,
    standardizing them into a pandas DataFrame ready for feature extraction and matching.
    """
    empty_df = pd.DataFrame(
        columns=[
            "Date",
            "Narration",
            "Debit",
            "Credit",
            "Bank_Name",
            "Account_Number",
            "Party_Name",
            "Txn_Ref",
        ]
    )

    if not person_id:
        return empty_df

    # First attempt lookup by AuditedPerson ID
    auditee = None
    try:
        auditee = AuditedPerson.objects.filter(id=person_id).first()
    except (ValueError, TypeError):
        pass

    # Fallback attempt: match via InvestigationProfile ID
    if not auditee:
        try:
            core_prof = InvestigationProfile.objects.filter(id=person_id).first()
            if core_prof:
                auditee = AuditedPerson.objects.filter(
                    full_name__iexact=core_prof.full_name
                ).first()
                if not auditee:
                    auditee = AuditedPerson.objects.filter(
                        full_name__icontains=core_prof.full_name.split()[0]
                    ).first()
        except Exception as e:
            logger.debug(f"Profile lookup fallback error: {e}")

    if not auditee:
        return empty_df

    # Query all transactions linked to any bank account of this auditee
    qs = (
        BankTransaction.objects.filter(account__person=auditee)
        .select_related("account")
        .order_by("txn_date", "created_at")
    )

    if limit > 0:
        qs = qs[:limit]

    records: list[dict[str, Any]] = []
    for t in qs:
        # Standardize transaction date
        date_str = ""
        if t.txn_date:
            date_str = t.txn_date.strftime("%Y-%m-%d")
        elif t.value_date:
            date_str = t.value_date.strftime("%Y-%m-%d")

        records.append(
            {
                "Date": date_str,
                "Narration": str(t.narration or "").strip(),
                "Debit": float(t.debit_amount or 0.0),
                "Credit": float(t.credit_amount or 0.0),
                "Bank_Name": str(t.account.bank_name or "").strip(),
                "Account_Number": str(t.account.account_number or "").strip(),
                "Party_Name": str(t.party_name or "").strip(),
                "Txn_Ref": str(t.txn_ref or "").strip(),
            }
        )

    if not records:
        return empty_df

    df = pd.DataFrame(records)
    return df


def generate_trail_sankey_chart(
    direct_df: pd.DataFrame,
    intermediate_df: pd.DataFrame,
    *,
    height: int = 500,
) -> str:
    """
    Generates an interactive Plotly Dark Sankey diagram visualizing fund flows:
    - Direct: Source Profile -> Destination Profile
    - 1-Hop Intermediate: Source Profile -> Intermediary X -> Destination Profile

    Strictly satisfies q_trail/INSTRUCTION.md:
    template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)'.
    """
    if direct_df.empty and intermediate_df.empty:
        # Generate an elegant empty state placeholder figure
        fig = go.Figure()
        fig.add_annotation(
            text="No fund flow links detected between the selected profiles.<br>Adjust profile selection or time window.",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font={"size": 14, "color": "#94a3b8"},
        )
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=height,
            margin={"l": 20, "r": 20, "t": 20, "b": 20},
        )
        return fig.to_html(include_plotlyjs=False, full_html=False)

    # Establish node index registry
    node_names: list[str] = []
    node_map: dict[str, int] = {}
    node_colors: list[str] = []

    def get_or_create_node(name: str, node_type: str = "subject") -> int:
        clean_name = str(name).strip()
        if clean_name not in node_map:
            idx = len(node_names)
            node_map[clean_name] = idx
            node_names.append(clean_name)
            if node_type == "subject":
                node_colors.append("#38bdf8")  # Sky Blue for Primary Auditees
            elif node_type == "intermediary":
                node_colors.append("#f59e0b")  # Amber / Gold for Candidate Intermediaries
            else:
                node_colors.append("#34d399")  # Emerald Green for Beneficiaries
            return idx
        return node_map[clean_name]

    sources: list[int] = []
    targets: list[int] = []
    values: list[float] = []
    link_labels: list[str] = []
    link_colors: list[str] = []

    # 1. Process Direct Transfers (Source -> Destination)
    if not direct_df.empty:
        for _, row in direct_df.iterrows():
            src_name = str(row.get("Sender_Person") or "Source").strip()
            dst_name = str(row.get("Recipient_Person") or "Destination").strip()
            amt = float(row.get("Amount") or 0.0)
            if amt <= 0:
                continue

            src_idx = get_or_create_node(src_name, "subject")
            dst_idx = get_or_create_node(dst_name, "destination")

            sources.append(src_idx)
            targets.append(dst_idx)
            values.append(amt)
            method = str(row.get("Match_Method", "Direct"))
            utr = str(row.get("UTR", "N/A"))
            link_labels.append(f"Direct ({method}) | ₹{amt:,.2f} | UTR: {utr}")
            # Semi-transparent Emerald for direct transfers
            link_colors.append("rgba(16, 185, 129, 0.45)")

    # 2. Process Intermediate Transfers (Source -> Intermediary X -> Destination)
    if not intermediate_df.empty:
        for _, row in intermediate_df.iterrows():
            inter_name = str(row.get("Intermediary_Entity") or "Conduit X").strip()
            src_name = str(row.get("Sender_Person") or "Originator").strip()
            dst_name = str(row.get("Recipient_Person") or "Beneficiary").strip()

            outflow_amt = float(row.get("Outflow_Amount") or 0.0)
            inflow_amt = float(row.get("Inflow_Amount") or 0.0)

            if outflow_amt <= 0:
                continue

            src_idx = get_or_create_node(src_name, "subject")
            inter_idx = get_or_create_node(f"[X] {inter_name}", "intermediary")
            dst_idx = get_or_create_node(dst_name, "destination")

            # Hop 1: Originator -> Intermediary X
            sources.append(src_idx)
            targets.append(inter_idx)
            values.append(outflow_amt)
            link_labels.append(f"Outflow to Conduit | ₹{outflow_amt:,.2f}")
            link_colors.append("rgba(245, 158, 11, 0.45)")  # Amber

            # Hop 2: Intermediary X -> Beneficiary
            if inflow_amt > 0:
                sources.append(inter_idx)
                targets.append(dst_idx)
                values.append(inflow_amt)
                ret_amt = float(row.get("Retention_Amount") or 0.0)
                link_labels.append(
                    f"Pass-Through Inflow | ₹{inflow_amt:,.2f} (Retained: ₹{ret_amt:,.2f})"
                )
                link_colors.append("rgba(234, 88, 12, 0.45)")  # Orange

    fig = go.Figure(
        data=[
            go.Sankey(
                node={
                    "pad": 18,
                    "thickness": 20,
                    "line": {"color": "rgba(255,255,255,0.2)", "width": 1},
                    "label": node_names,
                    "color": node_colors,
                },
                link={
                    "source": sources,
                    "target": targets,
                    "value": values,
                    "color": link_colors,
                    "customdata": link_labels,
                    "hovertemplate": "%{customdata}<extra></extra>",
                },
            )
        ]
    )

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#e2e8f0", "family": "Inter, sans-serif", "size": 12},
        height=height,
        margin={"l": 25, "r": 25, "t": 25, "b": 25},
    )

    return fig.to_html(include_plotlyjs=False, full_html=False)


def get_all_trail_cases() -> QuerySet[CaseDossier]:
    """
    Returns all forensic case dossiers ordered by latest update.
    """
    return CaseDossier.objects.all().order_by("-updated_at")


def get_trail_paths_by_case(case_id: str | uuid.UUID) -> QuerySet[FundTrailPath]:
    """
    Retrieves stitched fund trail paths for a specific case with prefetched nodes.
    """
    return (
        FundTrailPath.objects.filter(case_id=case_id)
        .select_related("case")
        .prefetch_related("pass_through_nodes")
        .order_by("-total_amount")
    )

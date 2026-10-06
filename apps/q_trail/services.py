"""
Q-Trail Business Logic & Service Mutations
=============================================================================
Orchestrates multi-profile money trail analysis across banking institutions:
1. Resolves profile transactions from Q-Bank ledger.
2. Vectorized reconciliation across multiple profiles (A -> B, B -> A).
3. Network intersection and 1-hop pass-through mapping (A -> X -> B).
4. Circular round-tripping loop detection.
5. Atomic persistence of investigation dossiers and stitched trail paths.
=============================================================================
"""

from __future__ import annotations

import itertools
import uuid
from decimal import Decimal
from typing import Any

import pandas as pd
from django.db import transaction
from django.utils import timezone
from loguru import logger
from q_bank.models import AuditedPerson

from core.models import InvestigationProfile

from .backend.reconciliation import (
    group_intermediate_transfers_by_intermediary,
    reconcile_and_match_network,
)
from .backend.workstation_builder import (
    build_chronological_beats,
    build_conduit_deck,
    build_topology_graph,
)
from .models import CaseDossier, FundTrailPath, PassThroughNode
from .selectors import get_transactions_df_for_profile


def _resolve_profile_entity(profile_id: str | uuid.UUID) -> tuple[str, str]:
    """
    Resolves canonical display name and entity identifier for an auditee/profile ID.
    Returns (resolved_name, resolved_id).
    """
    clean_id = str(profile_id).strip()
    try:
        person = AuditedPerson.objects.filter(id=clean_id).first()
        if person:
            return person.full_name, str(person.id)
    except Exception as e:
        logger.debug("Failed resolving AuditedPerson for {}: {}", clean_id, e)

    try:
        core_prof = InvestigationProfile.objects.filter(id=clean_id).first()
        if core_prof:
            matched_person = AuditedPerson.objects.filter(
                full_name__iexact=core_prof.full_name
            ).first()
            if matched_person:
                return matched_person.full_name, str(matched_person.id)
            return core_prof.full_name, str(core_prof.id)
    except Exception as e:
        logger.debug("Failed resolving InvestigationProfile for {}: {}", clean_id, e)

    return f"Profile {clean_id[:8]}", clean_id


def analyze_profiles_money_trail(
    profile_ids: list[str],
    *,
    time_window_days: int = 0,
    case_title: str = "",
    lead_investigator: str = "",
    save_dossier: bool = False,
) -> dict[str, Any]:
    """
    Executes forensic money trail and network reconciliation across a user-specified
    list of investigation profiles / auditees.

    Analyzes:
    - Direct 1-to-1 transfers between all pairs of selected profiles (bidirectional).
    - 1-hop intermediate pass-through conduits (Person A -> Conduit X -> Person B).
    - Circular round-tripping flows where funds loop back to an originator.

    Args:
        profile_ids: List of profile or AuditedPerson UUID strings.
        time_window_days: Maximum elapsed days between conduit outflow and inflow.
        case_title: Optional title if saving a forensic case dossier.
        lead_investigator: Optional name of the investigator.
        save_dossier: Whether to persist the generated paths in the database.

    Returns:
        dict[str, Any]: Comprehensive dossier containing DataFrames, metrics, and network graph data.
    """
    unique_profile_ids = list(
        dict.fromkeys([str(p).strip() for p in profile_ids if str(p).strip()])
    )

    empty_result = {
        "status": "success",
        "direct_transfers": pd.DataFrame(),
        "intermediate_transfers": pd.DataFrame(),
        "grouped_intermediaries": {},
        "circular_trails": [],
        "chronological_beats": [],
        "conduit_deck": [],
        "topology_graph": {
            "W": 1060,
            "H": 580,
            "R": 18,
            "nodes": [],
            "edges": [],
            "plates": [],
            "cols": [],
        },
        "metrics": {
            "total_profiles_analyzed": len(unique_profile_ids),
            "total_transactions_analyzed": 0,
            "total_direct_transfers_count": 0,
            "total_direct_volume_inr": 0.0,
            "total_intermediate_hops_count": 0,
            "total_outflow_to_intermediaries_inr": 0.0,
            "total_inflow_from_intermediaries_inr": 0.0,
            "total_retained_by_intermediaries_inr": 0.0,
            "unique_intermediaries_count": 0,
            "unique_intermediaries_list": [],
            "circular_paths_count": 0,
            "trail_keywords_count": 0,
            "keyword_hits_count": 0,
        },
        "trail_keywords": [],
        "analyzed_profiles": [],
    }

    if len(unique_profile_ids) < 2:
        logger.info("Fewer than 2 profiles supplied to Q-Trail; returning empty baseline.")
        return empty_result

    # 1. Fetch statement DataFrames and metadata for each selected profile
    profile_metadata: list[dict[str, Any]] = []
    profile_dfs: dict[str, pd.DataFrame] = {}
    total_txns_count = 0

    for pid in unique_profile_ids:
        name, resolved_id = _resolve_profile_entity(pid)
        df = get_transactions_df_for_profile(resolved_id)
        profile_dfs[resolved_id] = df
        txns_len = len(df)
        total_txns_count += txns_len
        tot_debit = float(df["Debit"].sum()) if not df.empty and "Debit" in df.columns else 0.0
        tot_credit = float(df["Credit"].sum()) if not df.empty and "Credit" in df.columns else 0.0

        profile_metadata.append(
            {
                "id": resolved_id,
                "name": name,
                "transactions_count": txns_len,
                "total_debit": tot_debit,
                "total_credit": tot_credit,
            }
        )

    # 2. Pairwise Reconciliation & Intermediate Conduit Mapping
    direct_records_list: list[pd.DataFrame] = []
    intermediate_records_list: list[pd.DataFrame] = []

    # Iterate over all ordered pairs (A, B) where A != B
    for (pid_a, df_a), (pid_b, df_b) in itertools.permutations(profile_dfs.items(), 2):
        if df_a.empty or df_b.empty:
            continue

        name_a = next((p["name"] for p in profile_metadata if p["id"] == pid_a), "Person A")
        name_b = next((p["name"] for p in profile_metadata if p["id"] == pid_b), "Person B")

        # Reconcile pair
        res = reconcile_and_match_network(
            statement_a=df_a,
            statement_b=df_b,
            person_a_name=name_a,
            person_b_name=name_b,
            time_window_days=time_window_days,
        )

        d_df = res.get("direct_transfers")
        if isinstance(d_df, pd.DataFrame) and not d_df.empty:
            direct_records_list.append(d_df)

        i_df = res.get("intermediate_transfers")
        if isinstance(i_df, pd.DataFrame) and not i_df.empty:
            # Annotate with sender and recipient names for multi-profile clarity
            annotated_i_df = i_df.copy()
            annotated_i_df["Sender_Person"] = name_a
            annotated_i_df["Recipient_Person"] = name_b
            intermediate_records_list.append(annotated_i_df)

    # 3. Concatenate and Deduplicate Across Permutations
    if direct_records_list:
        combined_direct = pd.concat(direct_records_list, ignore_index=True)
        # Deduplicate identical direct records that may appear in both permutations (A->B and B->A evaluation)
        combined_direct = combined_direct.drop_duplicates(
            subset=["Sender_Person", "Recipient_Person", "UTR", "Amount", "Transfer_Date"]
        ).reset_index(drop=True)
    else:
        combined_direct = pd.DataFrame()

    if intermediate_records_list:
        combined_intermediate = pd.concat(intermediate_records_list, ignore_index=True)
        combined_intermediate = combined_intermediate.drop_duplicates(
            subset=[
                "Sender_Person",
                "Recipient_Person",
                "Intermediary_Entity",
                "Outflow_Date",
                "Inflow_Date",
                "Outflow_Amount",
                "Inflow_Amount",
            ]
        ).reset_index(drop=True)
    else:
        combined_intermediate = pd.DataFrame()

    # 4. Resolve Profile Keywords & Annotate Transfers
    from core.profiles import get_profile_keywords

    trail_keywords_set: set[str] = set()
    for pid in unique_profile_ids:
        trail_keywords_set.update(get_profile_keywords(profile_id=pid))
    for pmeta in profile_metadata:
        trail_keywords_set.update(get_profile_keywords(custodian_name=pmeta["name"]))
    trail_keywords = sorted(trail_keywords_set)

    keyword_hits_count = 0
    if not combined_direct.empty:
        if trail_keywords:

            def _match_direct_kw(row):
                matched = []
                text = f"{row.get('Narration_Out', '')} {row.get('Narration_In', '')}".upper()
                for kw in trail_keywords:
                    clean_kw = kw.strip().upper()
                    if clean_kw and clean_kw in text and clean_kw not in matched:
                        matched.append(clean_kw)
                return ", ".join(matched)

            combined_direct["Matched_Keywords"] = combined_direct.apply(_match_direct_kw, axis=1)
            combined_direct["Keyword_Hit"] = combined_direct["Matched_Keywords"] != ""
            keyword_hits_count += int(combined_direct["Keyword_Hit"].sum())
        else:
            combined_direct["Matched_Keywords"] = ""
            combined_direct["Keyword_Hit"] = False

    if not combined_intermediate.empty:
        if trail_keywords:

            def _match_inter_kw(row):
                matched = []
                text = f"{row.get('Intermediary_Entity', '')} {row.get('Outflow_Narration', '')} {row.get('Inflow_Narration', '')}".upper()
                for kw in trail_keywords:
                    clean_kw = kw.strip().upper()
                    if clean_kw and clean_kw in text and clean_kw not in matched:
                        matched.append(clean_kw)
                return ", ".join(matched)

            combined_intermediate["Matched_Keywords"] = combined_intermediate.apply(
                _match_inter_kw, axis=1
            )
            combined_intermediate["Keyword_Hit"] = combined_intermediate["Matched_Keywords"] != ""
            keyword_hits_count += int(combined_intermediate["Keyword_Hit"].sum())
        else:
            combined_intermediate["Matched_Keywords"] = ""
            combined_intermediate["Keyword_Hit"] = False

    # 5. Group intermediate transfers by candidate intermediary entity
    grouped_intermediaries = group_intermediate_transfers_by_intermediary(combined_intermediate)

    # 5. Detect Circular Round-Tripping Loops & Multi-Hop Network Chains
    from apps.q_trail.backend.llm_narrative import generate_loop_forensic_narrative

    circular_trails: list[dict[str, Any]] = []
    flow_edges: dict[str, set[str]] = {p["name"]: set() for p in profile_metadata}

    # Pattern A: Direct Round-Trip (A sent funds to B, and B sent funds back to A within the window)
    if not combined_direct.empty:
        for _, row in combined_direct.iterrows():
            sender = row["Sender_Person"]
            recipient = row["Recipient_Person"]
            amt = float(row["Amount"])
            date = str(row["Transfer_Date"])
            if sender in flow_edges:
                flow_edges[sender].add(recipient)

            # Check if there exists a return transfer: recipient -> sender
            return_match = combined_direct[
                (combined_direct["Sender_Person"] == recipient)
                & (combined_direct["Recipient_Person"] == sender)
            ]
            if not return_match.empty:
                for _, ret_row in return_match.iterrows():
                    ret_amt = float(ret_row["Amount"])
                    ret_date = str(ret_row["Transfer_Date"])
                    loop_dict = {
                        "type": "Direct_Round_Trip",
                        "originator": sender,
                        "counterparty": recipient,
                        "initial_amount": amt,
                        "initial_date": date,
                        "return_amount": ret_amt,
                        "return_date": ret_date,
                        "retained_amount": 0.0,
                        "conduits": [],
                        "cycle_nodes": [sender, recipient, sender],
                        "hops": [
                            {
                                "hop_number": 1,
                                "sender": sender,
                                "recipient": recipient,
                                "outflow_amount": amt,
                                "inflow_amount": amt,
                                "retained_amount": 0.0,
                                "conduits": [],
                                "conduits_str": "Direct Banking",
                                "earliest_date": date,
                                "latest_date": date,
                                "has_intermediaries": False,
                                "has_direct": True,
                            },
                            {
                                "hop_number": 2,
                                "sender": recipient,
                                "recipient": sender,
                                "outflow_amount": ret_amt,
                                "inflow_amount": ret_amt,
                                "retained_amount": 0.0,
                                "conduits": [],
                                "conduits_str": "Direct Banking",
                                "earliest_date": ret_date,
                                "latest_date": ret_date,
                                "has_intermediaries": False,
                                "has_direct": True,
                            },
                        ],
                        "description": f"Direct circular flow between '{sender}' and '{recipient}'",
                    }
                    loop_dict["forensic_narrative"] = generate_loop_forensic_narrative(loop_dict)
                    circular_trails.append(loop_dict)

    # Pattern B: Intermediate Round-Trip (A -> X -> B, where B is also A or funds route back)
    if not combined_intermediate.empty:
        for _, row in combined_intermediate.iterrows():
            sender = row["Sender_Person"]
            recipient = row["Recipient_Person"]
            intermediary = row["Intermediary_Entity"]
            if sender in flow_edges:
                flow_edges[sender].add(recipient)

            if sender.lower() == recipient.lower():
                out_amt = float(row["Outflow_Amount"])
                in_amt = float(row["Inflow_Amount"])
                ret_amt = float(row.get("Retention_Amount", 0.0))
                out_date = str(row["Outflow_Date"])
                in_date = str(row["Inflow_Date"])
                loop_dict = {
                    "type": "Conduit_Self_Loop",
                    "originator": sender,
                    "counterparty": intermediary,
                    "initial_amount": out_amt,
                    "initial_date": out_date,
                    "return_amount": in_amt,
                    "return_date": in_date,
                    "retained_amount": ret_amt,
                    "conduits": [intermediary],
                    "cycle_nodes": [sender, intermediary, sender],
                    "hops": [
                        {
                            "hop_number": 1,
                            "sender": sender,
                            "recipient": intermediary,
                            "outflow_amount": out_amt,
                            "inflow_amount": out_amt,
                            "retained_amount": 0.0,
                            "conduits": [intermediary],
                            "conduits_str": intermediary,
                            "earliest_date": out_date,
                            "latest_date": out_date,
                            "has_intermediaries": True,
                            "has_direct": False,
                        },
                        {
                            "hop_number": 2,
                            "sender": intermediary,
                            "recipient": sender,
                            "outflow_amount": in_amt,
                            "inflow_amount": in_amt,
                            "retained_amount": ret_amt,
                            "conduits": [intermediary],
                            "conduits_str": intermediary,
                            "earliest_date": in_date,
                            "latest_date": in_date,
                            "has_intermediaries": True,
                            "has_direct": False,
                        },
                    ],
                    "description": f"Self-loop: '{sender}' received ₹{in_amt:,.2f} back via conduit '{intermediary}'",
                }
                loop_dict["forensic_narrative"] = generate_loop_forensic_narrative(loop_dict)
                circular_trails.append(loop_dict)

    # Pattern C: Multi-Hop Network Cycles (A -> B -> C -> A)
    visited_cycles: set[tuple[str, ...]] = set()
    node_list = [p["name"] for p in profile_metadata]

    def _calculate_cycle_metrics(cycle_nodes: list[str]) -> dict[str, Any]:
        """
        Calculates leg-by-leg inflow, outflow, conduit retentions, and dates
        for a multi-hop circular loop: cycle_nodes = [N_0, N_1, ..., N_k, N_0].
        """
        hops: list[dict[str, Any]] = []
        all_conduits: list[str] = []
        total_retained = 0.0

        for i in range(len(cycle_nodes) - 1):
            s_node = cycle_nodes[i]
            r_node = cycle_nodes[i + 1]

            # Direct transfers s_node -> r_node
            d_sub = (
                combined_direct[
                    (combined_direct["Sender_Person"] == s_node)
                    & (combined_direct["Recipient_Person"] == r_node)
                ]
                if not combined_direct.empty
                else pd.DataFrame()
            )
            d_amt = float(d_sub["Amount"].sum()) if not d_sub.empty else 0.0
            d_dates = (
                [str(d) for d in d_sub["Transfer_Date"].dropna() if str(d).strip()]
                if not d_sub.empty
                else []
            )

            # Intermediate conduit transfers s_node -> intermediary -> r_node
            i_sub = (
                combined_intermediate[
                    (combined_intermediate["Sender_Person"] == s_node)
                    & (combined_intermediate["Recipient_Person"] == r_node)
                ]
                if not combined_intermediate.empty
                else pd.DataFrame()
            )
            i_outflow = float(i_sub["Outflow_Amount"].sum()) if not i_sub.empty else 0.0
            i_inflow = float(i_sub["Inflow_Amount"].sum()) if not i_sub.empty else 0.0
            i_retained = float(i_sub["Retention_Amount"].sum()) if not i_sub.empty else 0.0
            i_conduits = (
                [str(c) for c in i_sub["Intermediary_Entity"].dropna().unique() if str(c).strip()]
                if not i_sub.empty
                else []
            )
            i_out_dates = (
                [str(d) for d in i_sub["Outflow_Date"].dropna() if str(d).strip()]
                if not i_sub.empty
                else []
            )
            i_in_dates = (
                [str(d) for d in i_sub["Inflow_Date"].dropna() if str(d).strip()]
                if not i_sub.empty
                else []
            )

            hop_outflow = d_amt + i_outflow
            hop_inflow = d_amt + i_inflow
            total_retained += i_retained

            for c in i_conduits:
                if c not in all_conduits:
                    all_conduits.append(c)

            leg_dates = sorted(d_dates + i_out_dates + i_in_dates)
            earliest_date = leg_dates[0] if leg_dates else "-"
            latest_date = leg_dates[-1] if leg_dates else "-"

            hops.append(
                {
                    "hop_number": i + 1,
                    "sender": s_node,
                    "recipient": r_node,
                    "outflow_amount": hop_outflow,
                    "inflow_amount": hop_inflow,
                    "retained_amount": i_retained,
                    "conduits": i_conduits,
                    "conduits_str": ", ".join(i_conduits) if i_conduits else "Direct Banking",
                    "earliest_date": earliest_date,
                    "latest_date": latest_date,
                    "has_intermediaries": bool(i_conduits),
                    "has_direct": d_amt > 0,
                }
            )

        # Initial leg is hop 1 (leaving start_node)
        initial_leg = hops[0] if hops else {}
        initial_amount = initial_leg.get("outflow_amount", 0.0)
        initial_date = initial_leg.get("earliest_date", "-")

        # Closing leg is the last hop (returning to start_node)
        closing_leg = hops[-1] if hops else {}
        return_amount = closing_leg.get("inflow_amount", 0.0)
        return_date = closing_leg.get("latest_date", "-")

        return {
            "initial_amount": initial_amount,
            "initial_date": initial_date,
            "return_amount": return_amount,
            "return_date": return_date,
            "total_retained": total_retained,
            "all_conduits": all_conduits,
            "hops": hops,
        }

    def _find_cycles(start_node: str, curr_node: str, path: list[str]) -> None:
        for nbr in flow_edges.get(curr_node, set()):
            if nbr == start_node and len(path) >= 2:
                canonical = tuple(sorted(path))
                if canonical not in visited_cycles:
                    visited_cycles.add(canonical)
                    cycle_nodes = path + [start_node]
                    cycle_desc = " → ".join(cycle_nodes)
                    metrics = _calculate_cycle_metrics(cycle_nodes)

                    loop_dict = {
                        "type": "Network_Loop_Chain",
                        "originator": start_node,
                        "counterparty": path[-1],
                        "initial_amount": metrics["initial_amount"],
                        "initial_date": metrics["initial_date"],
                        "return_amount": metrics["return_amount"],
                        "return_date": metrics["return_date"],
                        "retained_amount": metrics["total_retained"],
                        "conduits": metrics["all_conduits"],
                        "cycle_nodes": cycle_nodes,
                        "hops": metrics["hops"],
                        "description": f"Multi-hop closed loop: {cycle_desc}",
                    }
                    loop_dict["forensic_narrative"] = generate_loop_forensic_narrative(loop_dict)
                    circular_trails.append(loop_dict)
            elif nbr not in path and len(path) < 5:
                _find_cycles(start_node, nbr, path + [nbr])

    for n in node_list:
        _find_cycles(n, n, [n])

    # 6. Pairwise Comparison Matrix (Every Profile compared against Every Other Profile)
    pairwise_matrix: dict[str, dict[str, Any]] = {name: {} for name in node_list}
    pairwise_summaries: list[dict[str, Any]] = []

    for name_a in node_list:
        for name_b in node_list:
            if name_a == name_b:
                pairwise_matrix[name_a][name_b] = {
                    "is_self": True,
                    "has_flow": False,
                    "direct_count": 0,
                    "direct_volume": 0.0,
                    "intermediate_count": 0,
                    "intermediate_volume": 0.0,
                    "total_volume": 0.0,
                    "intermediaries": [],
                }
                continue

            direct_sub = (
                combined_direct[
                    (combined_direct["Sender_Person"] == name_a)
                    & (combined_direct["Recipient_Person"] == name_b)
                ]
                if not combined_direct.empty
                else pd.DataFrame()
            )
            inter_sub = (
                combined_intermediate[
                    (combined_intermediate["Sender_Person"] == name_a)
                    & (combined_intermediate["Recipient_Person"] == name_b)
                ]
                if not combined_intermediate.empty
                else pd.DataFrame()
            )

            d_count = len(direct_sub)
            d_vol = float(direct_sub["Amount"].sum()) if d_count > 0 else 0.0
            i_count = len(inter_sub)
            i_vol = float(inter_sub["Inflow_Amount"].sum()) if i_count > 0 else 0.0
            tot_vol = round(d_vol + i_vol, 2)
            conduits = (
                sorted(inter_sub["Intermediary_Entity"].unique().tolist()) if i_count > 0 else []
            )
            has_flow = (d_count + i_count) > 0

            info = {
                "is_self": False,
                "has_flow": has_flow,
                "direct_count": d_count,
                "direct_volume": round(d_vol, 2),
                "intermediate_count": i_count,
                "intermediate_volume": round(i_vol, 2),
                "total_volume": tot_vol,
                "intermediaries": conduits,
            }
            pairwise_matrix[name_a][name_b] = info

            pairwise_summaries.append(
                {
                    "pair_key": f"{name_a} → {name_b}",
                    "source": name_a,
                    "destination": name_b,
                    "direct_count": d_count,
                    "direct_volume": round(d_vol, 2),
                    "intermediate_count": i_count,
                    "intermediate_volume": round(i_vol, 2),
                    "total_volume": tot_vol,
                    "intermediaries": conduits,
                    "has_flow": has_flow,
                }
            )

    # 6. Aggregate Forensic Summary Metrics
    total_direct_vol = float(combined_direct["Amount"].sum()) if not combined_direct.empty else 0.0
    total_outflow_inter = (
        float(combined_intermediate["Outflow_Amount"].sum())
        if not combined_intermediate.empty
        else 0.0
    )
    total_inflow_inter = (
        float(combined_intermediate["Inflow_Amount"].sum())
        if not combined_intermediate.empty
        else 0.0
    )
    total_retained_inter = (
        float(combined_intermediate["Retention_Amount"].sum())
        if not combined_intermediate.empty
        else 0.0
    )

    metrics = {
        "total_profiles_analyzed": len(unique_profile_ids),
        "total_transactions_analyzed": total_txns_count,
        "total_direct_transfers_count": len(combined_direct),
        "total_direct_volume_inr": round(total_direct_vol, 2),
        "total_intermediate_hops_count": len(combined_intermediate),
        "total_outflow_to_intermediaries_inr": round(total_outflow_inter, 2),
        "total_inflow_from_intermediaries_inr": round(total_inflow_inter, 2),
        "total_retained_by_intermediaries_inr": round(total_retained_inter, 2),
        "unique_intermediaries_count": len(grouped_intermediaries),
        "unique_intermediaries_list": sorted(grouped_intermediaries.keys()),
        "circular_paths_count": len(circular_trails),
        "trail_keywords_count": len(trail_keywords),
        "keyword_hits_count": keyword_hits_count,
    }

    # 7. Optional Atomic Persistence
    dossier_obj = None
    if save_dossier:
        with transaction.atomic():
            case_num = f"TR-{timezone.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            dossier_obj = CaseDossier.objects.create(
                case_number=case_num,
                title=case_title
                or f"Money Trail Reconciliation ({len(unique_profile_ids)} Profiles)",
                lead_investigator=lead_investigator or "Forensic Auditor",
                status="Active",
            )

            # Persist Direct Trails
            if not combined_direct.empty:
                for _, row in combined_direct.iterrows():
                    FundTrailPath.objects.create(
                        case=dossier_obj,
                        source_entity=str(row["Sender_Person"]),
                        destination_entity=str(row["Recipient_Person"]),
                        total_amount=Decimal(str(row["Amount"])),
                        hop_count=1,
                        is_circular=False,
                        risk_score=60 if row["Match_Method"] == "FALLBACK_FUZZY" else 40,
                    )

            # Persist Intermediate Trails & Pass-Through Nodes
            if not combined_intermediate.empty:
                for _, row in combined_intermediate.iterrows():
                    trail_path = FundTrailPath.objects.create(
                        case=dossier_obj,
                        source_entity=str(row["Sender_Person"]),
                        destination_entity=str(row["Recipient_Person"]),
                        total_amount=Decimal(str(row["Outflow_Amount"])),
                        hop_count=2,
                        intermediate_hops=[
                            {
                                "intermediary": str(row["Intermediary_Entity"]),
                                "outflow_date": str(row["Outflow_Date"]),
                                "inflow_date": str(row["Inflow_Date"]),
                                "time_delta_days": float(row["Time_Delta_Days"]),
                            }
                        ],
                        is_circular=row["Sender_Person"] == row["Recipient_Person"],
                        risk_score=85 if float(row["Retention_Pct"]) > 10 else 75,
                    )

                    PassThroughNode.objects.create(
                        trail=trail_path,
                        entity_name=str(row["Intermediary_Entity"]),
                        inflow_amount=Decimal(str(row["Outflow_Amount"])),
                        outflow_amount=Decimal(str(row["Inflow_Amount"])),
                        retention_pct=float(row["Retention_Pct"]),
                    )

    # 8. Build Workstation V2 Interactive Structures
    chronological_beats = build_chronological_beats(
        direct_df=combined_direct,
        intermediate_df=combined_intermediate,
        circular_trails=circular_trails,
    )
    conduit_deck = build_conduit_deck(
        grouped_intermediaries=grouped_intermediaries,
        circular_trails=circular_trails,
        max_delta_days=time_window_days,
    )
    topology_graph = build_topology_graph(
        analyzed_profiles=profile_metadata,
        direct_df=combined_direct,
        intermediate_df=combined_intermediate,
        circular_trails=circular_trails,
    )

    return {
        "status": "success",
        "case_dossier": dossier_obj,
        "direct_transfers": combined_direct,
        "intermediate_transfers": combined_intermediate,
        "grouped_intermediaries": grouped_intermediaries,
        "circular_trails": circular_trails,
        "chronological_beats": chronological_beats,
        "conduit_deck": conduit_deck,
        "topology_graph": topology_graph,
        "pairwise_matrix": pairwise_matrix,
        "pairwise_summaries": pairwise_summaries,
        "metrics": metrics,
        "trail_keywords": trail_keywords,
        "analyzed_profiles": profile_metadata,
    }

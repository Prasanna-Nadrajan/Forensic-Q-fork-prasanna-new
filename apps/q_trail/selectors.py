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


def _clean_str(val) -> str:
    if val is None:
        return ""
    return str(val).strip()

def _format_inr_short(val) -> str:
    if val is None:
        return "₹0.00"
    v = float(val)
    abs_v = abs(v)
    sign = "-" if v < 0 else ""
    if abs_v >= 10000000:
        return f"{sign}₹{abs_v / 10000000:.2f}Cr"
    if abs_v >= 100000:
        return f"{sign}₹{abs_v / 100000:.2f}L"
    if abs_v >= 1000:
        return f"{sign}₹{abs_v / 1000:.1f}K"
    return f"{sign}₹{abs_v:,.2f}"

def build_topology_graph(patterns: list[dict]) -> dict:
    """
    Computes SVG coordinates, bezier curves, and HTML label plates for the
    interactive Multi-Hop Topology Canvas (`NetGraph`).
    """
    import re
    
    W = 1060
    R = 16
    plate_w = 205
    plate_h = 54

    origins_set = set()
    conduits_set = set()
    beneficiaries_set = set()

    for p in patterns:
        senders = [s.strip() for s in p["Person_X_Sender"].split(",") if s.strip()]
        receivers = [r.strip() for r in p["Person_BC_Receiver"].split(",") if r.strip()]
        inter = p["Person_A_Intermediary"]
        
        origins_set.update(senders)
        conduits_set.add(inter)
        beneficiaries_set.update(receivers)

    # Ensure conduits are distinct so 3-column topology flows left-to-right
    if conduits_set:
        origins_set = origins_set - conduits_set
        beneficiaries_set = beneficiaries_set - conduits_set

    origin_list = sorted(origins_set)
    conduit_list = sorted(conduits_set)
    beneficiary_list = sorted(beneficiaries_set)

    max_col_count = max(len(origin_list), len(conduit_list), len(beneficiary_list), 1)
    pitch = 84.0
    H = int(max(580.0, 130.0 + (max_col_count * pitch)))

    node_dict = {}

    def _distribute_y(items, col_x):
        count = len(items)
        if count == 0:
            return
        step = min(94.0, (H - 160.0) / max(count, 1))
        total_col_h = (count - 1) * step
        start_y = 80.0 + ((H - 120.0) - total_col_h) / 2.0
        for i, name in enumerate(items):
            if name in node_dict:
                continue
            y = start_y + (i * step)
            initial = name[0].upper() if name else "N"
            node_dict[name] = {
                "id": re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_"),
                "name": name,
                "label": name,
                "short": name.split()[0] if " " in name else name,
                "letter": initial,
                "x": col_x,
                "y": round(y, 1),
                "w": plate_w,
                "h": plate_h,
                "kind": "conduit" if col_x == 530 else "entity",
            }

    _distribute_y(origin_list, 160.0)
    _distribute_y(conduit_list, 530.0)
    _distribute_y(beneficiary_list, 900.0)

    nodes = list(node_dict.values())
    node_by_name = {n["name"]: n for n in nodes}
    node_by_id = {n["id"]: n for n in nodes}

    def _find_node(target_name):
        if not target_name:
            return None
        t_clean = _clean_str(target_name)
        if t_clean in node_by_name:
            return node_by_name[t_clean]
        t_lower = t_clean.lower()
        t_id = re.sub(r"[^a-zA-Z0-9]+", "_", t_lower).strip("_")
        if t_id in node_by_id:
            return node_by_id[t_id]
        return None

    edges = []
    edge_idx = 1
    half_w = plate_w / 2.0

    for p in patterns:
        senders = [s.strip() for s in p["Person_X_Sender"].split(",") if s.strip()]
        receivers = [r.strip() for r in p["Person_BC_Receiver"].split(",") if r.strip()]
        c_name = p["Person_A_Intermediary"]
        
        c_node = _find_node(c_name)
        if not c_node: continue
        
        if senders:
            in_amt = p["Amount_Leg_1"] / len(senders)
            for s_name in senders:
                s_node = _find_node(s_name)
                if s_node:
                    x1, y1 = s_node["x"] + half_w, s_node["y"]
                    x2, y2 = c_node["x"] - half_w, c_node["y"]
                    cx1 = x1 + (x2 - x1) * 0.5
                    cx2 = x1 + (x2 - x1) * 0.5
                    d = f"M {x1} {y1} C {cx1} {y1}, {cx2} {y2}, {x2} {y2}"
                    edges.append({
                        "id": f"L{edge_idx}", "from": s_node["id"], "to": c_node["id"],
                        "from_name": s_name, "to_name": c_name, "kind": "hop",
                        "amount": _format_inr_short(in_amt), "amount_num": in_amt,
                        "d": d, "color": "#38bdf8", "dashed": False, "utr": "", "via": c_name, "ret": 0.0,
                        "mid": {"x": round((x1 + x2) / 2, 1), "y": round((y1 + y2) / 2, 1)},
                    })
                    edge_idx += 1
                    
        if receivers:
            out_amt = p["Amount_Leg_2"] / len(receivers)
            for t_name in receivers:
                t_node = _find_node(t_name)
                if t_node:
                    x1, y1 = c_node["x"] + half_w, c_node["y"]
                    x2, y2 = t_node["x"] - half_w, t_node["y"]
                    cx1 = x1 + (x2 - x1) * 0.5
                    cx2 = x1 + (x2 - x1) * 0.5
                    d = f"M {x1} {y1} C {cx1} {y1}, {cx2} {y2}, {x2} {y2}"
                    edges.append({
                        "id": f"L{edge_idx}", "from": c_node["id"], "to": t_node["id"],
                        "from_name": c_name, "to_name": t_name, "kind": "hop",
                        "amount": _format_inr_short(out_amt), "amount_num": out_amt,
                        "d": d, "color": "#f59e0b", "dashed": False, "utr": "", "via": c_name, "ret": 0.0,
                        "mid": {"x": round((x1 + x2) / 2, 1), "y": round((y1 + y2) / 2, 1)},
                    })
                    edge_idx += 1

    plates = []
    for n in nodes:
        is_conduit = n["kind"] == "conduit"
        plates.append({
            "id": n["id"], "name": n["name"], "letter": n["letter"],
            "x": round(n["x"] - half_w, 1), "y": round(n["y"] - (plate_h / 2.0), 1),
            "w": plate_w, "h": plate_h,
            "meta": {
                "kind": n["kind"], "letter": n["letter"], "label": n["name"],
                "sub": "Conduit Intermediary" if is_conduit else "Auditee Profile",
                "foot": "Unlinked VPA/Entity" if is_conduit else "Ledger Linked",
            },
        })

    cols = [
        {"x": 160, "t": "ORIGIN SENDER"},
        {"x": 530, "t": "INTERMEDIARY CONDUITS (X)"},
        {"x": 900, "t": "BENEFICIARY RECEIVERS"},
    ]

    return {
        "W": W, "H": H, "R": R,
        "nodes": nodes, "node_by_id": node_by_id, "edges": edges,
        "plates": plates, "cols": cols, "cols_top": 45,
    }



    import plotly.graph_objects as go
    node_names = []
    node_map = {}
    node_colors = []

    def get_or_create_node(name: str, node_type: str = "subject") -> int:
        clean_name = str(name).strip()
        if clean_name not in node_map:
            idx = len(node_names)
            node_map[clean_name] = idx
            node_names.append(clean_name)
            if node_type == "sender":
                node_colors.append("#10b981")  # Emerald for Senders
            elif node_type == "intermediary":
                node_colors.append("#f59e0b")  # Amber for Intermediaries
            elif node_type == "receiver":
                node_colors.append("#f43f5e")  # Rose for Receivers
            else:
                node_colors.append("#94a3b8")
            return idx
        return node_map[clean_name]

    sources = []
    targets = []
    values = []
    labels = []

    for p in patterns:
        senders = [s.strip() for s in p["Person_X_Sender"].split(",") if s.strip()]
        receivers = [r.strip() for r in p["Person_BC_Receiver"].split(",") if r.strip()]
        intermediary = p["Person_A_Intermediary"]
        
        inter_idx = get_or_create_node(intermediary, "intermediary")
        
        if senders:
            in_amt = p["Amount_Leg_1"] / len(senders)
            for s in senders:
                s_idx = get_or_create_node(s, "sender")
                sources.append(s_idx)
                targets.append(inter_idx)
                values.append(in_amt)
                labels.append(p["Date_Leg_1"])
                
        if receivers:
            out_amt = p["Amount_Leg_2"] / len(receivers)
            for r in receivers:
                r_idx = get_or_create_node(r, "receiver")
                sources.append(inter_idx)
                targets.append(r_idx)
                values.append(out_amt)
                labels.append(p["Date_Leg_2"])

    fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(
                    pad=15, thickness=20, line=dict(color="black", width=0.5),
                    label=node_names, color=node_colors,
                ),
                link=dict(
                    source=sources, target=targets, value=values, label=labels,
                    color="rgba(148, 163, 184, 0.3)",
                ),
            )
        ]
    )

    fig.update_layout(
        template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=height, margin={"l": 20, "r": 20, "t": 40, "b": 20}, font=dict(color="white"),
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
def build_chronological_beats(patterns: list[dict]) -> list[dict]:
    """
    Constructs a sequential, chronological beat tape of all transaction legs.
    Investigators can scrub, play, and step through the flow chronologically.
    """
    raw_events = []

    for p in patterns:
        senders = [s.strip() for s in p["Person_X_Sender"].split(",") if s.strip()]
        receivers = [r.strip() for r in p["Person_BC_Receiver"].split(",") if r.strip()]
        conduit = p["Person_A_Intermediary"]
        
        out_date = str(p.get("Date_Leg_1", ""))
        in_date = str(p.get("Date_Leg_2", ""))
        
        if senders:
            out_amt = p["Amount_Leg_1"] / len(senders)
            for sender in senders:
                raw_events.append({
                    "date": out_date,
                    "kind": "hop",
                    "from": sender,
                    "to": conduit,
                    "amount": out_amt,
                    "retained": 0.0,
                    "utr": "",
                    "via": conduit,
                    "cap": f"{sender} dispatched ₹{out_amt:,.2f} to conduit '{conduit}'.",
                    "title": f"{sender} → {conduit}",
                })
                
        if receivers:
            in_amt = p["Amount_Leg_2"] / len(receivers)
            for recipient in receivers:
                raw_events.append({
                    "date": in_date,
                    "kind": "hop",
                    "from": conduit,
                    "to": recipient,
                    "amount": in_amt,
                    "retained": 0.0,
                    "utr": "",
                    "via": conduit,
                    "cap": f"Conduit '{conduit}' forwarded ₹{in_amt:,.2f} to {recipient}.",
                    "title": f"{conduit} → {recipient}",
                })

    def _parse_date_key(item):
        d = item.get("date", "")
        return d if d else "9999-99-99"

    raw_events.sort(key=_parse_date_key)

    beats = []
    cumulative_retained = 0.0

    for idx, ev in enumerate(raw_events):
        retained = ev.get("retained", 0.0)
        cumulative_retained += retained
        edge_id = f"L{idx + 1}"
        beats.append({
            "n": idx + 1,
            "kind": ev["kind"],
            "title": ev["title"],
            "cap": ev["cap"],
            "date": ev["date"],
            "amount": ev["amount"],
            "amount_short": _format_inr_short(ev["amount"]),
            "retained": retained,
            "retained_short": _format_inr_short(retained),
            "cumulative_retained": cumulative_retained,
            "cumulative_retained_short": _format_inr_short(cumulative_retained),
            "from_node": ev["from"],
            "to_node": ev["to"],
            "via": ev["via"],
            "utr": ev["utr"],
            "edge_id": edge_id,
        })

    summary_beat = {
        "n": len(beats) + 1,
        "kind": "summary",
        "title": "Case Position: Full Topology Reconciled",
        "cap": f"All {len(beats)} transaction legs reconciled.",
        "date": "All Dates",
        "amount": 0.0,
        "amount_short": "₹0.00",
        "retained": 0.0,
        "retained_short": "₹0.00",
        "cumulative_retained": cumulative_retained,
        "cumulative_retained_short": _format_inr_short(cumulative_retained),
        "from_node": "",
        "to_node": "",
        "via": "",
        "utr": "",
        "edge_id": "",
    }
    beats.append(summary_beat)

    return beats

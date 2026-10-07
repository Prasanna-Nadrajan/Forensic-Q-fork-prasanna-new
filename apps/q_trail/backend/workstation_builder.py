"""
Q-Trail Workstation Builder Engine
=============================================================================
Transforms reconciled money trail data into interactive forensic workstation structures:
1. Chronological Beat Sequence (Cinematic replay of fund flow).
2. Conduit Triage Deck (Multi-factor risk scored intermediary cards).
3. Multi-Hop Vector Topology (Dual-layer SVG + HTML DAG graph coordinates).
=============================================================================
"""

from __future__ import annotations

import math
import re
from typing import Any

import pandas as pd


def _clean_str(val: Any) -> str:
    if val is None or pd.isna(val):
        return ""
    return str(val).strip()


def _format_inr_short(val: float | int | None) -> str:
    """Formats number into short Indian currency representation (e.g. ₹4.50L, ₹60K)."""
    if val is None or pd.isna(val):
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


def build_chronological_beats(
    direct_df: pd.DataFrame,
    intermediate_df: pd.DataFrame,
    circular_trails: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Constructs a sequential, chronological beat tape of all transaction legs.
    Investigators can scrub, play, and step through the flow chronologically.
    """
    raw_events: list[dict[str, Any]] = []

    # 1. Direct transfers
    if not direct_df.empty:
        for _idx, row in direct_df.iterrows():
            sender = _clean_str(row.get("Sender_Person"))
            recipient = _clean_str(row.get("Recipient_Person"))
            amt = float(row.get("Amount", 0.0))
            date_str = _clean_str(row.get("Transfer_Date", ""))
            utr = _clean_str(row.get("UTR", ""))
            raw_events.append(
                {
                    "date": date_str,
                    "kind": "direct",
                    "from": sender,
                    "to": recipient,
                    "amount": amt,
                    "retained": 0.0,
                    "utr": utr,
                    "via": "",
                    "cap": f"{sender} transferred ₹{amt:,.2f} directly to {recipient} via {utr or 'banking channel'}.",
                    "title": f"{sender} → {recipient}",
                }
            )

    # 2. Intermediate conduit hops
    if not intermediate_df.empty:
        for _idx, row in intermediate_df.iterrows():
            sender = _clean_str(row.get("Sender_Person"))
            recipient = _clean_str(row.get("Recipient_Person"))
            conduit = _clean_str(row.get("Intermediary_Entity"))
            out_amt = float(row.get("Outflow_Amount", 0.0))
            in_amt = float(row.get("Inflow_Amount", 0.0))
            ret_amt = float(row.get("Retention_Amount", 0.0))
            ret_pct = float(row.get("Retention_Pct", 0.0))
            out_date = _clean_str(row.get("Outflow_Date", ""))
            in_date = _clean_str(row.get("Inflow_Date", ""))
            raw_delta = row.get("Time_Delta_Days", 0.0)
            try:
                delta_days = 0.0 if pd.isna(raw_delta) else float(raw_delta)
            except Exception:
                delta_days = 0.0
            int_delta = (
                int(delta_days) if not (math.isnan(delta_days) or math.isinf(delta_days)) else 0
            )

            # Leg 1: Sender -> Conduit
            raw_events.append(
                {
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
                }
            )

            # Leg 2: Conduit -> Recipient (reflecting retained margin)
            raw_events.append(
                {
                    "date": in_date,
                    "kind": "hop",
                    "from": conduit,
                    "to": recipient,
                    "amount": in_amt,
                    "retained": ret_amt,
                    "utr": "",
                    "via": conduit,
                    "cap": (
                        f"Conduit '{conduit}' forwarded ₹{in_amt:,.2f} to {recipient} "
                        f"after {int_delta}d (withholding ₹{ret_amt:,.2f} / {ret_pct:.1f}% fee)."
                    ),
                    "title": f"{conduit} → {recipient}",
                }
            )

    # 3. Circular round-trip legs
    for c_trail in circular_trails:
        orig = c_trail.get("originator", "")
        cpty = c_trail.get("counterparty", "")
        ret_amt = float(c_trail.get("return_amount", 0.0))
        ret_date = _clean_str(c_trail.get("return_date", ""))
        desc = c_trail.get("description", "")
        if ret_amt > 0 and ret_date and ret_date != "-":
            # Check if an existing event in raw_events already covers this return leg
            already_exists = False
            for ev in raw_events:
                if (
                    _clean_str(ev.get("from")).lower() == _clean_str(cpty).lower()
                    and _clean_str(ev.get("to")).lower() == _clean_str(orig).lower()
                    and abs(float(ev.get("amount", 0.0)) - ret_amt) < 1.0
                ):
                    ev["kind"] = "return"
                    ev["cap"] = (
                        f"Circuit closes: ₹{ret_amt:,.2f} returned to originator '{orig}'. {desc}"
                    )
                    ev["title"] = f"Loop Return: {cpty} → {orig}"
                    already_exists = True
                    break

            if not already_exists:
                raw_events.append(
                    {
                        "date": ret_date,
                        "kind": "return",
                        "from": cpty,
                        "to": orig,
                        "amount": ret_amt,
                        "retained": 0.0,
                        "utr": "",
                        "via": cpty,
                        "cap": f"Circuit closes: ₹{ret_amt:,.2f} returned to originator '{orig}'. {desc}",
                        "title": f"Loop Return: {cpty} → {orig}",
                    }
                )

    # Sort chronologically by date
    def _parse_date_key(item: dict[str, Any]) -> str:
        d = item.get("date", "")
        return d if d else "9999-99-99"

    raw_events.sort(key=_parse_date_key)

    beats: list[dict[str, Any]] = []
    cumulative_retained = 0.0

    for idx, ev in enumerate(raw_events):
        retained = ev.get("retained", 0.0)
        cumulative_retained += retained
        edge_id = f"L{idx + 1}"
        beats.append(
            {
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
            }
        )

    # Add final summary beat
    summary_beat = {
        "n": len(beats) + 1,
        "kind": "summary",
        "title": "Case Position: Full Topology Reconciled",
        "cap": (
            f"All {len(beats)} transaction legs reconciled. "
            f"Total retained conduit leakage: {_format_inr_short(cumulative_retained)}."
        ),
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


def build_conduit_deck(
    grouped_intermediaries: dict[str, Any],
    circular_trails: list[dict[str, Any]],
    max_delta_days: int = 3,
) -> list[dict[str, Any]]:
    """
    Ranks and scores 1-hop suspected intermediary conduits across 3 prioritization models:
    - Composite Model (balanced risk: retained + velocity + loop factor)
    - Retained Value Model (prioritizes largest absolute capital leakage)
    - Velocity Model (prioritizes ultra-rapid pass-throughs <= 1 day)
    """
    deck: list[dict[str, Any]] = []

    # Map of entities participating in circular loops
    loop_entities = set()
    for loop in circular_trails:
        loop_entities.add(_clean_str(loop.get("originator")).lower())
        loop_entities.add(_clean_str(loop.get("counterparty")).lower())
        for node in loop.get("cycle_nodes", []):
            loop_entities.add(_clean_str(node).lower())
        for conduit in loop.get("conduits", []):
            clean_c = _clean_str(conduit).lower()
            loop_entities.add(clean_c)
            slug = re.sub(r"[^a-zA-Z0-9]+", "_", clean_c).strip("_")
            loop_entities.add(slug)

    for raw_name, data in grouped_intermediaries.items():
        name = _clean_str(raw_name)
        slug_id = re.sub(r"[^a-zA-Z0-9]+", "_", name.lower()).strip("_")

        if isinstance(data, list):
            hops_count = len(data)
            outflow = sum(float(r.get("Outflow_Amount", 0.0)) for r in data)
            inflow = sum(float(r.get("Inflow_Amount", 0.0)) for r in data)
            retained = sum(float(r.get("Retention_Amount", 0.0)) for r in data)
            ret_pct = (retained / outflow * 100.0) if outflow > 0 else 0.0
            primary_sender = data[0].get("Sender_Person", "Auditee A") if data else "Auditee A"
            primary_recipient = (
                data[0].get("Recipient_Person", "Auditee B") if data else "Auditee B"
            )
            out_date = data[0].get("Outflow_Date", "") if data else ""
            in_date = data[0].get("Inflow_Date", "") if data else ""
            delta_days = float(data[0].get("Time_Delta_Days", 1.0)) if data else 1.0
        elif isinstance(data, dict):
            outflow = float(data.get("Total_Outflow", 0.0))
            inflow = float(data.get("Total_Inflow", 0.0))
            retained = float(data.get("Total_Retained", 0.0))
            ret_pct = float(data.get("Avg_Retention_Pct", 0.0))
            hops_count = int(data.get("Hops_Count", 1))
            details = data.get("Hops_Details", [])
            primary_sender = details[0].get("Sender", "Auditee A") if details else "Auditee A"
            primary_recipient = details[0].get("Recipient", "Auditee B") if details else "Auditee B"
            out_date = details[0].get("Outflow_Date", "") if details else ""
            delta_days = details[0].get("Time_Delta_Days", 1.0) if details else 1.0

        try:
            delta_days = float(delta_days) if not pd.isna(delta_days) else 1.0
            if math.isnan(delta_days) or math.isinf(delta_days):
                delta_days = 1.0
        except Exception:
            delta_days = 1.0

        is_loop = (
            slug_id in loop_entities
            or name.lower() in loop_entities
            or primary_sender.lower() == primary_recipient.lower()
        )

        # 1. Retained Value Score (0 to 100)
        val_score = min(100, int((retained / 50000.0) * 100)) if retained > 0 else 5

        # 2. Velocity Score (0 to 100: faster transit = higher score)
        if delta_days <= 0.5:
            vel_score = 98
        elif delta_days <= 1.0:
            vel_score = 90
        elif delta_days <= 2.0:
            vel_score = 75
        elif delta_days <= 3.0:
            vel_score = 60
        else:
            vel_score = max(20, int(100 - (delta_days * 10)))

        # 3. Composite Score (40% Retained + 30% Velocity + 30% Loop/Multi-hop factor)
        loop_bonus = 30 if is_loop else 10
        comp_score = int((val_score * 0.40) + (vel_score * 0.30) + loop_bonus)
        comp_score = max(10, min(99, comp_score))

        flags: list[str] = []
        if is_loop:
            flags.append("Participates in circular loop / round trip")
        if ret_pct >= 4.0:
            flags.append(f"Fee rate {ret_pct:.1f}% exceeds standard margin")
        if delta_days <= 1.0:
            flags.append("Rapid pass-through: funds moved within 24 hours")
        flags.append("Unlinked entity: No verified ledger attached")

        deck.append(
            {
                "id": slug_id,
                "name": name,
                "sender": primary_sender,
                "recipient": primary_recipient,
                "outflow_amount": outflow,
                "outflow_short": _format_inr_short(outflow),
                "inflow_amount": inflow,
                "inflow_short": _format_inr_short(inflow),
                "retained_amount": retained,
                "retained_short": _format_inr_short(retained),
                "retention_pct": round(ret_pct, 2),
                "outflow_date": out_date,
                "inflow_date": in_date,
                "delta_days": round(delta_days, 1),
                "hops_count": hops_count,
                "is_loop": is_loop,
                "flags": flags,
                "scores": {
                    "composite": comp_score,
                    "value": val_score,
                    "velocity": vel_score,
                },
            }
        )

    # Default sort by composite score descending
    deck.sort(key=lambda x: x["scores"]["composite"], reverse=True)
    return deck


def build_topology_graph(
    analyzed_profiles: list[dict[str, Any]],
    direct_df: pd.DataFrame,
    intermediate_df: pd.DataFrame,
    circular_trails: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Computes SVG coordinates, bezier curves, and HTML label plates for the
    interactive Multi-Hop Topology Canvas (`NetGraph`).
    """
    W = 1060
    R = 16
    plate_w = 205
    plate_h = 54

    # Categorize nodes into 3 columns:
    # Col 0 (x=160): Origins / Senders
    # Col 1 (x=530): Intermediary Conduits
    # Col 2 (x=900): Beneficiaries / Receivers
    origins_set: set[str] = set()
    conduits_set: set[str] = set()
    beneficiaries_set: set[str] = set()

    if not direct_df.empty:
        origins_set.update(direct_df["Sender_Person"].dropna().unique())
        beneficiaries_set.update(direct_df["Recipient_Person"].dropna().unique())

    if not intermediate_df.empty:
        origins_set.update(intermediate_df["Sender_Person"].dropna().unique())
        conduits_set.update(intermediate_df["Intermediary_Entity"].dropna().unique())
        beneficiaries_set.update(intermediate_df["Recipient_Person"].dropna().unique())

    # Ensure conduits are distinct so 3-column topology flows left-to-right
    if conduits_set:
        origins_set = origins_set - conduits_set
        beneficiaries_set = beneficiaries_set - conduits_set

    # Fallback if empty
    if not origins_set and analyzed_profiles:
        origins_set = {analyzed_profiles[0]["name"]}
        if len(analyzed_profiles) > 1:
            beneficiaries_set = {analyzed_profiles[1]["name"]}

    origin_list = sorted(origins_set)
    conduit_list = sorted(conduits_set)
    beneficiary_list = sorted(beneficiaries_set)

    # Dynamic Canvas Height calculation based on max column item count
    max_col_count = max(len(origin_list), len(conduit_list), len(beneficiary_list), 1)
    pitch = 84.0
    H = int(max(580.0, 130.0 + (max_col_count * pitch)))

    node_dict: dict[str, dict[str, Any]] = {}

    def _distribute_y(items: list[str], col_x: float) -> None:
        count = len(items)
        if count == 0:
            return
        # Calculate comfortable vertical pitch and vertically center the column
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

    def _find_node(target_name: str) -> dict[str, Any] | None:
        if not target_name:
            return None
        t_clean = _clean_str(target_name)
        if t_clean in node_by_name:
            return node_by_name[t_clean]
        t_lower = t_clean.lower()
        t_id = re.sub(r"[^a-zA-Z0-9]+", "_", t_lower).strip("_")
        if t_id in node_by_id:
            return node_by_id[t_id]
        for n_name, n_obj in node_by_name.items():
            n_lower = n_name.lower()
            if t_lower and n_lower and (t_lower in n_lower or n_lower in t_lower):
                return n_obj
        return None

    edges: list[dict[str, Any]] = []
    edge_idx = 1
    half_w = plate_w / 2.0

    # Add direct edges (dock from Origin right edge to Beneficiary left edge)
    if not direct_df.empty:
        for _, row in direct_df.iterrows():
            s_name = _clean_str(row.get("Sender_Person"))
            t_name = _clean_str(row.get("Recipient_Person"))
            amt = float(row.get("Amount", 0.0))
            utr = _clean_str(row.get("UTR", ""))
            s_node = _find_node(s_name)
            t_node = _find_node(t_name)
            if s_node and t_node:
                x1, y1 = s_node["x"] + half_w, s_node["y"]
                x2, y2 = t_node["x"] - half_w, t_node["y"]
                cx1 = x1 + (x2 - x1) * 0.45
                cx2 = x1 + (x2 - x1) * 0.55
                d = f"M {x1} {y1} C {cx1} {y1}, {cx2} {y2}, {x2} {y2}"
                mid_x = (x1 + x2) / 2
                mid_y = (y1 + y2) / 2
                edges.append(
                    {
                        "id": f"L{edge_idx}",
                        "from": s_node["id"],
                        "to": t_node["id"],
                        "from_name": s_name,
                        "to_name": t_name,
                        "kind": "direct",
                        "amount": _format_inr_short(amt),
                        "amount_num": amt,
                        "d": d,
                        "color": "#10b981",  # Emerald for direct
                        "dashed": False,
                        "utr": utr,
                        "via": "",
                        "ret": 0.0,
                        "mid": {"x": round(mid_x, 1), "y": round(mid_y, 1)},
                    }
                )
                edge_idx += 1

    # Add intermediate conduit edges
    if not intermediate_df.empty:
        for _, row in intermediate_df.iterrows():
            s_name = _clean_str(row.get("Sender_Person"))
            c_name = _clean_str(row.get("Intermediary_Entity"))
            t_name = _clean_str(row.get("Recipient_Person"))
            out_amt = float(row.get("Outflow_Amount", 0.0))
            in_amt = float(row.get("Inflow_Amount", 0.0))
            ret_amt = float(row.get("Retention_Amount", 0.0))

            s_node = _find_node(s_name)
            c_node = _find_node(c_name)
            t_node = _find_node(t_name)

            # Leg 1: Sender right edge -> Conduit left edge
            if s_node and c_node:
                x1, y1 = s_node["x"] + half_w, s_node["y"]
                x2, y2 = c_node["x"] - half_w, c_node["y"]
                cx1 = x1 + (x2 - x1) * 0.5
                cx2 = x1 + (x2 - x1) * 0.5
                d = f"M {x1} {y1} C {cx1} {y1}, {cx2} {y2}, {x2} {y2}"
                edges.append(
                    {
                        "id": f"L{edge_idx}",
                        "from": s_node["id"],
                        "to": c_node["id"],
                        "from_name": s_name,
                        "to_name": c_name,
                        "kind": "hop",
                        "amount": _format_inr_short(out_amt),
                        "amount_num": out_amt,
                        "d": d,
                        "color": "#38bdf8",  # Sky blue for conduit hop
                        "dashed": False,
                        "utr": "",
                        "via": c_name,
                        "ret": 0.0,
                        "mid": {"x": round((x1 + x2) / 2, 1), "y": round((y1 + y2) / 2, 1)},
                    }
                )
                edge_idx += 1

            # Leg 2: Conduit right edge -> Recipient left edge
            if c_node and t_node:
                x1, y1 = c_node["x"] + half_w, c_node["y"]
                x2, y2 = t_node["x"] - half_w, t_node["y"]
                cx1 = x1 + (x2 - x1) * 0.5
                cx2 = x1 + (x2 - x1) * 0.5
                d = f"M {x1} {y1} C {cx1} {y1}, {cx2} {y2}, {x2} {y2}"
                edges.append(
                    {
                        "id": f"L{edge_idx}",
                        "from": c_node["id"],
                        "to": t_node["id"],
                        "from_name": c_name,
                        "to_name": t_name,
                        "kind": "hop",
                        "amount": _format_inr_short(in_amt),
                        "amount_num": in_amt,
                        "d": d,
                        "color": "#f59e0b" if ret_amt > 0 else "#38bdf8",
                        "dashed": False,
                        "utr": "",
                        "via": c_name,
                        "ret": ret_amt,
                        "mid": {"x": round((x1 + x2) / 2, 1), "y": round((y1 + y2) / 2, 1)},
                    }
                )
                edge_idx += 1

    # Add return cycle edges (underneath the graph)
    for c_trail in circular_trails:
        orig = _clean_str(c_trail.get("originator"))
        cpty = _clean_str(c_trail.get("counterparty"))
        ret_amt = float(c_trail.get("return_amount", 0.0))
        orig_node = node_by_name.get(orig)
        cpty_node = node_by_name.get(cpty)
        if orig_node and cpty_node and ret_amt > 0:
            x1, y1 = cpty_node["x"], cpty_node["y"] + (plate_h / 2.0)
            x2, y2 = orig_node["x"], orig_node["y"] + (plate_h / 2.0)
            # Curve backwards under the entire diagram
            sweep_y = H - 35
            d = f"M {x1} {y1} C {x1} {sweep_y}, {x2} {sweep_y}, {x2} {y2}"
            edges.append(
                {
                    "id": f"L{edge_idx}",
                    "from": cpty_node["id"],
                    "to": orig_node["id"],
                    "from_name": cpty,
                    "to_name": orig,
                    "kind": "return",
                    "amount": _format_inr_short(ret_amt),
                    "amount_num": ret_amt,
                    "d": d,
                    "color": "#ef4444",  # Crimson for circular loop
                    "dashed": True,
                    "utr": "",
                    "via": cpty,
                    "ret": 0.0,
                    "mid": {"x": round((x1 + x2) / 2, 1), "y": sweep_y},
                }
            )
            edge_idx += 1

    # HTML label plates (centered exactly on node coordinates)
    plates: list[dict[str, Any]] = []
    for n in nodes:
        is_conduit = n["kind"] == "conduit"
        plates.append(
            {
                "id": n["id"],
                "name": n["name"],
                "letter": n["letter"],
                "x": round(n["x"] - half_w, 1),
                "y": round(n["y"] - (plate_h / 2.0), 1),
                "w": plate_w,
                "h": plate_h,
                "meta": {
                    "kind": n["kind"],
                    "letter": n["letter"],
                    "label": n["name"],
                    "sub": "Conduit Intermediary" if is_conduit else "Auditee Profile",
                    "foot": "Unlinked VPA/Entity" if is_conduit else "Ledger Linked",
                },
            }
        )

    cols = [
        {"x": 160, "t": "ORIGIN AUDITEES"},
        {"x": 530, "t": "INTERMEDIARY CONDUITS (X)"},
        {"x": 900, "t": "BENEFICIARY SINKS"},
    ]

    return {
        "W": W,
        "H": H,
        "R": R,
        "nodes": nodes,
        "node_by_id": node_by_id,
        "edges": edges,
        "plates": plates,
        "cols": cols,
        "cols_top": 45,
    }

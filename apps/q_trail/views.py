"""
Q-Trail Presentation & View Controllers
=============================================================================
Coordinates user profile selection, multi-bank network reconciliation,
interactive Plotly Dark Sankey fund-flow charts, and Tabulator match tables.
Conforms strictly to agentic-django guidelines: thin views, delegating to
services and selectors.
=============================================================================
"""

import json
from decimal import Decimal

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from loguru import logger

from core.audits import get_active_audit

from .selectors import (
    generate_trail_sankey_chart,
    get_all_trail_cases,
    get_available_profiles_for_trail,
)
from .services import analyze_profiles_money_trail


def _format_inr(value: float | Decimal | None) -> str:
    """Formats float/decimal into Indian Rupee comma grouping format."""
    if value is None:
        return "0.00"
    try:
        val = float(value)
        return f"{val:,.2f}"
    except (ValueError, TypeError):
        return "0.00"


@csrf_protect
@require_http_methods(["GET", "POST"])
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Trail Multi-Bank Money Trail & Network Matching Dashboard.
    Enables investigators to select multiple auditee profiles and trace
    direct transfers, 1-hop conduit intermediaries, and circular fund loops.
    """
    active_audit = get_active_audit(request)
    scope = request.GET.get("scope") or request.POST.get("scope")
    if not scope:
        scope = "audit" if active_audit else "all"

    all_profiles = get_available_profiles_for_trail(audit_id=None)
    audit_profiles = (
        get_available_profiles_for_trail(audit_id=active_audit.id) if active_audit else []
    )

    if scope == "audit" and active_audit:
        available_profiles = audit_profiles
    else:
        available_profiles = all_profiles

    compare_all = (
        request.GET.get("compare_all") == "1" or request.POST.get("action") == "compare_all"
    )

    # Parse profile IDs from POST or GET
    if compare_all:
        profiles_with_data = [p["id"] for p in available_profiles if p.get("has_data")]
        profile_ids = (
            profiles_with_data if profiles_with_data else [p["id"] for p in available_profiles]
        )
        time_window_str = request.POST.get(
            "time_window_days", request.GET.get("time_window_days", "0")
        )
        save_dossier = False
        case_title = ""
    elif request.method == "POST":
        profile_ids = request.POST.getlist("profile_ids")
        time_window_str = request.POST.get("time_window_days", "0")
        save_dossier = request.POST.get("save_dossier") == "on"
        case_title = request.POST.get("case_title", "").strip()
    else:
        profile_ids = request.GET.getlist("profile_ids")
        if not profile_ids and request.GET.get("profile_ids"):
            profile_ids = [
                p.strip() for p in request.GET.get("profile_ids", "").split(",") if p.strip()
            ]
        time_window_str = request.GET.get("time_window_days", "0")
        save_dossier = False
        case_title = ""

    try:
        time_window_days = max(0, min(365, int(time_window_str)))
    except (ValueError, TypeError):
        time_window_days = 0

    # Default auto-selection heuristic: select all profiles with available data
    if not profile_ids:
        profiles_with_data = [p["id"] for p in available_profiles if p.get("has_data")]
        if len(profiles_with_data) >= 2:
            profile_ids = profiles_with_data
        elif len(available_profiles) >= 2:
            profile_ids = [available_profiles[0]["id"], available_profiles[1]["id"]]
        elif available_profiles:
            profile_ids = [available_profiles[0]["id"]]

    # Execute money trail reconciliation
    analysis = analyze_profiles_money_trail(
        profile_ids=profile_ids,
        time_window_days=time_window_days,
        case_title=case_title,
        save_dossier=save_dossier,
    )

    direct_df = analysis["direct_transfers"]
    intermediate_df = analysis["intermediate_transfers"]
    metrics = analysis["metrics"]
    circular_trails = analysis["circular_trails"]
    analyzed_profiles = analysis["analyzed_profiles"]

    # Generate interactive Plotly Dark Sankey chart
    sankey_html = generate_trail_sankey_chart(direct_df, intermediate_df, height=480)

    # Format DataFrames for Tabulator tables
    direct_records = direct_df.to_dict(orient="records") if not direct_df.empty else []
    for r in direct_records:
        r["Amount_Formatted"] = f"₹{_format_inr(r.get('Amount'))}"

    intermediate_records = (
        intermediate_df.to_dict(orient="records") if not intermediate_df.empty else []
    )
    for r in intermediate_records:
        r["Outflow_Formatted"] = f"₹{_format_inr(r.get('Outflow_Amount'))}"
        r["Inflow_Formatted"] = f"₹{_format_inr(r.get('Inflow_Amount'))}"
        r["Retention_Formatted"] = f"₹{_format_inr(r.get('Retention_Amount'))}"
        r["Retention_Pct_Str"] = f"{float(r.get('Retention_Pct', 0.0)):.1f}%"

    # Format matrix structure for template rendering
    pairwise_matrix = analysis.get("pairwise_matrix", {})
    pairwise_summaries = analysis.get("pairwise_summaries", [])
    profile_names = [p["name"] for p in analyzed_profiles]

    formatted_matrix = []
    for name_a in profile_names:
        row_targets = []
        for name_b in profile_names:
            cell = pairwise_matrix.get(name_a, {}).get(name_b, {})
            tot = cell.get("total_volume", 0.0)
            row_targets.append(
                {
                    "target_name": name_b,
                    "is_self": cell.get("is_self", False),
                    "has_flow": cell.get("has_flow", False),
                    "direct_count": cell.get("direct_count", 0),
                    "direct_volume": cell.get("direct_volume", 0.0),
                    "direct_formatted": _format_inr(cell.get("direct_volume", 0.0)),
                    "intermediate_count": cell.get("intermediate_count", 0),
                    "intermediate_volume": cell.get("intermediate_volume", 0.0),
                    "intermediate_formatted": _format_inr(cell.get("intermediate_volume", 0.0)),
                    "total_volume": tot,
                    "total_formatted": _format_inr(tot),
                    "intermediaries": cell.get("intermediaries", []),
                }
            )
        formatted_matrix.append({"source_name": name_a, "targets": row_targets})

    # Format metrics for presentation
    formatted_metrics = {
        **metrics,
        "total_direct_volume_formatted": _format_inr(metrics["total_direct_volume_inr"]),
        "total_outflow_formatted": _format_inr(metrics["total_outflow_to_intermediaries_inr"]),
        "total_inflow_formatted": _format_inr(metrics["total_inflow_from_intermediaries_inr"]),
        "total_retained_formatted": _format_inr(metrics["total_retained_by_intermediaries_inr"]),
    }

    # Saved case dossiers for reference
    saved_cases = get_all_trail_cases()[:5]

    chronological_beats = analysis.get("chronological_beats", [])
    conduit_deck = analysis.get("conduit_deck", [])
    topology_graph = analysis.get("topology_graph", {})

    context = {
        "available_profiles": available_profiles,
        "selected_profile_ids": profile_ids,
        "time_window_days": time_window_days,
        "active_audit": active_audit,
        "scope": scope,
        "audit_profiles_count": len(audit_profiles),
        "all_profiles_count": len(all_profiles),
        "metrics": formatted_metrics,
        "sankey_figure_html": sankey_html,
        "direct_records": direct_records,
        "direct_records_json": json.dumps(direct_records),
        "intermediate_records": intermediate_records,
        "intermediate_records_json": json.dumps(intermediate_records),
        "circular_trails": circular_trails,
        "chronological_beats": chronological_beats,
        "beats_json": json.dumps(chronological_beats),
        "conduit_deck": conduit_deck,
        "conduit_deck_json": json.dumps(conduit_deck),
        "topology_graph": topology_graph,
        "topology_graph_json": json.dumps(topology_graph),
        "analyzed_profiles": analyzed_profiles,
        "profile_names": profile_names,
        "pairwise_matrix": formatted_matrix,
        "pairwise_summaries": pairwise_summaries,
        "saved_cases": saved_cases,
        "trail_keywords": analysis.get("trail_keywords", []),
    }

    return render(request, "q_trail/dashboard.html", context)


@csrf_protect
@require_POST
def analyze_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API endpoint for real-time asynchronous money trail analysis.
    Accepts JSON body or POST form data containing 'profile_ids' and 'time_window_days'.
    """
    try:
        if request.content_type == "application/json":
            payload = json.loads(request.body.decode("utf-8"))
            profile_ids = payload.get("profile_ids", [])
            time_window_days = int(payload.get("time_window_days", 0))
        else:
            profile_ids = request.POST.getlist("profile_ids")
            time_window_days = int(request.POST.get("time_window_days", 0))
    except Exception as e:
        logger.warning(f"Invalid API request payload to Q-Trail analyze: {e}")
        return JsonResponse({"status": "error", "message": "Invalid request payload."}, status=400)

    analysis = analyze_profiles_money_trail(
        profile_ids=profile_ids,
        time_window_days=time_window_days,
    )

    direct_df = analysis["direct_transfers"]
    intermediate_df = analysis["intermediate_transfers"]

    sankey_html = generate_trail_sankey_chart(direct_df, intermediate_df, height=450)

    direct_records = direct_df.to_dict(orient="records") if not direct_df.empty else []
    intermediate_records = (
        intermediate_df.to_dict(orient="records") if not intermediate_df.empty else []
    )

    return JsonResponse(
        {
            "status": "success",
            "metrics": analysis["metrics"],
            "direct_transfers": direct_records,
            "intermediate_transfers": intermediate_records,
            "circular_trails": analysis["circular_trails"],
            "chronological_beats": analysis.get("chronological_beats", []),
            "conduit_deck": analysis.get("conduit_deck", []),
            "topology_graph": analysis.get("topology_graph", {}),
            "pairwise_matrix": analysis.get("pairwise_matrix", {}),
            "pairwise_summaries": analysis.get("pairwise_summaries", []),
            "sankey_html": sankey_html,
        }
    )

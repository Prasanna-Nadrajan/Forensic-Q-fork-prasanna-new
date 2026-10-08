import json
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from loguru import logger

from core.audits import get_active_audit
from .selectors import get_available_profiles_for_trail, build_topology_graph, build_chronological_beats
from .services import analyze_profiles_money_trail

@csrf_protect
@require_http_methods(["GET", "POST"])
def dashboard_view(request: HttpRequest) -> HttpResponse:
    active_audit = get_active_audit(request)
    all_profiles = get_available_profiles_for_trail(audit_id=None)
    audit_profiles = get_available_profiles_for_trail(audit_id=active_audit.id) if active_audit else []

    scope = request.GET.get("scope") or request.POST.get("scope", "audit" if active_audit else "all")
    available_profiles = audit_profiles if scope == "audit" and active_audit else all_profiles

    if request.method == "POST":
        profile_ids = request.POST.getlist("profile_ids")
    else:
        profile_ids = request.GET.getlist("profile_ids")

    flat_ids = []
    for item in profile_ids:
        if "," in item:
            flat_ids.extend([x.strip() for x in item.split(",") if x.strip()])
        elif item.strip():
            flat_ids.append(item.strip())
    profile_ids = flat_ids

    # Select single profile auto if none selected
    if not profile_ids:
        profiles_with_data = [p["id"] for p in available_profiles if p.get("has_data")]
        if profiles_with_data:
            profile_ids = [profiles_with_data[0]]
        elif available_profiles:
            profile_ids = [available_profiles[0]["id"]]

    analysis = analyze_profiles_money_trail(profile_ids=profile_ids)
    
    topology_graph = build_topology_graph(patterns=analysis["patterns"])
    beats = build_chronological_beats(patterns=analysis["patterns"])

    context = {
        "available_profiles": available_profiles,
        "selected_profile_ids": profile_ids[:1],  # strictly limit to 1 visually
        "active_audit": active_audit,
        "scope": scope,
        "audit_profiles_count": len(audit_profiles),
        "all_profiles_count": len(all_profiles),
        "patterns": analysis["patterns"],
        "suspicious": analysis["suspicious"],
        "analyzed_profiles": analysis["analyzed_profiles"],
        "topology_graph_json": json.dumps(topology_graph),
        "beats_json": json.dumps(beats),
    }
    return render(request, "q_trail/dashboard.html", context)

@csrf_protect
@require_POST
def analyze_api_view(request: HttpRequest) -> JsonResponse:
    try:
        if request.content_type == "application/json":
            payload = json.loads(request.body.decode("utf-8"))
            profile_ids = payload.get("profile_ids", [])
        else:
            profile_ids = request.POST.getlist("profile_ids")
    except Exception as e:
        return JsonResponse({"status": "error", "message": "Invalid request payload."}, status=400)

    analysis = analyze_profiles_money_trail(profile_ids=profile_ids)
    return JsonResponse(analysis)

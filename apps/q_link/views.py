"""
Q-Link Presentation & View Controllers
Coordinates the interactive Knowledge Graph dashboard, Vis.js network data APIs,
entity inspection drawer, timeline visualizer, and Forensic Copilot agent chat.
Conforms strictly to agentic-django: thin views delegating to selectors and services.
"""

import json

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_POST
from loguru import logger

from core.audits import get_active_audit

from .backend.llm_agent import ForensicCopilotAgent
from .backend.sync_all import sync_all_modules
from .models import (
    EntityRelationship,
    EvidencePointer,
    ForensicEntity,
    RelationshipAlert,
)
from .selectors import (
    get_entity_by_id,
    get_entity_evidence,
    get_entity_network,
    get_entity_timeline,
    get_graph_overview,
    get_recent_alerts,
)
from .services import acknowledge_alert


@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Link Investigative Workstation:
    Renders top summary metrics, live relationship alerts, active targets,
    and initializes the interactive Vis.js network graph canvas.
    """
    active_audit = get_active_audit(request)
    scope = request.GET.get("scope")
    if not scope:
        scope = "audit" if active_audit else "all"

    # Key Metrics
    total_entities = ForensicEntity.objects.count()
    total_relationships = EntityRelationship.objects.count()
    total_evidence = EvidencePointer.objects.count()
    unack_alerts = RelationshipAlert.objects.filter(is_acknowledged=False).count()

    # Alerts & Targets
    alerts = get_recent_alerts(limit=10, unacknowledged_only=False)

    audit_profile_names: list[str] = []
    if active_audit:
        audit_profile_names = list(active_audit.profiles.values_list("full_name", flat=True))

    if scope == "audit" and active_audit and audit_profile_names:
        from django.db.models import Q

        audit_q = Q()
        for name in audit_profile_names:
            audit_q |= Q(display_name__iexact=name)

        audit_targets = ForensicEntity.objects.filter(audit_q).order_by("-risk_rating")
        targets = (
            audit_targets
            if audit_targets.exists()
            else ForensicEntity.objects.filter(is_target=True).order_by("-risk_rating")[:10]
        )
        initial_graph = get_graph_overview(max_nodes=120, filter_names=audit_profile_names)
    else:
        targets = ForensicEntity.objects.filter(is_target=True).order_by("-risk_rating")[:10]
        initial_graph = get_graph_overview(max_nodes=120)

    high_risk_entities = ForensicEntity.objects.filter(risk_rating__gte=50).order_by(
        "-risk_rating"
    )[:15]

    context = {
        "page_title": "Q-Link | Forensic Intelligence & Relationship Engine",
        "total_entities": total_entities,
        "total_relationships": total_relationships,
        "total_evidence": total_evidence,
        "unack_alerts": unack_alerts,
        "alerts": alerts,
        "targets": targets,
        "high_risk_entities": high_risk_entities,
        "initial_graph_json": json.dumps(initial_graph),
        "active_audit": active_audit,
        "scope": scope,
        "audit_profiles_count": len(audit_profile_names),
    }

    return render(request, "q_link/dashboard.html", context)


@require_GET
def api_network_data(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning graph nodes and edges.
    If entity_id is passed, traverses ego-network up to max_hops.
    Otherwise returns the top-level global knowledge graph.
    """
    entity_id = request.GET.get("entity_id")
    max_hops = int(request.GET.get("max_hops", 2))
    min_confidence = float(request.GET.get("min_confidence", 0.0))

    active_audit = get_active_audit(request)
    scope = request.GET.get("scope")
    if not scope:
        scope = "audit" if active_audit else "all"

    if entity_id:
        graph_data = get_entity_network(entity_id, max_hops=max_hops, min_confidence=min_confidence)
    elif scope == "audit" and active_audit:
        audit_names = list(active_audit.profiles.values_list("full_name", flat=True))
        graph_data = get_graph_overview(max_nodes=150, filter_names=audit_names)
    else:
        graph_data = get_graph_overview(max_nodes=150)

    return JsonResponse({"status": "success", **graph_data})

    return JsonResponse({"status": "success", **graph_data})


@require_GET
def api_entity_detail(request: HttpRequest, entity_id: str) -> JsonResponse:
    """
    JSON API returning complete dossier, aliases, direct edges, timeline,
    and underlying evidence citations for an entity.
    """
    entity = get_entity_by_id(entity_id)
    if not entity:
        return JsonResponse({"status": "error", "message": "Entity not found."}, status=404)

    # Timeline events
    timeline = get_entity_timeline(entity_id, limit=25)
    timeline_data = [
        {
            "id": str(t.id),
            "date": t.event_timestamp.strftime("%Y-%m-%d %H:%M"),
            "title": t.event_title,
            "description": t.event_description,
            "module": t.source_module,
            "severity": t.severity,
        }
        for t in timeline
    ]

    # Underlying Evidence Pointers
    evidence = get_entity_evidence(entity_id, limit=20)
    evidence_data = [
        {
            "id": str(e.id),
            "module": e.source_module,
            "model": e.source_model,
            "record_id": e.source_record_id,
            "url": e.evidence_url,
            "summary": e.summary_snippet,
            "date": e.occurred_at.strftime("%Y-%m-%d") if e.occurred_at else "N/A",
        }
        for e in evidence
    ]

    # Connected Relationships
    out_rels = [
        {
            "id": str(r.id),
            "target_id": str(r.target_entity_id),
            "target_name": r.target_entity.display_name,
            "type": r.relation_type,
            "weight": r.weight,
            "module": r.source_module,
            "confidence": r.confidence_score,
        }
        for r in entity.out_relations.select_related("target_entity")[:15]
    ]

    in_rels = [
        {
            "id": str(r.id),
            "source_id": str(r.source_entity_id),
            "source_name": r.source_entity.display_name,
            "type": r.relation_type,
            "weight": r.weight,
            "module": r.source_module,
            "confidence": r.confidence_score,
        }
        for r in entity.in_relations.select_related("source_entity")[:15]
    ]

    return JsonResponse(
        {
            "status": "success",
            "entity": {
                "id": str(entity.id),
                "name": entity.display_name,
                "type": entity.entity_type,
                "type_display": entity.get_entity_type_display(),
                "identifier": entity.identifier,
                "category": entity.category,
                "risk_rating": entity.risk_rating,
                "is_target": entity.is_target,
                "metadata": entity.metadata,
                "aliases": [a.alias_name for a in entity.aliases.all()],
            },
            "outgoing_relationships": out_rels,
            "incoming_relationships": in_rels,
            "timeline": timeline_data,
            "evidence": evidence_data,
        }
    )


@require_POST
@csrf_protect
def api_copilot_chat(request: HttpRequest) -> JsonResponse:
    """
    POST API for the Forensic Copilot Agent with Tool Calling:
    Executes investigative reasoning loops, tool queries against the graph,
    and returns synthesized findings.
    """
    try:
        data = json.loads(request.body.decode("utf-8"))
        query = data.get("query", "").strip()
        active_entity = data.get("entity_name")

        if not query:
            return JsonResponse(
                {"status": "error", "message": "Query cannot be empty."}, status=400
            )

        agent = ForensicCopilotAgent()
        result = agent.analyze_investigative_query(query, active_entity_name=active_entity)

        return JsonResponse({"status": "success", **result})
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": "Invalid JSON format."}, status=400)
    except Exception as err:
        logger.error(f"Error in api_copilot_chat: {err}")
        return JsonResponse({"status": "error", "message": str(err)}, status=500)


@require_POST
@csrf_protect
def api_sync_modules(request: HttpRequest) -> JsonResponse:
    """
    Triggers on-demand synchronization across all available modules.
    """
    try:
        stats = sync_all_modules()
        total_synced = sum(stats.values())
        return JsonResponse(
            {
                "status": "success",
                "message": f"Successfully synthesized {total_synced} forensic records into Q-Link.",
                "stats": stats,
            }
        )
    except Exception as err:
        logger.error(f"Error in api_sync_modules: {err}")
        return JsonResponse({"status": "error", "message": str(err)}, status=500)


@require_POST
@csrf_protect
def api_acknowledge_alert(request: HttpRequest, alert_id: str) -> JsonResponse:
    """
    Marks an intelligence alert as acknowledged.
    """
    success = acknowledge_alert(alert_id)
    if success:
        return JsonResponse({"status": "success", "message": "Alert acknowledged."})
    return JsonResponse({"status": "error", "message": "Alert not found."}, status=404)

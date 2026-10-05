"""
Q-Link Selectors
Read-only queries with proactive select_related and prefetch_related
to eliminate N+1 queries across the forensic knowledge graph.
"""

from collections import deque
from typing import Any

from django.core.exceptions import ValidationError
from django.db.models import Q, QuerySet

from .models import (
    EntityRelationship,
    EvidencePointer,
    ForensicEntity,
    ForensicTimelineEvent,
    RelationshipAlert,
)


def get_all_entities(
    *,
    entity_type: str | None = None,
    search_query: str | None = None,
    is_target: bool | None = None,
    min_risk: int = 0,
) -> QuerySet[ForensicEntity]:
    """
    Retrieves all forensic entities filtered by type, query, or risk level.
    Prefetches aliases for high-speed resolution.
    """
    qs = ForensicEntity.objects.prefetch_related("aliases").filter(risk_rating__gte=min_risk)

    if entity_type:
        qs = qs.filter(entity_type=entity_type)
    if is_target is not None:
        qs = qs.filter(is_target=is_target)
    if search_query:
        query = search_query.strip()
        qs = qs.filter(
            Q(display_name__icontains=query)
            | Q(identifier__icontains=query)
            | Q(aliases__alias_name__icontains=query)
        ).distinct()

    return qs.order_by("-risk_rating", "display_name")


def get_entity_by_id(entity_id: str) -> ForensicEntity | None:
    """
    Fetches a single entity by UUID with preloaded relationships and aliases.
    """
    try:
        return ForensicEntity.objects.prefetch_related(
            "aliases",
            "out_relations__target_entity",
            "in_relations__source_entity",
        ).get(id=entity_id)
    except (ForensicEntity.DoesNotExist, ValueError, TypeError, ValidationError):
        return None


def get_entity_network(
    entity_id: str,
    *,
    max_hops: int = 2,
    min_confidence: float = 0.5,
) -> dict[str, Any]:
    """
    Traverses the knowledge graph starting from entity_id up to max_hops (BFS).
    Returns nodes and edges structured for Vis.js / Cytoscape rendering.
    """
    root_entity = get_entity_by_id(entity_id)
    if not root_entity:
        return {"nodes": [], "edges": [], "root_id": entity_id}

    visited_node_ids: set[str] = {str(root_entity.id)}
    nodes_map: dict[str, dict[str, Any]] = {
        str(root_entity.id): {
            "id": str(root_entity.id),
            "label": root_entity.display_name,
            "type": root_entity.entity_type,
            "risk": root_entity.risk_rating,
            "is_target": root_entity.is_target,
            "is_root": True,
        }
    }
    edges_list: list[dict[str, Any]] = []

    queue: deque[tuple[str, int]] = deque([(str(root_entity.id), 0)])

    while queue:
        current_id, current_hop = queue.popleft()
        if current_hop >= max_hops:
            continue

        # Fetch both incoming and outgoing relationships
        relations = (
            EntityRelationship.objects.filter(
                Q(source_entity_id=current_id) | Q(target_entity_id=current_id),
                confidence_score__gte=min_confidence,
            )
            .select_related("source_entity", "target_entity")
            .prefetch_related("evidence_pointers")
        )

        for rel in relations:
            s_id = str(rel.source_entity_id)
            t_id = str(rel.target_entity_id)
            neighbor = rel.target_entity if s_id == current_id else rel.source_entity
            neighbor_id = str(neighbor.id)

            if neighbor_id not in nodes_map:
                nodes_map[neighbor_id] = {
                    "id": neighbor_id,
                    "label": neighbor.display_name,
                    "type": neighbor.entity_type,
                    "risk": neighbor.risk_rating,
                    "is_target": neighbor.is_target,
                    "is_root": False,
                }

            edges_list.append(
                {
                    "id": str(rel.id),
                    "from": s_id,
                    "to": t_id,
                    "label": rel.get_relation_type_display(),
                    "relation_type": rel.relation_type,
                    "confidence": rel.confidence_score,
                    "weight": rel.weight,
                    "module": rel.source_module,
                    "is_direct": rel.is_direct,
                    "evidence_count": rel.evidence_pointers.count(),
                }
            )

            if neighbor_id not in visited_node_ids:
                visited_node_ids.add(neighbor_id)
                queue.append((neighbor_id, current_hop + 1))

    return {
        "root_id": str(root_entity.id),
        "nodes": list(nodes_map.values()),
        "edges": edges_list,
    }


def find_paths_between(
    source_id: str,
    target_id: str,
    *,
    max_hops: int = 3,
) -> list[list[dict[str, Any]]]:
    """
    Finds all directed or bidirectional paths connecting source_id to target_id
    up to max_hops using Breadth-First Path Search.
    """
    if source_id == target_id:
        return []

    all_paths: list[list[dict[str, Any]]] = []
    # Queue stores list of relationship edge representations
    queue: deque[tuple[str, list[dict[str, Any]], set[str]]] = deque([(source_id, [], {source_id})])

    while queue:
        curr_node, current_path, visited = queue.popleft()
        if len(current_path) >= max_hops:
            continue

        outgoing = EntityRelationship.objects.filter(
            Q(source_entity_id=curr_node) | Q(target_entity_id=curr_node)
        ).select_related("source_entity", "target_entity")

        for rel in outgoing:
            s_id = str(rel.source_entity_id)
            t_id = str(rel.target_entity_id)
            next_node = t_id if s_id == curr_node else s_id

            edge_data = {
                "rel_id": str(rel.id),
                "from_id": s_id,
                "from_name": rel.source_entity.display_name,
                "to_id": t_id,
                "to_name": rel.target_entity.display_name,
                "relation_type": rel.relation_type,
                "weight": rel.weight,
                "module": rel.source_module,
            }

            if next_node == target_id:
                all_paths.append(current_path + [edge_data])
            elif next_node not in visited and len(current_path) + 1 < max_hops:
                queue.append((next_node, current_path + [edge_data], visited | {next_node}))

    return all_paths


def get_entity_timeline(entity_id: str, *, limit: int = 100) -> QuerySet[ForensicTimelineEvent]:
    """
    Fetches chronological sequence of events involving this entity or its direct relationships.
    """
    return (
        ForensicTimelineEvent.objects.filter(entity_id=entity_id)
        .select_related(
            "relationship", "relationship__source_entity", "relationship__target_entity"
        )
        .order_by("event_timestamp")[:limit]
    )


def get_entity_evidence(entity_id: str, *, limit: int = 50) -> QuerySet[EvidencePointer]:
    """
    Fetches raw evidence pointers linking to or from the entity across all modules.
    """
    return (
        EvidencePointer.objects.filter(
            Q(relationship__source_entity_id=entity_id)
            | Q(relationship__target_entity_id=entity_id)
        )
        .select_related(
            "relationship", "relationship__source_entity", "relationship__target_entity"
        )
        .order_by("-occurred_at", "-created_at")[:limit]
    )


def get_recent_alerts(
    *,
    limit: int = 20,
    unacknowledged_only: bool = False,
) -> QuerySet[RelationshipAlert]:
    """
    Fetches high-priority intelligence alerts for the workstation alert center.
    """
    qs = RelationshipAlert.objects.select_related("primary_entity")
    if unacknowledged_only:
        qs = qs.filter(is_acknowledged=False)
    return qs.order_by("-risk_score", "-created_at")[:limit]


def get_graph_overview(
    *,
    max_nodes: int = 80,
    min_risk: int = 0,
    filter_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generates a top-level network overview of the highest risk entities and their connections
    for the primary Q-Link dashboard view. If filter_names is provided, focuses on entities
    matching those names and their 1-hop connected neighbors.
    """
    if filter_names:
        clean_names = [n.strip() for n in filter_names if n.strip()]
        target_q = Q()
        for name in clean_names:
            target_q |= Q(display_name__iexact=name)

        target_entities = list(ForensicEntity.objects.filter(target_q))
        target_ids = [e.id for e in target_entities]

        if target_ids:
            relations = EntityRelationship.objects.filter(
                Q(source_entity_id__in=target_ids) | Q(target_entity_id__in=target_ids)
            )
            connected_ids = set(target_ids)
            for r in relations:
                connected_ids.add(r.source_entity_id)
                connected_ids.add(r.target_entity_id)

            entities = ForensicEntity.objects.filter(id__in=connected_ids).order_by(
                "-is_target", "-risk_rating"
            )[:max_nodes]
        else:
            entities = ForensicEntity.objects.filter(risk_rating__gte=min_risk).order_by(
                "-is_target", "-risk_rating"
            )[:max_nodes]
    else:
        entities = ForensicEntity.objects.filter(risk_rating__gte=min_risk).order_by(
            "-is_target", "-risk_rating"
        )[:max_nodes]

    entity_ids = [str(e.id) for e in entities]

    nodes = [
        {
            "id": str(e.id),
            "label": e.display_name,
            "type": e.entity_type,
            "risk": e.risk_rating,
            "is_target": e.is_target,
            "category": e.category,
        }
        for e in entities
    ]

    relationships = (
        EntityRelationship.objects.filter(
            source_entity_id__in=entity_ids,
            target_entity_id__in=entity_ids,
        )
        .select_related("source_entity", "target_entity")
        .prefetch_related("evidence_pointers")
    )

    edges = [
        {
            "id": str(r.id),
            "from": str(r.source_entity_id),
            "to": str(r.target_entity_id),
            "label": r.get_relation_type_display(),
            "relation_type": r.relation_type,
            "confidence": r.confidence_score,
            "weight": r.weight,
            "module": r.source_module,
            "is_direct": r.is_direct,
            "evidence_count": r.evidence_pointers.count(),
        }
        for r in relationships
    ]

    return {"nodes": nodes, "edges": edges, "total_entities": entities.count()}

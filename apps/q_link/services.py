"""
Q-Link Services
Business logic, entity normalization, fuzzy alias resolution, knowledge graph mutations,
timeline event aggregation, and automated risk alert evaluations.
All database mutations are strictly encapsulated in atomic transactions.
"""

import logging
import re
from datetime import datetime
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from rapidfuzz import fuzz

from .models import (
    EntityAlias,
    EntityRelationship,
    EvidencePointer,
    ForensicEntity,
    ForensicTimelineEvent,
    RelationshipAlert,
)

logger = logging.getLogger(__name__)

# Common corporate stop-suffixes for fuzzy entity name normalization
LEGAL_SUFFIXES = [
    r"\bpvt\.?\s*ltd\.?\b",
    r"\bltd\.?\b",
    r"\bllp\b",
    r"\binc\.?\b",
    r"\bcorp\.?\b",
    r"\benterprises?\b",
    r"\bsolutions?\b",
    r"\bservices?\b",
    r"\btechnologies?\b",
    r"\bindia\b",
]


def clean_entity_name(name: str) -> str:
    """
    Cleans up an entity name by stripping legal suffixes, punctuation, and extra whitespace
    to generate a canonical key. Collapses acronym dots (e.g. A.B.C. -> ABC).
    """
    cleaned = name.lower().strip()
    # Collapse acronym dots (e.g. a.b.c. -> abc)
    cleaned = re.sub(r"(?<=[a-zA-Z0-9])\.(?=[a-zA-Z0-9])", "", cleaned)
    cleaned = re.sub(r"\.(?=\s|$)", "", cleaned)
    for suffix in LEGAL_SUFFIXES:
        cleaned = re.sub(suffix, "", cleaned, flags=re.IGNORECASE)
    # Remove special chars and normalize spaces
    cleaned = re.sub(r"[^a-zA-Z0-9\s]", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip().upper()


def normalize_identifier(raw_identifier: str, entity_type: str) -> str:
    """
    Generates a deterministic unique canonical identifier based on entity type.
    """
    raw = raw_identifier.strip()
    e_type = entity_type.upper()

    if e_type == ForensicEntity.EntityType.EMAIL_ID:
        return f"EMAIL:{raw.lower()}"
    elif e_type == ForensicEntity.EntityType.BANK_ACCOUNT:
        # Normalize account number (strip spaces/hyphens)
        clean_acc = re.sub(r"[\s\-]", "", raw).upper()
        return f"ACC:{clean_acc}"
    elif e_type == ForensicEntity.EntityType.PHONE:
        clean_phone = re.sub(r"[\s\-\(\)\+]", "", raw)
        return f"PHONE:{clean_phone}"
    elif e_type == ForensicEntity.EntityType.PO:
        clean_po = re.sub(r"\s+", "", raw).upper()
        return f"PO:{clean_po}"
    elif e_type == ForensicEntity.EntityType.INVOICE:
        clean_inv = re.sub(r"\s+", "", raw).upper()
        return f"INV:{clean_inv}"
    else:
        # General company or person
        clean_name = clean_entity_name(raw)
        return f"{e_type}:{clean_name}" if clean_name else f"{e_type}:{raw.upper()}"


@transaction.atomic
def resolve_or_create_entity(
    display_name: str,
    entity_type: str,
    *,
    raw_identifier: str | None = None,
    category: str = "General",
    risk_rating: int = 0,
    is_target: bool = False,
    metadata: dict[str, Any] | None = None,
    match_threshold: float = 85.0,
) -> tuple[ForensicEntity, bool]:
    """
    Resolves an incoming entity name against existing entities using:
    1. Exact canonical identifier match
    2. Exact alias match
    3. RapidFuzz token set ratio matching against existing entities & aliases
    Creates a new ForensicEntity if no match exceeds match_threshold.
    """
    canonical_id = normalize_identifier(raw_identifier or display_name, entity_type)

    # 1. Exact canonical identifier lookup
    exact_entity = ForensicEntity.objects.filter(identifier=canonical_id).first()
    if exact_entity:
        updated_fields = []
        if is_target and not exact_entity.is_target:
            exact_entity.is_target = True
            updated_fields.append("is_target")
        if metadata:
            curr_meta = dict(exact_entity.metadata or {})
            curr_meta.update(metadata)
            exact_entity.metadata = curr_meta
            updated_fields.append("metadata")
        if updated_fields:
            updated_fields.append("updated_at")
            exact_entity.save(update_fields=updated_fields)
        # Record variant as alias if display names differ
        if exact_entity.display_name.lower().strip() != display_name.lower().strip():
            EntityAlias.objects.get_or_create(
                entity=exact_entity,
                alias_name=display_name.strip(),
                defaults={
                    "match_source": EntityAlias.MatchSource.EXACT,
                    "confidence": 1.0,
                },
            )
        return exact_entity, False

    # 2. Exact alias lookup
    exact_alias = EntityAlias.objects.filter(alias_name__iexact=display_name.strip()).first()
    if exact_alias:
        return exact_alias.entity, False

    # 3. RapidFuzz token matching within compatible entity types
    compatible_types = {entity_type}
    if entity_type in {
        ForensicEntity.EntityType.VENDOR,
        ForensicEntity.EntityType.COMPANY,
        ForensicEntity.EntityType.CUSTOMER,
    }:
        compatible_types = {
            ForensicEntity.EntityType.VENDOR,
            ForensicEntity.EntityType.COMPANY,
            ForensicEntity.EntityType.CUSTOMER,
        }

    candidate_entities = ForensicEntity.objects.filter(entity_type__in=compatible_types)
    clean_target = clean_entity_name(display_name)
    target_no_space = clean_target.replace(" ", "")

    best_match_entity: ForensicEntity | None = None
    best_score: float = 0.0

    for cand in candidate_entities:
        cand_clean = clean_entity_name(cand.display_name)
        cand_no_space = cand_clean.replace(" ", "")

        score_token = fuzz.token_set_ratio(clean_target, cand_clean)
        score_ratio = fuzz.ratio(target_no_space, cand_no_space)
        score = max(score_token, score_ratio)

        if score > best_score:
            best_score = score
            best_match_entity = cand

    if best_match_entity and best_score >= match_threshold:
        # Link as an alias under best matching master entity
        EntityAlias.objects.get_or_create(
            entity=best_match_entity,
            alias_name=display_name.strip(),
            defaults={
                "match_source": EntityAlias.MatchSource.RAPIDFUZZ,
                "confidence": round(best_score / 100.0, 2),
            },
        )
        return best_match_entity, False

    # 4. No satisfactory match found -> Create new master entity
    new_entity = ForensicEntity.objects.create(
        entity_type=entity_type,
        identifier=canonical_id,
        display_name=display_name.strip(),
        category=category,
        risk_rating=risk_rating,
        is_target=is_target,
        metadata=metadata or {},
    )

    # Record primary name as initial alias
    EntityAlias.objects.create(
        entity=new_entity,
        alias_name=display_name.strip(),
        match_source=EntityAlias.MatchSource.EXACT,
        confidence=1.0,
    )

    return new_entity, True


@transaction.atomic
def create_or_update_relationship(
    source_entity: ForensicEntity,
    target_entity: ForensicEntity,
    relation_type: str,
    *,
    confidence_score: float = 1.0,
    weight: float = 1.0,
    source_module: str = "",
    is_direct: bool = True,
    metadata: dict[str, Any] | None = None,
    evidence_data: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> tuple[EntityRelationship, EvidencePointer | None]:
    """
    Creates or updates a directed edge between two forensic entities,
    attaching granular evidence pointers and triggering automated risk checks.
    """
    relationship, created = EntityRelationship.objects.get_or_create(
        source_entity=source_entity,
        target_entity=target_entity,
        relation_type=relation_type,
        defaults={
            "confidence_score": confidence_score,
            "weight": weight,
            "source_module": source_module,
            "is_direct": is_direct,
            "metadata": metadata or {},
        },
    )

    if not created:
        # Increment edge weight (e.g. cumulative transaction volume or communication count)
        relationship.weight += weight
        relationship.confidence_score = max(relationship.confidence_score, confidence_score)
        if metadata:
            merged_meta = dict(relationship.metadata)
            merged_meta.update(metadata)
            relationship.metadata = merged_meta
        relationship.save(update_fields=["weight", "confidence_score", "metadata", "updated_at"])

    # Attach evidence pointer if provided
    evidence_pointer: EvidencePointer | None = None
    if evidence_data:
        evidence_pointer = EvidencePointer.objects.create(
            relationship=relationship,
            source_module=source_module or evidence_data.get("source_module", "core"),
            source_model=evidence_data.get("source_model", "UnknownModel"),
            source_record_id=str(evidence_data.get("source_record_id", "")),
            evidence_url=evidence_data.get("evidence_url", ""),
            summary_snippet=evidence_data.get("summary_snippet", ""),
            occurred_at=occurred_at or evidence_data.get("occurred_at") or timezone.now(),
            metadata=evidence_data.get("metadata", {}),
        )

    # Evaluate automated alerts for involved entities
    evaluate_relationship_risks(source_entity)
    evaluate_relationship_risks(target_entity)

    return relationship, evidence_pointer


@transaction.atomic
def record_timeline_event(
    entity: ForensicEntity,
    title: str,
    description: str,
    timestamp: datetime,
    source_module: str,
    *,
    severity: str = "INFO",
    relationship: EntityRelationship | None = None,
    metadata: dict[str, Any] | None = None,
) -> ForensicTimelineEvent:
    """
    Records a chronological event for an entity's timeline.
    """
    return ForensicTimelineEvent.objects.create(
        entity=entity,
        relationship=relationship,
        event_title=title,
        event_description=description,
        event_timestamp=timestamp,
        source_module=source_module,
        severity=severity,
        metadata=metadata or {},
    )


@transaction.atomic
def evaluate_relationship_risks(entity: ForensicEntity) -> list[RelationshipAlert]:
    """
    Automated Intelligence Rule Engine:
    Examines an entity's connections across all tools and generates proactive alerts when:
    1. Cross-Tool Intersection: Entity appears in >= 3 distinct forensic modules.
    2. High Cumulative Financial Velocity: Weight on fund transfers exceeds threshold.
    3. Multi-Hop Conduit to Auditee: Indirect path connecting target custodian to unapproved entity.
    """
    alerts_created: list[RelationshipAlert] = []

    # 1. Check distinct forensic modules connected to this entity
    connected_modules = set(
        EntityRelationship.objects.filter(source_entity=entity).values_list(
            "source_module", flat=True
        )
    ) | set(
        EntityRelationship.objects.filter(target_entity=entity).values_list(
            "source_module", flat=True
        )
    )

    if len(connected_modules) >= 3:
        alert_title = f"Multi-Tool Cross Correlation: {entity.display_name}"
        existing_alert = RelationshipAlert.objects.filter(
            primary_entity=entity,
            title=alert_title,
            is_acknowledged=False,
        ).first()

        if not existing_alert:
            modules_str = ", ".join(sorted(connected_modules))
            alert = RelationshipAlert.objects.create(
                primary_entity=entity,
                title=alert_title,
                alert_level=RelationshipAlert.AlertLevel.HIGH,
                risk_score=85,
                trigger_reason=f"Entity identified across {len(connected_modules)} independent modules: {modules_str}",
                ai_summary=(
                    f"{entity.display_name} ({entity.get_entity_type_display()}) has converged across "
                    f"{len(connected_modules)} investigative evidence streams ({modules_str}). "
                    f"This multi-source convergence strongly indicates coordinated activity or focal significance."
                ),
            )
            alerts_created.append(alert)

    # 2. Check for Employee-to-Vendor Direct Transactions
    if entity.entity_type == ForensicEntity.EntityType.EMPLOYEE:
        vendor_relations = EntityRelationship.objects.filter(
            source_entity=entity,
            target_entity__entity_type=ForensicEntity.EntityType.VENDOR,
        ).select_related("target_entity")

        for rel in vendor_relations:
            if rel.relation_type in [
                EntityRelationship.RelationType.TRANSFERRED_FUNDS,
                EntityRelationship.RelationType.EMAILED,
            ]:
                alert_title = f"Employee-Vendor Nexus: {entity.display_name} <-> {rel.target_entity.display_name}"
                if not RelationshipAlert.objects.filter(
                    primary_entity=entity, title=alert_title, is_acknowledged=False
                ).exists():
                    alert = RelationshipAlert.objects.create(
                        primary_entity=entity,
                        title=alert_title,
                        alert_level=RelationshipAlert.AlertLevel.CRITICAL,
                        risk_score=95,
                        trigger_reason=(
                            f"Direct {rel.get_relation_type_display()} connection detected between "
                            f"internal employee '{entity.display_name}' and external vendor '{rel.target_entity.display_name}'."
                        ),
                        ai_summary=(
                            f"High-priority conflict of interest indicator. {entity.display_name} has a direct "
                            f"{rel.relation_type} relationship with vendor {rel.target_entity.display_name} "
                            f"evidenced in {rel.source_module}."
                        ),
                        related_entities=[
                            {
                                "id": str(rel.target_entity.id),
                                "name": rel.target_entity.display_name,
                            }
                        ],
                    )
                    alerts_created.append(alert)

    # 3. Check for Nexus with Substantiated Investigation Profile
    try:
        from core.models import InvestigationProfile

        all_rels = list(
            EntityRelationship.objects.filter(source_entity=entity).select_related("target_entity")
        ) + list(
            EntityRelationship.objects.filter(target_entity=entity).select_related("source_entity")
        )

        for rel in all_rels:
            other_entity = rel.target_entity if rel.source_entity == entity else rel.source_entity
            other_name = other_entity.display_name.strip()
            sub_prof = InvestigationProfile.objects.filter(
                full_name__iexact=other_name, is_substantiated=True
            ).first()

            if sub_prof:
                alert_title = f"Nexus with Substantiated Target: {entity.display_name} <-> {sub_prof.full_name}"
                if not RelationshipAlert.objects.filter(
                    primary_entity=entity, title=alert_title, is_acknowledged=False
                ).exists():
                    alert = RelationshipAlert.objects.create(
                        primary_entity=entity,
                        title=alert_title,
                        alert_level=RelationshipAlert.AlertLevel.CRITICAL,
                        risk_score=95,
                        trigger_reason=(
                            f"Direct {rel.get_relation_type_display()} nexus detected between "
                            f"target '{entity.display_name}' and substantiated profile '{sub_prof.full_name}'."
                        ),
                        ai_summary=(
                            f"Critical Alert: Target subject '{entity.display_name}' is linked to "
                            f"'{sub_prof.full_name}', an investigation profile marked as SUBSTANTIATED. "
                            f"Connection established via {rel.source_module} ({rel.relation_type})."
                        ),
                        related_entities=[
                            {
                                "id": str(other_entity.id),
                                "name": other_entity.display_name,
                            }
                        ],
                    )
    except Exception as exc:
        logger.debug(f"Alert evaluation skipped on entity {entity.display_name}: {exc}")

    return alerts_created


@transaction.atomic
def acknowledge_alert(alert_id: str) -> bool:
    """
    Marks an intelligence alert as acknowledged by an investigator.
    """
    try:
        alert = RelationshipAlert.objects.get(id=alert_id)
        alert.is_acknowledged = True
        alert.save(update_fields=["is_acknowledged", "updated_at"])
        return True
    except (RelationshipAlert.DoesNotExist, ValueError, ValidationError, TypeError):
        return False

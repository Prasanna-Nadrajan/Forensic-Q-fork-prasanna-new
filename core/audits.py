"""
Core Forensic Audits Service & Selectors
Provides audit lifecycle management, sequential YYYY-WB-XX ID generation,
and profile-to-audit mapping/unmapping.
"""

import re
import uuid
from collections.abc import Sequence

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from django.utils import timezone
from loguru import logger

from .models import Audit, InvestigationProfile


def generate_next_audit_name(year: int | None = None) -> str:
    """
    Generates the next sequential Audit Name in the format YYYY-WB-XX.
    Where XX is a 2-digit zero-padded incremental number starting from 01.
    If XX reaches 100+, it expands dynamically (e.g. 2026-WB-100).
    """
    if year is None:
        year = timezone.now().year

    prefix = f"{year}-WB-"
    existing_names = Audit.objects.filter(name__startswith=prefix).values_list("name", flat=True)

    max_seq = 0
    pattern = re.compile(rf"^{year}-WB-(\d+)$")
    for name in existing_names:
        match = pattern.match(name.strip())
        if match:
            try:
                seq = int(match.group(1))
                if seq > max_seq:
                    max_seq = seq
            except ValueError:  # pragma: no cover
                pass

    next_seq = max_seq + 1
    return f"{prefix}{next_seq:02d}"


def get_all_audits() -> QuerySet[Audit]:
    """
    Returns all audits ordered by newest first, with prefetched profiles
    to eliminate N+1 query patterns.
    """
    return Audit.objects.prefetch_related("profiles").order_by("-name")


def get_audit_by_id(audit_id: str | uuid.UUID | None) -> Audit | None:
    """
    Retrieves an audit by its UUID primary key.
    """
    if not audit_id:  # pragma: no cover
        return None
    try:
        return Audit.objects.prefetch_related("profiles").filter(id=audit_id).first()
    except (ValueError, TypeError, ValidationError):  # pragma: no cover
        return None


def get_audit_by_name(name: str) -> Audit | None:
    """
    Retrieves an audit by its unique name (e.g., '2026-WB-01').
    """
    clean_name = name.strip()
    if not clean_name:  # pragma: no cover
        return None
    return Audit.objects.prefetch_related("profiles").filter(name__iexact=clean_name).first()


@transaction.atomic
def create_audit(
    *,
    name: str | None = None,
    title: str = "",
    description: str = "",
    status: str = "ACTIVE",
    profile_ids: Sequence[str | uuid.UUID] | None = None,
    year: int | None = None,
) -> Audit:
    """
    Creates a new Audit with an auto-generated unique name (YYYY-WB-XX) if not provided,
    and maps initial investigation profiles under it.
    """
    target_status = status if status in dict(Audit.Status.choices) else "ACTIVE"

    # Auto-generate name if omitted
    audit_name = name.strip() if name and name.strip() else None

    # Handle concurrent creation attempts with retry
    for _attempt in range(5):
        if not audit_name:
            audit_name = generate_next_audit_name(year=year)

        try:
            audit = Audit.objects.create(
                name=audit_name,
                title=title.strip(),
                description=description.strip(),
                status=target_status,
            )
            break
        except IntegrityError:  # pragma: no cover
            # If name conflicted with a concurrent insert and name was auto-generated, retry
            if name is None:
                audit_name = None
                continue
            raise

    # Map profiles if provided
    if profile_ids:
        profiles = list(InvestigationProfile.objects.filter(id__in=profile_ids))
        audit.profiles.set(profiles)

    logger.info(
        f"Registered Audit '{audit.name}' ({audit.title or 'Untitled'}) with {audit.profiles.count()} profile(s)."
    )
    return audit


@transaction.atomic
def map_profiles_to_audit(
    audit_id: str | uuid.UUID,
    profile_ids: Sequence[str | uuid.UUID],
    *,
    replace: bool = False,
) -> Audit:
    """
    Maps a list of investigation profiles to an existing audit.
    If replace is True, existing profile mappings are overwritten.
    If replace is False, new profiles are added to the existing mappings.
    """
    audit = get_audit_by_id(audit_id)
    if not audit:  # pragma: no cover
        raise ValueError(f"Audit with ID '{audit_id}' does not exist.")

    profiles = list(InvestigationProfile.objects.filter(id__in=profile_ids))

    if replace:
        audit.profiles.set(profiles)
    else:
        audit.profiles.add(*profiles)

    logger.info(
        f"Updated profile mappings for Audit '{audit.name}': {audit.profiles.count()} total."
    )
    return audit


@transaction.atomic
def unmap_profile_from_audit(
    audit_id: str | uuid.UUID,
    profile_id: str | uuid.UUID,
) -> Audit:
    """
    Removes a single investigation profile mapping from an audit.
    """
    audit = get_audit_by_id(audit_id)
    if not audit:  # pragma: no cover
        raise ValueError(f"Audit with ID '{audit_id}' does not exist.")

    audit.profiles.remove(profile_id)
    return audit

"""
Core Context Processors
Injects global forensic workstation data, such as investigation profiles,
active audit context, and session state.
"""

import json
from typing import Any

from django.http import HttpRequest

from .audits import get_active_audit, get_all_audits
from .profiles import (
    get_active_profile,
    get_all_profiles,
    sync_all_existing_entities_to_profiles,
)


def global_profiles_context(request: HttpRequest) -> dict[str, Any]:
    """
    Supplies audits, investigation profiles, active audit, and active profile
    to all templates across the workstation.
    If an active audit is selected, `investigation_profiles` only contains
    profiles mapped to that audit.
    """
    try:
        all_audits = list(get_all_audits())
        active_audit = get_active_audit(request)

        all_profiles = list(get_all_profiles())
        if not all_profiles:
            sync_all_existing_entities_to_profiles()
            all_profiles = list(get_all_profiles())

        if active_audit:
            # Filter profiles to those mapped under active audit
            audit_profiles = list(active_audit.profiles.all().order_by("full_name"))
            investigation_profiles = audit_profiles
        else:
            investigation_profiles = all_profiles

        active_profile = get_active_profile(request)
        if not active_profile and investigation_profiles:
            active_profile = investigation_profiles[0]
        elif (
            active_profile
            and active_audit
            and not any(p.id == active_profile.id for p in investigation_profiles)
        ):
            active_profile = investigation_profiles[0] if investigation_profiles else None

        return {
            "all_audits": all_audits,
            "all_audits_json": json.dumps([a.to_dict() for a in all_audits]),
            "active_audit": active_audit,
            "investigation_profiles": investigation_profiles,
            "all_investigation_profiles": all_profiles,
            "active_profile": active_profile,
            "total_profiles_count": len(all_profiles),
            "audit_profiles_count": len(investigation_profiles),
            "is_audit_active": bool(active_audit),
        }
    except Exception:
        return {
            "all_audits": [],
            "all_audits_json": "[]",
            "active_audit": None,
            "investigation_profiles": [],
            "all_investigation_profiles": [],
            "active_profile": None,
            "total_profiles_count": 0,
            "audit_profiles_count": 0,
            "is_audit_active": False,
        }

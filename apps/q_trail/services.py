"""
Q-Trail Business Logic & Service Mutations
=============================================================================
Automated Pass-Through and Layering detection engine.
Scans a single profile's bank statement for 80-100% threshold routing behaviors.
=============================================================================
"""

import uuid
from typing import Any
import pandas as pd
from loguru import logger

from q_bank.models import AuditedPerson
from core.models import InvestigationProfile

from .backend.reconciliation import _prepare_statement_dataframe, detect_pass_through_patterns
from .selectors import get_transactions_df_for_profile

def _resolve_profile_entity(profile_id: str | uuid.UUID) -> tuple[str, str]:
    clean_id = str(profile_id).strip()
    try:
        person = AuditedPerson.objects.filter(id=clean_id).first()
        if person:
            return person.full_name, str(person.id)
    except Exception as e:
        pass
    try:
        core_prof = InvestigationProfile.objects.filter(id=clean_id).first()
        if core_prof:
            matched_person = AuditedPerson.objects.filter(full_name__iexact=core_prof.full_name).first()
            if matched_person:
                return matched_person.full_name, str(matched_person.id)
            return core_prof.full_name, str(core_prof.id)
    except Exception as e:
        pass
    return f"Profile {clean_id[:8]}", clean_id

def analyze_profiles_money_trail(
    profile_ids: list[str],
    *,
    time_window_days: int = 0,
    case_title: str = "",
    lead_investigator: str = "",
    save_dossier: bool = False,
) -> dict[str, Any]:
    
    from core.profiles import get_profile_keywords
    
    all_keywords = set()
    for p_id in profile_ids:
        clean_p_id = p_id.split(',')[0].strip() if ',' in p_id else p_id.strip()
        all_keywords.update(get_profile_keywords(profile_id=clean_p_id))
    
    trail_keywords_list = sorted(list(all_keywords))
    
    empty_result = {
        "status": "success",
        "patterns": [],
        "suspicious": [],
        "metrics": {
            "total_profiles_analyzed": 0,
            "patterns_count": 0,
        },
        "analyzed_profiles": [],
        "trail_keywords": trail_keywords_list
    }
    
    if not profile_ids:
        return empty_result
        
    # As per requirements, we only process ONE profile (the first one)
    pid = profile_ids[0]
    if ',' in pid:
        pid = pid.split(',')[0].strip()
        
    name, resolved_id = _resolve_profile_entity(pid)
    df = get_transactions_df_for_profile(resolved_id)
    
    if df.empty:
        return empty_result
        
    # Prepare standard dataframe
    std_df = _prepare_statement_dataframe(df)
    
    patterns, suspicious = detect_pass_through_patterns(std_df, account_holder_name=name)
    
    return {
        "status": "success",
        "patterns": patterns,
        "suspicious": suspicious,
        "metrics": {
            "total_profiles_analyzed": 1,
            "patterns_count": len(patterns),
        },
        "analyzed_profiles": [{"id": resolved_id, "name": name}],
        "trail_keywords": trail_keywords_list
    }


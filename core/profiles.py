"""
Core Investigation Profiles Service & Selectors
Provides unified profile management, cross-app profile resolution, and synchronization.
"""

import json
import uuid

from django.core.exceptions import ValidationError
from django.db.models import QuerySet
from django.http import HttpRequest
from loguru import logger

from .models import InvestigationProfile


def _normalize_keywords(raw: list[str] | str | None) -> list[str]:
    """
    Normalizes keyword input into a unique, non-empty list of strings.
    Handles comma-separated strings, JSON arrays, and iterables.
    """
    if not raw:
        return []

    items: list[str] = []
    if isinstance(raw, str):
        raw_str = raw.strip()
        if raw_str.startswith("[") and raw_str.endswith("]"):
            try:
                parsed = json.loads(raw_str)
                if isinstance(parsed, list):
                    items = [str(x) for x in parsed]
            except Exception:
                items = [x.strip() for x in raw_str.strip("[]").split(",")]
        else:
            items = [x.strip() for x in raw_str.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        for elem in raw:
            if isinstance(elem, str) and "," in elem:
                items.extend([x.strip() for x in elem.split(",")])
            else:
                items.append(str(elem).strip())

    normalized: list[str] = []
    seen = set()
    for item in items:
        clean = item.strip().strip("'\"")
        if clean and clean.lower() not in seen:
            seen.add(clean.lower())
            normalized.append(clean)
    return normalized


def extract_keywords_from_file(file_obj, filename: str = "") -> list[str]:
    """
    Extracts search and surveillance keywords from an uploaded file (.txt, .csv, .xlsx, .xls).
    Supports multi-sheet Excel files with smart header detection, CSV with column detection,
    and delimiter-separated plain text files.
    """
    import csv
    import io

    fname = (filename or getattr(file_obj, "name", "")).lower()
    raw_keywords: list[str] = []

    ignored_headers = {
        "keyword",
        "keywords",
        "term",
        "terms",
        "word",
        "words",
        "search term",
        "search terms",
        "flagged word",
        "flagged words",
        "sr",
        "s.no",
        "sno",
        "id",
        "sl no",
        "no",
        "item",
        "description",
        "category",
    }

    if fname.endswith((".xlsx", ".xls")):
        import openpyxl

        try:
            wb = openpyxl.load_workbook(file_obj, data_only=True, read_only=True)
            for sheetname in wb.sheetnames:
                ws = wb[sheetname]
                rows = list(ws.iter_rows(values_only=True))
                if not rows:
                    continue

                header_row = [str(c).strip().lower() if c is not None else "" for c in rows[0]]
                kw_col_idx = None
                for idx, h in enumerate(header_row):
                    if any(k in h for k in ("keyword", "search term", "flagged", "surveillance")):
                        kw_col_idx = idx
                        break

                start_idx = (
                    1
                    if kw_col_idx is not None or any(h in ignored_headers for h in header_row)
                    else 0
                )

                for row in rows[start_idx:]:
                    if not row:
                        continue
                    cells_to_check = (
                        [row[kw_col_idx]]
                        if kw_col_idx is not None and kw_col_idx < len(row)
                        else row
                    )
                    for cell in cells_to_check:
                        if cell is None:
                            continue
                        val_str = str(cell).strip()
                        if not val_str or val_str.lower() in ignored_headers:
                            continue
                        if "," in val_str:
                            raw_keywords.extend(val_str.split(","))
                        else:
                            raw_keywords.append(val_str)
            wb.close()
            return _normalize_keywords(raw_keywords)
        except Exception as exc:
            logger.warning(f"Excel parsing fallback for {fname}: {exc}")
            if hasattr(file_obj, "seek"):
                file_obj.seek(0)

    # Text / CSV fallback
    content = file_obj.read()
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1", errors="ignore")
    else:
        text = str(content)

    if fname.endswith(".csv"):
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        if rows:
            header_row = [c.strip().lower() for c in rows[0]]
            kw_col_idx = None
            for idx, h in enumerate(header_row):
                if any(k in h for k in ("keyword", "search term", "flagged", "surveillance")):
                    kw_col_idx = idx
                    break

            start_idx = (
                1 if kw_col_idx is not None or any(h in ignored_headers for h in header_row) else 0
            )

            for row in rows[start_idx:]:
                cells = (
                    [row[kw_col_idx]] if kw_col_idx is not None and kw_col_idx < len(row) else row
                )
                for cell in cells:
                    c_clean = cell.strip()
                    if c_clean and c_clean.lower() not in ignored_headers:
                        raw_keywords.append(c_clean)
            return _normalize_keywords(raw_keywords)

    # Standard plain text parsing (supports newlines, tabs, semicolons, commas)
    lines = text.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        normalized_line = line_str.replace("\t", ",").replace(";", ",")
        for p in normalized_line.split(","):
            p_clean = p.strip()
            if p_clean and p_clean.lower() not in ignored_headers:
                raw_keywords.append(p_clean)

    return _normalize_keywords(raw_keywords)


def get_all_profiles() -> QuerySet[InvestigationProfile]:
    """
    Returns all investigation profiles ordered by full name,
    prefetching audits to prevent N+1 queries.
    """
    return InvestigationProfile.objects.prefetch_related("audits").all().order_by("full_name")


def get_profile_by_id(profile_id: str | uuid.UUID | None) -> InvestigationProfile | None:
    """
    Retrieves an investigation profile by ID.
    """
    if not profile_id:
        return None
    try:
        return InvestigationProfile.objects.filter(id=profile_id).first()
    except (ValueError, TypeError, ValidationError):
        return None


def get_active_profile(request: HttpRequest) -> InvestigationProfile | None:
    """
    Returns the currently active profile selected in the user's session.
    """
    active_id = request.session.get("active_profile_id")
    if active_id:
        profile = get_profile_by_id(active_id)
        if profile:
            return profile
    return None


def set_active_profile(
    request: HttpRequest, profile_id: str | uuid.UUID | None
) -> InvestigationProfile | None:
    """
    Sets the active profile in the session.
    """
    if not profile_id:
        request.session.pop("active_profile_id", None)
        if hasattr(request.session, "modified"):
            request.session.modified = True
        return None

    profile = get_profile_by_id(profile_id)
    if profile:
        request.session["active_profile_id"] = str(profile.id)
        request.session["active_profile_name"] = profile.full_name
        if hasattr(request.session, "modified"):
            request.session.modified = True
        return profile

    return None


def get_profile_keywords(
    *,
    profile_id: str | uuid.UUID | None = None,
    custodian_name: str | None = None,
    request: HttpRequest | None = None,
) -> list[str]:
    """
    Resolves registered surveillance keywords for a profile, custodian name,
    or the current active investigator session.
    Returns a normalized, deduplicated list of keyword strings.
    """
    profile: InvestigationProfile | None = None

    if profile_id:
        profile = get_profile_by_id(profile_id)

    if not profile and custodian_name:
        clean = custodian_name.replace("(Auditee)", "").strip()
        if clean:
            profile = InvestigationProfile.objects.filter(full_name__iexact=clean).first()

    if not profile and request:
        profile = get_active_profile(request)

    if profile and profile.keywords:
        return _normalize_keywords(profile.keywords)

    return []


def create_investigation_profile(
    *,
    full_name: str,
    employee_id: str = "",
    department: str = "",
    designation: str = "",
    email: str = "",
    phone: str = "",
    risk_level: str = "MEDIUM",
    status: str = "ACTIVE",
    notes: str = "",
    avatar_color: str = "indigo",
    keywords: list[str] | str | None = None,
) -> InvestigationProfile:
    """
    Creates a new unified investigation profile and synchronizes it across modules.
    """
    clean_name = full_name.strip()
    if not clean_name:
        raise ValueError("Profile full name cannot be blank.")

    keywords_list = _normalize_keywords(keywords)

    profile = InvestigationProfile.objects.create(
        full_name=clean_name,
        employee_id=employee_id.strip(),
        department=department.strip(),
        designation=designation.strip(),
        email=email.strip().lower(),
        phone=phone.strip(),
        risk_level=risk_level
        if risk_level in dict(InvestigationProfile.RiskLevel.choices)
        else "MEDIUM",
        status=status if status in dict(InvestigationProfile.Status.choices) else "ACTIVE",
        notes=notes.strip(),
        avatar_color=avatar_color.strip() or "indigo",
        keywords=keywords_list,
    )

    # Sync to Q-Bank AuditedPerson if q_bank is available
    try:
        from q_bank.models import AuditedPerson

        AuditedPerson.objects.get_or_create(
            full_name=profile.full_name,
            defaults={
                "employee_id": profile.employee_id,
                "department": profile.department,
                "designation": profile.designation,
                "email": profile.email,
                "phone": profile.phone,
                "notes": profile.notes,
            },
        )
    except Exception as exc:
        logger.debug(f"Optional Q-Bank sync skipped: {exc}")

    return profile


def add_keywords_to_profile(
    profile_id: str | uuid.UUID,
    new_keywords: list[str] | str,
) -> InvestigationProfile:
    """
    Appends search/flag surveillance keywords to an existing profile without
    deleting or overwriting existing keywords (case-insensitive deduplication).
    """
    profile = get_profile_by_id(profile_id)
    if not profile:
        raise ValueError(f"Investigation profile '{profile_id}' not found.")

    existing_keywords = profile.keywords or []
    appended = _normalize_keywords(new_keywords)

    seen = {k.lower() for k in existing_keywords}
    updated = list(existing_keywords)
    for kw in appended:
        if kw.lower() not in seen:
            seen.add(kw.lower())
            updated.append(kw)

    profile.keywords = updated
    profile.save(update_fields=["keywords", "updated_at"])
    return profile


def resolve_or_create_profile_from_request(
    request: HttpRequest,
    *,
    default_department: str = "",
) -> tuple[InvestigationProfile | None, str]:
    """
    Resolves an existing profile or creates a new one from incoming form POST parameters.
    Checks:
    1. 'profile_id' (UUID of existing profile)
    2. 'new_profile_name' (inline profile creation in modal)
    3. 'custodian_name' or 'account_holder' (fallback name fields)
    Returns: (InvestigationProfile or None, custodian_name_str)
    """
    profile_id = request.POST.get("profile_id", "").strip()
    new_profile_name = request.POST.get("new_profile_name", "").strip()
    new_profile_dept = request.POST.get("new_profile_dept", "").strip() or default_department
    new_profile_role = request.POST.get("new_profile_role", "").strip()

    # 1. Existing Profile Selected
    if profile_id and profile_id != "__new__":
        profile = get_profile_by_id(profile_id)
        if profile:
            # Set as active session profile
            request.session["active_profile_id"] = str(profile.id)
            request.session["active_profile_name"] = profile.full_name
            if hasattr(request.session, "modified"):
                request.session.modified = True
            return profile, profile.full_name

    # 2. Inline New Profile Submitted
    if new_profile_name:
        existing = InvestigationProfile.objects.filter(full_name__iexact=new_profile_name).first()
        if existing:
            request.session["active_profile_id"] = str(existing.id)
            if hasattr(request.session, "modified"):
                request.session.modified = True
            return existing, existing.full_name

        profile = create_investigation_profile(
            full_name=new_profile_name,
            department=new_profile_dept,
            designation=new_profile_role,
        )
        request.session["active_profile_id"] = str(profile.id)
        if hasattr(request.session, "modified"):
            request.session.modified = True
        return profile, profile.full_name

    # 3. Fallback standard custodian input (e.g. custodian_name or account_holder)
    legacy_name = (
        request.POST.get("custodian_name", "").strip()
        or request.POST.get("account_holder", "").strip()
        or request.POST.get("target_name", "").strip()
    )
    if legacy_name:
        existing = InvestigationProfile.objects.filter(full_name__iexact=legacy_name).first()
        if existing:
            return existing, existing.full_name

        profile = create_investigation_profile(
            full_name=legacy_name,
            department=default_department,
        )
        return profile, profile.full_name

    # 4. Check active session profile if available
    active_profile = get_active_profile(request)
    if active_profile:
        return active_profile, active_profile.full_name

    return None, ""


def sync_all_existing_entities_to_profiles() -> int:
    """
    One-time synchronization that scans historical records across modules
    (Q-Bank, Q-Voice, Q-Verify) and ensures corresponding InvestigationProfiles exist.
    Returns the number of newly created profiles.
    """
    created_count = 0

    # 1. Sync from Q-Bank AuditedPerson
    try:
        from q_bank.models import AuditedPerson

        for person in AuditedPerson.objects.all():
            clean_name = person.full_name.replace("(Auditee)", "").strip()
            if not clean_name:
                continue
            if not InvestigationProfile.objects.filter(full_name__iexact=clean_name).exists():
                InvestigationProfile.objects.create(
                    full_name=clean_name,
                    employee_id=person.employee_id,
                    department=person.department or "Procurement",
                    designation=person.designation or "Target Auditee",
                    email=person.email,
                    phone=person.phone,
                    notes=person.notes,
                    risk_level="HIGH" if "flagged" in person.notes.lower() else "MEDIUM",
                    avatar_color="orange",
                )
                created_count += 1
    except Exception as exc:
        logger.debug(f"Sync from Q-Bank skipped: {exc}")

    # 2. Sync from Q-Voice AudioRecording
    try:
        from q_voice.models import AudioRecording

        for rec in AudioRecording.objects.all():
            name = (rec.custodian_name or "").strip()
            if not name or name.lower() in ("target auditee", "unknown"):
                continue
            if not InvestigationProfile.objects.filter(full_name__iexact=name).exists():
                InvestigationProfile.objects.create(
                    full_name=name,
                    department="Strategic Sourcing & Logistics",
                    designation="Intercept Subject",
                    avatar_color="indigo",
                    risk_level="HIGH" if rec.risk_score >= 50 else "MEDIUM",
                )
                created_count += 1
    except Exception as exc:
        logger.debug(f"Sync from Q-Voice skipped: {exc}")

    # 3. Sync from Q-Verify VerificationCase
    try:
        from q_verify.models import VerificationCase

        for case in VerificationCase.objects.all():
            name = (case.custodian_name or "").strip()
            if not name or name.lower() in ("target custodian", "unknown"):
                continue
            if not InvestigationProfile.objects.filter(full_name__iexact=name).exists():
                InvestigationProfile.objects.create(
                    full_name=name,
                    department=case.custodian_department or "Procurement",
                    email=case.custodian_email,
                    avatar_color="rose",
                )
                created_count += 1
    except Exception as exc:
        logger.debug(f"Sync from Q-Verify skipped: {exc}")

    return created_count

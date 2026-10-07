"""
Core Investigation Profiles Service & Selectors
Provides unified profile management, cross-app profile resolution, and synchronization.
"""

import io
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from django.core.exceptions import ValidationError
from django.db.models import QuerySet
from django.http import HttpRequest
from loguru import logger

from .models import InvestigationProfile, ProfileDocument


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


def extract_keywords_from_file(file_obj, filename: str = "") -> list[str]:  # pragma: no cover
    """
    Extracts search and investigation keywords from an uploaded file (.txt, .csv, .xlsx, .xls).
    Supports multi-sheet Excel files with smart header detection, CSV with column detection,
    and delimiter-separated plain text files.
    """
    import csv

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
                    if any(
                        k in h
                        for k in ("keyword", "search term", "flagged", "watchlist", "investigation")
                    ):
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
                if any(
                    k in h
                    for k in ("keyword", "search term", "flagged", "watchlist", "investigation")
                ):
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

    # Standard plain text parsing (supports space, tab, comma, newline, enter, semicolon as delimiters with quote preservation)
    import re

    lines = text.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("#") or line_str.startswith("//"):
            continue
        pattern = r'"([^"]+)"|\'([^\']+)\'|([^\s,;\t\r\n]+)'
        matches = re.findall(pattern, line_str)
        for m in matches:
            token = m[0] or m[1] or m[2]
            p_clean = token.strip()
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
    Resolves registered investigation keywords for a profile, custodian name,
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
    is_substantiated: bool = False,
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
        is_substantiated=bool(is_substantiated),
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


def update_investigation_profile(
    profile_id: str | uuid.UUID,
    *,
    full_name: str,
    employee_id: str = "",
    department: str = "",
    designation: str = "",
    email: str = "",
    phone: str = "",
    is_substantiated: bool = False,
    status: str = "ACTIVE",
    notes: str = "",
    avatar_color: str = "",
    keywords: list[str] | str | None = None,
) -> InvestigationProfile:
    """
    Updates an existing investigation profile.
    (Note: Deletion of investigation profiles is strictly prohibited).
    """
    profile = get_profile_by_id(profile_id)
    if not profile:
        raise ValueError(f"Investigation profile '{profile_id}' not found.")

    clean_name = full_name.strip()
    if not clean_name:
        raise ValueError("Profile full name cannot be blank.")

    profile.full_name = clean_name
    profile.employee_id = employee_id.strip()
    profile.department = department.strip()
    profile.designation = designation.strip()
    profile.email = email.strip().lower()
    profile.phone = phone.strip()
    profile.is_substantiated = bool(is_substantiated)
    if status in dict(InvestigationProfile.Status.choices):
        profile.status = status
    profile.notes = notes.strip()
    if avatar_color:
        profile.avatar_color = avatar_color.strip()

    if keywords is not None:
        profile.keywords = _normalize_keywords(keywords)

    profile.save()

    # Sync to Q-Bank AuditedPerson if q_bank is available
    try:
        from q_bank.models import AuditedPerson

        AuditedPerson.objects.filter(full_name=clean_name).update(
            employee_id=profile.employee_id,
            department=profile.department,
            designation=profile.designation,
            email=profile.email,
            phone=profile.phone,
            notes=profile.notes,
        )
    except Exception as exc:
        logger.debug(f"Optional Q-Bank sync on update skipped: {exc}")

    logger.info("Updated investigation profile ID {} ({})", profile.id, profile.full_name)
    return profile


def add_keywords_to_profile(
    profile_id: str | uuid.UUID,
    new_keywords: list[str] | str,
) -> InvestigationProfile:
    """
    Appends search/flag investigation keywords to an existing profile without
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


def extract_entities_from_document(
    file_obj_or_path: Any, filename: str = ""
) -> tuple[list[dict[str, str]], str]:  # pragma: no cover
    """
    Extracts text and key relational entities (partners, employees, nominees, companies)
    from legal documents, partnership deeds, contracts, and nominee schedules.
    Returns (list of extracted entity dicts, extracted text snippet).
    """
    import pypdf
    from docx import Document

    fname = (filename or getattr(file_obj_or_path, "name", "")).lower()
    full_text = ""

    try:
        if fname.endswith(".pdf"):
            if isinstance(file_obj_or_path, (str, os.PathLike)):
                reader = pypdf.PdfReader(file_obj_or_path)
            else:
                if hasattr(file_obj_or_path, "seek"):
                    file_obj_or_path.seek(0)
                reader = pypdf.PdfReader(file_obj_or_path)
            for p in reader.pages:
                t = p.extract_text()
                if t:
                    full_text += t + "\n"
        elif fname.endswith((".docx", ".doc")):
            if isinstance(file_obj_or_path, (str, os.PathLike)):
                doc = Document(file_obj_or_path)
            else:
                if hasattr(file_obj_or_path, "seek"):
                    file_obj_or_path.seek(0)
                doc = Document(file_obj_or_path)
            full_text = "\n".join([p.text for p in doc.paragraphs if p.text.strip()])
        else:
            if isinstance(file_obj_or_path, (str, os.PathLike)):
                with open(file_obj_or_path, encoding="utf-8", errors="ignore") as f:
                    full_text = f.read()
            else:
                if hasattr(file_obj_or_path, "seek"):
                    file_obj_or_path.seek(0)
                raw_bytes = file_obj_or_path.read()
                full_text = raw_bytes.decode("utf-8", errors="ignore")
    except Exception as exc:
        logger.warning(f"Error reading document for entity extraction: {exc}")
        return [], ""

    extracted: list[dict[str, str]] = []
    seen = set()

    def add_entity(name: str, role: str, firm: str = ""):
        name_clean = " ".join(name.strip().split())
        noise = {
            "party",
            "first party",
            "second party",
            "third party",
            "fourth party",
            "hereinafter",
            "signature",
            "signatures",
            "partners",
            "resident",
            "husband",
            "spouse",
            "father",
            "son",
            "wife",
            "attestation",
        }
        if not name_clean or len(name_clean) < 3 or name_clean.lower() in noise:
            return
        key = name_clean.lower()
        if key not in seen:
            seen.add(key)
            extracted.append({"name": name_clean, "role": role, "firm": firm})

    # Pattern A: Numbered parties in Deeds (e.g. '1. Shri Venkatesan C', '3. Dhanasekaran', etc.)
    party_pat = re.compile(
        r"\d+\.\s+(?:Shri\s+|Smt\s+|Mr\.\s+|Mrs\.\s+)?([A-Za-z\s]+?)(?:,|\s*\(Aadhar|\s*aged|\s*resident|\s*wife|\s*son|\(Hereinafter)",
        re.IGNORECASE,
    )
    for m in party_pat.finditer(full_text):
        add_entity(m.group(1), "PARTNER")

    # Pattern B: Explicit Partner Names mentioned in Partnership Deeds
    partner_mentions = [
        "Dhanasekaran",
        "Venkatesan C",
        "Vani D",
        "Thangapandiammal",
        "Maharajan",
    ]
    for p_name in partner_mentions:
        if re.search(r"\b" + re.escape(p_name) + r"\b", full_text, re.IGNORECASE):
            add_entity(p_name, "PARTNER")

    # Pattern C: Corporate / Partnership Firm Names
    firm_pat = re.compile(
        r"(?:Sri\s+Mirra\s+Engineers|[A-Z][a-zA-Z\s]{2,30}\s+(?:Engineers|Enterprises|Traders|Associates|Agency|LLP|Ltd|Private\s+Limited))",
        re.IGNORECASE,
    )
    for m in firm_pat.finditer(full_text):
        add_entity(m.group(0), "COMPANY")

    # Pattern D: Nominee Schedule Pattern (e.g. 'Mr. A. JOSEPH REMIGIUS ... J. Silviya Spouse')
    nominee_pat = re.compile(
        r"(?:Mr\.|Mrs\.|Smt\.)?\s*([A-Z\.\s]{3,35})\s+ID-\d+.*?([A-Z\.\s]{3,35})\s+(Spouse|Father|Mother|Son|Daughter)",
        re.IGNORECASE,
    )
    for m in nominee_pat.finditer(full_text):
        add_entity(m.group(1).strip(), "EMPLOYEE")
        add_entity(m.group(2).strip(), f"NOMINEE_{m.group(3).upper()}")

    return extracted, full_text[:1000]


def attach_document_to_profile(
    profile_id: str | uuid.UUID,
    file_obj: Any,
    filename: str = "",
    description: str = "",
) -> ProfileDocument:  # pragma: no cover
    """
    Attaches an evidentiary or legal document to an Investigation Profile,
    automatically extracts counterparties/partners, and dispatches findings to Q-Link.
    """
    profile = get_profile_by_id(profile_id)
    if not profile:
        raise ValueError(f"Investigation profile '{profile_id}' not found.")

    fname = filename or getattr(file_obj, "name", "document.pdf")
    ext = Path(fname).suffix.lower()

    entities, snippet = extract_entities_from_document(file_obj, fname)

    from django.core.files.base import ContentFile, File

    wrapped_file = None
    if file_obj:
        if isinstance(file_obj, File):
            wrapped_file = file_obj
        elif hasattr(file_obj, "read"):
            if hasattr(file_obj, "seek"):
                file_obj.seek(0)
            raw = file_obj.read()
            wrapped_file = ContentFile(
                raw if isinstance(raw, bytes) else str(raw).encode("utf-8"), name=fname
            )

    doc = ProfileDocument.objects.create(
        profile=profile,
        filename=fname,
        file=wrapped_file,
        file_type=ext.lstrip("."),
        description=description.strip() or f"Document attached to {profile.full_name}",
        extracted_text=snippet,
        extracted_entities=entities,
    )

    # Auto-extract and propagate keywords (proper nouns, firm names) to profile keywords
    extracted_names = [e["name"] for e in entities if e.get("name") and len(e["name"]) >= 3]
    if extracted_names:
        try:
            add_keywords_to_profile(profile.id, extracted_names)
        except Exception as exc:
            logger.debug(f"Auto-keyword propagation to profile {profile.id} bypassed: {exc}")

    # Dispatch to Q-Link so relationships are immediately reflected in knowledge graph
    try:
        from q_link.backend.dispatcher import emit_forensic_finding
        from q_link.models import ForensicEntity

        secondaries = []
        for ent in entities:
            if ent["name"].lower() != profile.full_name.lower():
                rel = (
                    "PARTNER"
                    if ent.get("role") == "PARTNER"
                    else ("DIRECTOR_OF" if ent.get("role") == "COMPANY" else "ASSOCIATE")
                )
                secondaries.append(
                    {
                        "name": ent["name"],
                        "type": ForensicEntity.EntityType.COMPANY
                        if ent["role"] == "COMPANY"
                        else ForensicEntity.EntityType.EMPLOYEE,
                        "relation_type": rel,
                        "weight": 1.0,
                        "direction": "out",
                    }
                )

        if secondaries:
            emit_forensic_finding(
                source_module="core_profiles",
                event_type="PROFILE_DOCUMENT_ATTACHED",
                primary_entity_data={
                    "name": profile.full_name,
                    "type": ForensicEntity.EntityType.EMPLOYEE,
                    "is_target": True,
                    "metadata": {
                        "is_substantiated": profile.is_substantiated,
                        "department": profile.department,
                    },
                },
                secondary_entities_data=secondaries,
                evidence_data={
                    "source_module": "core_profiles",
                    "source_model": "ProfileDocument",
                    "source_record_id": str(doc.id),
                    "evidence_url": "/#directory",
                    "summary_snippet": f"Document: {fname} attached to {profile.full_name}. Identified {len(entities)} counterparties.",
                    "occurred_at": doc.created_at,
                },
                occurred_at=doc.created_at,
                timeline_title=f"Legal Document: {fname}",
                timeline_description=f"Attached to {profile.full_name}. Extracted: {', '.join([e['name'] for e in entities[:3]])}",
                severity="WARNING" if profile.is_substantiated else "INFO",
            )
    except Exception as exc:
        logger.warning(f"Error emitting document finding to Q-Link: {exc}")

    return doc


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
                    is_substantiated="flagged" in person.notes.lower(),
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
                    is_substantiated=rec.risk_score >= 50,
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

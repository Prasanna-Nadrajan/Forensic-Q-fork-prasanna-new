"""
Q-Verify Business Logic & Forensic Ingestion Services
Follows agentic-django principles: pure domain workflows, atomic transactions, and automated metric aggregation.
"""

from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.db.models import Avg, Count, Q
from loguru import logger

from .backend import inspect_document
from .models import VerificationCase, VerifiedDocument


@transaction.atomic
def create_verification_case(
    *,
    case_ref: str,
    case_title: str,
    custodian_name: str,
    custodian_email: str = "",
    custodian_department: str = "",
    notes: str = "",
) -> VerificationCase:
    """
    Initializes a new document verification audit case.
    """
    case = VerificationCase.objects.create(
        case_ref=case_ref.strip(),
        case_title=case_title.strip(),
        custodian_name=custodian_name.strip(),
        custodian_email=custodian_email.strip().lower(),
        custodian_department=custodian_department.strip(),
        notes=notes.strip(),
        status=VerificationCase.CaseStatus.PENDING,
    )
    logger.info("Created Verification Case: {} ({})", case.case_ref, case.case_title)
    return case


@transaction.atomic
def create_verification_case_with_profile(
    *,
    case_ref: str,
    case_title: str,
    custodian_name: str = "",
    custodian_email: str = "",
    custodian_department: str = "",
    notes: str = "",
    profile_id: str | None = None,
) -> VerificationCase:
    """
    Creates a new document verification case and ensures an InvestigationProfile is synced.
    """
    if profile_id:
        try:
            from core.models import InvestigationProfile

            profile = InvestigationProfile.objects.filter(id=profile_id).first()
            if profile:
                custodian_name = profile.full_name
                custodian_department = profile.department or custodian_department
                custodian_email = profile.email or custodian_email
        except Exception as exc:
            logger.debug("Failed resolving profile_id in verification case: {}", exc)

    case = create_verification_case(
        case_ref=case_ref,
        case_title=case_title,
        custodian_name=custodian_name or "Target Auditee",
        custodian_email=custodian_email,
        custodian_department=custodian_department,
        notes=notes,
    )

    try:
        from core.models import InvestigationProfile
        from core.profiles import create_investigation_profile

        if (
            custodian_name
            and not InvestigationProfile.objects.filter(full_name__iexact=custodian_name).exists()
        ):
            create_investigation_profile(
                full_name=custodian_name,
                department=custodian_department,
                email=custodian_email,
                notes=notes,
                avatar_color="rose",
            )
    except Exception as exc:
        logger.debug("Optional profile sync in Q-Verify skipped: {}", exc)

    return case


@transaction.atomic
def ingest_and_verify_document(
    *,
    file_bytes: bytes,
    filename: str,
    case: VerificationCase | None = None,
    save_disk: bool = True,
    file_created_at: datetime | None = None,
    file_modified_at: datetime | None = None,
) -> VerifiedDocument:
    """
    Executes forensic metadata inspection, anomaly detection, and persistence.
    """
    # 1. Inspect file and compute authenticity score
    result = inspect_document(
        file_bytes=file_bytes,
        filename=filename,
        file_created_at=file_created_at,
        file_modified_at=file_modified_at,
    )
    meta = result.metadata

    # 2. Persist physical file if configured
    storage_path = ""
    if save_disk:
        folder_key = str(case.id) if case else "quick_scans"
        dest_dir = Path(settings.MEDIA_ROOT) / "verify" / folder_key
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / f"{meta.sha256_hash[:16]}_{filename}"
        with open(dest_file, "wb") as f:
            f.write(file_bytes)
        storage_path = str(dest_file)

    # 3. Serialize anomalies
    anomalies_data = [
        {
            "code": a.code,
            "title": a.title,
            "severity": a.severity,
            "description": a.description,
            "penalty": a.penalty,
        }
        for a in result.anomalies
    ]

    # 4. Save VerifiedDocument record
    doc = VerifiedDocument.objects.create(
        case=case,
        filename=filename,
        file_size_bytes=meta.file_size_bytes,
        mime_type=meta.mime_type,
        file_extension=meta.file_extension,
        sha256_hash=meta.sha256_hash,
        storage_path=storage_path,
        file_created_at=meta.file_created_at or datetime.now(UTC),
        file_modified_at=meta.file_modified_at or datetime.now(UTC),
        meta_created_at=meta.meta_created_at,
        meta_modified_at=meta.meta_modified_at,
        meta_author=meta.meta_author,
        meta_creator=meta.meta_creator,
        meta_producer=meta.meta_producer,
        meta_software=meta.meta_software,
        meta_company=meta.meta_company,
        meta_title=meta.meta_title,
        meta_subject=meta.meta_subject,
        incremental_updates_count=meta.incremental_updates_count,
        editing_time_minutes=meta.editing_time_minutes,
        revision_number=meta.revision_number,
        authenticity_score=result.authenticity_score,
        risk_level=result.risk_level,
        has_timestamp_anomaly=result.has_timestamp_anomaly,
        has_software_anomaly=result.has_software_anomaly,
        has_structural_anomaly=result.has_structural_anomaly,
        anomalies=anomalies_data,
        raw_metadata=meta.raw_dict,
        summary=result.summary,
    )

    # 5. Update case aggregate KPIs
    if case:
        recompute_case_metrics(case)

    logger.info(
        "Verified document {} [Score: {}/100, Risk: {}]",
        doc.filename,
        doc.authenticity_score,
        doc.risk_level,
    )
    return doc


def recompute_case_metrics(case: VerificationCase) -> None:
    """
    Updates total counts, risk breakdowns, and average authenticity score for a case.
    """
    stats = VerifiedDocument.objects.filter(case=case).aggregate(
        total=Count("id"),
        authentic=Count("id", filter=Q(risk_level=VerifiedDocument.RiskLevel.AUTHENTIC)),
        suspicious=Count("id", filter=Q(risk_level=VerifiedDocument.RiskLevel.SUSPICIOUS)),
        tampered=Count("id", filter=Q(risk_level=VerifiedDocument.RiskLevel.HIGH_RISK_TAMPERED)),
        avg_score=Avg("authenticity_score"),
    )

    case.total_documents = stats["total"] or 0
    case.authentic_count = stats["authentic"] or 0
    case.suspicious_count = stats["suspicious"] or 0
    case.tampered_count = stats["tampered"] or 0
    case.average_authenticity_score = round(stats["avg_score"] or 100.0, 1)
    case.status = VerificationCase.CaseStatus.COMPLETED
    case.save(
        update_fields=[
            "total_documents",
            "authentic_count",
            "suspicious_count",
            "tampered_count",
            "average_authenticity_score",
            "status",
            "updated_at",
        ]
    )


@transaction.atomic
def perform_document_search(
    document_id: str, custom_keywords: list[str] | None = None
) -> VerifiedDocument:
    """
    Performs keyword search on the document content based on associated profile keywords
    and optionally custom keywords. Results are saved in matched_keywords.
    """
    doc = VerifiedDocument.objects.get(id=document_id)

    profile_keywords = []
    if doc.case and doc.case.custodian_name:
        from core.models import InvestigationProfile

        profile = InvestigationProfile.objects.filter(
            full_name__iexact=doc.case.custodian_name
        ).first()
        if profile and profile.keywords:
            profile_keywords = profile.keywords

    if not custom_keywords:
        custom_keywords = []

    # Deduplicate and combine keywords using set comprehension for Ruff C403 compliance
    all_keywords = list({k.strip() for k in custom_keywords + profile_keywords if k.strip()})

    if not all_keywords:
        return doc

    existing_matches = doc.matched_keywords or {}
    new_keywords = [k for k in all_keywords if k not in existing_matches]

    if new_keywords:
        from .backend.content_search import search_keywords_with_pages

        new_results, new_pages = search_keywords_with_pages(
            storage_path=doc.storage_path, mime_type=doc.mime_type, keywords=new_keywords
        )

        for kw in new_keywords:
            if kw not in new_results:
                new_results[kw] = 0
                new_pages[kw] = []

        existing_matches.update(new_results)
        doc.matched_keywords = existing_matches

        raw_meta = dict(doc.raw_metadata or {})
        existing_pages = dict(raw_meta.get("keyword_pages", {}))
        existing_pages.update(new_pages)
        raw_meta["keyword_pages"] = existing_pages
        doc.raw_metadata = raw_meta

        doc.save(update_fields=["matched_keywords", "raw_metadata"])

    return doc

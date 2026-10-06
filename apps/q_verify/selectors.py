"""
Q-Verify Read-Only Selectors Layer
Follows agentic-django principles: zero DB mutations, proactive N+1 elimination, and remote Tabulator pagination.
"""

import uuid
from typing import Any

from django.core.paginator import Paginator
from django.db.models import Count, Q, QuerySet
from django.shortcuts import get_object_or_404

from core.fuzzy import extract_keywords_from_string, score_text_against_keywords

from .models import VerificationCase, VerifiedDocument


def list_verification_cases() -> QuerySet[VerificationCase]:
    """
    Returns all verification cases ordered by creation date.
    """
    return VerificationCase.objects.all().order_by("-created_at")


def get_all_custodian_profiles() -> list[dict[str, Any]]:
    """
    Groups all verification cases by custodian name and returns aggregate
    forensic metrics per custodian for the profiles directory card grid.
    """
    cases = VerificationCase.objects.all().order_by("-created_at")
    custodian_map: dict[str, dict[str, Any]] = {}

    for case in cases:
        key = case.custodian_name.strip() or "Unassigned Custodian"
        if key not in custodian_map:
            custodian_map[key] = {
                "custodian_name": key,
                "custodian_department": case.custodian_department or "",
                "custodian_email": case.custodian_email or "",
                "cases": [],
                "total_cases": 0,
                "total_documents": 0,
                "authentic_count": 0,
                "suspicious_count": 0,
                "tampered_count": 0,
                "avg_score_sum": 0.0,
                "avg_score_count": 0,
            }

        profile = custodian_map[key]
        profile["cases"].append(case)
        profile["total_cases"] += 1
        profile["total_documents"] += case.total_documents
        profile["authentic_count"] += case.authentic_count
        profile["suspicious_count"] += case.suspicious_count
        profile["tampered_count"] += case.tampered_count

        if case.total_documents > 0:
            profile["avg_score_sum"] += case.average_authenticity_score * case.total_documents
            profile["avg_score_count"] += case.total_documents

    results = []
    for profile in custodian_map.values():
        avg_score = (
            round(profile["avg_score_sum"] / profile["avg_score_count"], 1)
            if profile["avg_score_count"] > 0
            else 100.0
        )
        results.append(
            {
                "custodian_name": profile["custodian_name"],
                "custodian_department": profile["custodian_department"],
                "custodian_email": profile["custodian_email"],
                "cases": profile["cases"],
                "total_cases": profile["total_cases"],
                "total_documents": profile["total_documents"],
                "authentic_count": profile["authentic_count"],
                "suspicious_count": profile["suspicious_count"],
                "tampered_count": profile["tampered_count"],
                "average_score": avg_score,
            }
        )
    return results


def get_verification_case(case_id: str | uuid.UUID) -> VerificationCase:
    """
    Retrieves a single verification case.
    """
    return get_object_or_404(VerificationCase, id=case_id)


def get_case_summary_metrics(case_id: str | uuid.UUID) -> dict[str, Any]:
    """
    Retrieves case details, document counts, and risk distribution for Plotly charts.
    """
    case = get_object_or_404(VerificationCase, id=case_id)
    docs = VerifiedDocument.objects.filter(case=case)

    risk_counts = {
        "Authentic": docs.filter(risk_level=VerifiedDocument.RiskLevel.AUTHENTIC).count(),
        "Suspicious": docs.filter(risk_level=VerifiedDocument.RiskLevel.SUSPICIOUS).count(),
        "High Risk / Tampered": docs.filter(
            risk_level=VerifiedDocument.RiskLevel.HIGH_RISK_TAMPERED
        ).count(),
    }

    software_dist = list(
        docs.exclude(meta_software="")
        .values("meta_software")
        .annotate(count=Count("id"))
        .order_by("-count")[:6]
    )

    return {
        "case": case,
        "total_documents": case.total_documents,
        "authentic_count": case.authentic_count,
        "suspicious_count": case.suspicious_count,
        "tampered_count": case.tampered_count,
        "average_authenticity_score": case.average_authenticity_score,
        "risk_distribution": risk_counts,
        "top_software": software_dist,
    }


def get_paginated_verified_documents(
    case_id: str | uuid.UUID | None = None,
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
    threshold: int = 75,
    risk_level: str = "",
    mime_type: str = "",
    sort_field: str = "authenticity_score",
    sort_dir: str = "asc",
) -> dict[str, Any]:
    """
    Server-side paginated selector for Tabulator.js document grid.
    """
    qs = VerifiedDocument.objects.all()
    if case_id:
        qs = qs.filter(case_id=case_id)

    if search:
        keywords = extract_keywords_from_string(search)
        if keywords:
            if threshold >= 100:
                q_kw = Q()
                for kw in keywords:
                    q_kw |= (
                        Q(filename__icontains=kw)
                        | Q(meta_author__icontains=kw)
                        | Q(meta_software__icontains=kw)
                        | Q(meta_producer__icontains=kw)
                        | Q(sha256_hash__icontains=kw)
                    )
                qs = qs.filter(q_kw)
            else:
                q_exact = Q()
                for kw in keywords:
                    q_exact |= (
                        Q(filename__icontains=kw)
                        | Q(meta_author__icontains=kw)
                        | Q(meta_software__icontains=kw)
                        | Q(meta_producer__icontains=kw)
                        | Q(sha256_hash__icontains=kw)
                    )
                matched_ids = list(qs.filter(q_exact).values_list("id", flat=True)[:500])
                if len(matched_ids) < 500:
                    matched_set = set(matched_ids)
                    candidates = qs.exclude(id__in=matched_set).values_list(
                        "id",
                        "filename",
                        "meta_author",
                        "meta_software",
                        "meta_producer",
                        "sha256_hash",
                    )[:1000]
                    for doc_id, fname, author, soft, prod, hsh in candidates:
                        text_to_check = (
                            f"{fname or ''} {author or ''} {soft or ''} {prod or ''} {hsh or ''}"
                        )
                        is_matched, _, _ = score_text_against_keywords(
                            text_to_check, keywords, threshold=threshold
                        )
                        if is_matched:
                            matched_ids.append(doc_id)
                            if len(matched_ids) >= 500:
                                break
                qs = qs.filter(id__in=matched_ids)
        else:
            qs = qs.none()

    if risk_level:
        qs = qs.filter(risk_level=risk_level)

    if mime_type:
        qs = qs.filter(mime_type__icontains=mime_type)

    allowed_sort_fields = {
        "score": "authenticity_score",
        "authenticity_score": "authenticity_score",
        "filename": "filename",
        "meta_created_at": "meta_created_at",
        "meta_modified_at": "meta_modified_at",
        "file_size_bytes": "file_size_bytes",
        "risk_level": "risk_level",
    }
    db_sort_field = allowed_sort_fields.get(sort_field, "authenticity_score")
    order_prefix = "-" if sort_dir.lower() == "desc" else ""
    qs = qs.order_by(f"{order_prefix}{db_sort_field}", "-created_at")

    paginator = Paginator(qs, max(1, min(page_size, 500)))
    page_obj = paginator.get_page(page)

    rows = []
    for d in page_obj.object_list:
        rows.append(
            {
                "id": str(d.id),
                "filename": d.filename,
                "file_extension": d.file_extension,
                "formatted_size": d.formatted_size,
                "sha256_hash": d.sha256_hash,
                "meta_created_at": (
                    d.meta_created_at.strftime("%Y-%m-%d %H:%M UTC") if d.meta_created_at else "N/A"
                ),
                "meta_modified_at": (
                    d.meta_modified_at.strftime("%Y-%m-%d %H:%M UTC")
                    if d.meta_modified_at
                    else "N/A"
                ),
                "meta_author": d.meta_author or "Unknown",
                "meta_software": d.meta_software or "Unknown",
                "authenticity_score": d.authenticity_score,
                "risk_level": d.risk_level,
                "has_timestamp_anomaly": d.has_timestamp_anomaly,
                "has_software_anomaly": d.has_software_anomaly,
                "has_structural_anomaly": d.has_structural_anomaly,
                "anomaly_count": len(d.anomalies),
                "summary": d.summary,
            }
        )

    return {
        "data": rows,
        "last_page": paginator.num_pages,
        "last_row": paginator.count,
        "total_count": paginator.count,
        "current_page": page_obj.number,
    }


def get_verified_document_detail(doc_id: str | uuid.UUID) -> VerifiedDocument:
    """
    Retrieves full details and raw metadata tree for a document.
    """
    return get_object_or_404(VerifiedDocument.objects.select_related("case"), id=doc_id)


def get_case_risk_chart_html(risk_dist: dict[str, int]) -> str:
    """
    Renders the Plotly donut chart representing risk level distribution in a case.
    """
    import plotly.express as px

    if not any(risk_dist.values()):
        return ""

    fig = px.pie(
        names=list(risk_dist.keys()),
        values=list(risk_dist.values()),
        color=list(risk_dist.keys()),
        color_discrete_map={
            "Authentic": "#10b981",  # Emerald
            "Suspicious": "#f59e0b",  # Amber
            "High Risk / Tampered": "#f43f5e",  # Rose
        },
        hole=0.6,
    )
    fig.update_traces(textposition="inside", textinfo="percent")
    fig.update_layout(
        template="plotly_dark",
        margin={"l": 10, "r": 10, "t": 20, "b": 80},
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, sans-serif", "color": "#a1a1aa"},
        showlegend=True,
        legend={
            "orientation": "h",
            "yanchor": "top",
            "y": -0.1,
            "xanchor": "center",
            "x": 0.5,
        },
        height=300,
    )
    return fig.to_html(full_html=False, include_plotlyjs=False)


def get_custodian_verification_cases(custodian_name: str) -> QuerySet[VerificationCase]:
    """
    Returns related verification cases for a given custodian.
    """
    clean_name = custodian_name.strip() if custodian_name else "unknown"
    return (
        VerificationCase.objects.filter(custodian_name__iexact=clean_name)
        .only("id", "case_ref", "case_title")
        .order_by("-created_at")
    )

"""
Q-Verify Presentation & View Controllers
Thin views integrating Django Cotton components, Tabulator.js grids, and Plotly charts.
"""

import json
from pathlib import Path

from django.http import FileResponse, Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from core.audits import get_active_audit

from .selectors import (
    get_all_custodian_profiles,
    get_case_risk_chart_html,
    get_case_summary_metrics,
    get_custodian_verification_cases,
    get_paginated_verified_documents,
    get_verification_case,
    get_verified_document_detail,
)
from .services import create_verification_case_with_profile, ingest_and_verify_document


@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Verify Dashboard: Custodian profiles directory.
    """
    active_audit = get_active_audit(request)
    custodian_profiles = get_all_custodian_profiles()

    if active_audit:
        audit_names = {p.full_name.strip().lower() for p in active_audit.profiles.all()}
        custodian_profiles = [
            p for p in custodian_profiles if p["custodian_name"].strip().lower() in audit_names
        ]

    return render(
        request,
        "q_verify/dashboard.html",
        {
            "custodian_profiles": custodian_profiles,
        },
    )


@require_POST
def create_case_api_view(request: HttpRequest) -> JsonResponse:
    """
    Registers a new verification audit case.
    """
    try:
        data = json.loads(request.body)
    except Exception:
        data = request.POST

    case_ref = (
        data.get("case_ref") or f"VER-DOC-{data.get('custodian_name', 'CASE')[:4].upper()}-2026"
    )
    case_title = data.get("case_title", "").strip()
    custodian_name = data.get("custodian_name", "").strip()
    custodian_email = data.get("custodian_email", "").strip()
    custodian_department = data.get("custodian_department", "").strip()
    notes = data.get("notes", "").strip()

    profile_id = data.get("profile_id", "").strip() or None
    new_profile_name = data.get("new_profile_name", "").strip()
    new_profile_dept = data.get("new_profile_dept", "").strip()

    if not custodian_name and new_profile_name:
        custodian_name = new_profile_name
        if not custodian_department and new_profile_dept:
            custodian_department = new_profile_dept

    if not case_title:
        return JsonResponse({"error": "Case title is required."}, status=400)

    if not custodian_name and not profile_id:
        return JsonResponse({"error": "Target auditee or profile is required."}, status=400)

    case = create_verification_case_with_profile(
        case_ref=case_ref,
        case_title=case_title,
        custodian_name=custodian_name,
        custodian_email=custodian_email,
        custodian_department=custodian_department,
        notes=notes,
        profile_id=profile_id,
    )

    return JsonResponse(
        {
            "success": True,
            "case_id": str(case.id),
            "case_ref": case.case_ref,
        }
    )


@require_GET
def case_detail_view(request: HttpRequest, case_id: str) -> HttpResponse:
    """
    Case Workstation: Tabulator evidence grid, Plotly risk chart, and slide-over reader.
    """
    summary = get_case_summary_metrics(case_id)
    case = summary["case"]

    # Plotly Risk Level Distribution Chart
    chart_html = ""
    if case.total_documents > 0:
        chart_html = get_case_risk_chart_html(summary["risk_distribution"])

    custodian_cases = get_custodian_verification_cases(case.custodian_name)

    return render(
        request,
        "q_verify/case_detail.html",
        {
            "case": case,
            "summary": summary,
            "chart_html": chart_html,
            "custodian_cases": custodian_cases,
        },
    )


@csrf_exempt
@require_POST
def upload_documents_api_view(request: HttpRequest, case_id: str) -> JsonResponse:
    """
    Batch ingests and analyzes uploaded files for a case.
    """
    case = get_verification_case(case_id)
    files = request.FILES.getlist("files") or request.FILES.getlist("file")

    if not files:
        return JsonResponse({"error": "No files provided in request payload."}, status=400)

    processed_docs = []
    for f in files:
        file_bytes = f.read()
        doc = ingest_and_verify_document(
            file_bytes=file_bytes,
            filename=f.name,
            case=case,
            save_disk=True,
        )
        processed_docs.append(
            {
                "id": str(doc.id),
                "filename": doc.filename,
                "score": doc.authenticity_score,
                "risk_level": doc.risk_level,
                "anomalies_count": len(doc.anomalies),
            }
        )

    return JsonResponse(
        {
            "success": True,
            "processed_count": len(processed_docs),
            "documents": processed_docs,
        }
    )


@csrf_exempt
@require_POST
def quick_scan_api_view(request: HttpRequest) -> JsonResponse:
    """
    Instant standalone file inspection without requiring an audit case.
    """
    files = request.FILES.getlist("files") or request.FILES.getlist("file")
    if not files:
        return JsonResponse({"error": "No file uploaded for quick scan."}, status=400)

    f = files[0]
    file_bytes = f.read()

    doc = ingest_and_verify_document(
        file_bytes=file_bytes,
        filename=f.name,
        case=None,
        save_disk=True,
    )

    return JsonResponse(
        {
            "success": True,
            "document": {
                "id": str(doc.id),
                "filename": doc.filename,
                "score": doc.authenticity_score,
                "risk_level": doc.risk_level,
                "meta_created_at": (
                    doc.meta_created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if doc.meta_created_at
                    else "N/A"
                ),
                "meta_modified_at": (
                    doc.meta_modified_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if doc.meta_modified_at
                    else "N/A"
                ),
                "meta_author": doc.meta_author or "Unknown",
                "meta_software": doc.meta_software or "Unknown",
                "anomalies": doc.anomalies,
                "summary": doc.summary,
            },
        }
    )


@require_GET
def documents_grid_api_view(request: HttpRequest, case_id: str) -> JsonResponse:
    """
    Paginated JSON endpoint for Tabulator.js data grid.
    """
    page = int(request.GET.get("page", 1))
    page_size = int(request.GET.get("size", 25))
    search = request.GET.get("search", "").strip()
    try:
        threshold = int(request.GET.get("threshold", 75))
    except (ValueError, TypeError):
        threshold = 75
    risk_level = request.GET.get("risk_level", "").strip()
    mime_type = request.GET.get("mime_type", "").strip()

    sort_field = (
        request.GET.get("sort[0][field]")
        or request.GET.get("sort_by")
        or request.GET.get("sort")
        or "authenticity_score"
    )
    sort_dir = request.GET.get("sort[0][dir]") or request.GET.get("dir") or "asc"

    result = get_paginated_verified_documents(
        case_id=case_id,
        page=page,
        page_size=page_size,
        search=search,
        threshold=threshold,
        risk_level=risk_level,
        mime_type=mime_type,
        sort_field=sort_field,
        sort_dir=sort_dir,
    )
    return JsonResponse(result)


@require_GET
def document_detail_api_view(request: HttpRequest, doc_id: str) -> JsonResponse:
    """
    Returns full extracted metadata, anomaly tree, and timestamps for the reader drawer.
    """
    doc = get_verified_document_detail(doc_id)
    return JsonResponse(
        {
            "id": str(doc.id),
            "filename": doc.filename,
            "formatted_size": doc.formatted_size,
            "mime_type": doc.mime_type,
            "sha256_hash": doc.sha256_hash,
            "authenticity_score": doc.authenticity_score,
            "risk_level": doc.risk_level,
            "file_created_at": (
                doc.file_created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if doc.file_created_at
                else "N/A"
            ),
            "file_modified_at": (
                doc.file_modified_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if doc.file_modified_at
                else "N/A"
            ),
            "meta_created_at": (
                doc.meta_created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if doc.meta_created_at
                else "N/A"
            ),
            "meta_modified_at": (
                doc.meta_modified_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if doc.meta_modified_at
                else "N/A"
            ),
            "meta_author": doc.meta_author or "Unknown / Unspecified",
            "meta_creator": doc.meta_creator or "Unknown",
            "meta_producer": doc.meta_producer or "Unknown",
            "meta_software": doc.meta_software or "Unknown",
            "meta_company": doc.meta_company or "Unknown",
            "meta_title": doc.meta_title or "(No Title)",
            "incremental_updates_count": doc.incremental_updates_count,
            "editing_time_minutes": doc.editing_time_minutes,
            "revision_number": doc.revision_number or "N/A",
            "has_timestamp_anomaly": doc.has_timestamp_anomaly,
            "has_software_anomaly": doc.has_software_anomaly,
            "has_structural_anomaly": doc.has_structural_anomaly,
            "anomalies": doc.anomalies,
            "raw_metadata": doc.raw_metadata,
            "summary": doc.summary,
            "has_file": bool(doc.storage_path and Path(doc.storage_path).exists()),
        }
    )


@require_GET
def download_document_view(request: HttpRequest, doc_id: str) -> FileResponse:
    """
    Downloads original physical document evidence.
    """
    doc = get_verified_document_detail(doc_id)
    if not doc.storage_path or not Path(doc.storage_path).exists():
        raise Http404("Physical document file not found on disk.")

    return FileResponse(
        open(doc.storage_path, "rb"),
        as_attachment=True,
        filename=doc.filename,
    )

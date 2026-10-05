"""
Q-Scan Views (Thin Presentation Layer)
Routes requests, validates parameters, and coordinates selectors & services.
"""

import csv
import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.http import FileResponse, Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_POST

from .selectors import (
    get_all_custodian_profiles,
    get_evidence_hits_query,
    get_paginated_evidence_hits,
    get_scan_dashboard_metrics,
    get_scanned_device_by_id,
)
from .services import (
    delete_scanned_device,
    ingest_scan_csv_file,
    update_evidence_hit_review,
)


@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Scan forensic dashboard displaying audited endpoints, keyword metrics,
    and high-performance remote-paginated evidence grid.
    """
    from core.audits import get_active_audit
    from core.profiles import get_profile_keywords

    active_audit = get_active_audit(request)
    metrics = get_scan_dashboard_metrics()
    custodian_profiles = get_all_custodian_profiles()

    if active_audit:
        audit_names = {p.full_name.strip().lower() for p in active_audit.profiles.all()}
        custodian_profiles = [
            p for p in custodian_profiles if p["custodian_name"].strip().lower() in audit_names
        ]

    active_profile_keywords = get_profile_keywords(request=request)

    context = {
        "metrics": metrics,
        "custodian_profiles": custodian_profiles,
        "active_profile_keywords": active_profile_keywords,
    }
    return render(request, "q_scan/dashboard.html", context)


@require_GET
def evidence_hits_api_view(request: HttpRequest) -> JsonResponse:
    """
    Server-side paginated AJAX endpoint for Tabulator evidence data grid.
    Handles remote pagination, multi-field searching, column sorting, and risk filtering.
    """
    try:
        page = int(request.GET.get("page", 1))
    except (ValueError, TypeError):
        page = 1

    try:
        page_size = int(request.GET.get("size", 25))
    except (ValueError, TypeError):
        page_size = 25

    search = request.GET.get("search") or request.GET.get("q") or ""
    try:
        threshold = int(request.GET.get("threshold", 75))
    except (ValueError, TypeError):
        threshold = 75
    keyword = request.GET.get("keyword", "").strip()
    match_type = request.GET.get("match_type", "").strip()
    risk_level = request.GET.get("risk_level", "").strip()
    device_id = request.GET.get("device_id", "").strip() or None

    sort_field = (
        request.GET.get("sort[0][field]")
        or request.GET.get("sort_by")
        or request.GET.get("sort")
        or "risk_score"
    )
    sort_dir = request.GET.get("sort[0][dir]") or request.GET.get("dir") or "desc"

    result = get_paginated_evidence_hits(
        device_id=device_id,
        page=page,
        page_size=page_size,
        search=search,
        threshold=threshold,
        keyword=keyword,
        match_type=match_type,
        risk_level=risk_level,
        sort_field=sort_field,
        sort_dir=sort_dir,
    )
    return JsonResponse(result)


@require_POST
def upload_scan_csv_view(request: HttpRequest) -> HttpResponse:
    """
    Receives and processes uploaded scan_results.csv files from field auditors.
    """
    if "csv_file" not in request.FILES:
        messages.error(request, "No CSV file provided. Please select a scan_results.csv file.")
        return redirect("q_scan:dashboard")

    uploaded_file = request.FILES["csv_file"]
    hostname = request.POST.get("hostname", "").strip() or Path(uploaded_file.name).stem.upper()
    scan_title = request.POST.get("scan_title", "").strip() or "Audited Endpoint Scan"
    custodian_name = request.POST.get("custodian_name", "").strip()
    drive_letter = request.POST.get("drive_letter", "C:\\").strip()

    from core.profiles import resolve_or_create_profile_from_request

    profile, resolved_name = resolve_or_create_profile_from_request(
        request, default_department="Endpoint Security"
    )
    if profile:
        custodian_name = profile.full_name
    elif not custodian_name and resolved_name:
        custodian_name = resolved_name

    try:
        device = ingest_scan_csv_file(
            csv_file_obj_or_path=uploaded_file,
            hostname=hostname,
            scan_title=scan_title,
            custodian_name=custodian_name,
            drive_letter=drive_letter,
        )
        messages.success(
            request,
            f"Successfully imported {device.total_matches_found:,} evidence hits from '{device.hostname}'.",
        )
    except Exception as e:
        messages.error(request, f"Failed to parse and import CSV file: {e}")

    return redirect("q_scan:dashboard")


@require_GET
def device_detail_view(request: HttpRequest, device_id: str) -> HttpResponse:
    """
    Displays deep-dive details and hits for a specific scanned device.
    Uses remote server-side pagination for instant rendering of massive hit datasets.
    """
    device = get_scanned_device_by_id(device_id)
    if not device:
        raise Http404("Scanned device not found")

    total_hits = device.hits.count()

    from .models import ScannedDevice

    custodian_devices = (
        ScannedDevice.objects.filter(
            custodian_name__iexact=device.custodian_name.strip()
            if device.custodian_name
            else "unknown"
        )
        .only("id", "hostname", "scan_title")
        .order_by("-created_at")
    )

    return render(
        request,
        "q_scan/device_detail.html",
        {
            "device": device,
            "total_hits": total_hits,
            "custodian_devices": custodian_devices,
        },
    )


@require_POST
def delete_device_view(request: HttpRequest, device_id: str) -> HttpResponse:
    """
    Deletes a device audit case and cascades to its evidence hits.
    """
    success = delete_scanned_device(device_id)
    if success:
        messages.success(request, "Endpoint scan case deleted successfully.")
    else:
        messages.error(request, "Target endpoint case could not be found.")
    return redirect("q_scan:dashboard")


@require_POST
def review_hit_api_view(request: HttpRequest, hit_id: str) -> JsonResponse:
    """
    AJAX endpoint to update analyst review status and notes on a hit.
    """
    try:
        data = json.loads(request.body)
        is_reviewed = bool(data.get("is_reviewed", True))
        reviewer_notes = str(data.get("reviewer_notes", ""))
        hit = update_evidence_hit_review(
            hit_id, is_reviewed=is_reviewed, reviewer_notes=reviewer_notes
        )
        if hit:
            return JsonResponse({"status": "ok", "is_reviewed": hit.is_reviewed})
        return JsonResponse({"status": "error", "message": "Hit not found"}, status=404)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=400)


def export_hits_csv_view(request: HttpRequest) -> HttpResponse:
    """
    Exports filtered evidence hits to a downloadable CSV file.
    """
    selected_device_id = request.GET.get("device_id", "").strip()
    selected_keyword = request.GET.get("keyword", "").strip()
    selected_match_type = request.GET.get("match_type", "").strip()

    hits = get_evidence_hits_query(
        device_id=selected_device_id or None,
        keyword=selected_keyword or None,
        match_type=selected_match_type or None,
    )

    response = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    response["Content-Disposition"] = 'attachment; filename="forensiq_scan_export.csv"'

    writer = csv.writer(response)
    writer.writerow(
        [
            "Hostname",
            "File Path",
            "Filename",
            "Matched Keyword",
            "Match Type",
            "Risk Score",
            "File Size (Bytes)",
            "Last Modified Date",
            "Detection Time",
            "Snippet / Context",
        ]
    )

    for h in hits:
        writer.writerow(
            [
                h.device.hostname,
                h.file_path,
                h.filename,
                h.matched_keyword,
                h.match_type,
                h.risk_score,
                h.file_size_bytes,
                h.file_modified_at.strftime("%Y-%m-%d %H:%M:%S") if h.file_modified_at else "",
                h.detection_timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if h.detection_timestamp
                else "",
                h.snippet,
            ]
        )

    return response


def download_tool_file_view(request: HttpRequest, filename: str) -> HttpResponse:
    """
    Serves portable scanner scripts (q_scan.py, config.json, build_exe.bat) to field auditors.
    """
    allowed_files = {
        "q_scan.exe": settings.BASE_DIR / "tools" / "q_scan" / "q_scan.exe",
        "q_scan_package.zip": settings.BASE_DIR / "tools" / "q_scan" / "q_scan_package.zip",
        "q_scan.py": settings.BASE_DIR / "tools" / "q_scan" / "q_scan.py",
        "config.json": settings.BASE_DIR / "tools" / "q_scan" / "config.json",
        "build_exe.bat": settings.BASE_DIR / "tools" / "q_scan" / "build_exe.bat",
        "build_exe.ps1": settings.BASE_DIR / "tools" / "q_scan" / "build_exe.ps1",
    }

    target_path = allowed_files.get(filename)
    if not target_path or not target_path.exists():
        raise Http404("Requested tool file not found")

    if filename == "config.json":
        import json

        from core.profiles import get_profile_keywords

        base_cfg = {}
        try:
            base_cfg = json.loads(target_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            base_cfg = {}

        profile_kws = get_profile_keywords(request=request)
        if profile_kws:
            existing_kws = base_cfg.get("keywords", [])
            seen_kws = {k.lower() for k in existing_kws}
            merged = list(existing_kws)
            for pkw in profile_kws:
                if pkw.lower() not in seen_kws:
                    seen_kws.add(pkw.lower())
                    merged.append(pkw)
            base_cfg["keywords"] = merged

        json_bytes = json.dumps(base_cfg, indent=4).encode("utf-8")
        resp = HttpResponse(json_bytes, content_type="application/json")
        resp["Content-Disposition"] = 'attachment; filename="config.json"'
        return resp

    return FileResponse(open(target_path, "rb"), as_attachment=True, filename=filename)


def _format_size(size_bytes: int) -> str:
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

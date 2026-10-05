"""
Q-Mail Presentation & View Controllers
Thin views integrating Django Cotton components, Tabulator.js grids, and Plotly charts.
"""

import json
from pathlib import Path

from django.http import FileResponse, Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from loguru import logger

from core.audits import get_active_audit

from .selectors import (
    get_all_custodian_profiles,
    get_attachment_by_id,
    get_email_detail,
    get_investigation_summary_metrics,
    get_mailbox_progress_state,
    get_paginated_investigation_emails,
)
from .services import (
    cancel_mailbox_processing,
    create_mailbox_investigation,
    handle_chunked_upload,
    recover_stalled_investigations,
    start_mailbox_processing,
)


@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Mail Dashboard: Lists all custodian profiles and upload portal.
    """
    recover_stalled_investigations()
    active_audit = get_active_audit(request)
    profiles = get_all_custodian_profiles()

    if active_audit:
        audit_names = {p.full_name.strip().lower() for p in active_audit.profiles.all()}
        profiles = [p for p in profiles if p["custodian_name"].strip().lower() in audit_names]

    return render(
        request,
        "q_mail/dashboard.html",
        {"custodian_profiles": profiles},
    )


@require_POST
def initiate_upload_view(request: HttpRequest) -> JsonResponse:
    """
    API endpoint to register audit/auditee details prior to chunked PST upload.
    """
    try:
        data = json.loads(request.body)
    except Exception:
        data = request.POST

    audit_ref = data.get("audit_ref") or f"AUD-{data.get('auditee_name', 'CASE')[:4].upper()}-2026"
    audit_name = data.get("audit_name", "").strip()
    auditee_name = data.get("auditee_name", "").strip()
    auditee_email = data.get("auditee_email", "").strip()
    auditee_department = data.get("auditee_department", "").strip()
    auditee_designation = data.get("auditee_designation", "").strip()
    pst_file_name = data.get("pst_file_name", "evidence.pst").strip()
    file_size_bytes = int(data.get("file_size_bytes", 0))

    profile_id = data.get("profile_id", "").strip() or None
    new_profile_name = data.get("new_profile_name", "").strip()
    new_profile_dept = data.get("new_profile_dept", "").strip()

    from core.profiles import create_investigation_profile, get_profile_by_id

    if profile_id:
        profile = get_profile_by_id(profile_id)
        if profile:
            auditee_name = profile.full_name
            if not auditee_email and profile.email:
                auditee_email = profile.email
            if not auditee_department and profile.department:
                auditee_department = profile.department
            if not auditee_designation and profile.designation:
                auditee_designation = profile.designation
    elif new_profile_name:
        auditee_name = new_profile_name
        if new_profile_dept and not auditee_department:
            auditee_department = new_profile_dept
        try:
            create_investigation_profile(
                full_name=new_profile_name,
                department=auditee_department,
                designation=auditee_designation,
                email=auditee_email,
            )
        except Exception as exc:
            logger.debug(f"Inline profile creation in Q-Mail: {exc}")

    if not (auditee_name and auditee_email):
        return JsonResponse({"error": "Auditee name and email are mandatory fields."}, status=400)

    investigation = create_mailbox_investigation(
        audit_ref=audit_ref,
        audit_name=audit_name or f"Audit of {auditee_name}",
        auditee_name=auditee_name,
        auditee_email=auditee_email,
        auditee_department=auditee_department,
        auditee_designation=auditee_designation,
        pst_file_name=pst_file_name,
        file_size_bytes=file_size_bytes,
    )

    logger.info(
        "Initiated PST investigation {} for auditee {} ({})",
        investigation.audit_ref,
        investigation.auditee_name,
        investigation.auditee_email,
    )

    return JsonResponse(
        {
            "success": True,
            "mailbox_id": str(investigation.id),
            "audit_ref": investigation.audit_ref,
        }
    )


@csrf_exempt
@require_POST
def chunk_upload_view(request: HttpRequest) -> JsonResponse:
    """
    Receives sequential binary chunks for 50GB PST uploads.
    """
    mailbox_id = request.POST.get("mailbox_id")
    chunk_index = int(request.POST.get("chunk_index", 0))
    total_chunks = int(request.POST.get("total_chunks", 1))
    chunk_file = request.FILES.get("chunk")

    if not (mailbox_id and chunk_file):
        return JsonResponse({"error": "Missing mailbox_id or chunk file payload."}, status=400)

    chunk_bytes = chunk_file.read()
    result = handle_chunked_upload(
        mailbox_id=mailbox_id,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        chunk_bytes=chunk_bytes,
    )

    # Automatically start background ingestion if last chunk uploaded
    if result["is_completed"]:
        start_mailbox_processing(mailbox_id)

    return JsonResponse({"success": True, **result})


@require_POST
def trigger_processing_view(request: HttpRequest, mailbox_id: str) -> JsonResponse:
    """
    Manually triggers or retries PST background processing.
    """
    start_mailbox_processing(mailbox_id)
    return JsonResponse({"success": True, "message": "Background ingestion worker started."})


@require_POST
def cancel_processing_view(request: HttpRequest, mailbox_id: str) -> JsonResponse:
    """
    Signals active background ingestion worker to stop immediately.
    """
    success = cancel_mailbox_processing(mailbox_id)
    return JsonResponse(
        {
            "success": success,
            "message": "Cancellation signal dispatched."
            if success
            else "No active processing worker to cancel.",
        }
    )


@require_GET
def progress_api_view(request: HttpRequest, mailbox_id: str) -> JsonResponse:
    """
    Live JSON polling endpoint for progress bar and extraction status.
    """
    state = get_mailbox_progress_state(mailbox_id)
    return JsonResponse(state)


@require_GET
def messages_api_view(request: HttpRequest, mailbox_id: str) -> JsonResponse:
    """
    High-performance paginated API endpoint for Tabulator.js data grid.
    Supports server-side pagination, remote sorting, multi-field search, and forensic checkpoint filters.
    """
    try:
        page = int(request.GET.get("page", 1))
    except (ValueError, TypeError):
        page = 1

    try:
        page_size = int(request.GET.get("size", 25))
    except (ValueError, TypeError):
        page_size = 25

    search = request.GET.get("search", "").strip()
    try:
        threshold = int(request.GET.get("threshold", 75))
    except (ValueError, TypeError):
        threshold = 75
    folder = request.GET.get("folder", "").strip()
    sender = request.GET.get("sender", "").strip()
    checkpoint = request.GET.get("checkpoint", "all").strip()
    participant_name = request.GET.get("participant_name", "").strip()
    start_date = request.GET.get("start_date", "").strip()
    end_date = request.GET.get("end_date", "").strip()
    custom_keyword = request.GET.get("custom_keyword", "").strip()

    has_attachments_val = request.GET.get("has_attachments")
    has_attachments = (
        True
        if has_attachments_val in ("true", "1")
        else (False if has_attachments_val in ("false", "0") else None)
    )

    # Handle Tabulator sort params
    sort_field = (
        request.GET.get("sort[0][field]")
        or request.GET.get("sort_by")
        or request.GET.get("sort")
        or "sent_date"
    )
    sort_dir = request.GET.get("sort[0][dir]") or request.GET.get("dir") or "desc"

    result = get_paginated_investigation_emails(
        mailbox_id,
        page=page,
        page_size=page_size,
        search=search,
        threshold=threshold,
        folder=folder,
        sender=sender,
        has_attachments=has_attachments,
        checkpoint=checkpoint,
        participant_name=participant_name,
        start_date=start_date,
        end_date=end_date,
        custom_keyword=custom_keyword,
        sort_field=sort_field,
        sort_dir=sort_dir,
    )

    return JsonResponse(result)


@require_GET
def checkpoints_summary_api_view(request: HttpRequest, mailbox_id: str) -> JsonResponse:
    """
    Live API endpoint returning aggregate metrics across all 10 Mail Checkpoints.
    """
    from .selectors import get_mailbox_checkpoints_summary

    summary = get_mailbox_checkpoints_summary(mailbox_id)
    return JsonResponse({"success": True, "checkpoints": summary})


@require_GET
def export_checkpoint_excel_view(request: HttpRequest, mailbox_id: str) -> HttpResponse:
    """
    Exports filtered forensic checkpoint emails to an Excel workbook stream.
    """
    import io

    import openpyxl

    from .selectors import get_paginated_investigation_emails

    checkpoint = request.GET.get("checkpoint", "all").strip()
    participant_name = request.GET.get("participant_name", "").strip()
    start_date = request.GET.get("start_date", "").strip()
    end_date = request.GET.get("end_date", "").strip()
    custom_keyword = request.GET.get("custom_keyword", "").strip()
    search = request.GET.get("search", "").strip()

    result = get_paginated_investigation_emails(
        mailbox_id,
        page=1,
        page_size=20000,
        checkpoint=checkpoint,
        participant_name=participant_name,
        start_date=start_date,
        end_date=end_date,
        custom_keyword=custom_keyword,
        search=search,
    )
    rows = result.get("data", [])

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Forensic Email Checkpoints"

    headers = [
        "Sent Date (UTC)",
        "Sender Name",
        "Sender Email",
        "Recipients (To)",
        "Recipients (Cc)",
        "Subject",
        "Folder",
        "Currency Mentioned",
        "1-on-1 Direct",
        "Personal Mail ID",
        "Primary Bank",
        "UPI Payment",
        "Matched Flags",
        "Risk Score",
        "Risk Level",
    ]
    ws.append(headers)

    for r in rows:
        badge_labels = ", ".join(b["label"] for b in r.get("badges", []))
        ws.append(
            [
                r.get("sent_date", ""),
                r.get("sender", ""),
                r.get("sender_email", ""),
                ", ".join(r.get("recipients_to", [])),
                ", ".join(r.get("recipients_cc", [])),
                r.get("subject", ""),
                r.get("folder", ""),
                "YES" if r.get("is_currency") else "NO",
                "YES" if r.get("is_no_cc_bcc") else "NO",
                "YES" if r.get("is_personal_sender") else "NO",
                "YES" if r.get("is_primary_bank") else "NO",
                "YES" if r.get("is_upi_payment") else "NO",
                badge_labels or "-",
                r.get("risk_score", 0),
                r.get("risk_level", "Low"),
            ]
        )

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    response = HttpResponse(
        output.read(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = (
        f'attachment; filename="forensiq_mail_checkpoints_{checkpoint}.xlsx"'
    )
    return response


@require_GET
def investigation_detail_view(request: HttpRequest, mailbox_id: str) -> HttpResponse:
    """
    Investigation Workstation: Tabulator.js email grid, Plotly counterparty charts, and evidence filters.
    """
    recover_stalled_investigations()
    summary = get_investigation_summary_metrics(mailbox_id)
    inv = summary["investigation"]

    from .models import MailboxInvestigation

    custodian_cases = (
        MailboxInvestigation.objects.filter(
            auditee_name__iexact=inv.auditee_name.strip() if inv.auditee_name else "unknown"
        )
        .only("id", "audit_ref", "audit_name")
        .order_by("-created_at")
    )

    return render(
        request,
        "q_mail/investigation_detail.html",
        {
            "investigation": inv,
            "summary": summary,
            "custodian_cases": custodian_cases,
        },
    )


@require_GET
def email_detail_api_view(request: HttpRequest, email_id: str) -> JsonResponse:
    """
    Returns complete email headers, body content, and attachment hashes for the reader drawer.
    """
    email = get_email_detail(email_id)
    attachments_data = [
        {
            "id": str(a.id),
            "filename": a.filename,
            "formatted_size": a.formatted_size,
            "sha256_hash": a.sha256_hash,
            "mime_type": a.mime_type,
            "has_file": bool(a.storage_path and Path(a.storage_path).exists()),
        }
        for a in email.attachments.all()
    ]

    return JsonResponse(
        {
            "id": str(email.id),
            "message_id": email.message_id,
            "subject": email.subject,
            "sender_name": email.sender_name,
            "sender_email": email.sender_email,
            "recipients_to": email.recipients_to,
            "recipients_cc": email.recipients_cc,
            "sent_date": email.sent_date.strftime("%Y-%m-%d %H:%M:%S UTC")
            if email.sent_date
            else "N/A",
            "folder_path": email.folder_path,
            "body_plain": email.body_plain,
            "body_html": email.body_html,
            "has_attachments": email.has_attachments,
            "attachments": attachments_data,
        }
    )


@require_GET
def download_attachment_view(request: HttpRequest, attachment_id: str) -> FileResponse:
    """
    Downloads physical evidence attachment with proper content-disposition.
    """
    attachment = get_attachment_by_id(attachment_id)
    if not attachment.storage_path or not Path(attachment.storage_path).exists():
        raise Http404("Physical attachment file not found on disk.")

    return FileResponse(
        open(attachment.storage_path, "rb"),
        as_attachment=True,
        filename=attachment.filename,
    )

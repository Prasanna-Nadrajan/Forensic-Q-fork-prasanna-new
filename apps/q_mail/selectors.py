"""
Q-Mail Read-Only Selectors Layer
Follows agentic-django principles: zero DB mutations, proactive N+1 elimination with select_related & prefetch_related.
"""

import uuid
from typing import Any

from django.core.paginator import Paginator
from django.db.models import Count, Max, Min, Q, QuerySet, Sum
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_date

from .backend.checkpoints import (
    DEFAULT_KEYWORDS,
    check_currency,
    check_no_cc_bcc,
    check_non_hmil,
    check_personal_sender,
    check_primary_bank,
    check_upi_payment,
    evaluate_email_checkpoints,
)
from .models import EmailAttachment, EmailMessage, EmailParticipant, MailboxInvestigation


def list_mailbox_investigations() -> QuerySet[MailboxInvestigation]:
    """
    Returns all audit mailbox investigations ordered by creation date.
    """
    return MailboxInvestigation.objects.all().order_by("-created_at")


def get_mailbox_investigation(mailbox_id: str | uuid.UUID) -> MailboxInvestigation:
    """
    Retrieves a single mailbox investigation instance.
    """
    return get_object_or_404(MailboxInvestigation, id=mailbox_id)


def get_mailbox_progress_state(mailbox_id: str | uuid.UUID) -> dict[str, Any]:
    """
    Fetches real-time ingestion state for live UI polling.
    """
    inv = get_object_or_404(MailboxInvestigation, id=mailbox_id)
    return {
        "id": str(inv.id),
        "audit_ref": inv.audit_ref,
        "auditee_name": inv.auditee_name,
        "status": inv.status,
        "status_display": inv.get_status_display(),
        "progress_percent": round(inv.progress_percent, 1),
        "processed_messages_count": inv.processed_messages_count,
        "attachment_count": inv.attachment_count,
        "current_folder": inv.current_folder,
        "error_message": inv.error_message,
        "is_cancellation_requested": inv.is_cancellation_requested,
        "last_heartbeat_at": inv.last_heartbeat_at.isoformat() if inv.last_heartbeat_at else None,
        "is_active": inv.status
        in (
            MailboxInvestigation.IngestionStatus.UPLOADING,
            MailboxInvestigation.IngestionStatus.PROCESSING,
        ),
    }


def get_mailbox_checkpoints_summary(mailbox_id: str | uuid.UUID) -> dict[str, Any]:
    """
    Computes real-time aggregation across all 10 Mail Checkpoints:
    1. Currency mentions
    2. Direct 1-on-1 (Without CC/BCC)
    3. Personal Webmail Senders (@gmail, @yahoo, etc.)
    4. External / Apart from HMIL
    5. Primary Bank Alerts (HDFC, SBI, ICICI, etc.)
    6. UPI Payments (PhonePe, GPay, Paytm, CRED)
    7. Default Keywords (PAYMENT, GIFT, SALARY, TAX, LOAN, CIBIL)
    """
    messages = EmailMessage.objects.filter(mailbox_id=mailbox_id).only(
        "id",
        "subject",
        "sender_email",
        "recipients_to",
        "recipients_cc",
        "recipients_bcc",
        "body_plain",
    )

    currency_count = 0
    no_cc_bcc_count = 0
    personal_sender_count = 0
    non_hmil_count = 0
    primary_bank_count = 0
    upi_payment_count = 0
    keyword_counts = dict.fromkeys(DEFAULT_KEYWORDS, 0)
    total_flagged = 0

    for msg in messages:
        text = f"{msg.subject or ''} {msg.body_plain or ''}"
        sender = msg.sender_email or ""
        recipients_to = msg.recipients_to or []
        recipients_cc = msg.recipients_cc or []
        recipients_bcc = msg.recipients_bcc or []

        has_curr = check_currency(text)
        has_no_cc = check_no_cc_bcc(recipients_cc, recipients_bcc)
        has_pers = check_personal_sender(sender)
        has_non_hmil = check_non_hmil(sender, recipients_to)
        has_bank = check_primary_bank(sender, msg.subject or "", msg.body_plain or "")
        has_upi = check_upi_payment(sender, msg.subject or "", msg.body_plain or "")

        matched_kws = [kw for kw in DEFAULT_KEYWORDS if kw in text.upper()]

        if has_curr:
            currency_count += 1
        if has_no_cc:
            no_cc_bcc_count += 1
        if has_pers:
            personal_sender_count += 1
        if has_non_hmil:
            non_hmil_count += 1
        if has_bank:
            primary_bank_count += 1
        if has_upi:
            upi_payment_count += 1
        for kw in matched_kws:
            keyword_counts[kw] += 1

        if any([has_curr, has_pers, has_bank, has_upi, matched_kws]):
            total_flagged += 1

    return {
        "total_emails": len(messages),
        "total_flagged": total_flagged,
        "currency_count": currency_count,
        "no_cc_bcc_count": no_cc_bcc_count,
        "personal_sender_count": personal_sender_count,
        "non_hmil_count": non_hmil_count,
        "primary_bank_count": primary_bank_count,
        "upi_payment_count": upi_payment_count,
        "default_keywords": keyword_counts,
        "total_keyword_hits": sum(keyword_counts.values()),
    }


def get_investigation_emails(
    mailbox_id: str | uuid.UUID,
    *,
    search: str = "",
    folder: str = "",
    sender: str = "",
    has_attachments: bool | None = None,
    min_risk: int = 0,
    limit: int = 2000,
) -> QuerySet[EmailMessage]:
    """
    Fetches email messages with pre-fetched attachments to eliminate N+1 queries.
    """
    qs = (
        EmailMessage.objects.filter(mailbox_id=mailbox_id)
        .select_related("mailbox")
        .prefetch_related("attachments")
        .order_by("-sent_date")
    )

    if search:
        qs = qs.filter(
            Q(subject__icontains=search)
            | Q(sender_email__icontains=search)
            | Q(sender_name__icontains=search)
            | Q(body_plain__icontains=search)
        )

    if folder:
        qs = qs.filter(folder_path=folder)

    if sender:
        qs = qs.filter(sender_email__icontains=sender)

    if has_attachments is not None:
        qs = qs.filter(has_attachments=has_attachments)

    if min_risk > 0:
        qs = qs.filter(risk_score__gte=min_risk)

    return qs[:limit]


def get_paginated_investigation_emails(
    mailbox_id: str | uuid.UUID,
    *,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
    folder: str = "",
    sender: str = "",
    has_attachments: bool | None = None,
    min_risk: int = 0,
    checkpoint: str = "all",  # all, currency, no_cc_bcc, personal_mail, non_hmil, primary_bank, upi_payments, payment, gift, salary, tax, loan, cibil
    participant_name: str = "",
    start_date: str = "",
    end_date: str = "",
    custom_keyword: str = "",
    sort_field: str = "sent_date",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    """
    High-performance server-side paginated selector with full forensic checkpoint evaluation.
    """
    qs = EmailMessage.objects.filter(mailbox_id=mailbox_id).prefetch_related("attachments")

    if search:
        qs = qs.filter(
            Q(subject__icontains=search)
            | Q(sender_email__icontains=search)
            | Q(sender_name__icontains=search)
            | Q(body_plain__icontains=search)
        )

    if folder:
        qs = qs.filter(folder_path=folder)

    if sender:
        qs = qs.filter(sender_email__icontains=sender)

    if participant_name:
        p_str = participant_name.strip()
        qs = qs.filter(
            Q(sender_name__icontains=p_str)
            | Q(sender_email__icontains=p_str)
            | Q(recipients_to__icontains=p_str)
            | Q(recipients_cc__icontains=p_str)
            | Q(recipients_bcc__icontains=p_str)
        )

    if custom_keyword:
        ck_str = custom_keyword.strip()
        qs = qs.filter(Q(subject__icontains=ck_str) | Q(body_plain__icontains=ck_str))

    if start_date:
        parsed_start = parse_date(start_date.strip())
        if parsed_start:
            qs = qs.filter(sent_date__date__gte=parsed_start)

    if end_date:
        parsed_end = parse_date(end_date.strip())
        if parsed_end:
            qs = qs.filter(sent_date__date__lte=parsed_end)

    if has_attachments is not None:
        qs = qs.filter(has_attachments=has_attachments)

    if min_risk > 0:
        qs = qs.filter(risk_score__gte=min_risk)

    # Safe sort mapping
    allowed_sort_fields = {
        "sent_date": "sent_date",
        "sender": "sender_email",
        "subject": "subject",
        "folder": "folder_path",
        "attachment_count": "attachment_count",
        "risk_score": "risk_score",
    }
    db_sort_field = allowed_sort_fields.get(sort_field, "sent_date")
    order_prefix = "-" if sort_dir.lower() == "desc" else ""
    qs = qs.order_by(f"{order_prefix}{db_sort_field}", "-created_at")

    # In-memory filter for complex regex / domain-based checkpoints if selected
    checkpoint_filter = checkpoint.lower().strip()
    all_matching_records = list(qs)

    if checkpoint_filter and checkpoint_filter != "all":
        filtered_list = []
        for m in all_matching_records:
            eval_res = evaluate_email_checkpoints(m)
            matched = False
            if checkpoint_filter == "currency":
                matched = eval_res["is_currency"]
            elif checkpoint_filter in ("no_cc_bcc", "without_cc_bcc", "direct"):
                matched = eval_res["is_no_cc_bcc"]
            elif checkpoint_filter in ("personal_mail", "personal", "personal_mail_id"):
                matched = eval_res["is_personal_sender"]
            elif checkpoint_filter in ("non_hmil", "external"):
                matched = eval_res["is_non_hmil"]
            elif checkpoint_filter in ("primary_bank", "bank"):
                matched = eval_res["is_primary_bank"]
            elif checkpoint_filter in ("upi_payments", "upi", "upi_payment"):
                matched = eval_res["is_upi_payment"]
            elif checkpoint_filter in ("default_keywords", "keywords"):
                matched = bool(eval_res["matched_default_keywords"])
            elif checkpoint_filter.upper() in DEFAULT_KEYWORDS:
                matched = checkpoint_filter.upper() in eval_res["matched_default_keywords"]

            if matched:
                filtered_list.append(m)
        all_matching_records = filtered_list

    paginator = Paginator(all_matching_records, max(1, min(page_size, 500)))
    page_obj = paginator.get_page(page)

    rows = []
    for m in page_obj.object_list:
        eval_res = evaluate_email_checkpoints(m)
        rows.append(
            {
                "id": str(m.id),
                "sent_date": m.sent_date.strftime("%Y-%m-%d %H:%M") if m.sent_date else "N/A",
                "sender": m.sender_name or m.sender_email,
                "sender_email": m.sender_email,
                "recipients_to": m.recipients_to,
                "recipients_cc": m.recipients_cc,
                "recipients_bcc": m.recipients_bcc,
                "subject": m.subject,
                "folder": m.folder_path.split("/")[-1] if m.folder_path else "Inbox",
                "has_attachments": m.has_attachments,
                "attachment_count": m.attachment_count,
                "risk_score": m.risk_score,
                "risk_level": m.risk_level,
                "is_flagged": m.is_flagged or bool(eval_res["badges"]),
                "badges": eval_res["badges"],
                "is_currency": eval_res["is_currency"],
                "is_no_cc_bcc": eval_res["is_no_cc_bcc"],
                "is_personal_sender": eval_res["is_personal_sender"],
                "is_primary_bank": eval_res["is_primary_bank"],
                "is_upi_payment": eval_res["is_upi_payment"],
            }
        )

    return {
        "data": rows,
        "last_page": paginator.num_pages,
        "last_row": paginator.count,
        "total_count": paginator.count,
        "current_page": page_obj.number,
    }


def get_email_detail(email_id: str | uuid.UUID) -> EmailMessage:
    """
    Retrieves full email details with all attachments.
    """
    return get_object_or_404(
        EmailMessage.objects.select_related("mailbox").prefetch_related("attachments"),
        id=email_id,
    )


def get_investigation_summary_metrics(mailbox_id: str | uuid.UUID) -> dict[str, Any]:
    """
    Aggregates high-level metrics across the investigation.
    """
    inv = get_object_or_404(MailboxInvestigation, id=mailbox_id)
    email_stats = EmailMessage.objects.filter(mailbox=inv).aggregate(
        total_emails=Count("id"),
        earliest_sent=Min("sent_date"),
        latest_sent=Max("sent_date"),
        with_attachments=Count("id", filter=Q(has_attachments=True)),
    )
    attachment_total = EmailAttachment.objects.filter(email__mailbox=inv).count()

    folders = list(
        EmailMessage.objects.filter(mailbox=inv).values_list("folder_path", flat=True).distinct()
    )

    checkpoints_summary = get_mailbox_checkpoints_summary(mailbox_id)

    return {
        "investigation": inv,
        "total_emails": email_stats["total_emails"] or 0,
        "total_attachments": attachment_total,
        "earliest_sent": email_stats["earliest_sent"],
        "latest_sent": email_stats["latest_sent"],
        "with_attachments": email_stats["with_attachments"] or 0,
        "folders": [f for f in folders if f],
        "checkpoints": checkpoints_summary,
    }


def get_top_counterparties(mailbox_id: str | uuid.UUID, limit: int = 10) -> list[dict[str, Any]]:
    """
    Returns top counterparties for Plotly chart visualization.
    """
    participants = EmailParticipant.objects.filter(mailbox_id=mailbox_id).order_by("-sent_count")[
        :limit
    ]
    return [
        {
            "email": p.email_address,
            "display_name": p.display_name or p.email_address.split("@")[0],
            "count": p.sent_count,
            "is_external": p.is_external_domain,
        }
        for p in participants
    ]


def get_global_mailbox_stats() -> dict[str, Any]:
    """
    Computes global aggregation metrics across all mailbox investigations.
    """
    investigations = list_mailbox_investigations()
    total_mailboxes = investigations.count()
    completed_count = investigations.filter(
        status=MailboxInvestigation.IngestionStatus.COMPLETED
    ).count()
    processing_count = investigations.filter(
        status=MailboxInvestigation.IngestionStatus.PROCESSING
    ).count()
    total_messages = investigations.aggregate(total=Sum("processed_messages_count"))["total"] or 0

    return {
        "investigations": investigations,
        "total_mailboxes": total_mailboxes,
        "completed_count": completed_count,
        "processing_count": processing_count,
        "total_messages": total_messages,
    }


def get_attachment_by_id(attachment_id: str | uuid.UUID) -> EmailAttachment:
    """
    Fetches an evidence attachment by its ID.
    """
    return get_object_or_404(EmailAttachment, id=attachment_id)

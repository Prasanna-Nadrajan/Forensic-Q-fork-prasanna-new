"""
Q-Mail Read-Only Selectors Layer
Follows agentic-django principles: zero DB mutations, proactive N+1 elimination with select_related & prefetch_related.
"""

import uuid
from typing import Any

from django.core.paginator import Paginator
from django.db.models import Count, Max, Min, Q, QuerySet
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_date

from core.fuzzy import extract_keywords_from_string, score_text_against_keywords

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

    inv = MailboxInvestigation.objects.filter(id=mailbox_id).first()
    profile_kws: list[str] = []
    if inv:
        from core.profiles import get_profile_keywords

        profile_kws = get_profile_keywords(custodian_name=inv.auditee_name)
    profile_keyword_counts = {kw.upper(): 0 for kw in profile_kws}

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
        matched_profile_kws = [kw for kw in profile_keyword_counts if kw in text.upper()]

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
        for kw in matched_profile_kws:
            profile_keyword_counts[kw] += 1

        if any([has_curr, has_pers, has_bank, has_upi, matched_kws, matched_profile_kws]):
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
        "profile_keywords": profile_keyword_counts,
        "total_profile_keyword_hits": sum(profile_keyword_counts.values()),
    }


def get_investigation_emails(
    mailbox_id: str | uuid.UUID,
    *,
    search: str = "",
    threshold: int = 75,
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
        keywords = extract_keywords_from_string(search)
        if keywords:
            if threshold >= 100:
                q_kw = Q()
                for kw in keywords:
                    q_kw |= (
                        Q(subject__icontains=kw)
                        | Q(sender_email__icontains=kw)
                        | Q(sender_name__icontains=kw)
                        | Q(body_plain__icontains=kw)
                    )
                qs = qs.filter(q_kw)
            else:
                q_exact = Q()
                for kw in keywords:
                    q_exact |= (
                        Q(subject__icontains=kw)
                        | Q(sender_email__icontains=kw)
                        | Q(sender_name__icontains=kw)
                        | Q(body_plain__icontains=kw)
                    )
                matched_ids = list(qs.filter(q_exact).values_list("id", flat=True)[:500])
                if len(matched_ids) < 500:
                    matched_set = set(matched_ids)
                    candidates = qs.exclude(id__in=matched_set).values_list(
                        "id", "subject", "sender_name", "sender_email", "body_plain"
                    )[:1000]
                    for msg_id, subj, sname, semail, body in candidates:
                        text_to_check = f"{subj or ''} {sname or ''} {semail or ''} {body[:500] if body else ''}"
                        is_matched, _, _ = score_text_against_keywords(
                            text_to_check, keywords, threshold=threshold
                        )
                        if is_matched:
                            matched_ids.append(msg_id)
                            if len(matched_ids) >= 500:
                                break
                qs = qs.filter(id__in=matched_ids)
        else:
            qs = qs.none()

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
    threshold: int = 75,
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
        keywords = extract_keywords_from_string(search)
        if keywords:
            if threshold >= 100:
                q_kw = Q()
                for kw in keywords:
                    q_kw |= (
                        Q(subject__icontains=kw)
                        | Q(sender_email__icontains=kw)
                        | Q(sender_name__icontains=kw)
                        | Q(body_plain__icontains=kw)
                    )
                qs = qs.filter(q_kw)
            else:
                q_exact = Q()
                for kw in keywords:
                    q_exact |= (
                        Q(subject__icontains=kw)
                        | Q(sender_email__icontains=kw)
                        | Q(sender_name__icontains=kw)
                        | Q(body_plain__icontains=kw)
                    )
                matched_ids = list(qs.filter(q_exact).values_list("id", flat=True)[:500])
                if len(matched_ids) < 500:
                    matched_set = set(matched_ids)
                    candidates = qs.exclude(id__in=matched_set).values_list(
                        "id", "subject", "sender_name", "sender_email", "body_plain"
                    )[:1000]
                    for msg_id, subj, sname, semail, body in candidates:
                        text_to_check = f"{subj or ''} {sname or ''} {semail or ''} {body[:500] if body else ''}"
                        is_matched, _, _ = score_text_against_keywords(
                            text_to_check, keywords, threshold=threshold
                        )
                        if is_matched:
                            matched_ids.append(msg_id)
                            if len(matched_ids) >= 500:
                                break
                qs = qs.filter(id__in=matched_ids)
        else:
            qs = qs.none()

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

    # Resolve auditee profile surveillance keywords
    inv = MailboxInvestigation.objects.filter(id=mailbox_id).first()
    profile_kws: list[str] = []
    if inv:
        from core.profiles import get_profile_keywords

        profile_kws = get_profile_keywords(custodian_name=inv.auditee_name)
    upper_profile_kws = [k.upper() for k in profile_kws]

    # In-memory filter for complex regex / domain-based checkpoints if selected
    checkpoint_filter = checkpoint.lower().strip()
    all_matching_records = list(qs)

    if checkpoint_filter and checkpoint_filter != "all":
        filtered_list = []
        for m in all_matching_records:
            eval_res = evaluate_email_checkpoints(m, profile_keywords=profile_kws)
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
            elif checkpoint_filter in ("profile_keywords", "profile_kw"):
                matched = bool(eval_res["matched_profile_keywords"])
            elif checkpoint_filter.upper() in upper_profile_kws:
                matched = checkpoint_filter.upper() in [
                    k.upper() for k in eval_res["matched_profile_keywords"]
                ]

            if matched:
                filtered_list.append(m)
        all_matching_records = filtered_list

    paginator = Paginator(all_matching_records, max(1, min(page_size, 500)))
    page_obj = paginator.get_page(page)

    rows = []
    for m in page_obj.object_list:
        eval_res = evaluate_email_checkpoints(m, profile_keywords=profile_kws)
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


def get_all_custodian_profiles() -> list[dict[str, Any]]:
    """
    Aggregates mailbox investigations into a single list of unique custodian profiles.
    """
    investigations = MailboxInvestigation.objects.prefetch_related("messages").all()
    profiles_dict = {}

    for inv in investigations:
        key = (inv.auditee_name, inv.auditee_department, inv.auditee_email)
        if key not in profiles_dict:
            profiles_dict[key] = {
                "custodian_name": inv.auditee_name,
                "custodian_department": inv.auditee_department,
                "custodian_email": inv.auditee_email,
                "cases": [],
                "total_cases": 0,
                "total_emails": 0,
                "total_attachments": 0,
                "flagged_emails": 0,
                "average_score": 0.0,  # Placeholder if needed
            }

        prof = profiles_dict[key]
        if not any(c["ref"] == inv.audit_ref for c in prof["cases"]):
            prof["cases"].append({"id": inv.id, "ref": inv.audit_ref})
        prof["total_cases"] += 1
        prof["total_emails"] += inv.processed_messages_count
        prof["total_attachments"] += inv.attachment_count

        # Count flagged messages in python to avoid N+1 if prefetched
        flagged_count = sum(1 for m in inv.messages.all() if m.is_flagged)
        prof["flagged_emails"] += flagged_count

    return list(profiles_dict.values())


def get_attachment_by_id(attachment_id: str | uuid.UUID) -> EmailAttachment:
    """
    Fetches an evidence attachment by its ID.
    """
    return get_object_or_404(EmailAttachment, id=attachment_id)

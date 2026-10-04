"""
Q-Chat Forensic Selectors
Query, compute, and aggregate corporate chat conversations, message streams, and collusion indicators.
"""

import uuid
from typing import Any

from django.core.paginator import Paginator
from django.db.models import Count, Max, Min, Q, QuerySet

from core.fuzzy import extract_keywords_from_string, score_text_against_keywords
from core.models import InvestigationProfile

from .backend.chat_parser import is_whatsapp_system_message
from .models import ChatChannel, ChatMessage


def get_chat_dashboard_metrics() -> dict[str, Any]:
    """
    Computes global metrics for the Q-Chat dashboard.
    """
    total_channels = ChatChannel.objects.count()
    total_messages = ChatMessage.objects.count()
    flagged_messages = ChatMessage.objects.filter(risk_score__gte=50).count()
    deleted_messages = ChatMessage.objects.filter(is_deleted=True).count()
    media_messages = ChatMessage.objects.filter(has_media=True).count()

    platforms = (
        ChatChannel.objects.values("platform")
        .annotate(channel_count=Count("id"), msg_count=Count("messages"))
        .order_by("-msg_count")
    )

    top_flagged_senders = list(
        ChatMessage.objects.filter(risk_score__gte=50)
        .exclude(sender_name__in=["System", "system", "WhatsApp", "whatsapp"])
        .values("sender_name")
        .annotate(flagged_count=Count("id"))
        .order_by("-flagged_count")[:6]
    )

    return {
        "total_channels": total_channels,
        "total_messages": total_messages,
        "flagged_messages": flagged_messages,
        "deleted_messages": deleted_messages,
        "media_messages": media_messages,
        "platforms": list(platforms),
        "top_flagged_senders": top_flagged_senders,
    }


def get_all_chat_channels() -> QuerySet[ChatChannel]:
    """
    Retrieves all chat channels ordered by most recent message.
    """
    return ChatChannel.objects.all().order_by("-last_message_at", "-created_at")


def get_all_custodian_profiles() -> list[dict[str, Any]]:
    """
    Groups all chat channels by custodian name and returns aggregate
    forensic metrics per custodian profile for the directory card grid.
    """
    channels = ChatChannel.objects.all().order_by("-last_message_at", "-created_at")
    profiles_map = {
        p.full_name.strip().lower(): p for p in InvestigationProfile.objects.all() if p.full_name
    }

    custodians_dict: dict[str, dict[str, Any]] = {}
    for ch in channels:
        raw_name = ch.custodian_name.strip() if ch.custodian_name else ""
        c_name = raw_name if raw_name else "General Custodian"
        if c_name not in custodians_dict:
            inv_prof = profiles_map.get(c_name.lower())
            custodians_dict[c_name] = {
                "custodian_name": c_name,
                "department": (
                    inv_prof.department
                    if inv_prof and inv_prof.department
                    else (
                        "Corporate Communications"
                        if c_name != "General Custodian"
                        else "General Auditee"
                    )
                ),
                "employee_id": inv_prof.employee_id if inv_prof else "",
                "designation": inv_prof.designation if inv_prof else "",
                "channels": [],
                "channels_count": 0,
                "total_messages": 0,
                "flagged_messages_count": 0,
                "participants_set": set(),
                "platforms": set(),
            }
        entry = custodians_dict[c_name]
        entry["channels"].append(ch)
        entry["total_messages"] += ch.total_messages
        entry["flagged_messages_count"] += ch.flagged_messages_count
        entry["platforms"].add(ch.get_platform_display())
        for p in ch.participants or []:
            if p and not is_whatsapp_system_message(p) and p.lower() not in ("system", "whatsapp"):
                entry["participants_set"].add(p)

    results = []
    for entry in custodians_dict.values():
        entry["channels_count"] = len(entry["channels"])
        entry["participant_count"] = len(entry["participants_set"])
        entry["platforms_list"] = sorted(entry["platforms"])
        results.append(entry)

    results.sort(
        key=lambda x: (
            0 if x["custodian_name"] != "General Custodian" else 1,
            -x["total_messages"],
            -x["channels_count"],
        )
    )
    return results


def get_custodian_profile_detail(custodian_name: str) -> dict[str, Any]:
    """
    Retrieves full custodian metadata, linked channels, and aggregate stats.
    """
    clean_name = custodian_name.strip()
    is_general = clean_name.lower() in ("general custodian", "unassigned", "")

    if is_general:
        channels_qs = ChatChannel.objects.filter(
            Q(custodian_name="")
            | Q(custodian_name__iexact="General Custodian")
            | Q(custodian_name__isnull=True)
        )
    else:
        channels_qs = ChatChannel.objects.filter(custodian_name__iexact=clean_name)

    channels = list(channels_qs.order_by("-last_message_at", "-created_at"))

    inv_prof = (
        InvestigationProfile.objects.filter(full_name__iexact=clean_name).first()
        if not is_general
        else None
    )

    total_msgs = sum(c.total_messages for c in channels)
    flagged_msgs = sum(c.flagged_messages_count for c in channels)
    participants_set = set()
    for ch in channels:
        for p in ch.participants or []:
            if p and not is_whatsapp_system_message(p) and p.lower() not in ("system", "whatsapp"):
                participants_set.add(p)

    return {
        "custodian_name": clean_name if not is_general else "General Custodian",
        "department": (
            inv_prof.department
            if inv_prof and inv_prof.department
            else ("Corporate Communications" if not is_general else "General Auditee")
        ),
        "employee_id": inv_prof.employee_id if inv_prof else "",
        "designation": inv_prof.designation if inv_prof else "",
        "channels": channels,
        "channels_count": len(channels),
        "total_messages": total_msgs,
        "flagged_messages_count": flagged_msgs,
        "participant_count": len(participants_set),
    }


def get_chat_channel_by_id(channel_id: str | uuid.UUID) -> ChatChannel | None:
    """
    Retrieves a single channel by primary key.
    """
    try:
        return ChatChannel.objects.get(id=channel_id)
    except (ChatChannel.DoesNotExist, ValueError):
        return None


def get_paginated_chat_messages(
    channel_id: str | uuid.UUID | None = None,
    *,
    custodian_name: str | None = None,
    page: int = 1,
    page_size: int = 50,
    search: str = "",
    threshold: int = 75,
    sender: str = "",
    flagged_only: bool = False,
    media_only: bool = False,
    deleted_only: bool = False,
    sort_dir: str = "asc",  # 'asc' for chronological chat stream, 'desc' for latest first
    right_sender: str = "",
) -> dict[str, Any]:
    """
    Retrieves paginated messages for a specific channel or custodian profile with flexible filters.
    Consistently assigns left vs right side per participant, and isolates system disclaimers.
    """
    if channel_id:
        qs = ChatMessage.objects.filter(channel_id=channel_id).select_related("channel")
    elif custodian_name:
        c_clean = custodian_name.strip()
        if c_clean.lower() in ("general custodian", "unassigned", ""):
            qs = ChatMessage.objects.filter(
                Q(channel__custodian_name="")
                | Q(channel__custodian_name__iexact="General Custodian")
                | Q(channel__custodian_name__isnull=True)
            ).select_related("channel")
        else:
            qs = ChatMessage.objects.filter(channel__custodian_name__iexact=c_clean).select_related(
                "channel"
            )
    else:
        qs = ChatMessage.objects.none()

    if search:
        keywords = extract_keywords_from_string(search)
        if keywords:
            matched_ids = []
            for msg_id, mtext, sname in qs.values_list("id", "message_text", "sender_name"):
                text_to_check = f"{mtext or ''} {sname or ''}"
                is_matched, _, _ = score_text_against_keywords(
                    text_to_check, keywords, threshold=threshold
                )
                if is_matched:
                    matched_ids.append(msg_id)
            qs = qs.filter(id__in=matched_ids)
        else:
            qs = qs.none()

    if sender:
        qs = qs.filter(sender_name__iexact=sender.strip())

    if flagged_only:
        qs = qs.filter(risk_score__gte=50)

    if media_only:
        qs = qs.filter(has_media=True)

    if deleted_only:
        qs = qs.filter(is_deleted=True)

    order_prefix = "-" if sort_dir.lower() == "desc" else ""
    qs = qs.order_by(f"{order_prefix}sent_at", f"{order_prefix}created_at")

    # Determine which participant should appear on the right side
    if not right_sender:
        try:
            target_cust = custodian_name.strip() if custodian_name else ""
            if not target_cust and channel_id:
                ch_obj = ChatChannel.objects.filter(id=channel_id).first()
                if ch_obj:
                    target_cust = ch_obj.custodian_name.strip()

            if target_cust and target_cust.lower() not in ("general custodian", "unassigned"):
                cust_lower = target_cust.lower()
                matching_senders = (
                    qs.exclude(sender_name__in=["System", "system", "WhatsApp", "whatsapp"])
                    .values_list("sender_name", flat=True)
                    .distinct()
                )
                for s_name in matching_senders:
                    if s_name.strip().lower() == cust_lower or cust_lower in s_name.strip().lower():
                        right_sender = s_name
                        break

            if not right_sender:
                first_senders = list(
                    qs.exclude(sender_name__in=["System", "system", "WhatsApp", "whatsapp"])
                    .order_by("sent_at", "created_at")
                    .values_list("sender_name", flat=True)
                )
                ordered_participants: list[str] = []
                for s_name in first_senders:
                    if (
                        s_name
                        and s_name not in ordered_participants
                        and not is_whatsapp_system_message(s_name)
                    ):
                        ordered_participants.append(s_name)

                if len(ordered_participants) >= 2:
                    right_sender = ordered_participants[1]
                elif len(ordered_participants) == 1:
                    right_sender = ordered_participants[0]
        except Exception:
            right_sender = ""

    from core.profiles import get_profile_keywords

    active_profile_kws: list[str] = []
    if custodian_name:
        active_profile_kws = get_profile_keywords(custodian_name=custodian_name)
    elif channel_id:
        try:
            ch_obj = ChatChannel.objects.filter(id=channel_id).first()
            if ch_obj and ch_obj.custodian_name:
                active_profile_kws = get_profile_keywords(custodian_name=ch_obj.custodian_name)
        except (ValueError, TypeError, ChatChannel.DoesNotExist):
            active_profile_kws = []

    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(page)

    rows = []
    for msg in page_obj:
        is_sys = (
            msg.sender_name.lower() in ("system", "whatsapp")
            or (isinstance(msg.raw_payload, dict) and msg.raw_payload.get("is_system", False))
            or is_whatsapp_system_message(msg.message_text)
            or is_whatsapp_system_message(msg.sender_name)
        )
        is_right = (
            (not is_sys)
            and bool(right_sender)
            and (msg.sender_name.strip().lower() == right_sender.strip().lower())
        )

        flagged = [] if is_sys else list(msg.flagged_terms or [])
        score = 0 if is_sys else msg.risk_score
        if not is_sys and active_profile_kws:
            msg_lower = msg.message_text.lower()
            for pkw in active_profile_kws:
                pkw_clean = pkw.strip().lower()
                if pkw_clean and pkw_clean in msg_lower and pkw not in flagged:
                    flagged.append(pkw)
                    score = max(score, 50)

        rows.append(
            {
                "id": str(msg.id),
                "channel_id": str(msg.channel_id),
                "channel_name": msg.channel.channel_name,
                "platform": msg.channel.platform,
                "platform_display": msg.channel.get_platform_display(),
                "sender_name": "System" if is_sys else msg.sender_name,
                "sender_handle": msg.sender_handle,
                "sent_at": msg.sent_at.strftime("%d %b %Y, %H:%M:%S") if msg.sent_at else "-",
                "sent_time": msg.sent_at.strftime("%H:%M") if msg.sent_at else "-",
                "sent_date": msg.sent_at.strftime("%d %b %Y") if msg.sent_at else "-",
                "message_text": msg.message_text,
                "has_media": msg.has_media,
                "media_type": msg.media_type,
                "media_filename": msg.media_filename,
                "is_deleted": msg.is_deleted,
                "is_edited": msg.is_edited,
                "risk_score": score,
                "flagged_terms": flagged,
                "is_system": is_sys,
                "is_right_side": is_right,
            }
        )

    return {
        "data": rows,
        "total_count": paginator.count,
        "last_page": paginator.num_pages,
        "current_page": page_obj.number,
        "has_next": page_obj.has_next(),
        "has_previous": page_obj.has_previous(),
        "next_page": page_obj.next_page_number() if page_obj.has_next() else None,
        "previous_page": page_obj.previous_page_number() if page_obj.has_previous() else None,
        "page_range": list(
            paginator.get_elided_page_range(page_obj.number, on_each_side=2, on_ends=1)
        )
        if paginator.num_pages > 1
        else [1],
        "right_sender": right_sender,
    }


def get_chat_participants_summary(
    channel_id: str | uuid.UUID | None = None,
    *,
    custodian_name: str | None = None,
) -> list[dict[str, Any]]:
    """
    Summarizes participants in a channel or custodian profile with message counts and flagged message counts.
    Excludes automated system and disclaimer messages.
    """
    if channel_id:
        base_qs = ChatMessage.objects.filter(channel_id=channel_id)
    elif custodian_name:
        c_clean = custodian_name.strip()
        if c_clean.lower() in ("general custodian", "unassigned", ""):
            base_qs = ChatMessage.objects.filter(
                Q(channel__custodian_name="")
                | Q(channel__custodian_name__iexact="General Custodian")
                | Q(channel__custodian_name__isnull=True)
            )
        else:
            base_qs = ChatMessage.objects.filter(channel__custodian_name__iexact=c_clean)
    else:
        return []

    raw_participants = (
        base_qs.exclude(sender_name__in=["System", "system", "WhatsApp", "whatsapp"])
        .values("sender_name")
        .annotate(
            total_msgs=Count("id"),
            flagged_msgs=Count("id", filter=Q(risk_score__gte=50)),
            deleted_msgs=Count("id", filter=Q(is_deleted=True)),
            first_seen=Min("sent_at"),
            last_seen=Max("sent_at"),
        )
        .order_by("-total_msgs")
    )

    results = []
    for p in raw_participants:
        # Ignore if sender name itself looks like a system notice
        if is_whatsapp_system_message(p["sender_name"]):
            continue

        results.append(
            {
                "sender_name": p["sender_name"],
                "total_msgs": p["total_msgs"],
                "flagged_msgs": p["flagged_msgs"],
                "deleted_msgs": p["deleted_msgs"],
                "first_seen": p["first_seen"].strftime("%d %b %Y") if p["first_seen"] else "-",
                "last_seen": p["last_seen"].strftime("%d %b %Y") if p["last_seen"] else "-",
            }
        )
    return results

"""
Q-Chat Views & Controllers
Thin presentation controllers coordinating chat selectors, services, and Cotton templates.
"""

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from core.audits import get_active_audit

from .selectors import (
    get_all_chat_channels,
    get_all_custodian_profiles,
    get_chat_channel_by_id,
    get_chat_dashboard_metrics,
    get_chat_participants_summary,
    get_custodian_profile_detail,
    get_paginated_chat_messages,
)
from .services import (
    delete_chat_channel,
    delete_custodian_channels,
    ingest_chat_export_file,
)


@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Chat Instant Messaging Forensics Dashboard.
    Organized by target custodian profile directory with aggregate metrics.
    """
    active_audit = get_active_audit(request)
    audit_names = None
    custodians = get_all_custodian_profiles()
    channels = get_all_chat_channels()

    if active_audit:
        audit_names = {p.full_name.strip().lower() for p in active_audit.profiles.all()}
        custodians = [c for c in custodians if c["custodian_name"].strip().lower() in audit_names]
        channels = [c for c in channels if c.custodian_name.strip().lower() in audit_names]

    metrics = get_chat_dashboard_metrics(audit_names=audit_names)

    context = {
        "metrics": metrics,
        "custodians": custodians,
        "channels": channels,
    }
    return render(request, "q_chat/dashboard.html", context)


@require_GET
def custodian_detail_view(request: HttpRequest, custodian_name: str) -> HttpResponse:
    """
    Forensic Profile Analysis Workspace for a specific Custodian.
    Provides multi-chat combined timeline or scoped channel analysis.
    """
    custodian_info = get_custodian_profile_detail(custodian_name)
    if not custodian_info["channels"]:
        raise Http404("No chat records found for this custodian profile.")

    channels = custodian_info["channels"]
    selected_channel_id = request.GET.get("channel_id", "").strip() or None
    selected_channel = None
    if selected_channel_id:
        selected_channel = next((c for c in channels if str(c.id) == selected_channel_id), None)

    # Active query parameters
    search = request.GET.get("q", "").strip()
    sender = request.GET.get("sender", "").strip()
    flagged_only = request.GET.get("flagged") == "1"
    media_only = request.GET.get("media") == "1"
    deleted_only = request.GET.get("deleted") == "1"
    right_sender = request.GET.get("right", "").strip() or request.GET.get("me", "").strip()

    try:
        threshold = int(request.GET.get("threshold", 75))
    except (ValueError, TypeError):
        threshold = 75
    try:
        page = int(request.GET.get("page", 1))
    except (ValueError, TypeError):
        page = 1
    if page < 1:
        page = 1

    query_channel_id = selected_channel.id if selected_channel else None
    query_custodian_name = None if selected_channel else custodian_name

    participants = get_chat_participants_summary(
        channel_id=query_channel_id,
        custodian_name=query_custodian_name,
    )

    messages_data = get_paginated_chat_messages(
        channel_id=query_channel_id,
        custodian_name=query_custodian_name,
        page=page,
        page_size=100,
        search=search,
        threshold=threshold,
        sender=sender,
        flagged_only=flagged_only,
        media_only=media_only,
        deleted_only=deleted_only,
        sort_dir="asc",
        right_sender=right_sender,
    )

    if selected_channel:
        view_total_messages = selected_channel.total_messages
        view_flagged_messages = selected_channel.flagged_messages_count
        view_channel_title = selected_channel.channel_name
        view_platform = selected_channel.get_platform_display()
    else:
        view_total_messages = custodian_info["total_messages"]
        view_flagged_messages = custodian_info["flagged_messages_count"]
        view_channel_title = "All Chats Combined"
        view_platform = f"{len(channels)} Channels"

    from core.profiles import get_profile_keywords

    profile_keywords = get_profile_keywords(custodian_name=custodian_name, request=request)
    profile_keywords_str = ", ".join(profile_keywords) if profile_keywords else ""

    context = {
        "custodian": custodian_info,
        "custodian_name": custodian_name,
        "channels": channels,
        "selected_channel": selected_channel,
        "selected_channel_id": str(selected_channel.id) if selected_channel else "",
        "profile_keywords": profile_keywords,
        "profile_keywords_str": profile_keywords_str,
        "view_metrics": {
            "total_messages": view_total_messages,
            "flagged_messages": view_flagged_messages,
            "channel_title": view_channel_title,
            "platform": view_platform,
            "participant_count": len(participants),
        },
        "participants": participants,
        "messages_data": messages_data,
        "search_query": search,
        "threshold": threshold,
        "selected_sender": sender,
        "flagged_only": flagged_only,
        "media_only": media_only,
        "deleted_only": deleted_only,
        "right_sender": messages_data.get("right_sender", ""),
    }
    return render(request, "q_chat/custodian_detail.html", context)


@require_GET
def channel_detail_view(request: HttpRequest, channel_id: str) -> HttpResponse:
    """
    Forensic Workspace for a specific Chat Channel.
    Delegates to custodian profile analysis with the channel selected.
    """
    channel = get_chat_channel_by_id(channel_id)
    if not channel:
        raise Http404("Chat Channel not found.")

    custodian_name = channel.custodian_name.strip() or "General Custodian"
    request_params = request.GET.copy()
    request_params["channel_id"] = str(channel.id)
    request.GET = request_params
    return custodian_detail_view(request, custodian_name=custodian_name)


@require_POST
def upload_chat_view(request: HttpRequest) -> HttpResponse:
    """
    Uploads and ingests a chat export file.
    """
    if "chat_file" not in request.FILES:
        messages.error(request, "No chat export file was provided.")
        return redirect("q_chat:dashboard")

    uploaded_file = request.FILES["chat_file"]
    platform = request.POST.get("platform", "WHATSAPP").strip()
    channel_name = request.POST.get("channel_name", "").strip()
    custodian_name = request.POST.get("custodian_name", "").strip()

    from core.profiles import resolve_or_create_profile_from_request

    profile, resolved_name = resolve_or_create_profile_from_request(
        request, default_department="Corporate Communications"
    )
    if profile:
        custodian_name = profile.full_name
    elif not custodian_name and resolved_name:
        custodian_name = resolved_name

    try:
        channel = ingest_chat_export_file(
            file_obj_or_content=uploaded_file,
            filename=uploaded_file.name,
            platform=platform,
            channel_name=channel_name,
            custodian_name=custodian_name,
        )
        messages.success(
            request,
            f"Successfully ingested {channel.total_messages:,} messages into '{channel.channel_name}' ({channel.get_platform_display()}).",
        )
        target_cust = channel.custodian_name.strip() or "General Custodian"
        redirect_url = reverse("q_chat:custodian_detail", kwargs={"custodian_name": target_cust})
        return redirect(f"{redirect_url}?channel_id={channel.id}")
    except Exception as e:
        messages.error(request, f"Failed to ingest chat export file: {e}")
        return redirect("q_chat:dashboard")


@require_POST
def delete_custodian_view(request: HttpRequest, custodian_name: str) -> HttpResponse:
    """
    Deletes all chat channels and messages for a custodian profile.
    """
    count = delete_custodian_channels(custodian_name)
    if count > 0:
        messages.success(
            request, f"Successfully deleted {count} chat channel(s) for '{custodian_name}'."
        )
    else:
        messages.error(request, "Target custodian chat records could not be found.")
    return redirect("q_chat:dashboard")


@require_POST
def delete_channel_view(request: HttpRequest, channel_id: str) -> HttpResponse:
    """
    Deletes a chat channel case and all associated messages.
    """
    success = delete_chat_channel(channel_id)
    if success:
        messages.success(request, "Chat channel record deleted successfully.")
    else:
        messages.error(request, "Target chat channel could not be found.")
    return redirect("q_chat:dashboard")


@require_GET
def messages_api_view(request: HttpRequest, channel_id: str) -> JsonResponse:
    """
    JSON endpoint for Tabulator or dynamic stream message loading.
    """
    try:
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("size", 50))
    except (ValueError, TypeError):
        page = 1
        page_size = 50

    search = request.GET.get("search") or request.GET.get("q") or ""
    sender = request.GET.get("sender", "").strip()
    flagged_only = request.GET.get("flagged") in ("1", "true")
    media_only = request.GET.get("media") in ("1", "true")
    deleted_only = request.GET.get("deleted") in ("1", "true")
    sort_dir = request.GET.get("dir", "asc")
    right_sender = request.GET.get("right", "").strip() or request.GET.get("me", "").strip()

    try:
        threshold = int(request.GET.get("threshold", 75))
    except (ValueError, TypeError):
        threshold = 75

    result = get_paginated_chat_messages(
        channel_id,
        page=page,
        page_size=page_size,
        search=search,
        threshold=threshold,
        sender=sender,
        flagged_only=flagged_only,
        media_only=media_only,
        deleted_only=deleted_only,
        sort_dir=sort_dir,
        right_sender=right_sender,
    )
    return JsonResponse(result)

"""
Q-Voice Forensic Views
Provides a common target custodians directory dashboard and unified profile forensic dossiers.
"""

import json
import uuid
from typing import Any

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from core.audits import get_active_audit
from core.profiles import resolve_or_create_profile_from_request

from .models import AudioRecording
from .selectors import (
    get_all_custodian_profiles,
    get_all_recordings,
    get_combined_timeline_for_custodian,
    get_custodian_profile_detail,
    get_global_voice_metrics,
    get_metrics_for_custodian,
    get_recording_by_id,
)
from .services import (
    delete_audio_recording,
    delete_custodian_recordings,
    get_voice_api_endpoint,
    ingest_audio_recording,
)


def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Common Q-Voice Hub & Target Custodians Directory Dashboard.
    Displays global platform metrics and the directory of all target custodian profiles.
    """
    active_audit = get_active_audit(request)
    custodians = get_all_custodian_profiles()
    recordings = get_all_recordings()

    if active_audit:
        audit_names = {p.full_name.strip().lower() for p in active_audit.profiles.all()}
        custodians = [c for c in custodians if c["custodian_name"].strip().lower() in audit_names]
        recordings = [r for r in recordings if r.custodian_name.strip().lower() in audit_names]

    context: dict[str, Any] = {
        "status": "idle",
        "custodians": custodians,
        "recordings": recordings,
        "global_metrics": get_global_voice_metrics(),
        "error_message": "",
        "voice_endpoint": get_voice_api_endpoint(),
    }

    # Handle file upload from modal on common dashboard
    if request.method == "POST":
        audio_file = request.FILES.get("audio_file")
        if not audio_file:
            context["error_message"] = "No audio file provided. Please choose a .wav or .mp3 file."
            context["status"] = "error"
        else:
            call_ref = request.POST.get("call_ref", "")
            call_title = request.POST.get("call_title", "")
            _profile, resolved_name = resolve_or_create_profile_from_request(
                request, default_department="Strategic Sourcing"
            )
            custodian_name = (
                resolved_name or request.POST.get("custodian_name", "").strip() or "Target Auditee"
            )

            recording, error_msg = ingest_audio_recording(
                audio_file=audio_file,
                call_ref=call_ref,
                call_title=call_title,
                custodian_name=custodian_name,
            )

            if (
                error_msg
                or not recording
                or recording.transcription_status == AudioRecording.TranscriptionStatus.FAILED
            ):
                context["error_message"] = (
                    error_msg or "Local transcription service failed to process audio."
                )
                context["status"] = "error"
            else:
                messages.success(
                    request, f"Transcription completed successfully: {recording.call_ref}"
                )
                target_cust = recording.custodian_name.strip() or "General Custodian"
                redirect_url = reverse(
                    "q_voice:custodian_detail", kwargs={"custodian_name": target_cust}
                )
                return redirect(f"{redirect_url}?recording_id={recording.id}")

    return render(request, "q_voice/dashboard.html", context)


def custodian_detail_view(request: HttpRequest, custodian_name: str) -> HttpResponse:
    """
    Forensic Profile Analysis Workspace for a specific Custodian.
    Provides multi-recording combined timeline or scoped recording analysis.
    """
    custodian_info = get_custodian_profile_detail(custodian_name)
    if not custodian_info["recordings"]:
        raise Http404(f"No voice recording cases found for custodian '{custodian_name}'.")

    recordings = custodian_info["recordings"]
    selected_recording_id = request.GET.get("recording_id", "").strip() or None
    selected_recording = None
    if selected_recording_id:
        selected_recording = next(
            (r for r in recordings if str(r.id) == selected_recording_id), None
        )

    query_recording_id = selected_recording.id if selected_recording else None
    timeline = get_combined_timeline_for_custodian(custodian_name, recording_id=query_recording_id)
    metrics = get_metrics_for_custodian(custodian_name, recording_id=query_recording_id)

    clean_json_timeline = [
        {
            "timestamp": item["timestamp"],
            "start_seconds": item["start_seconds"],
            "end_seconds": item["end_seconds"],
            "transcript": item["transcript"],
            "speaker": item["speaker"],
            "call_ref": item.get("call_ref", ""),
            "detected_intent": item.get("detected_intent", "General"),
            "risk_score": item.get("risk_score", 0),
            "detections": item["detections"],
            "detections_detail": item["detections_detail"],
        }
        for item in timeline
    ]

    context: dict[str, Any] = {
        "custodian": custodian_info,
        "custodian_name": custodian_name,
        "recordings": recordings,
        "selected_recording": selected_recording,
        "selected_recording_id": str(selected_recording.id) if selected_recording else "",
        "combined_timeline": timeline,
        "metrics": metrics,
        "timeline_json": json.dumps(clean_json_timeline),
        "all_recordings": get_all_recordings(),
        "voice_endpoint": get_voice_api_endpoint(),
    }

    return render(request, "q_voice/custodian_detail.html", context)


def recording_detail_view(request: HttpRequest, recording_id: uuid.UUID) -> HttpResponse:
    """
    Individual Audio Case Forensic Dossier View.
    Seamlessly routes into the unified custodian profile workspace with the recording selected.
    """
    recording = get_recording_by_id(recording_id)
    if not recording:
        raise Http404(f"Voice recording '{recording_id}' not found.")

    custodian_name = recording.custodian_name.strip() or "General Custodian"
    request_params = request.GET.copy()
    request_params["recording_id"] = str(recording.id)
    request.GET = request_params
    return custodian_detail_view(request, custodian_name=custodian_name)


def delete_custodian_view(request: HttpRequest, custodian_name: str) -> HttpResponse:
    """
    Deletes all audio recordings for a custodian profile and returns to the dashboard.
    """
    count = delete_custodian_recordings(custodian_name)
    if count > 0:
        messages.success(
            request, f"Successfully removed {count} audio recording(s) for '{custodian_name}'."
        )
    else:
        messages.error(request, "Target custodian recordings could not be found.")

    return redirect("q_voice:dashboard")


def delete_recording_view(request: HttpRequest, recording_id: uuid.UUID) -> HttpResponse:
    """
    Deletes an audio recording and returns to the custodian profile or dashboard.
    """
    recording = get_recording_by_id(recording_id)
    custodian_name = recording.custodian_name.strip() or "General Custodian" if recording else ""
    success = delete_audio_recording(recording_id)
    if success:
        messages.success(request, "Audio recording and acoustic dossier successfully removed.")
    else:
        messages.error(request, "Audio recording could not be found.")

    if custodian_name:
        remaining = get_custodian_profile_detail(custodian_name)
        if remaining["recordings"]:
            return redirect("q_voice:custodian_detail", custodian_name=custodian_name)

    return redirect("q_voice:dashboard")

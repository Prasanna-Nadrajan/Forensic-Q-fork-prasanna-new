import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .audits import (
    create_audit,
    generate_next_audit_name,
    get_all_audits,
    map_profiles_to_audit,
    set_active_audit,
)
from .modules import get_discovered_modules
from .profiles import (
    add_keywords_to_profile,
    attach_document_to_profile,
    create_investigation_profile,
    extract_keywords_from_file,
    get_all_profiles,
    set_active_profile,
    update_investigation_profile,
)


@csrf_protect
@require_http_methods(["GET", "POST"])
def portal_login_view(request):
    """
    Master Portal Password Login View.
    Authenticates investigative access using only a portal password key.
    """
    next_url = request.GET.get("next") or request.POST.get("next") or "/"

    # Sanitize next_url against open redirect
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    # If already logged in, redirect straight away
    if request.session.get("portal_authenticated", False):
        return redirect(next_url)

    error = None

    if request.method == "POST":
        password = request.POST.get("password", "").strip()
        expected_password = getattr(settings, "PORTAL_ACCESS_PASSWORD", "")

        if password and expected_password and password == expected_password:
            request.session["portal_authenticated"] = True
            request.session.modified = True
            return redirect(next_url)
        else:
            error = "Invalid portal access key. Please verify your credentials."

    return render(
        request,
        "core/login.html",
        {
            "error": error,
            "next": next_url,
        },
    )


@require_http_methods(["GET", "POST"])
def portal_logout_view(request):
    """
    Logout View to lock the workstation and clear session credentials.
    """
    request.session.flush()
    return redirect("/login/")


@require_GET
def landing_view(request: HttpRequest) -> HttpResponse:
    """
    ForensiQ Landing Page dynamically loading all modules from apps/ directory,
    registered investigation profiles with their investigation keywords,
    and forensic audits with mapped profiles.
    """
    modules = get_discovered_modules()
    profiles = [p.to_dict() for p in get_all_profiles()]
    audits = [a.to_dict() for a in get_all_audits()]
    next_audit_name = generate_next_audit_name()
    return render(
        request,
        "core/landing.html",
        {
            "modules": modules,
            "total_modules": len(modules),
            "profiles": profiles,
            "profiles_json": json.dumps(profiles),
            "audits": audits,
            "audits_json": json.dumps(audits),
            "next_audit_name": next_audit_name,
        },
    )


@require_POST
def create_profile_view(request: HttpRequest) -> HttpResponse:
    """
    Creates a new investigation profile with optional investigation keywords
    from modal submission or AJAX fetch.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    full_name = payload.get("full_name", "").strip()
    if not full_name:
        if is_json:
            return JsonResponse(
                {"status": "error", "message": "Target name is required."}, status=400
            )
        messages.error(request, "Target profile full name is required.")
        return redirect(payload.get("next", "/"))

    keywords_input = payload.get("keywords")
    if not keywords_input and not is_json:
        # Also check comma-separated keywords string from form post
        keywords_input = request.POST.get("keywords_input", "")

    is_substantiated_raw = payload.get("is_substantiated", False)
    is_substantiated = is_substantiated_raw in (True, "true", "True", "1", 1, "on")

    profile = create_investigation_profile(
        full_name=full_name,
        employee_id=payload.get("employee_id", "").strip(),
        department=payload.get("department", "").strip(),
        designation=payload.get("designation", "").strip(),
        email=payload.get("email", "").strip(),
        phone=payload.get("phone", "").strip(),
        is_substantiated=is_substantiated,
        notes=payload.get("notes", "").strip(),
        avatar_color=payload.get("avatar_color", "indigo").strip() or "indigo",
        keywords=keywords_input,
    )

    # Check for attached evidentiary / legal document file
    if "document_file" in request.FILES:
        try:
            attach_document_to_profile(
                profile_id=profile.id,
                file_obj=request.FILES["document_file"],
                filename=request.FILES["document_file"].name,
            )
        except Exception as exc:
            messages.warning(
                request, f"Profile created, but document processing had an issue: {exc}"
            )

    # Automatically set newly created profile as active in session
    set_active_profile(request, profile.id)

    if is_json:
        return JsonResponse({"status": "success", "profile": profile.to_dict()})

    messages.success(
        request, f"Investigation Profile '{profile.full_name}' successfully registered."
    )
    next_url = payload.get("next") or "/"
    return redirect(next_url)


@require_POST
def edit_profile_view(request: HttpRequest, profile_id: str) -> HttpResponse:
    """
    Updates an existing investigation profile.
    Supports JSON AJAX requests or standard HTML form submissions.
    (Note: Profile deletion is strictly prohibited).
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    full_name = payload.get("full_name", "").strip()
    if not full_name:
        if is_json:
            return JsonResponse(
                {"status": "error", "message": "Target name is required."}, status=400
            )
        messages.error(request, "Target profile full name is required.")
        return redirect(payload.get("next", "/"))

    keywords_input = payload.get("keywords")
    if not keywords_input and not is_json:
        keywords_input = request.POST.get("keywords_input", "")

    is_substantiated_raw = payload.get("is_substantiated", False)
    is_substantiated = is_substantiated_raw in (True, "true", "True", "1", 1, "on")

    try:
        profile = update_investigation_profile(
            profile_id=profile_id,
            full_name=full_name,
            employee_id=payload.get("employee_id", "").strip(),
            department=payload.get("department", "").strip(),
            designation=payload.get("designation", "").strip(),
            email=payload.get("email", "").strip(),
            phone=payload.get("phone", "").strip(),
            is_substantiated=is_substantiated,
            status=payload.get("status", "ACTIVE").strip() or "ACTIVE",
            notes=payload.get("notes", "").strip(),
            avatar_color=payload.get("avatar_color", "").strip(),
            keywords=keywords_input if keywords_input is not None else None,
        )

        if "document_file" in request.FILES:
            try:
                attach_document_to_profile(
                    profile_id=profile.id,
                    file_obj=request.FILES["document_file"],
                    filename=request.FILES["document_file"].name,
                )
            except Exception as exc:
                messages.warning(
                    request, f"Profile updated, but document processing had an issue: {exc}"
                )
    except ValueError as err:
        if is_json:
            return JsonResponse({"status": "error", "message": str(err)}, status=404)
        messages.error(request, str(err))
        return redirect(payload.get("next", "/"))
    except Exception as err:
        if is_json:
            return JsonResponse({"status": "error", "message": str(err)}, status=500)
        messages.error(request, f"Failed updating profile: {err}")
        return redirect(payload.get("next", "/"))

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "message": f"Investigation Profile '{profile.full_name}' successfully updated.",
                "profile": profile.to_dict(),
            }
        )

    messages.success(request, f"Investigation Profile '{profile.full_name}' successfully updated.")
    next_url = payload.get("next") or "/"
    return redirect(next_url)


@require_POST
def upload_profile_document_view(request: HttpRequest, profile_id: str) -> JsonResponse:
    """
    Attaches an evidentiary or legal document to an Investigation Profile.
    Extracts counterparties and synchronizes with Q-Link.
    """
    uploaded_file = request.FILES.get("file") or request.FILES.get("document_file")
    if not uploaded_file:
        return JsonResponse({"status": "error", "message": "No file uploaded."}, status=400)

    description = request.POST.get("description", "").strip()

    try:
        doc = attach_document_to_profile(
            profile_id=profile_id,
            file_obj=uploaded_file,
            filename=uploaded_file.name,
            description=description,
        )
        return JsonResponse(
            {
                "status": "success",
                "message": f"Successfully attached '{doc.filename}' to profile.",
                "document": doc.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse(
            {"status": "error", "message": f"Failed attaching document: {err}"}, status=500
        )


ALLOWED_KEYWORDS_EXTENSIONS = {".txt"}
MAX_KEYWORDS_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@require_POST
def add_profile_keywords_view(request: HttpRequest, profile_id: str) -> JsonResponse:
    """
    Appends search and investigation keywords to an existing investigation profile.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    keywords = payload.get("keywords")
    if not keywords:
        return JsonResponse(
            {"status": "error", "message": "At least one keyword is required."},
            status=400,
        )

    try:
        profile = add_keywords_to_profile(profile_id, keywords)
        return JsonResponse(
            {
                "status": "success",
                "message": f"Keywords appended to {profile.full_name}",
                "profile": profile.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=500)


@require_POST
def parse_keywords_file_view(request: HttpRequest) -> JsonResponse:
    """
    Parses and extracts keywords from an uploaded .txt file.
    Returns the extracted list of keywords for client-side tag insertion.
    """
    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return JsonResponse(
            {
                "status": "error",
                "message": "No file uploaded. Please select a .txt file.",
            },
            status=400,
        )

    ext = Path(uploaded_file.name).suffix.lower()
    if ext not in ALLOWED_KEYWORDS_EXTENSIONS:
        return JsonResponse(
            {
                "status": "error",
                "message": f"Unsupported file type '{ext}'. Only .txt files are supported for keyword upload.",
            },
            status=400,
        )

    if uploaded_file.size > MAX_KEYWORDS_FILE_SIZE:
        return JsonResponse(
            {"status": "error", "message": "File exceeds 10MB size limit."},
            status=400,
        )

    try:
        keywords = extract_keywords_from_file(uploaded_file, uploaded_file.name)
        return JsonResponse(
            {
                "status": "success",
                "filename": uploaded_file.name,
                "count": len(keywords),
                "keywords": keywords,
            }
        )
    except Exception as err:
        return JsonResponse(
            {"status": "error", "message": f"Failed parsing keywords file: {err}"},
            status=500,
        )


@require_POST
def upload_profile_keywords_file_view(request: HttpRequest, profile_id: str) -> JsonResponse:
    """
    Uploads a .txt keywords file and directly attaches
    extracted investigation keywords to an existing profile.
    """
    uploaded_file = request.FILES.get("file")
    if not uploaded_file:
        return JsonResponse(
            {
                "status": "error",
                "message": "No file uploaded. Please select a .txt file.",
            },
            status=400,
        )

    ext = Path(uploaded_file.name).suffix.lower()
    if ext not in ALLOWED_KEYWORDS_EXTENSIONS:
        return JsonResponse(
            {
                "status": "error",
                "message": f"Unsupported file type '{ext}'. Only .txt files are supported for keyword upload.",
            },
            status=400,
        )

    if uploaded_file.size > MAX_KEYWORDS_FILE_SIZE:
        return JsonResponse(
            {"status": "error", "message": "File exceeds 10MB size limit."},
            status=400,
        )

    try:
        keywords = extract_keywords_from_file(uploaded_file, uploaded_file.name)
        if not keywords:
            return JsonResponse(
                {"status": "error", "message": "No valid keywords found in the uploaded file."},
                status=400,
            )

        profile = add_keywords_to_profile(profile_id, keywords)
        return JsonResponse(
            {
                "status": "success",
                "message": f"Appended {len(keywords)} keywords from '{uploaded_file.name}' to {profile.full_name}.",
                "filename": uploaded_file.name,
                "added_count": len(keywords),
                "profile": profile.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse(
            {"status": "error", "message": f"Failed uploading keywords: {err}"},
            status=500,
        )


@require_POST
def set_active_profile_view(request: HttpRequest) -> HttpResponse:
    """
    Switches or clears the active investigation profile for the current investigator session.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    profile_id = payload.get("profile_id", "").strip()
    profile = set_active_profile(request, profile_id if profile_id else None)

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "active_profile": profile.to_dict() if profile else None,
            }
        )

    next_url = payload.get("next") or request.META.get("HTTP_REFERER") or "/"
    return redirect(next_url)


@require_POST
def set_active_audit_view(request: HttpRequest) -> HttpResponse:
    """
    Switches or clears the active audit for the current investigator session.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    audit_id = payload.get("audit_id", "").strip()
    audit = set_active_audit(request, audit_id if audit_id else None)

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "active_audit": audit.to_dict() if audit else None,
            }
        )

    next_url = payload.get("next") or request.META.get("HTTP_REFERER") or "/"
    return redirect(next_url)


@require_GET
def profile_list_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning all registered investigation profiles for client-side dropdowns and selectors.
    """
    profiles = get_all_profiles()
    return JsonResponse(
        {
            "status": "success",
            "profiles": [p.to_dict() for p in profiles],
        }
    )


@require_POST
def create_audit_view(request: HttpRequest) -> HttpResponse:
    """
    Creates a new Forensic Audit with an auto-generated unique name (YYYY-WB-XX)
    and maps initial investigation profiles under it.
    Supports both JSON AJAX submission and standard form POST.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    title = payload.get("title", "").strip()
    description = payload.get("description", "").strip()
    status = payload.get("status", "ACTIVE").strip() or "ACTIVE"
    name = payload.get("name", "").strip() or None

    # Handle profile IDs from JSON list or form getlist
    profile_ids = []
    if is_json:
        raw_pids = payload.get("profile_ids")
        if isinstance(raw_pids, list):
            profile_ids = [str(x).strip() for x in raw_pids if str(x).strip()]
    else:
        raw_list = request.POST.getlist("profile_ids")
        for item in raw_list:
            if not item:
                continue
            item_str = str(item).strip()
            if item_str.startswith("["):
                try:
                    profile_ids.extend(
                        [str(x).strip() for x in json.loads(item_str) if str(x).strip()]
                    )
                except Exception:
                    profile_ids.extend(
                        [x.strip() for x in item_str.strip("[]").split(",") if x.strip()]
                    )
            elif "," in item_str:
                profile_ids.extend([x.strip() for x in item_str.split(",") if x.strip()])
            else:
                profile_ids.append(item_str)

    try:
        audit = create_audit(
            name=name,
            title=title,
            description=description,
            status=status,
            profile_ids=profile_ids,
        )
    except Exception as err:
        if is_json:
            return JsonResponse({"status": "error", "message": str(err)}, status=400)
        messages.error(request, f"Failed to create audit: {err}")
        return redirect(payload.get("next", "/"))

    if is_json:
        return JsonResponse(
            {
                "status": "success",
                "audit": audit.to_dict(),
                "next_audit_name": generate_next_audit_name(),
            }
        )

    messages.success(request, f"Audit '{audit.name}' successfully created.")
    return redirect(payload.get("next", "/"))


@require_POST
def map_audit_profiles_view(request: HttpRequest, audit_id: str) -> JsonResponse:
    """
    Updates or replaces mapped investigation profiles under a specific audit.
    """
    is_json = (
        request.content_type == "application/json"
        or request.headers.get("x-requested-with") == "XMLHttpRequest"
    )
    if is_json and request.body:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            payload = {}
    else:
        payload = request.POST

    replace = bool(payload.get("replace", True))
    raw_pids = payload.get("profile_ids", [])
    if isinstance(raw_pids, str):
        try:
            raw_pids = json.loads(raw_pids)
        except Exception:
            raw_pids = [x.strip() for x in raw_pids.split(",") if x.strip()]

    try:
        audit = map_profiles_to_audit(audit_id, raw_pids, replace=replace)
        return JsonResponse(
            {
                "status": "success",
                "message": f"Updated profile mappings for Audit '{audit.name}'",
                "audit": audit.to_dict(),
            }
        )
    except ValueError as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=404)
    except Exception as err:
        return JsonResponse({"status": "error", "message": str(err)}, status=500)


@require_GET
def audit_list_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning all registered audits and their mapped profiles.
    """
    audits = get_all_audits()
    return JsonResponse(
        {
            "status": "success",
            "audits": [a.to_dict() for a in audits],
            "next_audit_name": generate_next_audit_name(),
        }
    )


@require_GET
def get_next_audit_name_api_view(request: HttpRequest) -> JsonResponse:
    """
    JSON API returning the next sequential auto-generated audit name (YYYY-WB-XX).
    """
    year_param = request.GET.get("year")
    year = int(year_param) if year_param and year_param.isdigit() else None
    return JsonResponse(
        {
            "status": "success",
            "next_name": generate_next_audit_name(year=year),
        }
    )

"""
Q-Bank Presentation & View Controllers
Thin controllers routing requests, coordinating selectors & services, and rendering Cotton templates.
"""

from pathlib import Path

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST
from loguru import logger

from core.audits import get_active_audit
from core.fuzzy import extract_keywords_from_file, extract_keywords_from_string
from core.profiles import get_profile_keywords, resolve_or_create_profile_from_request

from .backend.exporter import generate_frequent_counterparties_excel, generate_ledger_excel
from .selectors import (
    fuzzy_search_transactions,
    get_all_audited_persons,
    get_all_bank_accounts,
    get_all_statement_transactions,
    get_audited_person_by_id,
    get_bank_account_by_id,
    get_bank_dashboard_metrics,
    get_cdm_transactions,
    get_frequent_counterparties,
    get_frequent_transactions_breakdown,
    get_hyundai_details,
    get_paginated_bank_transactions,
    get_person_financial_metrics,
    get_yearwise_breakdown,
    resolve_bank_search_keywords,
)
from .services import (
    create_audited_person,
    delete_audited_person,
    delete_bank_account,
    ensure_account_linked_to_person,
    get_or_create_audited_person_from_profile,
    ingest_bank_statement_file,
)


@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Main Q-Bank Forensic Financial Dashboard.
    Presents the Audited Persons Directory as the primary operational entry point.
    """
    active_audit = get_active_audit(request)
    metrics = get_bank_dashboard_metrics()
    persons = get_all_audited_persons()
    accounts = get_all_bank_accounts()

    if active_audit:
        audit_names_set = {p.full_name.strip().lower() for p in active_audit.profiles.all()}
        audit_names_list = list(active_audit.profiles.values_list("full_name", flat=True))
        persons = [p for p in persons if p["full_name"].strip().lower() in audit_names_set]
        accounts = accounts.filter(person__full_name__in=audit_names_list)

    frequent_entities = get_frequent_counterparties(limit=10)

    context = {
        "metrics": metrics,
        "persons": persons,
        "accounts": accounts,
        "frequent_entities": frequent_entities,
    }
    return render(request, "q_bank/dashboard.html", context)


@require_GET
def person_detail_view(request: HttpRequest, person_id: str) -> HttpResponse:
    """
    Forensic Workspace for a specific Audited Person.
    Displays all linked bank accounts, statement files, combined/per-account metrics,
    the Data Overview grid, and the Streamlit st.tab forensic analysis engine.
    """
    person = get_audited_person_by_id(person_id)
    if not person:
        raise Http404("Audited Person profile not found.")

    accounts = list(person.bank_accounts.all().order_by("-created_at"))

    selected_account_id = request.GET.get("account_id", "").strip() or None
    selected_account = None
    if selected_account_id:
        selected_account = next((a for a in accounts if str(a.id) == selected_account_id), None)

    # Scoped calculations (either specific account or all statements of the person combined)
    query_account_id = selected_account.id if selected_account else None
    query_person_id = None if selected_account else person.id

    frequent_entities = get_frequent_counterparties(
        account_id=query_account_id, person_id=query_person_id, limit=50
    )
    frequent_breakdown = get_frequent_transactions_breakdown(
        account_id=query_account_id, person_id=query_person_id, min_transactions=2
    )
    yearwise = get_yearwise_breakdown(account_id=query_account_id, person_id=query_person_id)
    hyundai_details = get_hyundai_details(account_id=query_account_id, person_id=query_person_id)
    cdm_rows = get_cdm_transactions(account_id=query_account_id, person_id=query_person_id)
    all_transactions = get_all_statement_transactions(
        account_id=query_account_id, person_id=query_person_id
    )

    view_metrics = get_person_financial_metrics(person=person, selected_account=selected_account)
    profile_keywords = get_profile_keywords(custodian_name=person.full_name, request=request)
    profile_keywords_str = ", ".join(profile_keywords) if profile_keywords else ""

    context = {
        "person": person,
        "accounts": accounts,
        "selected_account": selected_account,
        "selected_account_id": str(selected_account.id) if selected_account else "",
        "profile_keywords": profile_keywords,
        "profile_keywords_str": profile_keywords_str,
        "view_metrics": view_metrics,
        "frequent_entities": frequent_entities,
        "frequent_breakdown": frequent_breakdown,
        "all_transactions": all_transactions,
        "yearwise": yearwise,
        "hyundai": hyundai_details,
        "cdm_rows": cdm_rows,
    }
    return render(request, "q_bank/person_detail.html", context)


@require_GET
def account_detail_view(request: HttpRequest, account_id: str) -> HttpResponse:
    """
    Direct link to a specific bank account; ensures it is linked to an AuditedPerson
    and redirects directly to the Person Multi-Statement Forensic Workspace.
    """
    account = get_bank_account_by_id(account_id)
    if not account:
        raise Http404("Bank account audit record not found.")

    account = ensure_account_linked_to_person(account)
    return redirect(f"/bank/person/{account.person_id}/?account_id={account.id}")


@require_POST
def create_person_view(request: HttpRequest) -> HttpResponse:
    """
    Creates a new Audited Person profile.
    """
    full_name = request.POST.get("full_name", "").strip()
    if not full_name:
        messages.error(request, "Person full name is required.")
        return redirect("q_bank:dashboard")

    person = create_audited_person(
        full_name=full_name,
        employee_id=request.POST.get("employee_id", "").strip(),
        department=request.POST.get("department", "").strip(),
        designation=request.POST.get("designation", "").strip(),
        pan_number=request.POST.get("pan_number", "").strip(),
        email=request.POST.get("email", "").strip(),
        phone=request.POST.get("phone", "").strip(),
        notes=request.POST.get("notes", "").strip(),
    )
    messages.success(request, f"Created audited profile for '{person.full_name}'.")
    return redirect("q_bank:person_detail", person_id=person.id)


@require_POST
def delete_person_view(request: HttpRequest, person_id: str) -> HttpResponse:
    """
    Deletes an audited person profile and all associated bank accounts.
    """
    success = delete_audited_person(person_id)
    if success:
        messages.success(request, "Audited person profile deleted successfully.")
    else:
        messages.error(request, "Target person profile could not be found.")
    return redirect("q_bank:dashboard")


@require_GET
def transactions_api_view(request: HttpRequest) -> JsonResponse:
    """
    High-performance server-side paginated JSON endpoint for Tabulator ledger grid.
    Supports scoping by account_id OR person_id.
    """
    try:
        page = int(request.GET.get("page", 1))
    except (ValueError, TypeError):
        page = 1

    try:
        page_size = int(request.GET.get("size", 25))
    except (ValueError, TypeError):
        page_size = 25

    account_id = request.GET.get("account_id", "").strip() or None
    person_id = request.GET.get("person_id", "").strip() or None
    search = request.GET.get("search") or request.GET.get("q") or ""
    try:
        threshold = int(request.GET.get("threshold", 75))
    except (ValueError, TypeError):
        threshold = 75
    filter_type = request.GET.get("filter_type", "all").strip()
    party_name = request.GET.get("party_name", "").strip()

    sort_field = (
        request.GET.get("sort[0][field]")
        or request.GET.get("sort_by")
        or request.GET.get("sort")
        or "txn_date"
    )
    sort_dir = request.GET.get("sort[0][dir]") or request.GET.get("dir") or "desc"

    result = get_paginated_bank_transactions(
        account_id=account_id,
        person_id=person_id,
        page=page,
        page_size=page_size,
        search=search,
        threshold=threshold,
        filter_type=filter_type,
        party_name=party_name,
        sort_field=sort_field,
        sort_dir=sort_dir,
    )
    return JsonResponse(result)


@require_http_methods(["GET", "POST"])
def fuzzy_search_api_view(request: HttpRequest) -> JsonResponse:
    """
    Live fuzzy sequence search endpoint for rapid narration text matching.
    Supports keywords via text parameter and/or uploaded keyword files (.xlsx, .txt, .csv).
    """
    account_id = (
        request.POST.get("account_id") or request.GET.get("account_id", "")
    ).strip() or None
    person_id = (request.POST.get("person_id") or request.GET.get("person_id", "")).strip() or None
    try:
        raw_thresh = request.POST.get("threshold") or request.GET.get("threshold", "80")
        threshold = int(raw_thresh)
    except (ValueError, TypeError):
        threshold = 80

    # Extract keywords from request (supports text input + attached file)
    raw_kw_param = request.POST.get("keywords")
    if raw_kw_param is None:
        raw_kw_param = request.GET.get("keywords")

    keywords_list, keywords_str = resolve_bank_search_keywords(
        request=request,
        person_id=person_id,
        account_id=account_id,
        raw_keywords=raw_kw_param,
    )

    matches = fuzzy_search_transactions(
        account_id=account_id,
        person_id=person_id,
        keywords=keywords_list,
        keywords_str=keywords_str,
        threshold=threshold,
    )
    return JsonResponse(
        {
            "status": "ok",
            "total_matches": len(matches),
            "matches": matches,
            "keywords_count": len(keywords_list) if keywords_list is not None else 0,
            "searched_keywords": keywords_list or [],
        }
    )


@require_http_methods(["GET", "POST"])
def parse_keywords_api_view(request: HttpRequest) -> JsonResponse:
    """
    Parses and extracts keywords from an uploaded file (.xlsx, .txt, .csv) or text.
    Returns extracted keywords list and metadata for immediate UI feedback.
    """
    uploaded_file = (
        request.FILES.get("file")
        or request.FILES.get("keywords_file")
        or request.FILES.get("file_upload")
    )
    if (
        not uploaded_file
        and "text" not in request.POST
        and "keywords" not in request.POST
        and "keywords" not in request.GET
    ):
        return JsonResponse(
            {"status": "error", "message": "No file or keywords provided."},
            status=400,
        )

    MAX_KEYWORD_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
    if uploaded_file and uploaded_file.size > MAX_KEYWORD_FILE_SIZE:
        return JsonResponse(
            {
                "status": "error",
                "message": "Uploaded keyword file exceeds maximum size limit (10MB).",
            },
            status=400,
        )

    filename = ""
    if uploaded_file:
        filename = uploaded_file.name
        try:
            keywords = extract_keywords_from_file(uploaded_file, filename=filename)
        except Exception as e:
            return JsonResponse(
                {"status": "error", "message": f"Failed to parse keyword file: {e}"},
                status=400,
            )
    else:
        raw_text = (
            request.POST.get("text", "")
            or request.POST.get("keywords", "")
            or request.GET.get("keywords", "")
        )
        keywords = extract_keywords_from_string(raw_text)

    return JsonResponse(
        {
            "status": "ok",
            "filename": filename,
            "total_count": len(keywords),
            "keywords": keywords,
        }
    )


@require_POST
def upload_statement_view(request: HttpRequest) -> HttpResponse:
    """
    Receives and processes uploaded bank statement files (Excel, CSV, Word, PDF).
    Associates the statement with a specific person.
    """
    if "statement_file" not in request.FILES:
        messages.error(request, "No bank statement file uploaded.")
        return redirect("q_bank:dashboard")

    uploaded_file = request.FILES["statement_file"]
    person_id = request.POST.get("person_id", "").strip() or None
    account_holder = request.POST.get("account_holder", "").strip()

    profile, resolved_name = resolve_or_create_profile_from_request(
        request, default_department="Financial Audit"
    )
    if profile:
        target_person = get_or_create_audited_person_from_profile(profile)
        person_id = str(target_person.id)
        account_holder = profile.full_name
    elif not account_holder:
        account_holder = Path(uploaded_file.name).stem

    bank_name = request.POST.get("bank_name", "").strip()
    statement_label = request.POST.get("statement_label", "").strip()
    account_number = request.POST.get("account_number", "").strip()

    try:
        account = ingest_bank_statement_file(
            file_obj_or_path=uploaded_file,
            filename=uploaded_file.name,
            account_holder=account_holder,
            bank_name=bank_name,
            statement_label=statement_label,
            account_number=account_number,
            person_id=person_id,
        )
        messages.success(
            request,
            f"Successfully imported {account.total_transactions:,} transactions for '{account.account_holder}' ({account.bank_name}).",
        )
        if account.person_id:
            return redirect(f"/bank/person/{account.person_id}/?account_id={account.id}")
        return redirect("q_bank:account_detail", account_id=account.id)
    except Exception as e:
        logger.opt(exception=True).error(
            "Failed to parse and import bank statement '{}': {}", uploaded_file.name, e
        )
        messages.error(request, f"Failed to parse and import bank statement: {e}")
        return redirect("q_bank:dashboard")


@require_POST
def delete_account_view(request: HttpRequest, account_id: str) -> HttpResponse:
    """
    Deletes a single bank statement/account audit and its transactions.
    """
    account = get_bank_account_by_id(account_id)
    person_id = account.person_id if account else None

    success = delete_bank_account(account_id)
    if success:
        messages.success(request, "Bank statement audit deleted successfully.")
    else:
        messages.error(request, "Target bank account could not be found.")

    if person_id:
        return redirect("q_bank:person_detail", person_id=person_id)
    return redirect("q_bank:dashboard")


@require_GET
def export_ledger_excel_view(request: HttpRequest) -> HttpResponse:
    """
    Exports filtered bank transactions to a native Excel workbook stream.
    """
    account_id = request.GET.get("account_id", "").strip() or None
    person_id = request.GET.get("person_id", "").strip() or None
    filter_type = request.GET.get("filter_type", "all").strip()

    result = get_paginated_bank_transactions(
        account_id=account_id,
        person_id=person_id,
        page=1,
        page_size=50000,
        filter_type=filter_type,
    )
    rows = result.get("data", [])
    output = generate_ledger_excel(rows)

    response = HttpResponse(
        output.read(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = 'attachment; filename="forensiq_bank_ledger.xlsx"'
    return response


@require_GET
def export_frequent_excel_view(request: HttpRequest) -> HttpResponse:
    """
    Exports frequent counterparties analysis to Excel.
    """
    account_id = request.GET.get("account_id", "").strip() or None
    person_id = request.GET.get("person_id", "").strip() or None
    frequent = get_frequent_counterparties(account_id=account_id, person_id=person_id, limit=500)

    output = generate_frequent_counterparties_excel(frequent)

    response = HttpResponse(
        output.read(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = 'attachment; filename="forensiq_frequent_counterparties.xlsx"'
    return response

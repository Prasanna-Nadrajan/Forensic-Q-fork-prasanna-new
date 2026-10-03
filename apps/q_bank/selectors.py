"""
Q-Bank Selectors Layer (Read-Only Queries)
Optimized, N+1 safe queries for financial dashboards, Tabulator grids, and analytical aggregations.
"""

import uuid
from typing import Any

from django.core.paginator import Paginator
from django.db.models import Avg, Count, Q, QuerySet, Sum

from core.fuzzy import extract_keywords_from_string, score_text_against_keywords

from .backend.statement_parser import format_inr
from .models import AuditedPerson, BankAccount, BankTransaction


def get_all_audited_persons() -> list[dict[str, Any]]:
    """
    Retrieves all audited persons with aggregate statistics across all their bank statements.
    """
    persons = (
        AuditedPerson.objects.prefetch_related("bank_accounts__transactions")
        .all()
        .order_by("-created_at")
    )
    results = []
    for p in persons:
        accounts = list(p.bank_accounts.all())
        total_txns = sum(a.total_transactions for a in accounts)
        total_debit = sum(a.total_debit for a in accounts)
        total_credit = sum(a.total_credit for a in accounts)
        cash_deposits = sum(a.cash_deposit_count for a in accounts)
        hyundai_count = sum(a.hyundai_count for a in accounts)
        high_risk_count = sum(a.high_risk_count for a in accounts)

        results.append(
            {
                "id": str(p.id),
                "full_name": p.full_name,
                "employee_id": p.employee_id,
                "department": p.department,
                "designation": p.designation,
                "pan_number": p.pan_number,
                "accounts_count": len(accounts),
                "accounts": accounts,
                "total_transactions": total_txns,
                "total_debit": float(total_debit),
                "total_debit_formatted": format_inr(total_debit),
                "total_credit": float(total_credit),
                "total_credit_formatted": format_inr(total_credit),
                "cash_deposit_count": cash_deposits,
                "hyundai_count": hyundai_count,
                "high_risk_count": high_risk_count,
                "created_at": p.created_at,
            }
        )
    return results


def get_audited_person_by_id(person_id: str | uuid.UUID) -> AuditedPerson | None:
    """
    Retrieves a single audited person by primary key.
    """
    try:
        return AuditedPerson.objects.prefetch_related("bank_accounts").get(id=person_id)
    except (AuditedPerson.DoesNotExist, ValueError):
        return None


def get_all_bank_accounts() -> QuerySet[BankAccount]:
    """
    Retrieves all audited bank accounts ordered by creation date.
    """
    return BankAccount.objects.select_related("person").all().order_by("-created_at")


def get_bank_account_by_id(account_id: str | uuid.UUID) -> BankAccount | None:
    """
    Retrieves a single bank account audit case by primary key.
    """
    try:
        return BankAccount.objects.select_related("person").get(id=account_id)
    except (BankAccount.DoesNotExist, ValueError):
        return None


def get_bank_dashboard_metrics() -> dict[str, Any]:
    """
    Aggregates high-level forensic metrics across all bank statement audits and persons.
    """
    total_persons = AuditedPerson.objects.count()
    total_accounts = BankAccount.objects.count()
    total_txns = BankTransaction.objects.count()

    sums = BankTransaction.objects.aggregate(
        total_debit=Sum("debit_amount"),
        total_credit=Sum("credit_amount"),
        cash_deposits=Count("id", filter=Q(is_cash_deposit=True)),
        hyundai_txns=Count("id", filter=Q(is_hyundai_related=True)),
        high_risk=Count("id", filter=Q(risk_score__gte=70)),
    )

    top_counterparties_qs = (
        BankTransaction.objects.exclude(
            party_name__in=["Internal Transfer", "Other Account Operations", "Unknown Entity"]
        )
        .values("party_name")
        .annotate(
            count=Count("id"),
            total_debit=Sum("debit_amount"),
            total_credit=Sum("credit_amount"),
        )
        .order_by("-count")[:6]
    )

    return {
        "total_persons": total_persons,
        "total_accounts": total_accounts,
        "total_txns": total_txns,
        "total_debit": float(sums["total_debit"] or 0),
        "total_debit_formatted": format_inr(sums["total_debit"] or 0),
        "total_credit": float(sums["total_credit"] or 0),
        "total_credit_formatted": format_inr(sums["total_credit"] or 0),
        "cash_deposit_count": sums["cash_deposits"] or 0,
        "hyundai_count": sums["hyundai_txns"] or 0,
        "high_risk_count": sums["high_risk"] or 0,
        "top_counterparties": list(top_counterparties_qs),
    }


def get_paginated_bank_transactions(
    *,
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
    page: int = 1,
    page_size: int = 25,
    search: str = "",
    filter_type: str = "all",  # all, cash_deposit, hyundai, high_risk, credit, debit
    party_name: str = "",
    sort_field: str = "txn_date",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    """
    High-performance server-side paginated selector for Tabulator transaction grids.
    Supports instant multi-field searching, direction filtering, and column sorting.
    """
    qs = BankTransaction.objects.select_related("account", "account__person").all()

    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    if party_name:
        qs = qs.filter(party_name__iexact=party_name.strip())

    if filter_type == "cash_deposit":
        qs = qs.filter(is_cash_deposit=True)
    elif filter_type == "hyundai":
        qs = qs.filter(is_hyundai_related=True)
    elif filter_type == "high_risk":
        qs = qs.filter(risk_score__gte=70)
    elif filter_type == "credit":
        qs = qs.filter(direction=BankTransaction.Direction.CREDIT)
    elif filter_type == "debit":
        qs = qs.filter(direction=BankTransaction.Direction.DEBIT)

    if search:
        q_str = search.strip()
        qs = qs.filter(
            Q(party_name__icontains=q_str)
            | Q(narration__icontains=q_str)
            | Q(txn_ref__icontains=q_str)
            | Q(account__account_holder__icontains=q_str)
            | Q(account__bank_name__icontains=q_str)
        )

    allowed_sort_fields = {
        "txn_date": "txn_date",
        "party_name": "party_name",
        "direction": "direction",
        "debit_amount": "debit_amount",
        "credit_amount": "credit_amount",
        "closing_balance": "closing_balance",
        "risk_score": "risk_score",
        "created_at": "created_at",
    }
    db_sort_field = allowed_sort_fields.get(sort_field, "txn_date")
    order_prefix = "-" if sort_dir.lower() == "desc" else ""
    qs = qs.order_by(f"{order_prefix}{db_sort_field}", "-created_at")

    paginator = Paginator(qs, max(1, min(page_size, 500)))
    page_obj = paginator.get_page(page)

    rows = []
    for t in page_obj.object_list:
        rows.append(
            {
                "id": str(t.id),
                "account_id": str(t.account.id),
                "account_holder": t.account.account_holder,
                "bank_name": t.account.bank_name,
                "txn_ref": t.txn_ref or "-",
                "txn_date": t.txn_date.strftime("%Y-%m-%d %H:%M")
                if t.txn_date
                else (t.value_date.strftime("%Y-%m-%d") if t.value_date else "-"),
                "narration": t.narration,
                "party_name": t.party_name,
                "upi_name": t.party_name,
                "name": t.party_name,
                "value_date": t.value_date.strftime("%d %b %Y")
                if t.value_date
                else (t.txn_date.strftime("%d %b %Y") if t.txn_date else "-"),
                "source_page": t.source_page or "Page_1",
                "direction": t.direction,
                "direction_label": t.get_direction_display(),
                "debit_amount": float(t.debit_amount),
                "debit_formatted": format_inr(t.debit_amount) if t.debit_amount > 0 else "-",
                "credit_amount": float(t.credit_amount),
                "credit_formatted": format_inr(t.credit_amount) if t.credit_amount > 0 else "-",
                "closing_balance": float(t.closing_balance),
                "closing_balance_formatted": format_inr(t.closing_balance),
                "is_cash_deposit": t.is_cash_deposit,
                "is_hyundai_related": t.is_hyundai_related,
                "risk_score": t.risk_score,
                "risk_level": t.risk_level,
                "status": t.status,
                "flag_reason": t.flag_reason or "-",
            }
        )

    return {
        "data": rows,
        "last_page": paginator.num_pages,
        "last_row": paginator.count,
        "total_count": paginator.count,
        "current_page": page_obj.number,
    }


def get_frequent_counterparties(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
    min_interactions: int = 2,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """
    Compiles high-frequency counterparties with interaction volume and total credit/debit aggregates.
    """
    qs = BankTransaction.objects.all()
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    qs = qs.exclude(
        party_name__in=["Internal Transfer", "Other Account Operations", "Unknown Entity", ""]
    )

    aggregates = (
        qs.values("party_name")
        .annotate(
            total_interactions=Count("id"),
            total_debit=Sum("debit_amount"),
            total_credit=Sum("credit_amount"),
            last_activity=Avg("debit_amount"),  # dummy placeholder
        )
        .filter(total_interactions__gte=min_interactions)
        .order_by("-total_interactions")[:limit]
    )

    results = []
    for item in aggregates:
        results.append(
            {
                "party_name": item["party_name"],
                "total_interactions": item["total_interactions"],
                "debit_total": float(item["total_debit"] or 0),
                "debit_formatted": format_inr(item["total_debit"] or 0),
                "credit_total": float(item["total_credit"] or 0),
                "credit_formatted": format_inr(item["total_credit"] or 0),
            }
        )
    return results


def get_yearwise_breakdown(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregates yearly credit vs debit volume for trend analysis and Plotly charts.
    """
    qs = BankTransaction.objects.filter(txn_date__isnull=False)
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    # Use Django dates / values extraction
    years_qs = (
        qs.values("txn_date__year")
        .annotate(
            total_debit=Sum("debit_amount"),
            total_credit=Sum("credit_amount"),
            count=Count("id"),
        )
        .order_by("txn_date__year")
    )

    results = []
    for item in years_qs:
        year_val = item["txn_date__year"]
        if year_val:
            results.append(
                {
                    "year": str(year_val),
                    "total_debit": float(item["total_debit"] or 0),
                    "total_debit_formatted": format_inr(item["total_debit"] or 0),
                    "total_credit": float(item["total_credit"] or 0),
                    "total_credit_formatted": format_inr(item["total_credit"] or 0),
                    "count": item["count"],
                }
            )
    return results


def get_hyundai_metrics(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
) -> dict[str, Any]:
    """
    Calculates specific forensic aggregations for Hyundai-related counterparties.
    """
    qs = BankTransaction.objects.filter(is_hyundai_related=True)
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    total_debit = qs.aggregate(Sum("debit_amount"))["debit_amount__sum"] or 0
    credits_only = qs.filter(credit_amount__gt=0)
    total_credit = credits_only.aggregate(Sum("credit_amount"))["credit_amount__sum"] or 0
    avg_credit = credits_only.aggregate(Avg("credit_amount"))["credit_amount__avg"] or 0

    return {
        "hyundai_present": qs.exists(),
        "total_count": qs.count(),
        "credit_count": credits_only.count(),
        "total_debit": float(total_debit),
        "total_debit_formatted": format_inr(total_debit),
        "total_credit": float(total_credit),
        "total_credit_formatted": format_inr(total_credit),
        "avg_credit_formatted": format_inr(avg_credit),
    }


def get_hyundai_details(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
) -> dict[str, Any]:
    """
    Returns Hyundai summary metrics along with the full list of Hyundai matching transaction rows.
    """
    metrics = get_hyundai_metrics(account_id=account_id, person_id=person_id)
    qs = BankTransaction.objects.filter(is_hyundai_related=True).order_by("-txn_date")
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    rows = []
    for t in qs:
        rows.append(
            {
                "date": t.txn_date.strftime("%d %b %Y") if t.txn_date else "-",
                "value_date": t.value_date.strftime("%d %b %Y") if t.value_date else "-",
                "narration": t.narration,
                "name": t.party_name,
                "upi_name": t.party_name,
                "debit_amount": float(t.debit_amount),
                "debit_formatted": format_inr(t.debit_amount) if t.debit_amount > 0 else "0",
                "credit_amount": float(t.credit_amount),
                "credit_formatted": format_inr(t.credit_amount) if t.credit_amount > 0 else "0",
                "closing_balance": float(t.closing_balance),
                "closing_balance_formatted": format_inr(t.closing_balance),
                "source_page": t.source_page or "Page_1",
            }
        )
    metrics["rows"] = rows
    return metrics


def get_cdm_transactions(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    """
    Retrieves all Cash Deposit Machine (CDM) rows for an account or person.
    """
    qs = BankTransaction.objects.filter(is_cash_deposit=True).order_by("-txn_date")
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    rows = []
    for t in qs:
        rows.append(
            {
                "date": t.txn_date.strftime("%d %b %Y") if t.txn_date else "-",
                "value_date": t.value_date.strftime("%d %b %Y") if t.value_date else "-",
                "narration": t.narration,
                "name": t.party_name,
                "upi_name": t.party_name,
                "debit_amount": float(t.debit_amount),
                "debit_formatted": format_inr(t.debit_amount) if t.debit_amount > 0 else "0",
                "credit_amount": float(t.credit_amount),
                "credit_formatted": format_inr(t.credit_amount),
                "closing_balance": float(t.closing_balance),
                "closing_balance_formatted": format_inr(t.closing_balance),
                "source_page": t.source_page or "Page_1",
            }
        )
    return rows


def get_all_statement_transactions(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    """
    Retrieves all transactions for an account or person, normalized with formatted
    amounts and dates, for analytical filtering in Tabulator or Alpine.js tables.
    """
    qs = BankTransaction.objects.all().order_by("-txn_date", "-created_at")
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    if limit > 0:
        qs = qs[:limit]

    rows = []
    for t in qs:
        rows.append(
            {
                "id": str(t.id),
                "date": t.txn_date.strftime("%d %b %Y") if t.txn_date else "-",
                "value_date": t.value_date.strftime("%d %b %Y") if t.value_date else "-",
                "narration": t.narration,
                "name": t.party_name,
                "upi_name": t.party_name,
                "party_name": t.party_name,
                "direction": t.direction,
                "debit_amount": float(t.debit_amount),
                "debit_formatted": format_inr(t.debit_amount) if t.debit_amount > 0 else "0.00",
                "credit_amount": float(t.credit_amount),
                "credit_formatted": format_inr(t.credit_amount) if t.credit_amount > 0 else "0.00",
                "closing_balance": float(t.closing_balance),
                "closing_balance_formatted": format_inr(t.closing_balance),
            }
        )
    return rows


def get_frequent_transactions_breakdown(
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
    min_transactions: int = 2,
) -> dict[str, Any]:
    """
    Groups frequent counterparties for Credit and Debit separately, calculates Days Diff
    between consecutive value dates per entity, and returns structured data for UI dropdowns.
    """
    qs = BankTransaction.objects.all()
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    qs = qs.exclude(
        party_name__in=["Internal Transfer", "Other Account Operations", "Unknown Entity", ""]
    )

    # --- CREDIT SECTION ---
    credit_qs = qs.filter(credit_amount__gt=0).order_by("party_name", "value_date", "txn_date")
    credit_counts = (
        credit_qs.values("party_name")
        .annotate(total=Count("id"))
        .filter(total__gte=min_transactions)
        .order_by("-total")
    )

    credit_choices = []
    credit_groups = {}
    for c in credit_counts:
        pname = c["party_name"]
        total = c["total"]
        selector_label = f"{pname} - {total} records"
        credit_choices.append({"name": pname, "selector": selector_label, "count": total})

        party_rows = credit_qs.filter(party_name=pname)
        rows_list = []
        prev_date = None
        for r in party_rows:
            current_vdate = r.value_date or r.txn_date
            days_diff = 0
            if prev_date and current_vdate:
                days_diff = max(0, (current_vdate.date() - prev_date.date()).days)
            if current_vdate:
                prev_date = current_vdate

            rows_list.append(
                {
                    "narration": r.narration,
                    "upi_name": r.party_name,
                    "value_date": current_vdate.strftime("%Y-%m-%d") if current_vdate else "-",
                    "days_diff": days_diff,
                    "debit_amount": float(r.debit_amount),
                    "debit_formatted": format_inr(r.debit_amount) if r.debit_amount > 0 else "0",
                    "credit_amount": float(r.credit_amount),
                    "credit_formatted": format_inr(r.credit_amount),
                    "closing_balance": format_inr(r.closing_balance),
                }
            )
        credit_groups[pname] = rows_list

    # --- DEBIT SECTION ---
    debit_qs = qs.filter(debit_amount__gt=0).order_by("party_name", "value_date", "txn_date")
    debit_counts = (
        debit_qs.values("party_name")
        .annotate(total=Count("id"))
        .filter(total__gte=min_transactions)
        .order_by("-total")
    )

    debit_choices = []
    debit_groups = {}
    for d in debit_counts:
        pname = d["party_name"]
        total = d["total"]
        selector_label = f"{pname} - {total} records"
        debit_choices.append({"name": pname, "selector": selector_label, "count": total})

        party_rows = debit_qs.filter(party_name=pname)
        rows_list = []
        prev_date = None
        for r in party_rows:
            current_vdate = r.value_date or r.txn_date
            days_diff = 0
            if prev_date and current_vdate:
                days_diff = max(0, (current_vdate.date() - prev_date.date()).days)
            if current_vdate:
                prev_date = current_vdate

            rows_list.append(
                {
                    "narration": r.narration,
                    "upi_name": r.party_name,
                    "value_date": current_vdate.strftime("%Y-%m-%d") if current_vdate else "-",
                    "days_diff": days_diff,
                    "debit_amount": float(r.debit_amount),
                    "debit_formatted": format_inr(r.debit_amount),
                    "credit_amount": float(r.credit_amount),
                    "credit_formatted": format_inr(r.credit_amount) if r.credit_amount > 0 else "0",
                    "closing_balance": format_inr(r.closing_balance),
                }
            )
        debit_groups[pname] = rows_list

    return {
        "credit_choices": credit_choices,
        "credit_groups": credit_groups,
        "debit_choices": debit_choices,
        "debit_groups": debit_groups,
    }


def fuzzy_search_transactions(
    *,
    account_id: str | uuid.UUID | None = None,
    person_id: str | uuid.UUID | None = None,
    keywords_str: str | None = None,
    keywords: list[str] | None = None,
    threshold: int = 80,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """
    Performs rapidfuzz fuzzy sequence matching against transaction narrations using centralized core.fuzzy.
    """
    clean_keywords = []
    seen = set()
    if keywords:
        for kw in keywords:
            k = kw.strip()
            if k and k.lower() not in seen:
                seen.add(k.lower())
                clean_keywords.append(k)

    if keywords_str is not None:
        for kw in extract_keywords_from_string(keywords_str):
            if kw.lower() not in seen:
                seen.add(kw.lower())
                clean_keywords.append(kw)
    elif keywords is None:
        # Default fallback
        clean_keywords = ["trust", "sarla"]

    if not clean_keywords:
        return []

    qs = BankTransaction.objects.select_related("account").all()
    if account_id:
        qs = qs.filter(account_id=account_id)
    elif person_id:
        qs = qs.filter(account__person_id=person_id)

    matches = []
    for t in qs.iterator(chunk_size=1000):
        narration = t.narration or ""
        if not narration:
            continue

        is_matched, best_score, matched_kw = score_text_against_keywords(
            narration, clean_keywords, threshold=threshold
        )
        if is_matched:
            matches.append(
                {
                    "id": str(t.id),
                    "txn_date": t.txn_date.strftime("%Y-%m-%d") if t.txn_date else "-",
                    "narration": t.narration,
                    "party_name": t.party_name,
                    "direction": t.direction,
                    "debit_formatted": format_inr(t.debit_amount) if t.debit_amount > 0 else "-",
                    "credit_formatted": format_inr(t.credit_amount) if t.credit_amount > 0 else "-",
                    "closing_balance_formatted": format_inr(t.closing_balance),
                    "fuzzy_score": best_score,
                    "matched_keyword": matched_kw,
                }
            )
            if len(matches) >= limit:
                break

    matches.sort(key=lambda x: x["fuzzy_score"], reverse=True)
    return matches


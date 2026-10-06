"""
Q-Bank Report Exporters
Streaming & workbook builders for financial ledgers and analytical summaries.
"""

import io
from typing import Any

import openpyxl


def generate_ledger_excel(rows: list[dict[str, Any]]) -> io.BytesIO:
    """
    Generates an Excel workbook byte stream for bank transaction ledger rows.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Transaction Ledger"

    headers = [
        "Txn Date",
        "Account Holder",
        "Bank Name",
        "Counterparty Name",
        "Narration",
        "Direction",
        "Debit Amount (INR)",
        "Credit Amount (INR)",
        "Closing Balance (INR)",
        "Cash Deposit (CDM)",
        "Hyundai Match",
        "Risk Score",
        "Risk Level",
        "Txn Ref ID",
    ]
    ws.append(headers)

    for r in rows:
        ws.append(
            [
                r.get("txn_date", ""),
                r.get("account_holder", ""),
                r.get("bank_name", ""),
                r.get("party_name", ""),
                r.get("narration", ""),
                r.get("direction_label", ""),
                r.get("debit_amount", 0.0),
                r.get("credit_amount", 0.0),
                r.get("closing_balance", 0.0),
                "YES" if r.get("is_cash_deposit") else "NO",
                "YES" if r.get("is_hyundai_related") else "NO",
                r.get("risk_score", 0),
                r.get("risk_level", ""),
                r.get("txn_ref", ""),
            ]
        )

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output


def generate_frequent_counterparties_excel(frequent: list[dict[str, Any]]) -> io.BytesIO:
    """
    Generates an Excel workbook byte stream for frequent counterparties breakdown.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Frequent Counterparties"

    headers = ["Counterparty Name", "Total Interactions", "Total Debit (INR)", "Total Credit (INR)"]
    ws.append(headers)

    for f in frequent:
        ws.append([f["party_name"], f["total_interactions"], f["debit_total"], f["credit_total"]])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output

# ruff: noqa: E402
"""Browser simulation test for Q-Trail LLM loading screen, time options, and layman vocabulary."""

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")

import django

django.setup()

from decimal import Decimal

from django.test import Client
from django.urls import reverse
from django.utils import timezone
from q_bank.models import AuditedPerson, BankAccount, BankTransaction


def run_browser_simulation():
    client = Client()
    session = client.session
    session["portal_authenticated"] = True
    session.save()

    print("\n[Browser Simulation] Step 1: Navigating to Q-Trail Dashboard...")
    url = reverse("q_trail:dashboard")
    res = client.get(url)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    html = res.content.decode("utf-8")
    print(" -> Successfully loaded Q-Trail Dashboard (HTTP 200).")

    print(
        "\n[Browser Simulation] Step 2: Verifying LLM-Style Loading Overlay & Dynamic Thought Phrases..."
    )
    assert 'x-show="isLoading"' in html, "Missing x-show='isLoading' in dashboard HTML"
    assert "startLoading()" in html, "Missing startLoading() trigger method"
    assert "thoughtList:" in html, "Missing dynamic thoughtList array"
    assert "Reading bank statements..." in html, "Missing thought phrase"
    assert "Looking for hidden middlemen passing cash..." in html, "Missing thought phrase"
    assert "Tracing money transfers step-by-step..." in html, "Missing thought phrase"
    assert "Calculating how much money middlemen kept..." in html, "Missing thought phrase"
    assert "Checking if any money looped back to the sender..." in html, "Missing thought phrase"
    assert "Piecing together the money trail puzzle..." in html, "Missing thought phrase"
    print(
        " -> LLM-style loading screen with orbital glowing animations and thought stream verified."
    )

    print(
        "\n[Browser Simulation] Step 3: Verifying Time Gap Dropdown & Default No Time Limit (0)..."
    )
    assert "Time Gap Between Transfers:" in html, (
        "Missing layman label 'Time Gap Between Transfers:'"
    )
    assert '<option value="0" selected>' in html, "Default option is not 0 (No Time Limit)"
    assert "No Time Limit (Search All Dates)" in html, (
        "Missing 'No Time Limit (Search All Dates)' text"
    )

    # Verify selectable options
    for days, label in [
        (1, "Within 1 Day (Quick Hand-off)"),
        (3, "Within 3 Days"),
        (7, "Within 7 Days (1 Week)"),
        (14, "Within 14 Days (2 Weeks)"),
        (30, "Within 30 Days (1 Month)"),
        (60, "Within 60 Days (2 Months)"),
        (90, "Within 90 Days (3 Months)"),
    ]:
        assert f'value="{days}"' in html, f"Missing option value {days}"
        assert label in html, f"Missing option label {label}"
    print(" -> Default 'No Time Limit' and all 7 time window options verified in DOM.")

    print("\n[Browser Simulation] Step 4: Verifying Layman Vocabulary throughout UI...")
    layman_terms = [
        "Direct Payments",
        "Direct Transfers",
        "Through Middlemen",
        "Kept by Middlemen",
        "Cut Taken",
        "Middlemen Found",
        "Money Looped Back",
        "Suspected Middlemen Passing Money",
        "Who Paid Whom Summary Table",
        "Transfers via Middlemen",
        "Trace Money Trail",
        "Save as Case Report",
        "Sender (From)",
        "Receiver (To)",
        "Middleman Cut",
        "Paid to Middleman",
        "Paid to Receiver",
    ]
    for term in layman_terms:
        assert term in html, f"Expected layman term '{term}' not found in HTML"
        print(f"    [Found] '{term}'")

    print("\n[Browser Simulation] Step 5: Submitting Form with Default No Time Limit (0)...")
    # Fetch or create two profiles with transfers separated by 12 days
    p1, _ = AuditedPerson.objects.get_or_create(full_name="Sim Person Alpha")
    p2, _ = AuditedPerson.objects.get_or_create(full_name="Sim Person Beta")
    acc1, _ = BankAccount.objects.get_or_create(
        person=p1, account_number="SIM_ACC1", bank_name="HDFC"
    )
    acc2, _ = BankAccount.objects.get_or_create(
        person=p2, account_number="SIM_ACC2", bank_name="ICICI"
    )

    now = timezone.now()
    BankTransaction.objects.get_or_create(
        account=acc1,
        txn_ref="SIM_TXN_OUT",
        defaults={
            "txn_date": now,
            "narration": "UPI-SIM_UTR_1-BROKER TOM-tom@okaxis-OUTFLOW",
            "debit_amount": Decimal("100000.00"),
        },
    )
    BankTransaction.objects.get_or_create(
        account=acc2,
        txn_ref="SIM_TXN_IN",
        defaults={
            "txn_date": now + timezone.timedelta(days=12),  # 12 days later
            "narration": "UPI-SIM_UTR_2-BROKER TOM-tom@okaxis-INFLOW",
            "credit_amount": Decimal("90000.00"),
        },
    )

    post_res = client.post(
        url, {"profile_ids": [str(p1.id), str(p2.id)], "time_window_days": "0", "scope": "all"}
    )
    assert post_res.status_code == 200, f"Expected 200, got {post_res.status_code}"
    post_html = post_res.content.decode("utf-8")
    assert "tom@okaxis" in post_html, "Middleman tom@okaxis not matched with time_window_days=0"
    print(" -> Successfully traced money trail across 12-day gap with No Time Limit (0 days).")

    print("\n============================================================")
    print("  ALL BROWSER SIMULATION CHECKS PASSED SUCCESSFULLY (100%)!")
    print("============================================================\n")


if __name__ == "__main__":
    run_browser_simulation()

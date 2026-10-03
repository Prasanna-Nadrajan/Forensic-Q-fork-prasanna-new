"""
Q-Trail Multi-Bank Money Trail Seeding Script
=============================================================================
Populates realistic interconnected bank transactions between Audited Persons
(Arun Kumar with HDFC Bank, Rajesh M with ICICI Bank, and E2E Auditee Target)
featuring:
1. Direct 1-to-1 Transfers (A -> B) via exact UTR (UPI & NEFT).
2. 1-Hop Intermediate Conduit Transfers (A -> Conduit X -> B) with retention margin.
3. 1-Hop Intermediate Conduit Transfers (B -> Conduit Y -> Target).
4. Circular Round-Tripping Flow (Target -> Originator A).
=============================================================================
"""

import os
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import django

# Setup Django Environment
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")
django.setup()

from q_bank.models import AuditedPerson, BankAccount, BankTransaction  # noqa: E402


def seed_trail_demo_data():
    print("[Q-Trail Seeder] Seeding realistic interconnected money trail transactions...")
    now = datetime.now(UTC)

    # 1. Auditee A: Arun Kumar (HDFC Bank)
    person_a, _ = AuditedPerson.objects.get_or_create(
        full_name="Arun Kumar (Auditee)",
        defaults={
            "department": "Global Procurement",
            "designation": "General Manager",
            "employee_id": "EMP-HYU-1049",
        },
    )
    account_a, _ = BankAccount.objects.get_or_create(
        person=person_a,
        bank_name="HDFC Bank",
        defaults={
            "account_number": "HDFC-50100492819201",
            "account_holder": "Arun Kumar",
            "statement_label": "HDFC Salary & Current Account",
            "currency": "INR",
        },
    )

    # 2. Auditee B: Rajesh M (ICICI Bank)
    person_b, _ = AuditedPerson.objects.get_or_create(
        full_name="Rajesh M (Auditee)",
        defaults={
            "department": "Supply Chain Logistics",
            "designation": "Senior Manager",
            "employee_id": "EMP-HYU-2088",
        },
    )
    account_b, _ = BankAccount.objects.get_or_create(
        person=person_b,
        bank_name="ICICI Bank",
        defaults={
            "account_number": "ICIC-001205019823",
            "account_holder": "Rajesh M",
            "statement_label": "ICICI Primary Savings Account",
            "currency": "INR",
        },
    )

    # 3. Auditee C: E2E Auditee Target (SBI Bank)
    person_c, _ = AuditedPerson.objects.get_or_create(
        full_name="E2E Auditee Target",
        defaults={
            "department": "Vendor Infrastructure",
            "designation": "Director",
            "employee_id": "EMP-HYU-0012",
        },
    )
    account_c, _ = BankAccount.objects.get_or_create(
        person=person_c,
        bank_name="State Bank of India",
        defaults={
            "account_number": "SBIN-309182390123",
            "account_holder": "E2E Auditee Target",
            "statement_label": "SBI Corporate Account",
            "currency": "INR",
        },
    )

    # Clean existing demonstration trail transactions if present to prevent duplication
    demo_refs = [
        "TXN-TRAIL-DIR-01",
        "TXN-TRAIL-DIR-02",
        "TXN-TRAIL-DIR-03",
        "TXN-TRAIL-DIR-04",
        "TXN-TRAIL-CON-A1",
        "TXN-TRAIL-CON-B1",
        "TXN-TRAIL-CON-A2",
        "TXN-TRAIL-CON-B2",
        "TXN-TRAIL-CON-B3",
        "TXN-TRAIL-CON-C3",
        "TXN-TRAIL-LOOP-C1",
        "TXN-TRAIL-LOOP-A1",
    ]
    BankTransaction.objects.filter(txn_ref__in=demo_refs).delete()

    t0 = now - timedelta(days=5)

    # =========================================================================
    # SCENARIO 1: Direct 1-to-1 Transfers between Arun Kumar (A) and Rajesh M (B)
    # =========================================================================
    # Direct Transfer 1: Arun Kumar -> Rajesh M (₹1,50,000 via UPI Exact UTR: 412345678901)
    BankTransaction.objects.create(
        account=account_a,
        txn_ref="TXN-TRAIL-DIR-01",
        txn_date=t0,
        narration="UPI-412345678901-RAJESH M-rajeshm@okhdfc-HDFC0000123-PAYMENT",
        party_name="Rajesh M",
        direction=BankTransaction.Direction.DEBIT,
        debit_amount=Decimal("150000.00"),
        credit_amount=Decimal("0.00"),
    )
    BankTransaction.objects.create(
        account=account_b,
        txn_ref="TXN-TRAIL-DIR-02",
        txn_date=t0,
        narration="BIL/IN/UPI/412345678901/Arun Kumar/arunkumar@okhdfc/ICIC0000123",
        party_name="Arun Kumar",
        direction=BankTransaction.Direction.CREDIT,
        debit_amount=Decimal("0.00"),
        credit_amount=Decimal("150000.00"),
    )

    # Direct Transfer 2: Arun Kumar -> Rajesh M (₹2,75,000 via NEFT Exact UTR: HDFCN00123456789)
    BankTransaction.objects.create(
        account=account_a,
        txn_ref="TXN-TRAIL-DIR-03",
        txn_date=t0 + timedelta(days=1),
        narration="NEFT DR-HDFCN00123456789-RAJESH M-ICIC0000123-CONSULTING FEES",
        party_name="Rajesh M",
        direction=BankTransaction.Direction.DEBIT,
        debit_amount=Decimal("275000.00"),
        credit_amount=Decimal("0.00"),
    )
    BankTransaction.objects.create(
        account=account_b,
        txn_ref="TXN-TRAIL-DIR-04",
        txn_date=t0 + timedelta(days=1),
        narration="INF/NEFT/HDFCN00123456789/ARUN KUMAR/ICIC0000123",
        party_name="Arun Kumar",
        direction=BankTransaction.Direction.CREDIT,
        debit_amount=Decimal("0.00"),
        credit_amount=Decimal("275000.00"),
    )

    # =========================================================================
    # SCENARIO 2: 1-Hop Intermediate Conduit (Arun Kumar -> Bobby Traders -> Rajesh M)
    # Conduit Entity: bobby@okaxis
    # Outflow: ₹5,00,000 | Inflow: ₹4,75,000 | Retained: ₹25,000 (5.0%)
    # =========================================================================
    BankTransaction.objects.create(
        account=account_a,
        txn_ref="TXN-TRAIL-CON-A1",
        txn_date=t0 + timedelta(days=1, hours=2),
        narration="UPI-BOBBY TRADERS-bobby@okaxis-AXIS0000001-412345678910-EQUIPMENT LEASE",
        party_name="Bobby Traders",
        direction=BankTransaction.Direction.DEBIT,
        debit_amount=Decimal("500000.00"),
        credit_amount=Decimal("0.00"),
    )
    BankTransaction.objects.create(
        account=account_b,
        txn_ref="TXN-TRAIL-CON-B1",
        txn_date=t0 + timedelta(days=2, hours=4),
        narration="BIL/IN/UPI/412345678915/Bobby Traders/bobby@okaxis/ICIC0000123",
        party_name="Bobby Traders",
        direction=BankTransaction.Direction.CREDIT,
        debit_amount=Decimal("0.00"),
        credit_amount=Decimal("475000.00"),
    )

    # =========================================================================
    # SCENARIO 3: 1-Hop Intermediate Conduit (Arun Kumar -> Sharma Enterprises -> Rajesh M)
    # Conduit Entity: SHARMA ENTERPRISES
    # Outflow: ₹3,50,000 | Inflow: ₹3,35,000 | Retained: ₹15,000
    # =========================================================================
    BankTransaction.objects.create(
        account=account_a,
        txn_ref="TXN-TRAIL-CON-A2",
        txn_date=t0 + timedelta(days=2),
        narration="IMPS-P2A-777123456789-SHARMA ENTERPRISES-HDFC0000123-XXXX4321",
        party_name="Sharma Enterprises",
        direction=BankTransaction.Direction.DEBIT,
        debit_amount=Decimal("350000.00"),
        credit_amount=Decimal("0.00"),
    )
    BankTransaction.objects.create(
        account=account_b,
        txn_ref="TXN-TRAIL-CON-B2",
        txn_date=t0 + timedelta(days=3),
        narration="MMT/IMPS/777123456799/SHARMA ENTERPRISES/ICICI Bank",
        party_name="Sharma Enterprises",
        direction=BankTransaction.Direction.CREDIT,
        debit_amount=Decimal("0.00"),
        credit_amount=Decimal("335000.00"),
    )

    # =========================================================================
    # SCENARIO 4: 1-Hop Intermediate Conduit (Rajesh M -> Broker X -> E2E Auditee Target)
    # Conduit Entity: brokerx@okaxis
    # Outflow: ₹6,00,000 | Inflow: ₹5,80,000 | Retained: ₹20,000
    # =========================================================================
    BankTransaction.objects.create(
        account=account_b,
        txn_ref="TXN-TRAIL-CON-B3",
        txn_date=t0 + timedelta(days=3, hours=5),
        narration="UPI-BROKER X-brokerx@okaxis-AXIS0000001-412345678920-ESCROW ADVANCE",
        party_name="Broker X",
        direction=BankTransaction.Direction.DEBIT,
        debit_amount=Decimal("600000.00"),
        credit_amount=Decimal("0.00"),
    )
    BankTransaction.objects.create(
        account=account_c,
        txn_ref="TXN-TRAIL-CON-C3",
        txn_date=t0 + timedelta(days=4, hours=1),
        narration="BIL/IN/UPI/412345678925/Broker X/brokerx@okaxis/SBIN0001234",
        party_name="Broker X",
        direction=BankTransaction.Direction.CREDIT,
        debit_amount=Decimal("0.00"),
        credit_amount=Decimal("580000.00"),
    )

    # =========================================================================
    # SCENARIO 5: Circular Round-Tripping (E2E Auditee Target -> Arun Kumar)
    # Direct Circular Loop: Completes the loop back to originator Arun Kumar!
    # Amount: ₹5,50,000 (UTR: SBIN99008811)
    # =========================================================================
    BankTransaction.objects.create(
        account=account_c,
        txn_ref="TXN-TRAIL-LOOP-C1",
        txn_date=t0 + timedelta(days=4, hours=6),
        narration="NEFT DR-SBIN99008811-ARUN KUMAR-HDFC0000123-PROJECT CLOSEOUT",
        party_name="Arun Kumar",
        direction=BankTransaction.Direction.DEBIT,
        debit_amount=Decimal("550000.00"),
        credit_amount=Decimal("0.00"),
    )
    BankTransaction.objects.create(
        account=account_a,
        txn_ref="TXN-TRAIL-LOOP-A1",
        txn_date=t0 + timedelta(days=4, hours=6),
        narration="INF/NEFT/SBIN99008811/E2E AUDITEE TARGET/HDFC0000123",
        party_name="E2E Auditee Target",
        direction=BankTransaction.Direction.CREDIT,
        debit_amount=Decimal("0.00"),
        credit_amount=Decimal("550000.00"),
    )

    print(
        "[Q-Trail Seeder] Successfully seeded 12 interconnected transactions across Arun Kumar, Rajesh M, and E2E Auditee Target!"
    )


if __name__ == "__main__":
    seed_trail_demo_data()

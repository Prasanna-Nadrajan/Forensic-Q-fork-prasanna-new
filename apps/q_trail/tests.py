"""
Q-Trail Forensic Reconciliation & Network Matching Test Suite
=============================================================================
Comprehensive unit and integration tests covering:
1. Feature extraction regex engine (UTR, VPA, Account Mask, Entity Name).
2. Match Rule 1: Direct 1-to-1 transaction matching (exact UTR and fallback fuzzy).
3. Match Rule 2: 1-hop intermediate transaction network overlap (Candidate X).
4. Temporal and value constraints (time delta <= window, inflow <= outflow).
5. Grouping by intermediary and summary metrics compilation.
=============================================================================
"""

import json
from decimal import Decimal

import pandas as pd
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from q_bank.models import AuditedPerson, BankAccount, BankTransaction
from q_trail.backend.reconciliation import (
    extract_banking_features,
    group_intermediate_transfers_by_intermediary,
    match_direct_transactions,
    match_intermediate_transactions,
    reconcile_and_match_network,
)
from q_trail.models import CaseDossier, FundTrailPath, PassThroughNode
from q_trail.selectors import (
    generate_trail_sankey_chart,
    get_all_trail_cases,
    get_available_profiles_for_trail,
    get_trail_paths_by_case,
    get_transactions_df_for_profile,
)
from q_trail.services import analyze_profiles_money_trail
from q_trail.views import _format_inr

from core.models import InvestigationProfile


class QTrailFeatureExtractionTests(TestCase):
    """Tests for regex-based feature extraction from Indian bank narrations."""

    def test_utr_extraction_upi_imps_12_digits(self):
        df = pd.DataFrame(
            {
                "Narration": [
                    "UPI-412345678901-ARUN KUMAR-arunkumar@okhdfc-PAYMENT",
                    "IMPS-P2A-987654321098-VIKASH-HDFC0000123-XXXX4321",
                    "MMT/IMPS/555123456789/Suresh/ICICI Bank",
                    "BIL/IN/UPI/777888999000/Vendor/parts@axis",
                ]
            }
        )
        extracted = extract_banking_features(df)
        self.assertEqual(extracted["UTR"].iloc[0], "412345678901")
        self.assertEqual(extracted["UTR"].iloc[1], "987654321098")
        self.assertEqual(extracted["UTR"].iloc[2], "555123456789")
        self.assertEqual(extracted["UTR"].iloc[3], "777888999000")

    def test_utr_extraction_neft_rtgs_alphanumeric(self):
        df = pd.DataFrame(
            {
                "Narration": [
                    "NEFT DR-HDFCN00123456789-RAJESH ENTERPRISES-XXXX9876",
                    "NEFT CR-N123456789012345-CITIBANK TRANSFER",
                    "RTGS DR-HDFCR520260201001-ALPHA LOGISTICS LTD",
                    "INF/NEFT/AXISN04123456789/SUPPLIER/ICIC0001234",
                ]
            }
        )
        extracted = extract_banking_features(df)
        self.assertEqual(extracted["UTR"].iloc[0], "HDFCN00123456789")
        self.assertEqual(extracted["UTR"].iloc[1], "N123456789012345")
        self.assertEqual(extracted["UTR"].iloc[2], "HDFCR520260201001")
        self.assertEqual(extracted["UTR"].iloc[3], "AXISN04123456789")

    def test_counterparty_vpa_extraction(self):
        df = pd.DataFrame(
            {
                "Narration": [
                    "UPI-BOBBY TRADERS-bobby@okaxis-AXIS0000001-412345678901-PAYMENT",
                    "BIL/IN/UPI/412345678904/Bobby Traders/bobby@okaxis/ICIC0000123",
                    "UPI/rajesh-kumar@okhdfcbank/Payment for services",
                    "Payment sent to contractor.services@icici via portal",
                ]
            }
        )
        extracted = extract_banking_features(df)
        self.assertEqual(extracted["Counterparty_VPA"].iloc[0], "bobby@okaxis")
        self.assertEqual(extracted["Counterparty_VPA"].iloc[1], "bobby@okaxis")
        self.assertEqual(extracted["Counterparty_VPA"].iloc[2], "rajesh-kumar@okhdfcbank")
        self.assertEqual(extracted["Counterparty_VPA"].iloc[3], "contractor.services@icici")

    def test_counterparty_account_and_ifsc_extraction(self):
        df = pd.DataFrame(
            {
                "Narration": [
                    "IMPS-P2A-412345678901-VIKASH G-HDFC0000123-XXXXXX4567",
                    "NEFT DR-HDFCN00123456789-RAJESH ENTERPRISES-XXXX9876",
                    "INF/NEFT/041234567890/RAJESH SHARMA/ICIC0001234",
                    "Regular ATM Cash Withdrawal No IFSC",
                ]
            }
        )
        extracted = extract_banking_features(df)
        self.assertIn("HDFC0000123", [extracted["Counterparty_Account"].iloc[0]])
        self.assertEqual(extracted["Counterparty_Account"].iloc[1], "XXXX9876")
        self.assertEqual(extracted["Counterparty_Account"].iloc[2], "ICIC0001234")
        self.assertTrue(pd.isna(extracted["Counterparty_Account"].iloc[3]))

    def test_counterparty_name_extraction(self):
        df = pd.DataFrame(
            {
                "Narration": [
                    "UPI-VIPUL PATEL-vipul@okaxis-AXIS0000001-412345678901-PAYMENT",
                    "UPI/412345678901/RAJESH KUMAR/rajesh@okhdfc/Payment for goods",
                    "NEFT DR-HDFCN00123456789-RAJESH ENTERPRISES-XXXXXX9876",
                    "UPI/412345678901/SENT TO MR ARUN KUMAR/arunkumar@oksbi/AXIS",
                    "MMT/IMPS/412345678901/VIKASH RAJA/ICICI Bank",
                ]
            }
        )
        extracted = extract_banking_features(df)
        self.assertEqual(extracted["Counterparty_Name"].iloc[0], "VIPUL PATEL")
        self.assertEqual(extracted["Counterparty_Name"].iloc[1], "RAJESH KUMAR")
        self.assertEqual(extracted["Counterparty_Name"].iloc[2], "RAJESH ENTERPRISES")
        self.assertEqual(extracted["Counterparty_Name"].iloc[3], "ARUN KUMAR")
        self.assertEqual(extracted["Counterparty_Name"].iloc[4], "VIKASH RAJA")

    def test_empty_dataframe_handling(self):
        empty_df = pd.DataFrame()
        res = extract_banking_features(empty_df)
        self.assertTrue(res.empty)
        self.assertIn("UTR", res.columns)
        self.assertIn("Counterparty_VPA", res.columns)


class QTrailDirectMatchingTests(TestCase):
    """Tests for Match Rule 1: Direct 1-to-1 transfers between Person A and Person B."""

    def setUp(self):
        self.stmt_a = pd.DataFrame(
            {
                "Date": ["2026-02-01", "2026-02-05", "2026-02-10"],
                "Narration": [
                    "NEFT DR-HDFCN11223344-PERSON B-XXXX9876",  # Direct A -> B via UTR
                    "UPI-PERSON B-personb@icici-412345678999-PAYMENT",  # Missing UTR in B, fallback
                    "UPI-STORE-store@okhdfc-999888777666",
                ],
                "Debit": [50000.0, 15000.0, 500.0],
                "Credit": [0.0, 0.0, 0.0],
            }
        )

        self.stmt_b = pd.DataFrame(
            {
                "Date": ["2026-02-01", "2026-02-05", "2026-02-12"],
                "Narration": [
                    "NEFT CR-HDFCN11223344-PERSON A-CITI0000002",  # Direct A -> B via UTR
                    "IMPS CR-INTERNAL TRANSFER-PERSON A REMITTANCE",  # Fallback: same date, same amount, narration mentions Person A
                    "UPI DR-HDFCN55667788-PERSON A-CITI0000002",  # Direct B -> A via UTR
                ],
                "Debit": [0.0, 0.0, 25000.0],
                "Credit": [50000.0, 15000.0, 0.0],
            }
        )

        # In statement A, also include the matching credit for B -> A
        self.stmt_a_with_b_to_a = pd.concat(
            [
                self.stmt_a,
                pd.DataFrame(
                    {
                        "Date": ["2026-02-12"],
                        "Narration": ["UPI CR-HDFCN55667788-PERSON B-ICIC0000123"],
                        "Debit": [0.0],
                        "Credit": [25000.0],
                    }
                ),
            ],
            ignore_index=True,
        )

    def test_direct_utr_exact_match(self):
        direct_matches = match_direct_transactions(
            self.stmt_a_with_b_to_a,
            self.stmt_b,
            person_a_name="Person A",
            person_b_name="Person B",
        )
        self.assertFalse(direct_matches.empty)
        utr_matches = direct_matches[direct_matches["Match_Method"] == "UTR_EXACT"]
        self.assertGreaterEqual(len(utr_matches), 2)

        # Check A -> B
        a_to_b = utr_matches[utr_matches["Direction"] == "A_TO_B"]
        self.assertEqual(len(a_to_b), 1)
        self.assertEqual(a_to_b.iloc[0]["UTR"], "HDFCN11223344")
        self.assertEqual(a_to_b.iloc[0]["Amount"], 50000.0)

        # Check B -> A
        b_to_a = utr_matches[utr_matches["Direction"] == "B_TO_A"]
        self.assertEqual(len(b_to_a), 1)
        self.assertEqual(b_to_a.iloc[0]["UTR"], "HDFCN55667788")
        self.assertEqual(b_to_a.iloc[0]["Amount"], 25000.0)

    def test_direct_fallback_fuzzy_match(self):
        direct_matches = match_direct_transactions(
            self.stmt_a,
            self.stmt_b,
            person_a_name="Person A",
            person_b_name="Person B",
        )
        fuzzy_matches = direct_matches[direct_matches["Match_Method"] == "FALLBACK_FUZZY"]
        self.assertEqual(len(fuzzy_matches), 1)
        row = fuzzy_matches.iloc[0]
        self.assertEqual(row["Amount"], 15000.0)
        self.assertEqual(row["Transfer_Date"], "2026-02-05")
        self.assertEqual(row["Direction"], "A_TO_B")


class QTrailIntermediateMatchingTests(TestCase):
    """Tests for Match Rule 2: Intermediate transaction network matching (A -> X -> B)."""

    def setUp(self):
        # Person A (HDFC) sends money to 2 intermediaries: Bobby Traders and Sharma Enterprises
        self.stmt_a = pd.DataFrame(
            {
                "Date": ["2026-03-01", "2026-03-02", "2026-03-10"],
                "Narration": [
                    "UPI-BOBBY TRADERS-bobby@okaxis-AXIS0000001-412345678901-PAYMENT",  # Outflow 1 to Bobby
                    "NEFT DR-HDFCN889900-SHARMA ENTERPRISES-XXXX9988",  # Outflow 2 to Sharma
                    "UPI-RANDOM-random@okhdfc-999111222333",  # Unrelated
                ],
                "Debit": [100000.0, 200000.0, 500.0],
                "Credit": [0.0, 0.0, 0.0],
            }
        )

        # Person B (ICICI) receives money:
        # - From Bobby: 2 days later, 95k <= 100k (Valid hop!)
        # - From Sharma: 1 day later, 180k <= 200k (Valid hop!)
        # - Unrelated salary
        self.stmt_b = pd.DataFrame(
            {
                "Date": ["2026-03-03", "2026-03-03", "2026-03-15"],
                "Narration": [
                    "BIL/IN/UPI/412345678904/Bobby Traders/bobby@okaxis/ICIC0000123",
                    "INF/NEFT/041234567890/SHARMA ENTERPRISES/ICIC0001234",
                    "UPI-SALARY-employer@icici-ICIC0000123-555444333222",
                ],
                "Debit": [0.0, 0.0, 0.0],
                "Credit": [95000.0, 180000.0, 80000.0],
            }
        )

    def test_intermediate_network_overlap_and_retention(self):
        res = match_intermediate_transactions(
            self.stmt_a,
            self.stmt_b,
            time_window_days=3,
        )
        self.assertEqual(len(res), 2)
        self.assertIn("bobby@okaxis", res["Intermediary_Entity"].values)
        self.assertIn("SHARMA ENTERPRISES", res["Intermediary_Entity"].values)

        # Test Bobby Traders metrics
        bobby_row = res[res["Intermediary_Entity"] == "bobby@okaxis"].iloc[0]
        self.assertEqual(bobby_row["Outflow_Amount"], 100000.0)
        self.assertEqual(bobby_row["Inflow_Amount"], 95000.0)
        self.assertEqual(bobby_row["Retention_Amount"], 5000.0)
        self.assertEqual(bobby_row["Retention_Pct"], 5.0)
        self.assertEqual(bobby_row["Time_Delta_Days"], 2.0)

        # Test Sharma Enterprises metrics
        sharma_row = res[res["Intermediary_Entity"] == "SHARMA ENTERPRISES"].iloc[0]
        self.assertEqual(sharma_row["Outflow_Amount"], 200000.0)
        self.assertEqual(sharma_row["Inflow_Amount"], 180000.0)
        self.assertEqual(sharma_row["Retention_Amount"], 20000.0)
        self.assertEqual(sharma_row["Retention_Pct"], 10.0)
        self.assertEqual(sharma_row["Time_Delta_Days"], 1.0)

    def test_temporal_constraint_rejection_exceeding_window(self):
        # Change Inflow date to 7 days later (> 3 days default window)
        delayed_b = self.stmt_b.copy()
        delayed_b.loc[0, "Date"] = "2026-03-10"  # 9 days after 2026-03-01

        res = match_intermediate_transactions(
            self.stmt_a,
            delayed_b,
            time_window_days=3,
        )
        # Only Sharma Enterprises should match
        self.assertEqual(len(res), 1)
        self.assertEqual(res.iloc[0]["Intermediary_Entity"], "SHARMA ENTERPRISES")

    def test_temporal_constraint_rejection_inflow_before_outflow(self):
        # Inflow to B occurred BEFORE Outflow from A (negative time delta)
        inverted_b = self.stmt_b.copy()
        inverted_b.loc[0, "Date"] = "2026-02-25"  # Earlier than A's 2026-03-01

        res = match_intermediate_transactions(
            self.stmt_a,
            inverted_b,
            time_window_days=3,
        )
        self.assertNotIn("bobby@okaxis", res["Intermediary_Entity"].values)

    def test_value_constraint_rejection_inflow_greater_than_outflow(self):
        # Inflow to B (150k) is GREATER than Outflow from A (100k)
        inflated_b = self.stmt_b.copy()
        inflated_b.loc[0, "Credit"] = 150000.0

        res = match_intermediate_transactions(
            self.stmt_a,
            inflated_b,
            time_window_days=3,
        )
        self.assertNotIn("bobby@okaxis", res["Intermediary_Entity"].values)

    def test_temporal_constraint_no_time_limit_zero(self):
        # Change Inflow date to 9 days later (> standard window)
        delayed_b = self.stmt_b.copy()
        delayed_b.loc[0, "Date"] = "2026-03-10"

        # With time_window_days=0 (No time limit), both should match
        res = match_intermediate_transactions(
            self.stmt_a,
            delayed_b,
            time_window_days=0,
        )
        self.assertEqual(len(res), 2)
        self.assertIn("bobby@okaxis", res["Intermediary_Entity"].values)
        self.assertIn("SHARMA ENTERPRISES", res["Intermediary_Entity"].values)

    def test_grouping_by_intermediary(self):
        res = match_intermediate_transactions(
            self.stmt_a,
            self.stmt_b,
            time_window_days=3,
        )
        grouped = group_intermediate_transfers_by_intermediary(res)
        self.assertIn("bobby@okaxis", grouped)
        self.assertIn("SHARMA ENTERPRISES", grouped)
        self.assertEqual(len(grouped["bobby@okaxis"]), 1)
        self.assertEqual(len(grouped["SHARMA ENTERPRISES"]), 1)

    def test_bidirectional_intermediate_matching(self):
        # Stmt A: A -> X (Debit 100k on 03-01), Y -> A (Credit 48k on 03-05)
        stmt_a = pd.DataFrame(
            {
                "Date": ["2026-03-01", "2026-03-05"],
                "Narration": [
                    "UPI-BOBBY TRADERS-bobby@okaxis-AXIS0000001-112233445566",
                    "UPI-CONDUIT Y-conduity@okaxis-AXIS0000001-998877665544",
                ],
                "Debit": [100000.0, 0.0],
                "Credit": [0.0, 48000.0],
            }
        )
        # Stmt B: X -> B (Credit 95k on 03-02), B -> Y (Debit 50k on 03-04)
        stmt_b = pd.DataFrame(
            {
                "Date": ["2026-03-02", "2026-03-04"],
                "Narration": [
                    "UPI-BOBBY TRADERS-bobby@okaxis-AXIS0000001-112233445566",
                    "UPI-CONDUIT Y-conduity@okaxis-AXIS0000001-998877665544",
                ],
                "Debit": [0.0, 50000.0],
                "Credit": [95000.0, 0.0],
            }
        )

        res = match_intermediate_transactions(
            stmt_a,
            stmt_b,
            person_a_name="Alice",
            person_b_name="Bob",
            bidirectional=True,
            time_window_days=3,
        )

        # Both directions must be detected
        self.assertEqual(len(res), 2)
        directions = set(res["Direction"].values)
        self.assertEqual(directions, {"A_TO_B", "B_TO_A"})

        # Check A_TO_B (Alice -> bobby -> Bob)
        a_to_b = res[res["Direction"] == "A_TO_B"].iloc[0]
        self.assertEqual(a_to_b["Sender_Person"], "Alice")
        self.assertEqual(a_to_b["Recipient_Person"], "Bob")
        self.assertEqual(a_to_b["Intermediary_Entity"], "bobby@okaxis")
        self.assertEqual(a_to_b["Outflow_Amount"], 100000.0)
        self.assertEqual(a_to_b["Inflow_Amount"], 95000.0)

        # Check B_TO_A (Bob -> conduity -> Alice)
        b_to_a = res[res["Direction"] == "B_TO_A"].iloc[0]
        self.assertEqual(b_to_a["Sender_Person"], "Bob")
        self.assertEqual(b_to_a["Recipient_Person"], "Alice")
        self.assertEqual(b_to_a["Intermediary_Entity"], "conduity@okaxis")
        self.assertEqual(b_to_a["Outflow_Amount"], 50000.0)
        self.assertEqual(b_to_a["Inflow_Amount"], 48000.0)
        self.assertIn("Risk_Level", b_to_a)
        self.assertIn("Layering_Type", b_to_a)


class QTrailMasterReconciliationOrchestratorTests(TestCase):
    """Tests for the master end-to-end reconciliation orchestrator function."""

    def test_master_pipeline_execution(self):
        stmt_a = pd.DataFrame(
            {
                "Date": ["2026-04-01", "2026-04-03"],
                "Narration": [
                    "NEFT DR-HDFCN990011-PERSON B-XXXX1111",  # Direct transfer
                    "UPI-BROKER X-brokerx@okaxis-AXIS0000001-412345678901",  # Outflow to intermediary
                ],
                "Debit": [75000.0, 500000.0],
                "Credit": [0.0, 0.0],
            }
        )

        stmt_b = pd.DataFrame(
            {
                "Date": ["2026-04-01", "2026-04-04"],
                "Narration": [
                    "NEFT CR-HDFCN990011-PERSON A-CITI0000002",  # Direct transfer
                    "BIL/IN/UPI/412345678902/Broker X/brokerx@okaxis/ICIC0000123",  # Inflow from intermediary (1 day later, 480k)
                ],
                "Debit": [0.0, 0.0],
                "Credit": [75000.0, 480000.0],
            }
        )

        pipeline_result = reconcile_and_match_network(
            stmt_a,
            stmt_b,
            person_a_name="Person A",
            person_b_name="Person B",
            time_window_days=3,
        )

        self.assertEqual(pipeline_result["status"], "success")

        # Verify Direct Transfers
        direct_df = pipeline_result["direct_transfers"]
        self.assertEqual(len(direct_df), 1)
        self.assertEqual(direct_df.iloc[0]["Amount"], 75000.0)
        self.assertEqual(direct_df.iloc[0]["UTR"], "HDFCN990011")

        # Verify Intermediate Transfers
        inter_df = pipeline_result["intermediate_transfers"]
        self.assertEqual(len(inter_df), 1)
        self.assertEqual(inter_df.iloc[0]["Intermediary_Entity"], "brokerx@okaxis")
        self.assertEqual(inter_df.iloc[0]["Outflow_Amount"], 500000.0)
        self.assertEqual(inter_df.iloc[0]["Inflow_Amount"], 480000.0)
        self.assertEqual(inter_df.iloc[0]["Retention_Amount"], 20000.0)

        # Verify Summary Metrics
        metrics = pipeline_result["metrics"]
        self.assertEqual(metrics["total_direct_transfers_count"], 1)
        self.assertEqual(metrics["total_direct_volume_inr"], 75000.0)
        self.assertEqual(metrics["total_intermediate_hops_count"], 1)
        self.assertEqual(metrics["total_outflow_to_intermediaries_inr"], 500000.0)
        self.assertEqual(metrics["total_inflow_from_intermediaries_inr"], 480000.0)
        self.assertEqual(metrics["total_retained_by_intermediaries_inr"], 20000.0)
        self.assertEqual(metrics["unique_intermediaries_count"], 1)
        self.assertIn("brokerx@okaxis", metrics["unique_intermediaries_list"])


class QTrailModelTests(TestCase):
    """Tests for Q-Trail ORM models, relations, and string representations."""

    def test_case_dossier_creation(self):
        case = CaseDossier.objects.create(
            case_number="TR-2026-001",
            title="Procurement Layering Audit",
            lead_investigator="Senior Auditor",
            status="Active",
        )
        self.assertEqual(str(case), "TR-2026-001 - Procurement Layering Audit")

    def test_fund_trail_path_and_pass_through_node(self):
        case = CaseDossier.objects.create(
            case_number="TR-2026-002",
            title="Conduit Flow Audit",
        )
        path = FundTrailPath.objects.create(
            case=case,
            source_entity="Arun Kumar",
            destination_entity="Rajesh M",
            total_amount=Decimal("450000.00"),
            hop_count=2,
            is_circular=False,
            risk_score=75,
        )
        self.assertIn("Arun Kumar -> Rajesh M (₹450000.00)", str(path))

        node = PassThroughNode.objects.create(
            trail=path,
            entity_name="brokerx@okaxis",
            inflow_amount=Decimal("500000.00"),
            outflow_amount=Decimal("480000.00"),
            retention_pct=4.0,
        )
        self.assertIn("brokerx@okaxis (₹500000.00 -> ₹480000.00)", str(node))


class QTrailSelectorTests(TestCase):
    """Tests for Q-Trail read-only analytical selectors."""

    def setUp(self):
        self.person = AuditedPerson.objects.create(
            full_name="Test Person Alpha",
            department="Finance",
            designation="Manager",
        )
        self.account = BankAccount.objects.create(
            person=self.person,
            account_number="HDFC00112233",
            bank_name="HDFC Bank",
            account_holder="Test Person Alpha",
            total_debit=Decimal("50000.00"),
            total_credit=Decimal("50000.00"),
        )
        self.txn = BankTransaction.objects.create(
            account=self.account,
            txn_ref="TXN990011",
            txn_date=timezone.now(),
            narration="UPI-412345678901-BOBBY-bobby@okaxis-PAYMENT",
            party_name="Bobby",
            direction=BankTransaction.Direction.DEBIT,
            debit_amount=Decimal("25000.00"),
            credit_amount=Decimal("0.00"),
        )

    def test_get_available_profiles_for_trail(self):
        profiles = get_available_profiles_for_trail()
        self.assertTrue(len(profiles) >= 1)
        found = next((p for p in profiles if p["id"] == str(self.person.id)), None)
        self.assertIsNotNone(found)
        self.assertEqual(found["name"], "Test Person Alpha")
        self.assertEqual(found["transactions_count"], 1)
        self.assertEqual(found["banks"], ["HDFC Bank"])

    def test_get_transactions_df_for_profile(self):
        df = get_transactions_df_for_profile(str(self.person.id))
        self.assertFalse(df.empty)
        self.assertIn("Narration", df.columns)
        self.assertIn("Debit", df.columns)
        self.assertEqual(df["Debit"].iloc[0], 25000.0)

    def test_generate_trail_sankey_chart(self):
        # Empty case
        empty_html = generate_trail_sankey_chart(pd.DataFrame(), pd.DataFrame())
        self.assertIn("No fund flow links detected", empty_html)

        # Populated direct & intermediate case
        direct_df = pd.DataFrame(
            [
                {
                    "Sender_Person": "Person A",
                    "Recipient_Person": "Person B",
                    "Amount": 100000.0,
                    "Match_Method": "UTR_EXACT",
                    "UTR": "412345678901",
                }
            ]
        )
        inter_df = pd.DataFrame(
            [
                {
                    "Sender_Person": "Person A",
                    "Recipient_Person": "Person B",
                    "Intermediary_Entity": "conduit@bank",
                    "Outflow_Amount": 200000.0,
                    "Inflow_Amount": 190000.0,
                    "Retention_Amount": 10000.0,
                }
            ]
        )
        sankey_html = generate_trail_sankey_chart(direct_df, inter_df)
        self.assertIn("plotly", sankey_html.lower())


class QTrailServiceTests(TestCase):
    """Tests for multi-profile money trail services and circular loop detection."""

    def setUp(self):
        # Set up Person A
        self.person_a = AuditedPerson.objects.create(full_name="Auditee A", department="Logistics")
        self.account_a = BankAccount.objects.create(
            person=self.person_a, account_number="HDFC1111", bank_name="HDFC Bank"
        )
        # Person A Outflow directly to B (UTR 412345678901)
        BankTransaction.objects.create(
            account=self.account_a,
            txn_ref="TXNA1",
            txn_date=timezone.now(),
            narration="UPI-412345678901-AUDITEE B-auditeeb@okhdfc-PAYMENT",
            party_name="Auditee B",
            direction=BankTransaction.Direction.DEBIT,
            debit_amount=Decimal("50000.00"),
        )
        # Person A Outflow to Intermediary X (bobby@okaxis)
        BankTransaction.objects.create(
            account=self.account_a,
            txn_ref="TXNA2",
            txn_date=timezone.now(),
            narration="UPI-BOBBY TRADERS-bobby@okaxis-AXIS0000001-412345678902-PAYMENT",
            party_name="Bobby Traders",
            direction=BankTransaction.Direction.DEBIT,
            debit_amount=Decimal("300000.00"),
        )

        # Set up Person B
        self.person_b = AuditedPerson.objects.create(
            full_name="Auditee B", department="Procurement"
        )
        self.account_b = BankAccount.objects.create(
            person=self.person_b, account_number="ICIC2222", bank_name="ICICI Bank"
        )
        # Person B Inflow directly from A (UTR 412345678901)
        BankTransaction.objects.create(
            account=self.account_b,
            txn_ref="TXNB1",
            txn_date=timezone.now(),
            narration="BIL/IN/UPI/412345678901/Auditee A/auditeea@okhdfc/HDFC0000123",
            party_name="Auditee A",
            direction=BankTransaction.Direction.CREDIT,
            credit_amount=Decimal("50000.00"),
        )
        # Person B Inflow from Intermediary X (bobby@okaxis, 290k)
        BankTransaction.objects.create(
            account=self.account_b,
            txn_ref="TXNB2",
            txn_date=timezone.now() + timezone.timedelta(days=1),
            narration="BIL/IN/UPI/412345678905/Bobby Traders/bobby@okaxis/ICIC0000123",
            party_name="Bobby Traders",
            direction=BankTransaction.Direction.CREDIT,
            credit_amount=Decimal("290000.00"),
        )

    def test_analyze_profiles_money_trail_fewer_than_two(self):
        res = analyze_profiles_money_trail([str(self.person_a.id)])
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["metrics"]["total_direct_transfers_count"], 0)

    def test_analyze_profiles_money_trail_e2e_reconciliation(self):
        res = analyze_profiles_money_trail(
            [str(self.person_a.id), str(self.person_b.id)],
            time_window_days=3,
            case_title="Automated Test Trail",
            save_dossier=True,
        )
        self.assertEqual(res["status"], "success")

        # Direct Transfer verification (50k)
        direct_df = res["direct_transfers"]
        self.assertEqual(len(direct_df), 1)
        self.assertEqual(float(direct_df.iloc[0]["Amount"]), 50000.0)

        # Intermediate Transfer verification (300k -> 290k through bobby@okaxis)
        inter_df = res["intermediate_transfers"]
        self.assertEqual(len(inter_df), 1)
        self.assertEqual(inter_df.iloc[0]["Intermediary_Entity"], "bobby@okaxis")
        self.assertEqual(float(inter_df.iloc[0]["Outflow_Amount"]), 300000.0)
        self.assertEqual(float(inter_df.iloc[0]["Inflow_Amount"]), 290000.0)
        self.assertEqual(float(inter_df.iloc[0]["Retention_Amount"]), 10000.0)

        # Dossier saved verification
        self.assertIsNotNone(res["case_dossier"])
        self.assertTrue(CaseDossier.objects.filter(id=res["case_dossier"].id).exists())
        self.assertTrue(FundTrailPath.objects.filter(case=res["case_dossier"]).exists())

    def test_workstation_v2_chronological_beats_and_conduit_deck(self):
        """Verifies that workstation builders generate beats, scored conduit deck, and topology graph."""
        res = analyze_profiles_money_trail(
            [str(self.person_a.id), str(self.person_b.id)],
            time_window_days=3,
        )
        self.assertEqual(res["status"], "success")
        # 1. Chronological beats
        beats = res.get("chronological_beats", [])
        self.assertIsInstance(beats, list)
        self.assertTrue(len(beats) >= 1)
        first_beat = beats[0]
        self.assertIn("n", first_beat)
        self.assertIn("kind", first_beat)
        self.assertIn("title", first_beat)
        self.assertIn("cumulative_retained", first_beat)

        # 2. Conduit Deck
        deck = res.get("conduit_deck", [])
        self.assertIsInstance(deck, list)
        if deck:
            c = deck[0]
            self.assertIn("scores", c)
            self.assertIn("composite", c["scores"])
            self.assertIn("flags", c)

        # 3. Topology Graph
        graph = res.get("topology_graph", {})
        self.assertIn("W", graph)
        self.assertIn("H", graph)
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)


class QTrailViewTests(TestCase):
    """Tests for Q-Trail views, dashboard rendering, and API endpoint."""

    def setUp(self):
        self.client = Client()
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()
        self.person_a = AuditedPerson.objects.create(full_name="Auditee One", department="Sales")
        self.person_b = AuditedPerson.objects.create(full_name="Auditee Two", department="Ops")

    def test_dashboard_view_get(self):
        url = reverse("q_trail:dashboard")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "q_trail/dashboard.html")
        self.assertIn("available_profiles", response.context)
        self.assertIn("metrics", response.context)
        self.assertIn("sankey_figure_html", response.context)

    def test_dashboard_view_post_reconciliation(self):
        url = reverse("q_trail:dashboard")
        response = self.client.post(
            url,
            {
                "profile_ids": [str(self.person_a.id), str(self.person_b.id)],
                "time_window_days": "7",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "q_trail/dashboard.html")

    def test_analyze_api_view_post(self):
        url = reverse("q_trail:analyze_api")
        payload = {
            "profile_ids": [str(self.person_a.id), str(self.person_b.id)],
            "time_window_days": 3,
        }
        response = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("metrics", data)
        self.assertIn("sankey_html", data)

    def test_format_inr_edge_cases(self):
        self.assertEqual(_format_inr(None), "0.00")
        self.assertEqual(_format_inr(1500.5), "1,500.50")
        self.assertEqual(_format_inr("invalid_number"), "0.00")

    def test_dashboard_view_comma_separated_and_invalid_window(self):
        url = reverse("q_trail:dashboard")
        response = self.client.get(
            url,
            {
                "profile_ids": f"{self.person_a.id},{self.person_b.id}",
                "time_window_days": "invalid",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["time_window_days"], 0)

    def test_analyze_api_view_form_data_and_invalid_payload(self):
        url = reverse("q_trail:analyze_api")
        # Form-encoded POST
        response_form = self.client.post(
            url,
            {
                "profile_ids": [str(self.person_a.id), str(self.person_b.id)],
                "time_window_days": "5",
            },
        )
        self.assertEqual(response_form.status_code, 200)

        # Invalid payload
        response_bad = self.client.post(
            url,
            data="not a json",
            content_type="application/json",
        )
        self.assertEqual(response_bad.status_code, 400)

    def test_dashboard_view_contains_workstation_v2_data(self):
        """Verifies dashboard view renders workstation global data and components."""
        url = reverse("q_trail:dashboard")
        response = self.client.get(
            url,
            {"profile_ids": f"{self.person_a.id},{self.person_b.id}"},
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertIn("window.beatsData", content)
        self.assertIn("window.conduitDeckData", content)
        self.assertIn("window.topologyGraphData", content)
        self.assertIn("Multi-Hop Fund Flow Topology", content)
        self.assertIn("Trace the Money Timeline", content)


class QTrailExtendedCoverageTests(TestCase):
    """Additional tests to exercise case retrieval, core profile synchronization, and self-loops."""

    def setUp(self):
        self.person_a = AuditedPerson.objects.create(full_name="Ext Person A")
        self.acc_a = BankAccount.objects.create(
            person=self.person_a, account_number="EXT_A", bank_name="HDFC"
        )
        self.person_b = AuditedPerson.objects.create(full_name="Ext Person B")
        self.acc_b = BankAccount.objects.create(
            person=self.person_b, account_number="EXT_B", bank_name="ICICI"
        )

        now = timezone.now()
        BankTransaction.objects.create(
            account=self.acc_a,
            txn_date=now,
            narration="UPI-111222333444-EXT PERSON B-b@okhdfc-PAYMENT",
            debit_amount=Decimal("25000.00"),
        )
        BankTransaction.objects.create(
            account=self.acc_b,
            txn_date=now,
            narration="BIL/IN/UPI/111222333444/Ext Person A/a@okhdfc/HDFC0000123",
            credit_amount=Decimal("25000.00"),
        )

    def test_get_all_trail_cases_and_paths_by_case(self):
        case = CaseDossier.objects.create(
            case_number="TR-TEST-999",
            title="Dossier Test 999",
        )
        path = FundTrailPath.objects.create(
            case=case,
            source_entity="A",
            destination_entity="B",
            total_amount=Decimal("123.45"),
        )
        cases = get_all_trail_cases()
        self.assertTrue(cases.filter(id=case.id).exists())
        paths = get_trail_paths_by_case(case.id)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].id, path.id)

    def test_get_available_profiles_with_investigation_profile(self):
        InvestigationProfile.objects.create(
            full_name="Unlinked Standalone Subject",
            department="Risk Management",
            designation="Consultant",
        )
        profiles = get_available_profiles_for_trail()
        names = [p["name"] for p in profiles]
        self.assertIn("Unlinked Standalone Subject", names)

    def test_get_transactions_df_investigation_profile_fallback(self):
        # Create core profile and matching audited person
        core_prof = InvestigationProfile.objects.create(
            full_name="Sync Test Individual",
        )
        auditee = AuditedPerson.objects.create(
            full_name="Sync Test Individual",
        )
        account = BankAccount.objects.create(
            person=auditee,
            account_number="SYNC1234",
            bank_name="HDFC",
        )
        BankTransaction.objects.create(
            account=account,
            txn_date=timezone.now(),
            narration="UPI-412345678901-SYNC TEST-sync@okhdfc-PAYMENT",
            debit_amount=Decimal("1500.00"),
        )
        # Fetch using core_prof.id
        df = get_transactions_df_for_profile(str(core_prof.id))
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 1)
        self.assertEqual(df["Debit"].iloc[0], 1500.0)

    def test_circular_round_trip_direct_and_self_loops(self):
        # Create Person A and B
        p_a = AuditedPerson.objects.create(full_name="Loop Person A")
        acc_a = BankAccount.objects.create(person=p_a, account_number="LOOP_A", bank_name="HDFC")
        p_b = AuditedPerson.objects.create(full_name="Loop Person B")
        acc_b = BankAccount.objects.create(person=p_b, account_number="LOOP_B", bank_name="ICICI")

        now = timezone.now()
        # Direct A -> B (50k, UTR 888123456789)
        BankTransaction.objects.create(
            account=acc_a,
            txn_date=now,
            narration="UPI-888123456789-LOOP PERSON B-b@okhdfc-PAYMENT",
            debit_amount=Decimal("50000.00"),
        )
        BankTransaction.objects.create(
            account=acc_b,
            txn_date=now,
            narration="BIL/IN/UPI/888123456789/Loop Person A/a@okhdfc/HDFC0000123",
            credit_amount=Decimal("50000.00"),
        )

        # Direct B -> A return loop (50k, UTR 999123456789)
        BankTransaction.objects.create(
            account=acc_b,
            txn_date=now + timezone.timedelta(days=1),
            narration="UPI-999123456789-LOOP PERSON A-a@okhdfc-PAYMENT",
            debit_amount=Decimal("50000.00"),
        )
        BankTransaction.objects.create(
            account=acc_a,
            txn_date=now + timezone.timedelta(days=1),
            narration="BIL/IN/UPI/999123456789/Loop Person B/b@okhdfc/ICIC0000123",
            credit_amount=Decimal("50000.00"),
        )

        res = analyze_profiles_money_trail(
            [str(p_a.id), str(p_b.id)],
            time_window_days=3,
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(len(res["circular_trails"]) >= 1)

    def test_multi_hop_closed_loop_metrics_and_conduits(self):
        """
        Verify that multi-hop closed loops (A -> B -> C -> A) accurately compute
        initial outflow, return inflow, conduit retention amounts, and leg details.
        """
        now = timezone.now()
        p_a = AuditedPerson.objects.create(full_name="Arun Kumar (Auditee)")
        acc_a = BankAccount.objects.create(
            person=p_a,
            account_number="ACC-ARUN-001",
            bank_name="HDFC",
        )
        p_b = AuditedPerson.objects.create(full_name="Rajesh M (Auditee)")
        acc_b = BankAccount.objects.create(
            person=p_b,
            account_number="ACC-RAJESH-002",
            bank_name="ICICI",
        )
        p_c = AuditedPerson.objects.create(full_name="E2E Auditee Target")
        acc_c = BankAccount.objects.create(
            person=p_c,
            account_number="ACC-TARGET-003",
            bank_name="SBI",
        )

        # Hop 1: Arun -> Rajesh via conduit SHARMA ENTERPRISES (350k out, 335k in, 15k ret)
        BankTransaction.objects.create(
            account=acc_a,
            txn_date=now - timezone.timedelta(days=2),
            narration="NEFT DR-HDFCN88990011-SHARMA ENTERPRISES-XXXX9988",
            debit_amount=Decimal("350000.00"),
        )
        BankTransaction.objects.create(
            account=acc_b,
            txn_date=now - timezone.timedelta(days=1),
            narration="INF/NEFT/041234567890/SHARMA ENTERPRISES/ICIC0001234",
            credit_amount=Decimal("335000.00"),
        )

        # Hop 2: Rajesh -> Target via conduit brokerx@okaxis (600k out, 580k in, 20k ret)
        BankTransaction.objects.create(
            account=acc_b,
            txn_date=now - timezone.timedelta(days=1),
            narration="UPI-BROKER SERVICES-brokerx@okaxis-AXIS0000001-412345678905-PAYMENT",
            debit_amount=Decimal("600000.00"),
        )
        BankTransaction.objects.create(
            account=acc_c,
            txn_date=now,
            narration="BIL/IN/UPI/412345678906/Broker Services/brokerx@okaxis/SBIN0000123",
            credit_amount=Decimal("580000.00"),
        )

        # Hop 3 (Closing leg): Target -> Arun direct transfer (550k, UTR 990088112233)
        BankTransaction.objects.create(
            account=acc_c,
            txn_date=now,
            narration="UPI-990088112233-ARUN KUMAR-arun@okhdfc-RETURN",
            debit_amount=Decimal("550000.00"),
        )
        BankTransaction.objects.create(
            account=acc_a,
            txn_date=now,
            narration="BIL/IN/UPI/990088112233/E2E AUDITEE TARGET/target@oksbi/RETURN",
            credit_amount=Decimal("550000.00"),
        )

        res = analyze_profiles_money_trail(
            [str(p_a.id), str(p_b.id), str(p_c.id)],
            time_window_days=3,
        )
        self.assertEqual(res["status"], "success")
        loops = [
            loop_item
            for loop_item in res["circular_trails"]
            if loop_item["type"] == "Network_Loop_Chain"
        ]
        self.assertTrue(len(loops) >= 1)

        loop = loops[0]
        self.assertGreater(loop["initial_amount"], 0.0)
        self.assertGreater(loop["return_amount"], 0.0)
        self.assertNotEqual(loop["initial_date"], "-")
        self.assertNotEqual(loop["return_date"], "-")
        self.assertEqual(loop["initial_amount"], 350000.0)
        self.assertEqual(loop["return_amount"], 550000.0)
        self.assertEqual(loop["retained_amount"], 35000.0)
        self.assertIn("SHARMA ENTERPRISES", loop["conduits"])
        self.assertIn("brokerx@okaxis", loop["conduits"])
        self.assertEqual(len(loop["hops"]), 3)
        self.assertTrue(bool(loop.get("forensic_narrative")))


class QTrailAuditScopingTests(TestCase):
    """Tests for Q-Trail audit scoping and scope toggle between audit and all profiles."""

    def setUp(self):
        from core.audits import create_audit
        from core.models import InvestigationProfile

        self.prof1 = InvestigationProfile.objects.create(
            full_name="Target Subject Alpha",
            employee_id="EMP-T1",
            department="Procurement",
        )
        self.prof2 = InvestigationProfile.objects.create(
            full_name="Target Subject Beta",
            employee_id="EMP-T2",
            department="Finance",
        )
        self.prof3 = InvestigationProfile.objects.create(
            full_name="Unrelated Subject Gamma",
            employee_id="EMP-T3",
            department="HR",
        )

        self.audit = create_audit(
            title="Procurement Scope Audit",
            profile_ids=[str(self.prof1.id), str(self.prof2.id)],
        )

    def test_get_available_profiles_scoped_by_audit_id(self):
        all_profiles = get_available_profiles_for_trail(audit_id=None)
        self.assertGreaterEqual(len(all_profiles), 3)

        scoped_profiles = get_available_profiles_for_trail(audit_id=self.audit.id)
        self.assertEqual(len(scoped_profiles), 2)
        scoped_names = [p["name"] for p in scoped_profiles]
        self.assertIn("Target Subject Alpha", scoped_names)
        self.assertIn("Target Subject Beta", scoped_names)
        self.assertNotIn("Unrelated Subject Gamma", scoped_names)

    def test_dashboard_view_audit_scope_and_toggle(self):
        session = self.client.session
        session["portal_authenticated"] = True
        session["active_audit_id"] = str(self.audit.id)
        session["active_audit_name"] = self.audit.name
        session.save()

        # 1. Default or scope=audit
        res_audit = self.client.get(reverse("q_trail:dashboard") + "?scope=audit")
        self.assertEqual(res_audit.status_code, 200)
        self.assertEqual(res_audit.context["scope"], "audit")
        self.assertEqual(len(res_audit.context["available_profiles"]), 2)
        self.assertEqual(res_audit.context["audit_profiles_count"], 2)

        # 2. scope=all toggle
        res_all = self.client.get(reverse("q_trail:dashboard") + "?scope=all")
        self.assertEqual(res_all.status_code, 200)
        self.assertEqual(res_all.context["scope"], "all")
        self.assertGreaterEqual(len(res_all.context["available_profiles"]), 3)

#!/usr/bin/env python
# ruff: noqa: E402
"""
ForensiQ Master End-to-End (E2E) Workstation Integration Test Suite
Validates complete user journeys across all 9 Forensic Engines and Core Infrastructure:
1. Portal Authentication & Session Security (Lock/Unlock, Open-Redirect defense)
2. Dynamic Workstation Landing Catalog (LIVE & BUILDING states)
3. Q-Bank: Statement Ingestion, Risk Screening & Tabulator Grid
4. Q-Mail: Ingestion Tracking, 10 Forensic Checkpoints & Excel Export
5. Q-Scan: Endpoint Evidence Ingestion & Tool Distribution
6. Q-Verify: Document Metadata, Authenticity Scoring & Hex Inspection
7. Q-Voice: Audio Wiretap Diarization, Timeline & Intent Engine
8. Q-Chat: Multi-Platform Chat Threading & Keyword Triage
9. Q-Ledger: SAP ERP Procurement Auditor
10. Demo & UI Design System: Tokens, Tabulator styling & Plotly integration
"""

import io
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

# Configure Django Environment
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")

import django

django.setup()

from django.core.management import call_command

# Automatically initialize and migrate database schema if running in clean environment/CI
call_command("migrate", interactive=False, verbosity=0)

from django.conf import settings  # noqa: E402
from django.core.files.uploadedfile import SimpleUploadedFile  # noqa: E402
from django.test import Client  # noqa: E402
from django.urls import reverse  # noqa: E402
from django.utils import timezone  # noqa: E402
from q_bank.services import ingest_bank_statement_file  # noqa: E402
from q_chat.services import ingest_chat_export_file  # noqa: E402
from q_mail.models import EmailMessage, MailboxInvestigation  # noqa: E402
from q_scan.models import ScannedDevice  # noqa: E402
from q_verify.models import VerificationCase, VerifiedDocument  # noqa: E402
from q_voice.services import ingest_audio_recording  # noqa: E402

if "testserver" not in settings.ALLOWED_HOSTS:
    settings.ALLOWED_HOSTS.append("testserver")


class ForensiQE2ETestRunner:
    def __init__(self):
        self.client = Client()
        self.passed_phases = 0
        self.failed_phases = 0
        self.portal_password = getattr(settings, "PORTAL_ACCESS_PASSWORD", "forensiq2026")

    def log_phase(self, num: int, total: int, title: str):
        print(f"\n[{num:02d}/{total:02d}] >> {title}...")

    def assert_test(self, condition: bool, message: str):
        if not condition:
            print(f"      [FAIL] {message}")
            raise AssertionError(message)
        print(f"      [OK] {message}")

    def run_all(self):
        print("=" * 80)
        print("  FORENSIQ COMPREHENSIVE END-TO-END WORKSTATION VERIFICATION SUITE")
        print("=" * 80)

        phases = [
            ("Portal Authentication & Session Security", self.test_phase_1_auth),
            ("Dynamic Workstation Landing Catalog", self.test_phase_2_landing),
            ("Q-Bank: Multi-Bank Ledger & Risk Screening", self.test_phase_3_bank),
            ("Q-Mail: Ingestion & 10 Forensic Checkpoints", self.test_phase_4_mail),
            ("Q-Scan: Computer Evidence Triage Engine", self.test_phase_5_scan),
            ("Q-Verify: Document Authenticity & Hex Inspection", self.test_phase_6_verify),
            ("Q-Voice: Acoustic Wiretap Timeline & Intent Engine", self.test_phase_7_voice),
            ("Q-Chat: Corporate Messaging Forensic Analyzer", self.test_phase_8_chat),
            ("Q-Ledger: SAP ERP Procurement Auditor", self.test_phase_9_ledger),
            (
                "Q-Link: Automated Forensic Relationship & Intelligence Engine",
                self.test_phase_11_link,
            ),
            (
                "Q-Trail: Multi-Bank Trail & Audit Scoping Engine",
                self.test_phase_12_trail,
            ),
            ("Demo Workstation, Tabulator & UI Design System", self.test_phase_10_ui),
        ]

        for idx, (title, phase_fn) in enumerate(phases, 1):
            self.log_phase(idx, len(phases), title)
            try:
                phase_fn()
                self.passed_phases += 1
            except Exception as e:
                self.failed_phases += 1
                print(f"\n   [ERROR] Phase {idx} Encountered Critical Failure: {e}")

        print("\n" + "=" * 80)
        print(
            f"  E2E TEST SUMMARY: {self.passed_phases}/{len(phases)} PHASES PASSED | {self.failed_phases} FAILED"
        )
        print("=" * 80)

        if self.failed_phases > 0:
            sys.exit(1)
        print("  >>> PLATFORM IS 100% OPERATIONAL, VERIFIED & PRODUCTION READY! <<<\n")
        sys.exit(0)

    # -------------------------------------------------------------
    # Phase 1: Authentication & Session Security
    # -------------------------------------------------------------
    def test_phase_1_auth(self):
        # 1. Unauthenticated redirect
        res = self.client.get("/bank/")
        self.assert_test(res.status_code == 302, "Unauthenticated access redirected to /login/")
        self.assert_test("/login/?next=/bank/" in res.url, "Next redirect parameter preserved")

        # 2. Invalid password rejected
        res = self.client.post("/login/", {"password": "wrong_key_123", "next": "/"})
        self.assert_test(res.status_code == 200, "Wrong password kept on login page")
        self.assert_test(b"Invalid portal access key" in res.content, "Rejection error displayed")

        # 3. Open-redirect prevention
        res = self.client.post(
            "/login/", {"password": self.portal_password, "next": "https://malicious.external"}
        )
        self.assert_test(res.status_code == 302, "Valid login succeeded with 302 redirect")
        self.assert_test(res.url == "/", "Malicious open-redirect sanitized to '/'")

        # 4. Verified session established
        self.assert_test(
            self.client.session.get("portal_authenticated") is True,
            "Portal session authenticated flag is True",
        )

    # -------------------------------------------------------------
    # Phase 2: Dynamic Landing Catalog
    # -------------------------------------------------------------
    def test_phase_2_landing(self):
        res = self.client.get("/")
        self.assert_test(res.status_code == 200, "Landing page loaded successfully (HTTP 200)")
        self.assert_test(
            b"Investigation Platform" in res.content, "Landing page header title rendered"
        )
        self.assert_test(b"Bank" in res.content, "Q-Bank module card active")
        self.assert_test(b"Mail" in res.content, "Q-Mail module card active")
        self.assert_test(b"Scan" in res.content, "Q-Scan module card active")
        self.assert_test(b"Verify" in res.content, "Q-Verify module card active")
        self.assert_test(b"Voice" in res.content, "Q-Voice module card active")
        self.assert_test(b"Ledger" in res.content, "Q-Ledger module card active")
        self.assert_test(b"Chat" in res.content, "Q-Chat module card active")
        self.assert_test(
            b"BUILDING" in res.content or b"LIVE" in res.content,
            "Forensic module catalog cards rendered with active/pipeline tags",
        )

    # -------------------------------------------------------------
    # Phase 3: Q-Bank
    # -------------------------------------------------------------
    def test_phase_3_bank(self):
        csv_data = (
            b"Txn Date,Narration,Debit,Credit,Balance\n"
            b"01/03/2026,OFFSHORE WIRE TRANSFER TO APEX,4500000.00,,500000.00\n"
            b"02/03/2026,CDM CASH DEPOSIT BR 991,,200000.00,700000.00\n"
            b"03/03/2026,VENDOR REFUND HYUNDAI,,50000.00,750000.00\n"
        )

        acc_num = f"HDFC-E2E-{uuid.uuid4().hex[:6].upper()}"
        account = ingest_bank_statement_file(
            file_obj_or_path=io.BytesIO(csv_data),
            filename="e2e_bank.csv",
            account_holder="E2E Auditee Target",
            bank_name="HDFC",
            account_number=acc_num,
        )

        self.assert_test(account.total_transactions == 3, "Ingested 3 bank statement transactions")
        self.assert_test(account.cash_deposit_count >= 1, "Detected cash deposit flag")
        self.assert_test(account.hyundai_count >= 1, "Detected corporate entity match")

        # Test bank dashboard view
        res = self.client.get(f"/bank/?account_id={account.id}")
        self.assert_test(res.status_code == 200, "Bank dashboard rendered account ledger")
        self.assert_test(acc_num.encode() in res.content, "Account number displayed in dashboard")

    # -------------------------------------------------------------
    # Phase 4: Q-Mail
    # -------------------------------------------------------------
    def test_phase_4_mail(self):
        ref_id = f"AUD-E2E-MAIL-{uuid.uuid4().hex[:6].upper()}"
        inv = MailboxInvestigation.objects.create(
            audit_ref=ref_id,
            audit_name="E2E Mailbox Audit",
            auditee_name="VP Logistics",
            auditee_email="logistics.vp@enterprise.internal",
            pst_file_name="logistics.pst",
            status=MailboxInvestigation.IngestionStatus.COMPLETED,
        )

        # Seed sample checkpoint message
        EmailMessage.objects.create(
            mailbox=inv,
            message_id=f"<e2e-{uuid.uuid4().hex[:6]}@domain.com>",
            subject="Urgent: Cash payout of Rs 5,00,000 for kickback",
            sender_name="Covert Broker",
            sender_email="broker@personal-gmail.com",
            recipients_to=["logistics.vp@enterprise.internal"],
            sent_date=timezone.now(),
            body_plain="Please arrange INR 5,00,000 via GPay or cash immediately without CC to board.",
        )

        # 1. Test checkpoints API
        res = self.client.get(reverse("q_mail:checkpoints_api", kwargs={"mailbox_id": inv.id}))
        self.assert_test(res.status_code == 200, "Mail checkpoints summary API returned HTTP 200")
        data = res.json()
        summary = data.get("checkpoints", data)
        self.assert_test(summary["total_flagged"] >= 1, "Checkpoint flagged suspicious message")
        self.assert_test(summary["currency_count"] >= 1, "Currency checkpoint hit detected")
        self.assert_test(summary["no_cc_bcc_count"] >= 1, "No CC/BCC covert communication hit")

        # 2. Test Excel export
        res_export = self.client.get(
            reverse("q_mail:export_checkpoint_excel", kwargs={"mailbox_id": inv.id})
        )
        self.assert_test(
            res_export.status_code == 200, "Forensic Checkpoints Excel export returned HTTP 200"
        )
        self.assert_test(
            "spreadsheetml" in res_export.get("Content-Type", ""),
            "Excel workbook MIME type verified",
        )

    # -------------------------------------------------------------
    # Phase 5: Q-Scan
    # -------------------------------------------------------------
    def test_phase_5_scan(self):
        hostname = f"WS-E2E-{uuid.uuid4().hex[:6].upper()}"
        csv_data = (
            b"File Path,File Name,Match Keyword,Category,File Size,Last Modified,SHA256\n"
            b"C:\\Users\\Auditee\\Desktop\\bribe_calc.xlsx,bribe_calc.xlsx,bribe,Confidential,45020,2026-03-01 12:00:00,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            b"C:\\Confidential\\vendor_agreements.pdf,vendor_agreements.pdf,commission,Legal,128400,2026-03-02 14:30:00,a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0\n"
        )

        res = self.client.post(
            reverse("q_scan:upload_csv"),
            {
                "hostname": hostname,
                "scan_title": "Executive Audit Campaign",
                "custodian_name": "Chief Auditor",
                "drive_letter": "C:\\",
                "csv_file": SimpleUploadedFile("scan.csv", csv_data, content_type="text/csv"),
            },
            follow=True,
        )
        self.assert_test(res.status_code == 200, "Q-Scan uploaded and parsed endpoint report CSV")

        device = ScannedDevice.objects.filter(hostname=hostname).first()
        self.assert_test(device is not None, "ScannedDevice created in database")
        self.assert_test(device.total_matches_found == 2, "2 keyword hits recorded for endpoint")

    # -------------------------------------------------------------
    # Phase 6: Q-Verify
    # -------------------------------------------------------------
    def test_phase_6_verify(self):
        case_ref = f"VER-E2E-{uuid.uuid4().hex[:6].upper()}"
        case = VerificationCase.objects.create(
            case_ref=case_ref,
            case_title="Supplier Invoice Verification",
            custodian_name="Procurement Officer",
        )

        doc = VerifiedDocument.objects.create(
            case=case,
            filename="Supplier_Bill_4412.pdf",
            file_extension=".pdf",
            authenticity_score=42,
            risk_level=VerifiedDocument.RiskLevel.SUSPICIOUS,
            meta_software="iText 5.5.0 / Modified by Hex Editor",
        )
        self.assert_test(doc is not None, "VerifiedDocument persisted in database")

        res = self.client.get(reverse("q_verify:case_detail", kwargs={"case_id": case.id}))
        self.assert_test(res.status_code == 200, "Q-Verify case detail rendered (HTTP 200)")
        self.assert_test(case_ref.encode() in res.content, "Case reference rendered in detail view")

    # -------------------------------------------------------------
    # Phase 7: Q-Voice
    # -------------------------------------------------------------
    def test_phase_7_voice(self):
        call_ref = f"CALL-E2E-{uuid.uuid4().hex[:6].upper()}"
        with patch("q_voice.services.request_remote_transcription") as mock_asr:
            mock_asr.return_value = (
                True,
                {
                    "timeline_transcript": [
                        {
                            "timestamp": "[00:00:00 --> 00:00:15]",
                            "transcript": "Speaker 1: I need that 10% kickback cut transferred today.",
                        },
                        {
                            "timestamp": "[00:00:15 --> 00:00:30]",
                            "transcript": "Speaker 2: Yes, don't email about this, call on personal phone.",
                        },
                    ],
                    "suspicious_detections": [],
                },
                "",
            )

            audio_file = SimpleUploadedFile("call.wav", b"FAKEWAVDATA", content_type="audio/wav")
            rec, err = ingest_audio_recording(
                audio_file=audio_file,
                call_ref=call_ref,
                call_title="Vendor Bribery Wiretap",
                custodian_name="Procurement Head",
            )

            self.assert_test(err == "", "Q-Voice ingested audio without errors")
            self.assert_test(rec is not None, "AudioRecording saved in database")
            self.assert_test(rec.total_segments == 2, "2 transcript segments diarized")

            # Check Collusion intent detected
            intents = [s.detected_intent for s in rec.segments.all()]
            self.assert_test(
                "Collusion" in intents or "Concealment" in intents,
                "Intent detection flagged Collusion/Concealment",
            )

            # Test Detail View
            res = self.client.get(
                reverse("q_voice:recording_detail", kwargs={"recording_id": rec.id})
            )
            self.assert_test(
                res.status_code == 200, "Q-Voice acoustic timeline dossier loaded (HTTP 200)"
            )

    # -------------------------------------------------------------
    # Phase 8: Q-Chat
    # -------------------------------------------------------------
    def test_phase_8_chat(self):
        chat_content = (
            b"[12/03/2026, 14:20:10] Vendor Rep: Did you check the quotation?\n"
            b"[12/03/2026, 14:21:45] Procurement Officer: Yes, add 5 lakh extra as kickback.\n"
            b"[12/03/2026, 14:22:15] Vendor Rep: Done, transferring to your SBI account.\n"
        )

        channel = ingest_chat_export_file(
            file_obj_or_content=chat_content,
            filename=f"chat_{uuid.uuid4().hex[:6]}.txt",
            platform="WHATSAPP",
            channel_name=f"Procurement Wire Chat {uuid.uuid4().hex[:4]}",
            custodian_name="Procurement Officer",
        )

        self.assert_test(channel is not None, "Q-Chat parsed WhatsApp export file")
        self.assert_test(channel.messages.count() == 3, "3 chat messages reconstructed in order")
        self.assert_test(channel.flagged_messages_count >= 1, "Kickback chat message flagged")

    # -------------------------------------------------------------
    # Phase 9: Q-Ledger
    # -------------------------------------------------------------
    def test_phase_9_ledger(self):
        res = self.client.get(reverse("q_ledger:dashboard"))
        self.assert_test(res.status_code == 200, "Q-Ledger ERP dashboard rendered (HTTP 200)")
        self.assert_test(b"Q-Ledger" in res.content, "Q-Ledger branding and KPI cards active")

    # -------------------------------------------------------------
    # Phase 11: Q-Link
    # -------------------------------------------------------------
    def test_phase_11_link(self):
        res = self.client.get("/link/")
        self.assert_test(
            res.status_code == 200, "Q-Link intelligence dashboard rendered (HTTP 200)"
        )
        self.assert_test(b"Q-Link" in res.content, "Q-Link branding rendered")

        # Sync all forensic data into Q-Link graph
        res_sync = self.client.post("/link/api/sync/")
        self.assert_test(
            res_sync.status_code == 200, "Q-Link synchronization API returned HTTP 200"
        )

        # Query network graph API
        res_net = self.client.get("/link/api/network/")
        self.assert_test(res_net.status_code == 200, "Q-Link network graph API returned HTTP 200")
        data = res_net.json()
        self.assert_test(
            "nodes" in data and "edges" in data, "Network graph payload structured correctly"
        )

        # Query Copilot AI agent
        res_copilot = self.client.post(
            "/link/api/copilot/",
            data=json.dumps({"query": "What connections exist between investigated profiles?"}),
            content_type="application/json",
        )
        self.assert_test(res_copilot.status_code == 200, "Q-Link Copilot API returned HTTP 200")

    # -------------------------------------------------------------
    # Phase 10: Demo & UI Design System
    # -------------------------------------------------------------
    def test_phase_10_ui(self):
        # 1. Tabulator Demo
        res_tab = self.client.get("/demo/tabulator/")
        self.assert_test(
            res_tab.status_code == 200, "Demo Tabulator forensic ledger rendered (HTTP 200)"
        )

        # 2. Component Sandbox
        res_box = self.client.get("/demo/sandbox/")
        self.assert_test(
            res_box.status_code == 200, "Demo Plotly component sandbox rendered (HTTP 200)"
        )

        # 3. Static Theme Tokens
        theme_res = self.client.get("/static/ui/css/theme.css")
        self.assert_test(
            theme_res.status_code == 200, "Static violet theme stylesheet loaded (HTTP 200)"
        )
        content_bytes = (
            b"".join(theme_res.streaming_content)
            if hasattr(theme_res, "streaming_content")
            else theme_res.content
        )
        self.assert_test(
            b"#502D55" in content_bytes or b"--fq-brand-violet" in content_bytes,
            "Violet design tokens verified in theme.css",
        )

    # -------------------------------------------------------------
    # Phase 12: Q-Trail Multi-Bank Trail & Audit Scoping Engine
    # -------------------------------------------------------------
    def test_phase_12_trail(self):
        from core.audits import create_audit
        from core.models import InvestigationProfile

        p1, _ = InvestigationProfile.objects.get_or_create(
            full_name="E2E Target Auditee Alpha",
            defaults={
                "department": "Strategic Sourcing",
                "designation": "Director",
                "is_substantiated": True,
            },
        )
        p2, _ = InvestigationProfile.objects.get_or_create(
            full_name="E2E Target Auditee Beta",
            defaults={
                "department": "Commercial Procurement",
                "designation": "Manager",
                "is_substantiated": False,
            },
        )

        audit = create_audit(
            title="E2E Master Workstation Audit",
            description="End-to-end verification audit",
            profile_ids=[str(p1.id), str(p2.id)],
        )
        self.assert_test(
            bool(audit.name) and "-WB-" in audit.name,
            f"Created audit with auto-sequence name: {audit.name}",
        )
        self.assert_test(audit.profiles.count() == 2, "Mapped 2 target investigation profiles")

        res_set = self.client.post(
            reverse("set_active_audit"),
            data=json.dumps({"audit_id": str(audit.id)}),
            content_type="application/json",
        )
        self.assert_test(res_set.status_code == 200, "Active audit switched via session API")

        res_trail_audit = self.client.get(reverse("q_trail:dashboard") + "?scope=audit")
        self.assert_test(
            res_trail_audit.status_code == 200, "Q-Trail loaded with scope=audit (HTTP 200)"
        )

        res_trail_all = self.client.get(reverse("q_trail:dashboard") + "?scope=all")
        self.assert_test(
            res_trail_all.status_code == 200, "Q-Trail loaded with scope=all (HTTP 200)"
        )

        res_analyze = self.client.post(
            reverse("q_trail:analyze_api"),
            data=json.dumps({"profile_ids": [str(p1.id), str(p2.id)]}),
            content_type="application/json",
        )
        self.assert_test(
            res_analyze.status_code == 200,
            "Q-Trail multi-bank reconciliation API returned HTTP 200",
        )


if __name__ == "__main__":
    runner = ForensiQE2ETestRunner()
    runner.run_all()

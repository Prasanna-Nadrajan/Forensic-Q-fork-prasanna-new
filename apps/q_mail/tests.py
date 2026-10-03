import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from .models import EmailAttachment, MailboxInvestigation


class QMailUploadAndIngestionTests(TestCase):
    def setUp(self):
        self.client = Client()
        # Set portal session auth so middleware permits access
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

    @patch("q_mail.views.start_mailbox_processing")
    def test_initiate_upload_and_chunked_streaming(self, mock_start_processing):
        # 1. Test initiating upload
        init_url = reverse("q_mail:upload_initiate")
        payload = {
            "audit_ref": "AUD-TEST-2026-001",
            "audit_name": "Test Forensic Audit",
            "auditee_name": "John Doe",
            "auditee_email": "john.doe@enterprise.internal",
            "auditee_department": "Finance",
            "auditee_designation": "Director",
            "pst_file_name": "sample_evidence.pst",
            "file_size_bytes": 3000,
        }
        res = self.client.post(
            init_url,
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        mailbox_id = data["mailbox_id"]

        # Verify DB object
        inv = MailboxInvestigation.objects.get(id=mailbox_id)
        self.assertEqual(inv.audit_ref, "AUD-TEST-2026-001")
        self.assertEqual(inv.auditee_name, "John Doe")

        # 2. Test uploading file in 3 binary chunks
        chunk_url = reverse("q_mail:upload_chunk")
        full_content = b"PST_HEADER_DUMMY_BINARY_DATA_" * 100
        expected_sha256 = hashlib.sha256(full_content).hexdigest()

        chunk_size = len(full_content) // 3
        chunks = [
            full_content[:chunk_size],
            full_content[chunk_size : chunk_size * 2],
            full_content[chunk_size * 2 :],
        ]

        for idx, chunk_bytes in enumerate(chunks):
            chunk_file = SimpleUploadedFile(
                f"chunk_{idx}.bin", chunk_bytes, content_type="application/octet-stream"
            )
            chunk_res = self.client.post(
                chunk_url,
                data={
                    "mailbox_id": mailbox_id,
                    "chunk_index": idx,
                    "total_chunks": len(chunks),
                    "chunk": chunk_file,
                },
            )
            self.assertEqual(chunk_res.status_code, 200)
            chunk_data = chunk_res.json()
            self.assertTrue(chunk_data["success"])

            if idx == len(chunks) - 1:
                self.assertTrue(chunk_data["is_completed"])
                self.assertEqual(chunk_data["file_sha256"], expected_sha256)

        # 3. Verify file on disk
        inv.refresh_from_db()
        expected_path = Path(settings.MEDIA_ROOT) / "uploads" / "pst" / f"{mailbox_id}.pst"
        self.assertTrue(expected_path.exists())
        self.assertEqual(inv.file_sha256, expected_sha256)
        self.assertEqual(inv.file_size_bytes, len(full_content))

        # 4. Test progress API
        progress_url = reverse("q_mail:progress_api", kwargs={"mailbox_id": mailbox_id})
        prog_res = self.client.get(progress_url)
        self.assertEqual(prog_res.status_code, 200)
        self.assertEqual(prog_res.json()["audit_ref"], "AUD-TEST-2026-001")

        # 5. Test paginated messages API
        messages_url = reverse("q_mail:messages_api", kwargs={"mailbox_id": mailbox_id})
        msg_res = self.client.get(messages_url)
        self.assertEqual(msg_res.status_code, 200)
        self.assertIn("data", msg_res.json())
        self.assertIn("last_page", msg_res.json())

        # Cleanup test upload file
        if expected_path.exists():
            expected_path.unlink()

    def test_cancellation_flow(self):
        inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-CANCEL-001",
            audit_name="Cancellation Test",
            auditee_name="Jane Doe",
            auditee_email="jane.doe@enterprise.internal",
            status=MailboxInvestigation.IngestionStatus.PROCESSING,
        )

        cancel_url = reverse("q_mail:cancel_process", kwargs={"mailbox_id": inv.id})
        res = self.client.post(cancel_url)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["success"])

        inv.refresh_from_db()
        self.assertTrue(inv.is_cancellation_requested)

        # Check progress API returns cancellation flag
        prog_url = reverse("q_mail:progress_api", kwargs={"mailbox_id": inv.id})
        prog_res = self.client.get(prog_url)
        self.assertEqual(prog_res.status_code, 200)
        self.assertTrue(prog_res.json()["is_cancellation_requested"])

    def test_stalled_investigation_recovery(self):
        from datetime import UTC, datetime, timedelta

        from .services import recover_stalled_investigations

        # 1. Stalled investigation (heartbeat 10 minutes ago)
        stalled_inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-STALL-001",
            audit_name="Stall Test",
            auditee_name="Stalled User",
            auditee_email="stalled@enterprise.internal",
            status=MailboxInvestigation.IngestionStatus.PROCESSING,
            last_heartbeat_at=datetime.now(UTC) - timedelta(minutes=10),
        )

        # 2. Healthy active investigation (heartbeat 5 seconds ago)
        active_inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-ACTIVE-002",
            audit_name="Active Test",
            auditee_name="Active User",
            auditee_email="active@enterprise.internal",
            status=MailboxInvestigation.IngestionStatus.PROCESSING,
            last_heartbeat_at=datetime.now(UTC) - timedelta(seconds=5),
        )

        # Run recovery
        recovered_count = recover_stalled_investigations(stale_seconds=180)
        self.assertEqual(recovered_count, 1)

        stalled_inv.refresh_from_db()
        active_inv.refresh_from_db()

        self.assertEqual(stalled_inv.status, MailboxInvestigation.IngestionStatus.STALLED)
        self.assertIn("interrupted", stalled_inv.error_message)
        self.assertEqual(active_inv.status, MailboxInvestigation.IngestionStatus.PROCESSING)

    @patch("q_mail.services.threading.Thread")
    def test_restart_resumes_stalled_investigation(self, mock_thread):
        inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-RESUME-001",
            audit_name="Resume Test",
            auditee_name="Resume User",
            auditee_email="resume@enterprise.internal",
            status=MailboxInvestigation.IngestionStatus.STALLED,
            error_message="Previous crash",
            is_cancellation_requested=True,
        )

        # Trigger restart
        process_url = reverse("q_mail:trigger_process", kwargs={"mailbox_id": inv.id})
        res = self.client.post(process_url)
        self.assertEqual(res.status_code, 200)
        mock_thread.assert_called_once()

        inv.refresh_from_db()
        self.assertEqual(inv.status, MailboxInvestigation.IngestionStatus.PROCESSING)
        self.assertFalse(inv.is_cancellation_requested)
        self.assertEqual(inv.error_message, "")


class QMailCheckpointsAndSelectorsTests(TestCase):
    def setUp(self):
        from .backend.checkpoints import (
            check_currency,
            check_no_cc_bcc,
            check_non_hmil,
            check_personal_sender,
            check_primary_bank,
            check_upi_payment,
            evaluate_email_checkpoints,
            match_default_keywords,
        )

        self.check_currency = check_currency
        self.check_no_cc_bcc = check_no_cc_bcc
        self.check_non_hmil = check_non_hmil
        self.check_personal_sender = check_personal_sender
        self.check_primary_bank = check_primary_bank
        self.check_upi_payment = check_upi_payment
        self.evaluate_email_checkpoints = evaluate_email_checkpoints
        self.match_default_keywords = match_default_keywords

        self.inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-CHK-001",
            audit_name="Checkpoint Audit",
            auditee_name="Checkpoint User",
            auditee_email="chk@enterprise.internal",
            status=MailboxInvestigation.IngestionStatus.COMPLETED,
        )

    def test_checkpoint_rules(self):
        self.assertTrue(self.check_currency("Please wire ₹ 5,00,000 for invoice payment"))
        self.assertTrue(self.check_currency("Total sum of 45 Lakhs INR"))
        self.assertFalse(self.check_currency("Standard meeting scheduled at 3pm"))

        self.assertTrue(self.check_no_cc_bcc([], []))
        self.assertFalse(self.check_no_cc_bcc(["boss@corp.com"], []))

        self.assertTrue(self.check_personal_sender("vendor@gmail.com"))
        self.assertFalse(self.check_personal_sender("employee@hyundai.com"))

        self.assertTrue(self.check_non_hmil("vendor@external.com", ["user@external.com"]))
        self.assertFalse(self.check_non_hmil("user@hmil.net", ["boss@hmil.net"]))

        self.assertTrue(self.check_primary_bank("alerts@hdfcbank.net", "Account credited", ""))
        self.assertTrue(self.check_upi_payment("pay@phonepe.com", "UPI payment received", ""))

        kws = self.match_default_keywords("Here is the TAX invoice and SALARY bonus document")
        self.assertIn("TAX", kws)
        self.assertIn("SALARY", kws)

    def test_mailbox_selectors_and_pagination(self):
        from .models import EmailMessage
        from .selectors import (
            get_mailbox_investigation,
            get_mailbox_progress_state,
            get_paginated_investigation_emails,
            list_mailbox_investigations,
        )

        email = EmailMessage.objects.create(
            mailbox=self.inv,
            subject="Confidential settlement of ₹ 10 Lakhs",
            sender_name="Secret Vendor",
            sender_email="secret@gmail.com",
            recipients_to=["chk@enterprise.internal"],
            recipients_cc=[],
            recipients_bcc=[],
            body_plain="Please find attached payment receipt for the wire transfer",
            risk_score=85,
        )

        eval_res = self.evaluate_email_checkpoints(email)
        self.assertTrue(eval_res["is_currency"])
        self.assertTrue(eval_res["is_no_cc_bcc"])
        self.assertTrue(eval_res["is_personal_sender"])

        # Check selectors
        inv_list = list_mailbox_investigations()
        self.assertGreaterEqual(inv_list.count(), 1)

        fetched = get_mailbox_investigation(self.inv.id)
        self.assertEqual(fetched.id, self.inv.id)

        prog = get_mailbox_progress_state(self.inv.id)
        self.assertEqual(prog["status"], MailboxInvestigation.IngestionStatus.COMPLETED)

        # Paginated emails across checkpoints
        for cp in (
            "currency",
            "without_cc_bcc",
            "personal",
            "external",
            "bank",
            "upi",
            "keywords",
            "all",
        ):
            page_res = get_paginated_investigation_emails(
                self.inv.id, page=1, page_size=10, checkpoint=cp
            )
            self.assertIn("data", page_res)

        from .selectors import get_global_mailbox_stats

        landing_metrics = get_global_mailbox_stats()
        self.assertGreaterEqual(landing_metrics["total_mailboxes"], 1)

        # Excel export view
        client = Client()
        session = client.session
        session["portal_authenticated"] = True
        session.save()
        export_resp = client.get(
            reverse("q_mail:export_checkpoint_excel", kwargs={"mailbox_id": self.inv.id})
        )
        self.assertEqual(export_resp.status_code, 200)

    @patch("pypff.file")
    def test_pst_stream_parser_complete(self, mock_pypff_file):
        from datetime import UTC, datetime
        from pathlib import Path
        from unittest.mock import MagicMock

        from .backend.pst_parser import PSTStreamParser

        # Setup mock PST structure
        mock_instance = mock_pypff_file.return_value
        root_folder = MagicMock()
        root_folder.get_name.return_value = "Top of Personal Folders"
        root_folder.get_number_of_sub_messages.return_value = 1
        root_folder.get_number_of_sub_folders.return_value = 1

        # Mock Message
        mock_msg = MagicMock()
        mock_msg.get_subject.return_value = "Wire Payment of INR 500000"
        mock_msg.get_sender_name.return_value = "Auditee Manager"
        mock_msg.get_sender_email_address.return_value = "manager@enterprise.internal"
        mock_msg.get_conversation_topic.return_value = "Settlement"
        mock_msg.get_client_submit_time.return_value = datetime.now(UTC)
        mock_msg.get_delivery_time.return_value = datetime.now(UTC)
        mock_msg.get_plain_text_body.return_value = b"Please approve the transfer"
        mock_msg.get_html_body.return_value = b"<p>Please approve the transfer</p>"
        mock_msg.get_importance.return_value = 2
        mock_msg.get_number_of_recipients.return_value = 3

        r1 = MagicMock()
        r1.get_name.return_value = "Target Auditor"
        r1.get_email_address.return_value = "auditor@enterprise.internal"
        r1.type = 1

        r2 = MagicMock()
        r2.get_name.return_value = "CC Contact"
        r2.get_email_address.return_value = "cc@enterprise.internal"
        r2.type = 2

        r3 = MagicMock()
        r3.get_name.return_value = "BCC Contact"
        r3.get_email_address.return_value = "bcc@enterprise.internal"
        r3.type = 3

        mock_msg.get_recipient.side_effect = [r1, r2, r3]

        # Attachment
        mock_msg.get_number_of_attachments.return_value = 1
        att = MagicMock()
        att.get_long_filename.return_value = "statement.pdf"
        att.get_size.return_value = 24
        att.read_buffer.side_effect = [b"ATTACHMENT_BINARY_PAYLOAD", None]
        mock_msg.get_attachment.return_value = att

        root_folder.get_sub_message.return_value = mock_msg

        # Subfolder
        sub_folder = MagicMock()
        sub_folder.get_name.return_value = "Inbox"
        sub_folder.get_number_of_sub_messages.return_value = 0
        sub_folder.get_number_of_sub_folders.return_value = 0
        root_folder.get_sub_folder.return_value = sub_folder

        mock_instance.get_root_folder.return_value = root_folder

        with tempfile.TemporaryDirectory() as tmp_dir:
            pst_file = Path(tmp_dir) / "evidence.pst"
            pst_file.write_bytes(b"DUMMY_PST_BYTES")
            att_dir = Path(tmp_dir) / "attachments"

            progress_calls = []

            def on_progress(folder, processed, total):
                progress_calls.append((folder, processed, total))

            parser = PSTStreamParser(
                pst_file,
                attachments_dir=att_dir,
                progress_callback=on_progress,
                check_cancellation_callback=lambda: False,
            )
            messages = list(parser.parse_messages())
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].subject, "Wire Payment of INR 500000")
            self.assertEqual(len(messages[0].attachments), 1)
            self.assertEqual(messages[0].attachments[0].filename, "statement.pdf")

    @patch("apps.q_mail.backend.pst_parser.pypff")
    def test_pst_parser_embedded_msg(self, mock_pypff):
        import tempfile
        from pathlib import Path
        from unittest.mock import MagicMock

        from apps.q_mail.backend.pst_parser import PSTStreamParser

        mock_instance = MagicMock()
        mock_pypff.file.return_value = mock_instance
        root_folder = MagicMock()
        root_folder.get_number_of_sub_folders.return_value = 0
        root_folder.get_number_of_sub_messages.return_value = 1

        mock_msg = MagicMock()
        mock_msg.get_number_of_attachments.return_value = 1

        att = MagicMock()
        att.get_long_filename.return_value = None
        att.get_number_of_record_sets.return_value = 2
        att.get_size.return_value = 24
        att.read_buffer.side_effect = [b"MAPI_DATA", None]

        rs1 = MagicMock()
        rs1.get_number_of_entries.return_value = 1
        entry1 = MagicMock()
        entry1.entry_type = 0x3001
        entry1.get_data.return_value = "Embedded Test".encode("utf-16le")
        rs1.get_entry.return_value = entry1

        rs2 = MagicMock()
        rs2.get_number_of_entries.return_value = 1
        entry2 = MagicMock()
        entry2.entry_type = 0x3705
        entry2.get_data.return_value = (5).to_bytes(4, "little")
        rs2.get_entry.return_value = entry2

        att.get_record_set.side_effect = [rs1, rs2]
        mock_msg.get_attachment.return_value = att

        root_folder.get_sub_message.return_value = mock_msg
        mock_instance.get_root_folder.return_value = root_folder

        with tempfile.TemporaryDirectory() as tmp_dir:
            pst_file = Path(tmp_dir) / "evidence.pst"
            pst_file.write_bytes(b"DUMMY")
            parser = PSTStreamParser(
                pst_file, attachments_dir=Path(tmp_dir), check_cancellation_callback=lambda: False
            )
            messages = list(parser.parse_messages())
            self.assertEqual(len(messages), 1)
            self.assertEqual(len(messages[0].attachments), 1)
            self.assertEqual(messages[0].attachments[0].filename, "Embedded Test.msg")

    @patch("apps.q_mail.backend.pst_parser.pypff")
    def test_pst_parser_embedded_msg_exception(self, mock_pypff):
        import tempfile
        from pathlib import Path
        from unittest.mock import MagicMock

        from apps.q_mail.backend.pst_parser import PSTStreamParser

        mock_instance = MagicMock()
        mock_pypff.file.return_value = mock_instance
        root_folder = MagicMock()
        root_folder.get_number_of_sub_folders.return_value = 0
        root_folder.get_number_of_sub_messages.return_value = 1

        mock_msg = MagicMock()
        mock_msg.get_number_of_attachments.return_value = 1

        att = MagicMock()
        att.get_long_filename.return_value = None
        att.get_number_of_record_sets.side_effect = Exception("Mocked Exception")
        att.get_size.return_value = 24
        att.read_buffer.side_effect = [b"MAPI_DATA", None]

        mock_msg.get_attachment.return_value = att
        root_folder.get_sub_message.return_value = mock_msg
        mock_instance.get_root_folder.return_value = root_folder

        with tempfile.TemporaryDirectory() as tmp_dir:
            pst_file = Path(tmp_dir) / "evidence.pst"
            pst_file.write_bytes(b"DUMMY")
            parser = PSTStreamParser(
                pst_file, attachments_dir=Path(tmp_dir), check_cancellation_callback=lambda: False
            )
            messages = list(parser.parse_messages())
            self.assertEqual(len(messages), 1)
            self.assertEqual(len(messages[0].attachments), 1)
            self.assertTrue(messages[0].attachments[0].filename.startswith("attachment_"))

    def test_execute_pst_ingestion_and_selectors(self):
        from datetime import UTC, datetime
        from unittest.mock import MagicMock, patch

        from .backend.pst_parser import ParsedAttachment, ParsedEmail
        from .selectors import (
            get_email_detail,
            get_investigation_emails,
            get_investigation_summary_metrics,
            get_top_counterparties,
        )
        from .services import _execute_pst_ingestion

        tmp_pst = tempfile.NamedTemporaryFile(suffix=".pst", delete=False)
        tmp_pst.write(b"DUMMY_BINARY_PST_DATA")
        tmp_pst.close()

        inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-EXEC-001",
            audit_name="PST Execution Test",
            auditee_name="Execution Auditee",
            auditee_email="exec@enterprise.internal",
            pst_file_path=tmp_pst.name,
            status=MailboxInvestigation.IngestionStatus.PROCESSING,
        )

        mock_email = ParsedEmail(
            message_id="<test1@pst.audit>",
            subject="Tax and Payment Transfer of 15 Lakhs",
            sender_name="Vendor Lead",
            sender_email="vendor@gmail.com",
            recipients_to=["exec@enterprise.internal"],
            recipients_cc=[],
            recipients_bcc=[],
            sent_date=datetime.now(UTC),
            delivery_date=datetime.now(UTC),
            folder_path="Inbox",
            body_plain="Please find the cash payment attached",
            importance=2,
            attachments=[
                ParsedAttachment(
                    filename="contract.pdf",
                    file_size_bytes=1024,
                    mime_type="application/pdf",
                    file_extension=".pdf",
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    storage_path="",
                )
            ],
        )

        with patch("q_mail.services.PSTStreamParser") as mock_parser_cls:
            mock_parser_instance = MagicMock()
            mock_parser_instance.parse_messages.return_value = [mock_email]
            mock_parser_instance.total_messages_processed = 1
            mock_parser_instance.is_cancelled = False
            mock_parser_cls.return_value = mock_parser_instance

            _execute_pst_ingestion(str(inv.id))

        inv.refresh_from_db()
        self.assertEqual(inv.processed_messages_count, 1)
        self.assertEqual(inv.messages.count(), 1)

        # Test selectors with ingested message
        saved_msg = inv.messages.first()
        self.assertIsNotNone(saved_msg)

        detail = get_email_detail(saved_msg.id)
        self.assertEqual(detail.id, saved_msg.id)

        metrics = get_investigation_summary_metrics(inv.id)
        self.assertEqual(metrics["total_emails"], 1)

        counterparties = get_top_counterparties(inv.id)
        self.assertGreaterEqual(len(counterparties), 1)

        emails = get_investigation_emails(inv.id, sender="vendor@gmail.com")
        self.assertEqual(emails.count(), 1)

        # Authenticate client session
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        # Test investigation detail view
        res_detail = self.client.get(reverse("q_mail:detail", args=[inv.id]))
        self.assertEqual(res_detail.status_code, 200)

        # Test email detail API
        res_email = self.client.get(reverse("q_mail:email_detail", args=[saved_msg.id]))
        self.assertEqual(res_email.status_code, 200)
        self.assertEqual(res_email.json()["id"], str(saved_msg.id))

        # Test attachment download view
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(b"%PDF-1.4 attachment evidence")
            tmp_path = tmp.name

        attachment = EmailAttachment.objects.create(
            email=saved_msg,
            filename="evidence.pdf",
            storage_path=tmp_path,
        )
        dl_url = reverse("q_mail:download_attachment", args=[attachment.id])
        res_dl = self.client.get(dl_url)
        self.assertEqual(res_dl.status_code, 200)
        self.assertIn("attachment", res_dl["Content-Disposition"])
        res_dl.close()

        # Attachment download 404
        attachment.storage_path = "/non/existent/evidence.pdf"
        attachment.save()
        res_dl_404 = self.client.get(dl_url)
        self.assertEqual(res_dl_404.status_code, 404)

        Path(tmp_path).unlink(missing_ok=True)

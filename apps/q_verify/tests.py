"""
Q-Verify Automated Test Suite
Unit tests for PDF inspector, Office inspector, Discrepancy analyzer, and API endpoints.
"""

import io
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pypdf
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse
from PIL import Image

from .backend import (
    DiscrepancyAnalyzer,
    ImageInspector,
    OfficeInspector,
    ParsedMetadata,
    PDFInspector,
)
from .models import VerificationCase, VerifiedDocument
from .services import create_verification_case, ingest_and_verify_document


class QVerifyUnitTests(TestCase):
    def setUp(self):
        self.client = Client()
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

    def test_discrepancy_analyzer_tampered_timestamp(self):
        now = datetime.now(UTC)
        meta = ParsedMetadata(
            filename="tampered_contract.pdf",
            file_size_bytes=1024,
            mime_type="application/pdf",
            file_extension=".pdf",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            meta_created_at=now,
            meta_modified_at=now - timedelta(days=30),  # Modified before Created!
            meta_software="Canva Online Editor",
            incremental_updates_count=2,
        )

        result = DiscrepancyAnalyzer.analyze(meta)
        self.assertLess(result.authenticity_score, 50)
        self.assertEqual(result.risk_level, "HIGH_RISK_TAMPERED")
        self.assertTrue(result.has_timestamp_anomaly)
        self.assertTrue(result.has_software_anomaly)
        self.assertTrue(result.has_structural_anomaly)

    def test_office_inspector(self):
        # Create synthetic docProps/core.xml, app.xml, and custom.xml in zip stream
        core_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                           xmlns:dc="http://purl.org/dc/elements/1.1/"
                           xmlns:dcterms="http://purl.org/dc/terms/">
            <dc:creator>John Auditor</dc:creator>
            <cp:lastModifiedBy>Jane Reviewer</cp:lastModifiedBy>
            <dc:title>Audit Investigation Summary</dc:title>
            <dc:subject>Procurement Fraud Assessment</dc:subject>
            <cp:revision>5</cp:revision>
            <dcterms:created>2026-03-01T10:00:00Z</dcterms:created>
            <dcterms:modified>2026-03-05T14:30:00Z</dcterms:modified>
        </cp:coreProperties>"""

        app_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
            <Application>Microsoft Office Word</Application>
            <AppVersion>16.0000</AppVersion>
            <Company>Hyundai Corp</Company>
            <TotalTime>invalid_int_failsafe</TotalTime>
        </Properties>"""

        custom_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties">
            <property name="Classification">RESTRICTED</property>
        </Properties>"""

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("docProps/core.xml", core_xml)
            zf.writestr("docProps/app.xml", app_xml)
            zf.writestr("docProps/custom.xml", custom_xml)

        zip_bytes = buf.getvalue()
        meta = OfficeInspector.inspect(zip_bytes, "audit_memo.docx")

        self.assertEqual(meta.meta_author, "John Auditor")
        self.assertEqual(meta.meta_last_modified_by, "Jane Reviewer")
        self.assertEqual(meta.meta_title, "Audit Investigation Summary")
        self.assertEqual(meta.meta_subject, "Procurement Fraud Assessment")
        self.assertEqual(meta.meta_company, "Hyundai Corp")
        self.assertEqual(meta.editing_time_minutes, 0)
        self.assertEqual(meta.revision_number, "5")
        self.assertEqual(
            meta.raw_dict.get("custom_properties", {}).get("Classification"), "RESTRICTED"
        )

        # Corrupt archive parsing
        corrupt_meta = OfficeInspector.inspect(b"NOT_A_VALID_ZIP_STREAM", "corrupted.docx")
        self.assertIn("parser_error", corrupt_meta.raw_dict)

        # Invalid custom.xml exception handling
        buf_bad_custom = io.BytesIO()
        with zipfile.ZipFile(buf_bad_custom, "w") as zf:
            zf.writestr("docProps/custom.xml", b"<unclosed xml tag")
        bad_custom_meta = OfficeInspector.inspect(buf_bad_custom.getvalue(), "bad_custom.docx")
        self.assertNotIn("custom_properties", bad_custom_meta.raw_dict)

        # Static date parsing methods
        self.assertIsNone(OfficeInspector._parse_iso_date(""))
        self.assertIsNone(OfficeInspector._parse_iso_date("invalid_iso_date"))
        parsed_dt = OfficeInspector._parse_iso_date("2026-03-01T10:00:00")
        self.assertIsNotNone(parsed_dt)
        self.assertEqual(parsed_dt.tzinfo, UTC)

    def test_create_case_and_ingest_document_service(self):
        case = create_verification_case(
            case_ref="VER-TEST-2026-001",
            case_title="Supplier Invoice Authenticity Review",
            custodian_name="Amitabh Sen",
            custodian_department="Procurement",
        )
        self.assertEqual(case.status, VerificationCase.CaseStatus.PENDING)

        dummy_pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (Invoice #9901) >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n9\n%%EOF"

        doc = ingest_and_verify_document(
            file_bytes=dummy_pdf,
            filename="Invoice_9901.pdf",
            case=case,
            save_disk=False,
        )

        self.assertEqual(doc.case, case)
        self.assertEqual(doc.filename, "Invoice_9901.pdf")

        case.refresh_from_db()
        self.assertEqual(case.total_documents, 1)
        self.assertEqual(case.status, VerificationCase.CaseStatus.COMPLETED)

    def test_quick_scan_api(self):
        dummy_docx = b"PK\x03\x04" + b"\x00" * 30
        file = SimpleUploadedFile(
            "quick_contract.docx", dummy_docx, content_type="application/octet-stream"
        )

        url = reverse("q_verify:quick_scan")
        res = self.client.post(url, data={"files": file})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["document"]["filename"], "quick_contract.docx")

    def test_case_detail_and_tabulator_grid_api(self):
        case = VerificationCase.objects.create(
            case_ref="VER-GRID-001",
            case_title="Grid Test Case",
            custodian_name="Test Custodian",
        )
        VerifiedDocument.objects.create(
            case=case,
            filename="Doc_Alpha.pdf",
            authenticity_score=95,
            risk_level=VerifiedDocument.RiskLevel.AUTHENTIC,
        )
        VerifiedDocument.objects.create(
            case=case,
            filename="Doc_Beta.pdf",
            authenticity_score=35,
            risk_level=VerifiedDocument.RiskLevel.HIGH_RISK_TAMPERED,
        )

        # 1. Test case detail view
        detail_url = reverse("q_verify:case_detail", kwargs={"case_id": case.id})
        res = self.client.get(detail_url)
        self.assertEqual(res.status_code, 200)

        # 2. Test Tabulator Grid API
        grid_url = reverse("q_verify:documents_grid_api", kwargs={"case_id": case.id})
        grid_res = self.client.get(grid_url)
        self.assertEqual(grid_res.status_code, 200)
        grid_data = grid_res.json()
        self.assertEqual(grid_data["total_count"], 2)
        self.assertEqual(len(grid_data["data"]), 2)

        # 3. Test filter by search
        search_res = self.client.get(f"{grid_url}?search=Alpha")
        self.assertEqual(search_res.status_code, 200)
        self.assertEqual(search_res.json()["total_count"], 1)

    def test_pdf_inspector_valid_pdf(self):
        writer = pypdf.PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer.add_metadata(
            {
                "/Title": "Executive Agreement",
                "/Author": "Auditor General",
                "/Producer": "ReportLab PDF Engine",
                "/Creator": "Automated Billing System",
            }
        )
        pdf_buf = io.BytesIO()
        writer.write(pdf_buf)
        pdf_bytes = pdf_buf.getvalue()

        meta = PDFInspector.inspect(pdf_bytes, "agreement.pdf")
        self.assertEqual(meta.meta_title, "Executive Agreement")
        self.assertEqual(meta.meta_author, "Auditor General")
        self.assertEqual(meta.meta_producer, "ReportLab PDF Engine")
        self.assertEqual(meta.file_extension, ".pdf")
        self.assertFalse(meta.is_encrypted)

    def test_image_inspector_valid_image(self):
        img = Image.new("RGB", (150, 150), color=(255, 0, 0))
        img_buf = io.BytesIO()
        img.save(img_buf, format="PNG")
        png_bytes = img_buf.getvalue()

        meta = ImageInspector.inspect(png_bytes, "invoice_scan.png")
        self.assertEqual(meta.file_extension, ".png")
        self.assertEqual(meta.mime_type, "image/png")
        self.assertIn("dimensions", meta.raw_dict)
        self.assertEqual(meta.raw_dict["dimensions"]["width"], 150)

    def test_dashboard_and_case_views(self):
        # Dashboard view
        dash_res = self.client.get(reverse("q_verify:dashboard"))
        self.assertEqual(dash_res.status_code, 200)

        # Case create API
        create_res = self.client.post(
            reverse("q_verify:case_create"),
            data={
                "case_title": "Tender Document Audit",
                "custodian_name": "Procurement Officer",
                "custodian_department": "Supply Chain",
            },
        )
        self.assertEqual(create_res.status_code, 200)
        data = create_res.json()
        self.assertTrue(data["success"])
        case_id = data["case_id"]

        # Document detail API
        doc = VerifiedDocument.objects.create(
            case_id=case_id,
            filename="Test_Tender.pdf",
            authenticity_score=92,
            risk_level=VerifiedDocument.RiskLevel.AUTHENTIC,
            raw_metadata={"page_count": 5},
        )
        doc_res = self.client.get(reverse("q_verify:document_detail", kwargs={"doc_id": doc.id}))
        self.assertEqual(doc_res.status_code, 200)
        self.assertEqual(doc_res.json()["filename"], "Test_Tender.pdf")

    def test_pdf_date_parsing_and_normalization(self):
        # Standard PDF date format with positive timezone offset
        dt_pos = PDFInspector._parse_pdf_date("D:20260315143022+05'30'")
        self.assertIsNotNone(dt_pos)
        self.assertEqual(dt_pos.year, 2026)
        self.assertEqual(dt_pos.month, 3)
        self.assertEqual(dt_pos.day, 15)

        # Standard PDF date format with negative timezone offset
        dt_neg = PDFInspector._parse_pdf_date("D:20260315143022-04'00'")
        self.assertIsNotNone(dt_neg)

        # Without timezone offset
        dt_no_tz = PDFInspector._parse_pdf_date("D:20260315143022")
        self.assertIsNotNone(dt_no_tz)

        # ISO format
        dt_iso = PDFInspector._parse_pdf_date("2026-03-15T14:30:22Z")
        self.assertIsNotNone(dt_iso)

        # Edge cases: empty / invalid strings
        self.assertIsNone(PDFInspector._parse_pdf_date(""))
        self.assertIsNone(PDFInspector._parse_pdf_date("invalid_date_format"))

        # Normalization
        self.assertIsNone(PDFInspector._normalize_dt(None))
        naive = datetime(2026, 1, 1, 12, 0)
        norm = PDFInspector._normalize_dt(naive)
        self.assertEqual(norm.tzinfo, UTC)

    def test_image_inspector_exif_tags_and_corrupt_bytes(self):
        # Exif date parsing
        self.assertIsNone(ImageInspector._parse_exif_date(""))
        self.assertIsNone(ImageInspector._parse_exif_date("invalid"))
        parsed_dt = ImageInspector._parse_exif_date("2026:05:20 18:45:00")
        self.assertIsNotNone(parsed_dt)
        self.assertEqual(parsed_dt.year, 2026)
        self.assertEqual(parsed_dt.month, 5)

        # PIL image with EXIF metadata
        img = Image.new("RGB", (100, 100), color=(0, 255, 0))
        exif = img.getexif()
        # 271: Make, 272: Model, 305: Software, 306: DateTime
        exif[271] = "Canon"
        exif[272] = "EOS R5"
        exif[305] = "Photoshop Elements 2026"
        exif[306] = "2026:02:15 10:30:00"

        img_buf = io.BytesIO()
        img.save(img_buf, format="JPEG", exif=exif)
        jpeg_bytes = img_buf.getvalue()

        meta = ImageInspector.inspect(jpeg_bytes, "captured_receipt.jpg")
        self.assertEqual(meta.file_extension, ".jpg")
        self.assertEqual(meta.mime_type, "image/jpeg")
        self.assertIn("Photoshop", meta.meta_software)
        self.assertIn("Canon", meta.meta_creator)
        self.assertIsNotNone(meta.meta_modified_at)

        # Corrupt image bytes
        meta_corrupt = ImageInspector.inspect(b"this_is_not_an_image", "damaged.jpg")
        self.assertIn("parser_error", meta_corrupt.raw_dict)

    def test_upload_documents_api_view(self):
        case = VerificationCase.objects.create(
            case_ref="VER-UPLOAD-001",
            case_title="Batch Document Inspection Case",
            custodian_name="Dr. Banner",
        )
        url = reverse("q_verify:case_upload", kwargs={"case_id": case.id})

        # Test empty upload payload
        res_empty = self.client.post(url, data={})
        self.assertEqual(res_empty.status_code, 400)

        # Test valid multiple file upload
        f1 = SimpleUploadedFile("doc1.pdf", b"%PDF-1.4\n%%EOF", content_type="application/pdf")
        f2 = SimpleUploadedFile("doc2.pdf", b"%PDF-1.4\n%%EOF", content_type="application/pdf")
        res_valid = self.client.post(url, data={"files": [f1, f2]})
        self.assertEqual(res_valid.status_code, 200)
        data = res_valid.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["processed_count"], 2)

    def test_download_document_view(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(b"%PDF-1.4 physical test content\n%%EOF")
            tmp_path = tmp.name

        doc = VerifiedDocument.objects.create(
            filename="physical_contract.pdf",
            authenticity_score=90,
            risk_level=VerifiedDocument.RiskLevel.AUTHENTIC,
            storage_path=tmp_path,
        )

        dl_url = reverse("q_verify:document_download", kwargs={"doc_id": doc.id})
        res = self.client.get(dl_url)
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment", res["Content-Disposition"])
        res.close()

        # Test 404 when file does not exist on disk
        doc.storage_path = "/non/existent/path/document.pdf"
        doc.save()
        res_404 = self.client.get(dl_url)
        self.assertEqual(res_404.status_code, 404)

        # Clean up temp file
        Path(tmp_path).unlink(missing_ok=True)

    def test_discrepancy_analyzer_software_and_future_date(self):
        # Software anomaly
        meta_sw = ParsedMetadata(
            filename="edited_invoice.pdf",
            file_size_bytes=2048,
            mime_type="application/pdf",
            file_extension=".pdf",
            sha256_hash="abc",
            meta_software="Adobe Photoshop CC 2026",
        )
        res_sw = DiscrepancyAnalyzer.analyze(meta_sw)
        self.assertTrue(res_sw.has_software_anomaly)

        # Future creation date anomaly
        now = datetime.now(UTC)
        meta_future = ParsedMetadata(
            filename="future_invoice.pdf",
            file_size_bytes=2048,
            mime_type="application/pdf",
            file_extension=".pdf",
            sha256_hash="xyz",
            meta_created_at=now + timedelta(days=365),
            meta_modified_at=now + timedelta(days=365),
        )
        res_future = DiscrepancyAnalyzer.analyze(meta_future)
        self.assertTrue(res_future.has_timestamp_anomaly)

    def test_discrepancy_analyzer_extended_gap_and_zero_edit_time(self):
        now = datetime.now(UTC)

        # 1. Extended revision gap (>180 days) and FS vs Meta discrepancy (>365 days)
        meta_gap = ParsedMetadata(
            filename="gap_doc.docx",
            file_size_bytes=4096,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            file_extension=".docx",
            sha256_hash="11223344",
            file_created_at=now,
            meta_created_at=now - timedelta(days=400),
            meta_modified_at=now - timedelta(days=100),
            editing_time_minutes=0,
            revision_number="6",
        )
        res_gap = DiscrepancyAnalyzer.analyze(meta_gap)
        flag_codes = [f.code for f in res_gap.anomalies]
        self.assertIn("EXTENDED_TIME_GAP", flag_codes)
        self.assertIn("FS_META_DISCREPANCY", flag_codes)
        self.assertIn("OFFICE_ZERO_EDIT_TIME", flag_codes)

        # 2. Stripped metadata
        meta_stripped = ParsedMetadata(
            filename="stripped.pdf",
            file_size_bytes=1024,
            mime_type="application/pdf",
            file_extension=".pdf",
            sha256_hash="55667788",
            meta_created_at=None,
            meta_author="",
            meta_software="",
        )
        res_stripped = DiscrepancyAnalyzer.analyze(meta_stripped)
        stripped_codes = [f.code for f in res_stripped.anomalies]
        self.assertIn("METADATA_STRIPPED", stripped_codes)

    def test_get_all_custodian_profiles(self):
        from .models import VerificationCase
        from .selectors import get_all_custodian_profiles

        # Create cases with different custodians
        VerificationCase.objects.create(
            case_ref="CUST-1",
            case_title="Test Custodian 1",
            custodian_name="Alice Auditee",
            custodian_department="Finance",
            total_documents=2,
            authentic_count=1,
            suspicious_count=1,
            tampered_count=0,
            average_authenticity_score=75.0,
        )
        VerificationCase.objects.create(
            case_ref="CUST-2",
            case_title="Test Custodian 2",
            custodian_name="Alice Auditee",  # Same custodian
            total_documents=1,
            authentic_count=1,
            average_authenticity_score=100.0,
        )
        VerificationCase.objects.create(
            case_ref="CUST-3",
            case_title="Test Custodian 3",
            custodian_name="Bob Auditee",
            total_documents=1,
            tampered_count=1,
            average_authenticity_score=20.0,
        )

        profiles = get_all_custodian_profiles()

        # We should have 2 profiles (Alice and Bob)
        self.assertEqual(len(profiles), 2)

        # Check Alice's profile aggregation
        alice_profile = next((p for p in profiles if p["custodian_name"] == "Alice Auditee"), None)
        self.assertIsNotNone(alice_profile)
        self.assertEqual(alice_profile["total_cases"], 2)
        self.assertEqual(alice_profile["total_documents"], 3)
        self.assertEqual(alice_profile["authentic_count"], 2)
        self.assertEqual(alice_profile["suspicious_count"], 1)

        # Check average score: (75.0 * 2 + 100.0 * 1) / 3 = 250 / 3 = 83.33... -> rounded to 83.3
        self.assertAlmostEqual(alice_profile["average_score"], 83.3)

        # Check Bob's profile aggregation
        bob_profile = next((p for p in profiles if p["custodian_name"] == "Bob Auditee"), None)
        self.assertIsNotNone(bob_profile)
        self.assertEqual(bob_profile["total_cases"], 1)
        self.assertEqual(bob_profile["tampered_count"], 1)
        self.assertEqual(bob_profile["average_score"], 20.0)

    def test_get_case_risk_chart_html(self):
        from .selectors import get_case_risk_chart_html

        # Test empty
        html_empty = get_case_risk_chart_html(
            {"Authentic": 0, "Suspicious": 0, "High Risk / Tampered": 0}
        )
        self.assertEqual(html_empty, "")

        # Test with values
        html = get_case_risk_chart_html(
            {"Authentic": 5, "Suspicious": 2, "High Risk / Tampered": 1}
        )
        self.assertIn("<div", html)
        self.assertIn("plotly", html.lower())


class DocumentSearchTests(TestCase):
    def setUp(self):
        from core.models import InvestigationProfile

        from .models import VerificationCase, VerifiedDocument

        self.profile = InvestigationProfile.objects.create(
            full_name="Test Target", email="test@target.com", keywords=["Confidential", "Secret"]
        )
        self.case = VerificationCase.objects.create(
            case_title="Search Test Case", custodian_name=self.profile.full_name
        )
        self.doc = VerifiedDocument.objects.create(
            case=self.case, filename="test_doc.txt", mime_type="text/plain", authenticity_score=100
        )
        import os
        import tempfile

        content = (
            b"This is a Secret document containing confidential information and some custom_kw."
        )
        fd, temp_path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "wb") as f:
            f.write(content)

        self.doc.storage_path = temp_path
        self.doc.save()

    def tearDown(self):
        import os

        if hasattr(self, "doc") and self.doc.storage_path and os.path.exists(self.doc.storage_path):
            os.remove(self.doc.storage_path)

    def test_perform_document_search(self):
        from .services import perform_document_search

        # Test search with profile keywords + custom keywords
        doc = perform_document_search(self.doc.id, custom_keywords=["custom_kw"])
        self.assertIn("Secret", doc.matched_keywords)
        self.assertIn("Confidential", doc.matched_keywords)
        self.assertIn("custom_kw", doc.matched_keywords)
        self.assertEqual(doc.matched_keywords["Secret"], 1)

    def test_document_search_api_view(self):
        import json

        from django.test import Client

        c = Client()
        session = c.session
        session["portal_authenticated"] = True
        session.save()

        response = c.post(
            f"/verify/document/{self.doc.id}/search/",
            data=json.dumps({"custom_keywords": ["information"]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("information", data["matched_keywords"])
        self.assertIn("Secret", data["matched_keywords"])

    def test_content_search_backends(self):
        import sys

        from apps.q_verify.backend.content_search import (
            _extract_text_from_docx,
            _extract_text_from_image_ocr,
            _extract_text_from_pdf_ocr,
            _extract_text_from_xlsx,
            search_keywords_in_file,
        )

        # 1. Test missing files (graceful exception handling)
        self.assertEqual(_extract_text_from_pdf_ocr("non_existent.pdf"), "")
        self.assertEqual(_extract_text_from_image_ocr("non_existent.jpg"), "")
        self.assertEqual(_extract_text_from_docx("non_existent.docx"), "")
        self.assertEqual(_extract_text_from_xlsx("non_existent.xlsx"), "")

        # 2. Test PDF OCR success path via sys.modules mock
        mock_pytesseract = MagicMock()
        mock_pytesseract.image_to_string.return_value = "secret information inside pdf"
        mock_pdf2image = MagicMock()
        mock_pdf2image.convert_from_path.return_value = ["fake_image"]

        sys.modules["pytesseract"] = mock_pytesseract
        sys.modules["pdf2image"] = mock_pdf2image
        try:
            text = _extract_text_from_pdf_ocr("fake.pdf")
            self.assertIn("secret information", text)
        finally:
            del sys.modules["pytesseract"]
            del sys.modules["pdf2image"]

        # 3. Test PDF PyPDF fallback success path via sys.modules
        mock_pdf2image.convert_from_path.side_effect = Exception("No poppler")
        sys.modules["pdf2image"] = mock_pdf2image
        with patch("pypdf.PdfReader") as mock_reader:
            mock_page = MagicMock()
            mock_page.extract_text.return_value = "fallback secret"
            mock_reader.return_value.pages = [mock_page]
            try:
                text = _extract_text_from_pdf_ocr("fake.pdf")
                self.assertIn("fallback secret", text)
            finally:
                del sys.modules["pdf2image"]

        # 4. Test Image OCR success path
        mock_pytesseract = MagicMock()
        mock_pytesseract.image_to_string.return_value = "image secret"
        mock_pil = MagicMock()

        sys.modules["pytesseract"] = mock_pytesseract
        sys.modules["PIL"] = mock_pil
        try:
            text = _extract_text_from_image_ocr("fake.jpg")
            self.assertIn("image secret", text)
        finally:
            del sys.modules["pytesseract"]
            del sys.modules["PIL"]

        # 5. Test DOCX success path
        mock_docx = MagicMock()
        mock_p = MagicMock()
        mock_p.text = "docx secret"
        mock_docx.Document.return_value.paragraphs = [mock_p]
        sys.modules["docx"] = mock_docx
        try:
            text = _extract_text_from_docx("fake.docx")
            self.assertEqual(text, "docx secret")
        finally:
            del sys.modules["docx"]

        # 6. Test XLSX success path
        mock_openpyxl = MagicMock()
        mock_sheet = MagicMock()
        mock_sheet.iter_rows.return_value = [("xlsx", "secret")]
        mock_openpyxl.load_workbook.return_value.worksheets = [mock_sheet]
        sys.modules["openpyxl"] = mock_openpyxl
        try:
            text = _extract_text_from_xlsx("fake.xlsx")
            self.assertEqual(text, "xlsx secret")
        finally:
            del sys.modules["openpyxl"]

        # 7. Test full pipeline success
        with patch(
            "apps.q_verify.backend.content_search._extract_text_from_pdf_ocr",
            return_value="fraud detected",
        ):
            res = search_keywords_in_file("test.pdf", "application/pdf", ["fraud", "notfound"])
            self.assertEqual(res.get("fraud"), 1)
            self.assertEqual(res.get("notfound"), 0)

        with patch(
            "apps.q_verify.backend.content_search._extract_text_from_docx", return_value="fraud"
        ):
            res = search_keywords_in_file(
                "test.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ["fraud"],
            )
            self.assertEqual(res.get("fraud"), 1)

        with patch(
            "apps.q_verify.backend.content_search._extract_text_from_xlsx", return_value="fraud"
        ):
            res = search_keywords_in_file(
                "test.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ["fraud"],
            )
            self.assertEqual(res.get("fraud"), 1)

        with patch(
            "apps.q_verify.backend.content_search._extract_text_from_image_ocr",
            return_value="fraud",
        ):
            res = search_keywords_in_file("test.jpg", "image/jpeg", ["fraud"])
            self.assertEqual(res.get("fraud"), 1)

import csv
import io
import json
import os
import tempfile
import uuid
import zipfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from .backend.disk_scanner import HighPerformanceDiskScanner, load_or_create_config
from .models import FileEvidenceHit, ScannedDevice
from .selectors import (
    format_file_size,
    get_all_scanned_devices,
    get_evidence_hits_query,
    get_paginated_evidence_hits,
    get_scan_dashboard_metrics,
    get_scanned_device_by_id,
    get_top_matched_keywords,
)
from .services import delete_scanned_device, ingest_scan_csv_file


class HighPerformanceDiskScannerTests(TestCase):
    """
    Test suite for Q-Scan filesystem scanner and deep document/archive extraction engine.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)
        self.output_csv = self.root_path / "test_results.csv"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_filename_match(self):
        # Create file with keyword in filename
        target_file = self.root_path / "employee_password_list.txt"
        target_file.write_text("Regular content here", encoding="utf-8")

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["password"],
            search_contents=False,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertEqual(stats["matches_found"], 1)
        self.assertTrue(self.output_csv.exists())

        with open(self.output_csv, encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
            self.assertEqual(len(rows), 2)  # Header + 1 match row
            self.assertEqual(rows[1][2], "password")
            self.assertEqual(rows[1][3], "FILENAME")

    def test_content_boundary_split_match(self):
        # Test boundary overlap buffer by splitting keyword across 64-byte chunks
        chunk_size = 64
        secret_keyword = "confidential_audit_token"
        pad_len = chunk_size - 10
        content = ("A" * pad_len) + secret_keyword + ("B" * 50)

        test_file = self.root_path / "stream_data.log"
        test_file.write_text(content, encoding="utf-8")

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=[secret_keyword],
            search_contents=True,
            chunk_size_bytes=chunk_size,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertEqual(stats["matches_found"], 1)
        with open(self.output_csv, encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1][2], secret_keyword)
            self.assertEqual(rows[1][3], "CONTENT_TEXT")
            self.assertIn("confidential_audit_token", rows[1][6])

    def test_deep_docx_inspection(self):
        # Create a mock .docx archive (zip with word/document.xml)
        docx_file = self.root_path / "report.docx"
        mock_doc_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body>
                <w:p><w:r><w:t>Confidential kickback settlement agreement</w:t></w:r></w:p>
            </w:body>
        </w:document>"""

        with zipfile.ZipFile(docx_file, "w") as z:
            z.writestr("word/document.xml", mock_doc_xml)

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["kickback"],
            search_contents=True,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertEqual(stats["matches_found"], 1)
        with open(self.output_csv, encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
            self.assertEqual(rows[1][2], "kickback")
            self.assertEqual(rows[1][3], "CONTENT_DOCX")

    def test_deep_zip_inspection(self):
        # Create a mock .zip containing an inner secret text file
        zip_file = self.root_path / "backup.zip"
        with zipfile.ZipFile(zip_file, "w") as z:
            z.writestr("notes/offshore_accounts.txt", "Bank balance in Panama: $5,000,000")

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["offshore"],
            search_contents=True,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertGreaterEqual(stats["matches_found"], 1)
        with open(self.output_csv, encoding="utf-8-sig") as f:
            rows = list(csv.reader(f))
            self.assertEqual(rows[1][2], "offshore")

    def test_directory_and_extension_exclusions(self):
        # Excluded folder
        excluded_dir = self.root_path / ".git" / "logs"
        excluded_dir.mkdir(parents=True)
        (excluded_dir / "secret.txt").write_text("password=123", encoding="utf-8")

        # Excluded extension
        (self.root_path / "library.dll").write_text("password=123", encoding="utf-8")

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["password"],
            exclude_directories=[str(self.root_path / ".git")],
            exclude_extensions=[".dll"],
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertEqual(stats["matches_found"], 0)

    def test_config_loader(self):
        cfg_path = self.root_path / "config.json"
        created_cfg = load_or_create_config(cfg_path)
        self.assertTrue(cfg_path.exists())
        self.assertIn("keywords", created_cfg)
        self.assertIn("exclude_directories", created_cfg)

        # Existing valid config
        loaded_cfg = load_or_create_config(cfg_path)
        self.assertEqual(loaded_cfg["keywords"], created_cfg["keywords"])

        # Corrupted config raises error
        corrupt_cfg = self.root_path / "corrupt_config.json"
        corrupt_cfg.write_text("{not valid json", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            load_or_create_config(corrupt_cfg)

    def test_format_long_path_and_clean_display_path(self):
        # Long path formatting
        p_normal = "C:\\audit\\reports\\memo.docx"
        p_long = HighPerformanceDiskScanner.format_long_path(p_normal)
        self.assertTrue(p_long.startswith("\\\\?\\") or os.name != "nt")

        # Path that already has prefix
        p_already_long = "\\\\?\\C:\\audit\\reports\\memo.docx"
        self.assertEqual(
            HighPerformanceDiskScanner.format_long_path(p_already_long), p_already_long
        )

        # UNC path
        p_unc = "\\\\fileserver\\share\\memo.docx"
        p_unc_formatted = HighPerformanceDiskScanner.format_long_path(p_unc)
        if os.name == "nt":
            self.assertTrue(p_unc_formatted.startswith("\\\\?\\UNC\\"))

        # Clean display path
        self.assertEqual(
            HighPerformanceDiskScanner.clean_display_path("\\\\?\\C:\\audit\\memo.docx"),
            "C:\\audit\\memo.docx",
        )
        self.assertEqual(
            HighPerformanceDiskScanner.clean_display_path("\\\\?\\UNC\\fileserver\\share\\doc.pdf"),
            "\\\\fileserver\\share\\doc.pdf",
        )
        self.assertEqual(
            HighPerformanceDiskScanner.clean_display_path("C:\\plain\\path.txt"),
            "C:\\plain\\path.txt",
        )

    def test_is_directory_excluded_variations(self):
        target_root = str(self.root_path)
        exclude_dir = str(self.root_path / "excluded_dir")
        scanner = HighPerformanceDiskScanner(
            target_directories=[target_root],
            keywords=["secret"],
            exclude_directories=[exclude_dir, "sub_exclude"],
        )

        # Target root should not be excluded
        self.assertFalse(scanner.is_directory_excluded(target_root))

        # Configured exclusion matches
        self.assertTrue(scanner.is_directory_excluded(exclude_dir))
        self.assertTrue(
            scanner.is_directory_excluded(str(self.root_path / "excluded_dir" / "nested"))
        )
        self.assertTrue(scanner.is_directory_excluded(str(self.root_path / "sub_exclude" / "data")))

        # Normal non-excluded folder
        self.assertFalse(scanner.is_directory_excluded(str(self.root_path / "normal_data")))

    def test_format_file_size(self):
        self.assertEqual(HighPerformanceDiskScanner.format_file_size(500), "500.00 B")
        self.assertEqual(HighPerformanceDiskScanner.format_file_size(2048), "2.00 KB")
        self.assertEqual(HighPerformanceDiskScanner.format_file_size(5 * 1024 * 1024), "5.00 MB")
        self.assertEqual(
            HighPerformanceDiskScanner.format_file_size(3 * 1024 * 1024 * 1024), "3.00 GB"
        )
        self.assertEqual(
            HighPerformanceDiskScanner.format_file_size(2 * 1024 * 1024 * 1024 * 1024), "2.00 TB"
        )
        self.assertIn(
            "PB", HighPerformanceDiskScanner.format_file_size(2000 * 1024 * 1024 * 1024 * 1024)
        )

    def test_clean_display_path(self):
        self.assertEqual(
            HighPerformanceDiskScanner.clean_display_path("\\\\?\\UNC\\server\\share\\folder"),
            "\\\\server\\share\\folder",
        )
        self.assertEqual(
            HighPerformanceDiskScanner.clean_display_path("\\\\?\\C:\\Folder\\File.txt"),
            "C:\\Folder\\File.txt",
        )
        self.assertEqual(
            HighPerformanceDiskScanner.clean_display_path("C:\\Normal\\Path.txt"),
            "C:\\Normal\\Path.txt",
        )

    def test_deep_xlsx_and_pptx_inspection(self):
        # Create mock .xlsx
        xlsx_file = self.root_path / "accounts.xlsx"
        mock_shared_strings = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
            <si><t>Offshore shell payment illicit remittance</t></si>
        </sst>"""
        with zipfile.ZipFile(xlsx_file, "w") as z:
            z.writestr("xl/sharedStrings.xml", mock_shared_strings)

        # Create mock .pptx
        pptx_file = self.root_path / "pitch.pptx"
        mock_slide = b"""<?xml version="1.0" encoding="UTF-8"?>
        <p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
               xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
            <p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Executive illicit bonus pool</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>
        </p:sld>"""
        with zipfile.ZipFile(pptx_file, "w") as z:
            z.writestr("ppt/slides/slide1.xml", mock_slide)

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["illicit"],
            search_contents=True,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertEqual(stats["matches_found"], 2)
        with open(self.output_csv, encoding="utf-8-sig") as f:
            content = f.read()
            self.assertIn("CONTENT_XLSX", content)
            self.assertIn("CONTENT_PPTX", content)

    def test_nested_zip_office_document_and_corrupt_archive(self):
        # Nested zip with inner docx and a directory entry
        inner_docx_buf = io.BytesIO()
        with zipfile.ZipFile(inner_docx_buf, "w") as inner_z:
            inner_z.writestr(
                "word/document.xml",
                b"<w:document><w:body><w:p><w:r><w:t>Confidential slush fund transfer</w:t></w:r></w:p></w:body></w:document>",
            )

        outer_zip = self.root_path / "complex_archive.zip"
        with zipfile.ZipFile(outer_zip, "w") as outer_z:
            # 1. Directory entry inside zip
            outer_z.writestr("folder/", "")
            # 2. Nested docx file
            outer_z.writestr("folder/inner_contract.docx", inner_docx_buf.getvalue())
            # 3. Text member matching keyword
            outer_z.writestr("folder/notes.txt", "Another slush fund entry in plain text")

        # Corrupt archive
        corrupt_zip = self.root_path / "broken_archive.zip"
        corrupt_zip.write_bytes(b"NOT_A_VALID_ZIP_HEADER_DATA_12345")

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["slush fund"],
            search_contents=True,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()

        self.assertGreaterEqual(stats["matches_found"], 1)
        self.assertGreaterEqual(stats["errors_bypassed"], 1)
        with open(self.output_csv, encoding="utf-8-sig") as f:
            content = f.read()
            self.assertIn("CONTENT_ZIP_OFFICE", content)

    def test_scan_with_progress_callback_and_interruption(self):
        # Create nested folders and files
        sub_dir = self.root_path / "level1" / "level2"
        sub_dir.mkdir(parents=True)
        (sub_dir / "target.txt").write_text("classified audit document", encoding="utf-8")

        callbacks_received = []

        def on_progress(p: dict):
            callbacks_received.append(p)

        scanner = HighPerformanceDiskScanner(
            target_directories=[str(self.root_path)],
            keywords=["classified"],
            exclude_directories=[],
            progress_callback=on_progress,
            output_csv_path=self.output_csv,
        )
        stats = scanner.run_scan()
        self.assertGreaterEqual(stats["matches_found"], 1)
        self.assertGreaterEqual(stats["dirs_scanned"], 2)

        # Test interruption flag
        scanner.is_interrupted = True
        stats_interrupted = scanner.run_scan()
        self.assertIsNotNone(stats_interrupted)


class QScanDjangoServiceAndViewsTests(TestCase):
    """
    Test suite for Q-Scan Django services, selectors, and views.
    """

    def setUp(self):
        self.client = Client()
        # Authenticate session
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

    def test_csv_ingestion_service(self):
        csv_data = """Timestamp,File Path,Matched Keyword,Match Type,File Size (Bytes),Last Modified Date,Matching Context/Snippet
2026-09-27 01:00:00 UTC,C:\\Users\\CEO\\Desktop\\secret_passwords.txt,password,CONTENT_TEXT,1024,2026-09-26 12:00:00,admin password was updated
2026-09-27 01:01:00 UTC,C:\\Users\\CEO\\Documents\\vendor_kickback.docx,kickback,CONTENT_DOCX,45000,2026-09-25 10:00:00,kickback payout approved
"""
        device = ingest_scan_csv_file(
            csv_file_obj_or_path=csv_data,
            hostname="WS-FINANCE-01",
            scan_title="Q3 Internal Audit",
            custodian_name="Finance Director",
            drive_letter="C:\\",
        )

        self.assertEqual(device.hostname, "WS-FINANCE-01")
        self.assertEqual(device.total_matches_found, 2)
        self.assertEqual(FileEvidenceHit.objects.filter(device=device).count(), 2)

        metrics = get_scan_dashboard_metrics()
        self.assertEqual(metrics["total_devices"], 1)
        self.assertEqual(metrics["total_hits"], 2)

    def test_dashboard_and_export_views(self):
        # Create test device and hit
        device = ScannedDevice.objects.create(
            hostname="WS-EXEC-09",
            scan_title="Executive Audit",
            total_matches_found=1,
        )
        FileEvidenceHit.objects.create(
            device=device,
            file_path="C:\\pass.txt",
            filename="pass.txt",
            matched_keyword="password",
            match_type=FileEvidenceHit.MatchType.FILENAME,
            risk_score=90,
        )

        # Dashboard View
        resp = self.client.get(reverse("q_scan:dashboard"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "WS-EXEC-09")

        # Detail View
        detail_resp = self.client.get(reverse("q_scan:device_detail", args=[device.id]))
        self.assertEqual(detail_resp.status_code, 200)
        self.assertContains(detail_resp, "Executive Audit")

        # Export CSV View
        export_resp = self.client.get(reverse("q_scan:export_csv"))
        self.assertEqual(export_resp.status_code, 200)
        self.assertIn(b"WS-EXEC-09", export_resp.content)

        # Delete Device
        delete_scanned_device(device.id)
        self.assertEqual(ScannedDevice.objects.count(), 0)
        self.assertEqual(FileEvidenceHit.objects.count(), 0)

    def test_format_file_size(self):
        self.assertEqual(format_file_size(500), "500.00 B")
        self.assertEqual(format_file_size(2048), "2.00 KB")
        self.assertEqual(format_file_size(10485760), "10.00 MB")
        self.assertEqual(format_file_size(10737418240), "10.00 GB")

    def test_selectors_and_pagination(self):
        device = ScannedDevice.objects.create(
            hostname="WS-SELECT-01",
            scan_title="Selector Verification",
        )
        h1 = FileEvidenceHit.objects.create(
            device=device,
            file_path="C:\\Evidence\\kickbacks.xlsx",
            filename="kickbacks.xlsx",
            matched_keyword="kickback",
            match_type=FileEvidenceHit.MatchType.CONTENT_DOCX,
            risk_score=85,
        )
        FileEvidenceHit.objects.create(
            device=device,
            file_path="C:\\Evidence\\salary_sheet.csv",
            filename="salary_sheet.csv",
            matched_keyword="salary",
            match_type=FileEvidenceHit.MatchType.CONTENT_TEXT,
            risk_score=30,
        )

        all_devs = get_all_scanned_devices()
        self.assertGreaterEqual(all_devs.count(), 1)

        fetched = get_scanned_device_by_id(device.id)
        self.assertEqual(fetched.id, device.id)
        self.assertIsNone(get_scanned_device_by_id("invalid-id"))

        # Query hits with filters
        hits = get_evidence_hits_query(device_id=device.id, keyword="kickback")
        self.assertEqual(hits.count(), 1)

        # Pagination & sorting
        page_res = get_paginated_evidence_hits(
            device_id=device.id,
            page=1,
            page_size=10,
            search="kickbacks",
            risk_level="high",
            sort_field="risk_score",
            sort_dir="desc",
        )
        self.assertEqual(page_res["total_count"], 1)
        self.assertEqual(page_res["data"][0]["id"], str(h1.id))

        # Top keywords
        top_kws = get_top_matched_keywords()
        self.assertGreaterEqual(len(top_kws), 1)

    def test_evidence_api_and_review_toggle(self):
        device = ScannedDevice.objects.create(
            hostname="WS-API-01",
            scan_title="API Verification",
        )
        hit = FileEvidenceHit.objects.create(
            device=device,
            file_path="C:\\secret.txt",
            filename="secret.txt",
            matched_keyword="password",
            match_type=FileEvidenceHit.MatchType.FILENAME,
            risk_score=95,
            is_reviewed=False,
        )

        # Tabulator Evidence API endpoint
        api_url = reverse("q_scan:hits_api")
        resp = self.client.get(api_url, {"device_id": str(device.id)})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["last_row"], 1)

        # Toggle review status
        toggle_url = reverse("q_scan:review_hit_api", kwargs={"hit_id": hit.id})
        toggle_resp = self.client.post(
            toggle_url,
            data=json.dumps({"is_reviewed": True, "reviewer_notes": "Reviewed"}),
            content_type="application/json",
        )
        self.assertEqual(toggle_resp.status_code, 200)
        hit.refresh_from_db()
        self.assertTrue(hit.is_reviewed)

    def test_download_tool_file_view(self):
        # Valid tool file download
        res = self.client.get(reverse("q_scan:download_tool", kwargs={"filename": "q_scan.py"}))
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment", res["Content-Disposition"])
        res.close()

        # Invalid tool file download -> 404
        res_404 = self.client.get(
            reverse("q_scan:download_tool", kwargs={"filename": "non_existent.py"})
        )
        self.assertEqual(res_404.status_code, 404)

    def test_device_views_workflow(self):
        # 1. Upload CSV endpoint with file
        csv_data = (
            b"Timestamp,Hostname,MatchedKeyword,MatchType,FilePath,RiskScore,Snippet\n"
            b"2026-03-01 10:00:00,WS-AUTO-01,secret,FILENAME,C:\\secret.txt,90,secret file\n"
        )
        upload_file = SimpleUploadedFile("scan_results.csv", csv_data, content_type="text/csv")

        upload_url = reverse("q_scan:upload_csv")
        res_up = self.client.post(
            upload_url,
            data={
                "csv_file": upload_file,
                "hostname": "WS-AUTO-01",
                "scan_title": "Field Audit",
                "custodian_name": "Audit Custodian",
                "drive_letter": "C",
            },
        )
        self.assertEqual(res_up.status_code, 302)
        dev = ScannedDevice.objects.filter(hostname="WS-AUTO-01").first()
        self.assertIsNotNone(dev)

        # 2. Upload CSV endpoint without file
        res_empty = self.client.post(upload_url, data={})
        self.assertEqual(res_empty.status_code, 302)

        # 3. Device detail view
        detail_url = reverse("q_scan:device_detail", kwargs={"device_id": dev.id})
        res_det = self.client.get(detail_url)
        self.assertEqual(res_det.status_code, 200)
        self.assertIn(b"WS-AUTO-01", res_det.content)

        # 4. Device detail view 404
        res_det_404 = self.client.get(
            reverse("q_scan:device_detail", kwargs={"device_id": uuid.uuid4()})
        )
        self.assertEqual(res_det_404.status_code, 404)

        # 5. Export hits CSV view
        exp_url = f"{reverse('q_scan:export_csv')}?device_id={dev.id}"
        res_exp = self.client.get(exp_url)
        self.assertEqual(res_exp.status_code, 200)
        self.assertIn("text/csv", res_exp["Content-Type"])

        # 6. Delete device view
        del_url = reverse("q_scan:delete_device", kwargs={"device_id": dev.id})
        res_del = self.client.post(del_url)
        self.assertEqual(res_del.status_code, 302)
        self.assertFalse(ScannedDevice.objects.filter(id=dev.id).exists())

        # 7. Delete non-existent device
        res_del_404 = self.client.post(
            reverse("q_scan:delete_device", kwargs={"device_id": uuid.uuid4()})
        )
        self.assertEqual(res_del_404.status_code, 302)

    def test_directory_exclusion_logic(self):
        root = Path(tempfile.gettempdir()) / "scan_test_dir"
        scanner = HighPerformanceDiskScanner(
            keywords=["confidential"],
            target_directories=[str(root)],
            exclude_directories=[".git", "node_modules", str(root / "custom_skip")],
        )
        # Targeted root must NOT be excluded
        self.assertFalse(scanner.is_directory_excluded(str(root)))
        # Subdirectories matching exclusion parts or prefix
        self.assertTrue(scanner.is_directory_excluded(str(root / ".git")))
        self.assertTrue(scanner.is_directory_excluded(str(root / ".git" / "objects")))
        self.assertTrue(scanner.is_directory_excluded(str(root / "node_modules" / "package")))
        self.assertTrue(scanner.is_directory_excluded(str(root / "custom_skip")))
        self.assertTrue(scanner.is_directory_excluded(str(root / "custom_skip" / "deep")))
        # Non-excluded normal directory
        self.assertFalse(scanner.is_directory_excluded(str(root / "normal_folder")))

    def test_evidence_hits_fuzzy_and_filtering(self):
        from .selectors import get_evidence_hits_query, get_paginated_evidence_hits

        dev = ScannedDevice.objects.create(
            hostname="WS-FUZZY-01",
            custodian_name="Auditee 1",
        )
        hit1 = FileEvidenceHit.objects.create(
            device=dev,
            filename="confidential_memo.docx",
            file_path="C:\\Docs\\confidential_memo.docx",
            matched_keyword="confidential",
            match_type="content",
            snippet="Contains confidential project details",
            risk_score=85,
        )
        hit2 = FileEvidenceHit.objects.create(
            device=dev,
            filename="budget_draft.xlsx",
            file_path="C:\\Docs\\budget_draft.xlsx",
            matched_keyword="budget",
            match_type="filename",
            snippet="Quarterly budget draft",
            risk_score=50,
        )
        hit3 = FileEvidenceHit.objects.create(
            device=dev,
            filename="notes.txt",
            file_path="C:\\Docs\\notes.txt",
            matched_keyword="notes",
            match_type="content",
            snippet="Personal notes",
            risk_score=20,
        )
        self.assertIsNotNone(hit2)
        self.assertIsNotNone(hit3)

        # 1. Filter by keyword & match_type
        qs1 = get_evidence_hits_query(keyword="confidential", match_type="content")
        self.assertIn(hit1, qs1)

        # 2. Exact search_query (threshold >= 100)
        qs_exact = get_evidence_hits_query(search_query="confidential", threshold=100)
        self.assertIn(hit1, qs_exact)

        # 3. Fuzzy search_query (threshold < 100)
        qs_fuzzy = get_evidence_hits_query(search_query="confidentil", threshold=70)
        self.assertIn(hit1, qs_fuzzy)

        # 4. get_paginated_evidence_hits with risk_level (high, medium, low)
        page_high = get_paginated_evidence_hits(risk_level="high")
        self.assertEqual(len(page_high["data"]), 1)
        self.assertEqual(page_high["data"][0]["filename"], "confidential_memo.docx")

        page_med = get_paginated_evidence_hits(risk_level="medium")
        self.assertEqual(len(page_med["data"]), 1)
        self.assertEqual(page_med["data"][0]["filename"], "budget_draft.xlsx")

        page_low = get_paginated_evidence_hits(risk_level="low")
        self.assertEqual(len(page_low["data"]), 1)
        self.assertEqual(page_low["data"][0]["filename"], "notes.txt")

        # 5. get_paginated_evidence_hits fuzzy search
        page_fuzz = get_paginated_evidence_hits(search="budgt", threshold=70)
        self.assertEqual(len(page_fuzz["data"]), 1)
        self.assertEqual(page_fuzz["data"][0]["filename"], "budget_draft.xlsx")

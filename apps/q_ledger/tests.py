import io
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from .backend.analysis_functions import indian_rupee_format
from .backend.data_preprocessing import (
    dfmain,
    get_master_gl_data,
    get_master_sloc_data,
    process_data,
    process_mara_data,
)
from .models import (
    ERPThreeWayMatch,
    LedgerDataset,
    LedgerMasterConfig,
    PurchaseOrder,
    VendorMaster,
)
from .selectors import prepare_table_dict


class QLedgerModelTests(TestCase):
    def test_ledger_master_config_str(self):
        cfg = LedgerMasterConfig.objects.create(gl_account_count=120, sloc_count=45)
        self.assertIn("120 GLs", str(cfg))
        self.assertIn("45 SLocs", str(cfg))

    def test_ledger_dataset_str(self):
        ds = LedgerDataset.objects.create(
            title="Q4 FY25 SAP PRPO Extract", record_count=3500, total_spend=Decimal("45000000.00")
        )
        self.assertIn("Q4 FY25", str(ds))
        self.assertIn("3500 records", str(ds))

    def test_erp_three_way_match_and_vendor(self):
        vendor = VendorMaster.objects.create(
            vendor_code="V-9001",
            vendor_name="Global Heavy Electricals Ltd",
            gstin="33AABCG1234F1Z5",
        )
        self.assertEqual(str(vendor), "V-9001 - Global Heavy Electricals Ltd")

        po = PurchaseOrder.objects.create(
            po_number="PO-2026-9901",
            vendor=vendor,
            po_date=timezone.now(),
            total_amount=Decimal("150000.00"),
            approved_by="Executive Director",
        )
        self.assertIn("PO #PO-2026-9901", str(po))

        match = ERPThreeWayMatch.objects.create(
            po=po,
            invoice_number="INV-4412",
            grn_number="GRN-8812",
            po_amount=Decimal("150000.00"),
            grn_amount=Decimal("150000.00"),
            invoice_amount=Decimal("175000.00"),
            variance_amount=Decimal("25000.00"),
            has_anomaly=True,
            anomaly_type="Price Inflation / Over-billing",
        )
        self.assertIn("PO-2026-9901", str(match))
        self.assertIn("25000", str(match))


class QLedgerSelectorAndAnalysisTests(TestCase):
    def test_prepare_table_dict_empty(self):
        result = prepare_table_dict(None)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["rows"], "[]")
        self.assertEqual(result["columns"], "[]")

        empty_df = pd.DataFrame()
        result_empty = prepare_table_dict(empty_df)
        self.assertEqual(result_empty["count"], 0)

    def test_prepare_table_dict_with_data(self):
        df = pd.DataFrame(
            {
                "PO_Number": ["PO-101", "PO-102"],
                "Amount": [50000, 120000],
                "Date": [pd.Timestamp("2026-03-15"), pd.Timestamp("2026-03-20")],
                "Notes": [None, "Verified"],
            }
        )
        result = prepare_table_dict(df, max_rows=10)
        self.assertEqual(result["count"], 2)
        import json

        cols = json.loads(result["columns"])
        rows = json.loads(result["rows"])
        self.assertEqual(len(cols), 4)
        self.assertEqual(rows[0]["PO_Number"], "PO-101")
        self.assertEqual(rows[0]["Date"], "2026-03-15")
        self.assertEqual(rows[0]["Notes"], "—")

    def test_get_checkpoint_tables_and_charts_execution(self):
        from .selectors import (
            get_checkpoint_tables,
            get_ledger_charts,
            get_ledger_kpis,
            get_top_rankings,
        )

        # 1. Empty input
        empty_tables = get_checkpoint_tables(None, None)
        self.assertIn("checkpoint_material", empty_tables)

        empty_charts = get_ledger_charts(None)
        self.assertIsNone(empty_charts["vendor_chart_html"])

        # 2. Rich dataset input
        sample_df = pd.DataFrame(
            {
                "S/Loc": ["SL01", "SL01"],
                "Vendor": ["V-101", "V-101"],
                "Vendor Code & Name": ["V-101 Supplier", "V-101 Supplier"],
                "Creater": ["USER1", "USER1"],
                "Material": ["M-9901", "M-9901"],
                "Material Type": ["ERSA", "ERSA"],
                "Material Type.": ["ERSA", "ERSA"],
                "Material Type Description": ["Raw Material", "Raw Material"],
                "Description": ["High tensile steel coil", "High tensile steel coil"],
                "Spec": ["IS 2062", "IS 2062"],
                "G/L acct": ["410001", "410001"],
                "G/L acct.": ["410001", "410001"],
                "G/L Acct Long Text": ["Raw material", "Raw material"],
                "Cost Ctr": ["CC-01", "CC-01"],
                "Cost Ctr.": ["CC-01", "CC-01"],
                "PO Date": ["2022-01-01", "2024-01-01"],
                "Purchase order": ["PO-1001", "PO-1001"],
                "PO Currency": ["INR", "INR"],
                "Net price": [5000, 5000],
                "PO Qty": [100, 100],
                "Pstng Date": ["2023-01-01", "2024-06-01"],
                "GR Qty": [80, 80],
                "PO Rem": [20, 20],
                "PO Rem.": [20, 20],
                "Amount LC": [400000, 400000],
            }
        )
        sample_df2 = pd.DataFrame({"Material": ["M-9901"], "Material Type": ["ERSA"]})

        tables = get_checkpoint_tables(sample_df, sample_df2)
        self.assertIn("checkpoint_material", tables)
        self.assertIn("checkpoint_ersa", tables)
        self.assertIn("checkpoint_openpo", tables)
        self.assertIn("checkpoint_unitprice", tables)

        charts = get_ledger_charts(sample_df)
        self.assertIsInstance(charts, dict)

        kpis = get_ledger_kpis(sample_df)
        self.assertGreater(kpis["total_amount_raw"], 0)

        rankings = get_top_rankings(sample_df)
        self.assertIn("top_vendors", rankings)

    def test_indian_rupee_format(self):
        formatted = indian_rupee_format(150000)
        self.assertIn("1.50 L", formatted)

        cr_formatted = indian_rupee_format(25000000)
        self.assertIn("2.50 Cr", cr_formatted)

        zero_formatted = indian_rupee_format(0)
        self.assertIn("0", zero_formatted)

        err_formatted = indian_rupee_format("invalid")
        self.assertEqual(err_formatted, "₹ 0")

    def test_analysis_mater_list(self):
        from .backend.analysis_functions import mater_list

        raw_df = pd.DataFrame(
            {
                "S/Loc": ["SL01"],
                "Vendor Code & Name": ["V-101 Supplier"],
                "Creater": ["USER1"],
                "Material": ["M-9901"],
                "Material Type Description": ["Raw Material"],
                "Description": ["High tensile steel coil"],
                "Spec": ["IS 2062"],
                "G/L acct.": ["410001"],
                "Cost Ctr.": ["CC-01"],
                "PO Date": ["2026-01-10"],
                "Purchase order": ["PO-1001"],
                "PO Currency": ["INR"],
                "Net price": [5000],
                "PO Qty": [100],
                "Pstng Date": ["2026-01-20"],
                "GR Qty": [80],
                "Amount LC": [400000],
            }
        )
        res = mater_list(raw_df, raw_df)
        self.assertEqual(len(res), 1)
        self.assertIn("PO Rem", res.columns)
        self.assertEqual(res["PO Rem"].iloc[0], 20)

    def test_analysis_ersa(self):
        from .backend.analysis_functions import ersa

        raw_df = pd.DataFrame(
            {
                "G/L acct": ["400100", "500200"],
                "Creater": ["USER_A", "USER_B"],
                "Material Type": ["ERSA", "FERT"],
                "PO Date": ["2026-02-01", "2026-02-02"],
                "Description": ["Spares part A", "Finished Product B"],
                "Material": ["MAT-A", "MAT-B"],
            }
        )
        res = ersa(raw_df, raw_df)
        self.assertEqual(len(res), 1)
        self.assertEqual(res["Material"].iloc[0], "MAT-A")

    def test_analysis_indir_mat(self):
        from .backend.analysis_functions import indir_mat

        raw_df = pd.DataFrame(
            {
                "Vendor": ["V1", "V1"],
                "Material": ["MAT-X", "MAT-X"],
                "Net price": [100.0, 100.0],
                "PO Date": ["2023-01-01", "2026-01-01"],  # > 730 days
                "Material Type": ["HIBE", "HIBE"],
                "Description": ["Indirect oil filter", "Indirect oil filter"],
                "Cost Ctr.": ["CC-01", "CC-01"],
                "Vendor Code & Name": ["V1 Vendor", "V1 Vendor"],
                "PO Currency": ["INR", "INR"],
            }
        )
        res = indir_mat(raw_df)
        self.assertFalse(res.empty)
        self.assertIn("Date_Diff", res.columns)

    def test_analysis_dif_mat3_and_group_by_words(self):
        from .backend.analysis_functions import dif_mat3, group_by_words

        raw_df = pd.DataFrame(
            {
                "Description": [
                    "precision ball bearing 6205",
                    "ball precision 6205 bearing",
                    "unrelated hydraulic pump",
                ],
                "Material": ["M1", "M2", "M3"],
                "Spec": ["SP1", "SP2", "SP3"],
            }
        )
        grouped = group_by_words(raw_df)
        self.assertEqual(len(grouped), 2)

        df, df2, res = dif_mat3(raw_df, raw_df)
        self.assertEqual(len(res), 2)

    def test_analysis_openpo(self):
        from .backend.analysis_functions import openpo

        raw_df = pd.DataFrame(
            {
                "Purchase order": ["PO-900"],
                "G/L acct.": ["410001"],
                "Material": ["M-900"],
                "Description": ["Conveyor Belt"],
                "PO Qty": [50],
                "PO Currency": ["INR"],
                "Material Type.": ["ROH"],
                "Spec": ["Standard"],
                "GR Qty": [10],
                "PO Date": ["2022-01-01"],  # > 750 days ago
                "Net price": [1000.0],
            }
        )
        res = openpo(raw_df)
        self.assertEqual(len(res), 1)
        self.assertEqual(res["PO Rem."].iloc[0], 40)

    def test_analysis_tab66_and_process_data_t7(self):
        from .backend.analysis_functions import process_data_t7, tab66

        raw_df = pd.DataFrame(
            {
                "Material": ["M1", "M1"],
                "Purchase order": ["PO-1", "PO-1"],
                "Pstng Date": ["2023-01-01", "2024-06-01"],  # > 365 days
                "PO Date": ["2022-01-01", "2022-01-01"],  # > 365 days from Pstng Date
                "PO Qty": [10, 10],
                "GR Qty": [5, 5],
                "Cost Ctr.": ["CC-01", "CC-01"],
                "Vendor Code & Name": ["V1", "V1"],
                "Description": ["Desc", "Desc"],
                "Spec": ["S", "S"],
                "G/L acct.": ["G1", "G1"],
            }
        )
        comb, filtered = tab66(raw_df)
        self.assertFalse(comb.empty)

        res_t7, err = process_data_t7(raw_df)
        self.assertIsNone(err)
        self.assertIsNotNone(res_t7)

    def test_plotly_chart_engines(self):
        from .backend.analysis_functions import row2_c1, row2_c2, row2_c3

        sample_df = pd.DataFrame(
            {
                "Vendor": ["Vendor A", "Vendor B", "Vendor A"],
                "Year": [2024, 2024, 2025],
                "PO Date": ["2024-01-01", "2024-06-01", "2025-01-01"],
                "Cost Ctr": ["CC-10", "CC-20", "CC-10"],
                "G/L acct": ["400100", "400200", "400100"],
                "Amount LC": [1500000, 2500000, 3000000],
            }
        )
        fig1 = row2_c1(sample_df, sample_df)
        self.assertIsNotNone(fig1)

        fig2 = row2_c2(sample_df)
        self.assertIsNotNone(fig2)

        table3, fig3 = row2_c3(sample_df)
        self.assertIsNotNone(table3)
        self.assertIsNotNone(fig3)

    def test_data_preprocessing_helpers(self):
        from .backend.data_preprocessing import dfmain, get_master_gl_data, get_master_sloc_data

        gl_df = get_master_gl_data()
        self.assertIsInstance(gl_df, pd.DataFrame)

        sloc_df = get_master_sloc_data()
        self.assertIsInstance(sloc_df, pd.DataFrame)

        main_df = pd.DataFrame(
            {
                "PO Date": ["2025-05-01"],
                "Material": ["M-101"],
                "G/L acct": ["410001"],
                "S/Loc": ["SL01"],
                "Vendor": ["V-101"],
                "Name 1": ["Global Corp"],
                "Cost Ctr": ["CC-01"],
                "PO Qty": [10],
                "GR Qty": [10],
                "Amount LC": [50000],
            }
        )
        mara_df = pd.DataFrame({"Material": ["M-101"], "Material Type": ["ROH"]})
        enriched, mara_out = dfmain(main_df, mara_df)
        self.assertIn("Material Type Description", enriched.columns)

    def test_process_data_excel_and_mara(self):
        from .backend.data_preprocessing import process_data, process_mara_data

        prpo_df = pd.DataFrame(
            {
                "S/Loc": ["SL01"],
                "Supplier": ["V-101"],
                "Name 1": ["Global Corp"],
                "Creater": ["USER1"],
                "Material": ["M-101"],
                "Description": ["Test Material"],
                "Spec": ["Standard"],
                "Unit": ["EA"],
                "G/L Acct": [410001],
                "Cost Ctr": ["CC-01"],
                "PO Date": ["2026-01-01"],
                "Purchase order": ["PO-1001"],
                "PO Currency": ["INR"],
                "Net price": [500],
                "PO Qty": [100],
                "Pstng Date": ["2026-01-10"],
                "GR Qty": [100],
                "Amount LC": [50000],
            }
        )
        prpo_buf = io.BytesIO()
        prpo_df.to_excel(prpo_buf, index=False)
        prpo_buf.seek(0)
        uploaded_prpo = SimpleUploadedFile(
            "prpo.xlsx",
            prpo_buf.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        processed = process_data([uploaded_prpo])
        self.assertIsNotNone(processed)
        self.assertEqual(len(processed), 1)

        mara_data = [
            ["SAP Report: MARA Material Master Extract", ""],
            ["Generated on: 2026-01-01", ""],
            ["Selection: Plant 1000", ""],
            ["Material", "Material Type"],
            ["M-101", "ROH"],
        ]
        mara_df = pd.DataFrame(mara_data)
        mara_buf = io.BytesIO()
        mara_df.to_excel(mara_buf, index=False, header=False)
        mara_buf.seek(0)
        uploaded_mara = SimpleUploadedFile(
            "mara.xlsx",
            mara_buf.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        processed_mara = process_mara_data([uploaded_mara])
        self.assertIsNotNone(processed_mara)
        self.assertEqual(len(processed_mara), 1)


class QLedgerViewsTests(TestCase):
    def setUp(self):
        self.client = Client()
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

    def test_dashboard_view_unauthenticated(self):
        anon_client = Client()
        res = anon_client.get(reverse("q_ledger:dashboard"))
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login/", res.url)

    def test_dashboard_view_authenticated(self):
        res = self.client.get(reverse("q_ledger:dashboard"))
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Q-Ledger", res.content)

    def test_reset_data_view(self):
        res = self.client.get(reverse("q_ledger:reset_data"), follow=True)
        self.assertEqual(res.status_code, 200)

    def test_dashboard_view_with_data_and_filters(self):
        cache_dir = Path(settings.MEDIA_ROOT) / "q_ledger_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        sample_df = pd.DataFrame(
            {
                "S/Loc": ["SL01", "SL02"],
                "Vendor": ["V-101", "V-102"],
                "Name 1": ["Global Corp", "Apex Corp"],
                "Vendor Code & Name": ["V-101 - Global Corp", "V-102 - Apex Corp"],
                "Creater": ["USER1", "USER2"],
                "Material": ["M-101", "M-102"],
                "Material Type": ["ROH", "ERSA"],
                "Material Type.": ["ROH - Raw", "ERSA - Spares"],
                "Material Type Description": ["Raw Material", "Spares"],
                "Description": ["High tensile rod", "Ball bearing 6205"],
                "Spec": ["IS 2062", "Standard"],
                "G/L acct": ["410001", "410002"],
                "G/L acct.": ["410001", "410002"],
                "G/L Acct Long Text": ["Raw material", "Spares account"],
                "Cost Ctr": ["CC-01", "CC-02"],
                "Cost Ctr.": ["CC-01", "CC-02"],
                "PO Date": ["2026-01-01", "2026-01-02"],
                "Purchase order": ["PO-1001", "PO-1002"],
                "PO Currency": ["INR", "INR"],
                "Net price": [5000, 2500],
                "PO Qty": [10, 20],
                "Pstng Date": ["2026-01-10", "2026-01-12"],
                "GR Qty": [10, 15],
                "PO Rem": [0, 5],
                "Amount LC": [50000, 50000],
            }
        )
        sample_df2 = pd.DataFrame(
            {
                "Material": ["M-101", "M-102"],
                "Material Type": ["ROH", "ERSA"],
            }
        )
        sample_df.to_json(cache_dir / "df.json", orient="split", date_format="iso")
        sample_df2.to_json(cache_dir / "df2.json", orient="split", date_format="iso")

        # 1. GET with active data
        res = self.client.get(reverse("q_ledger:dashboard"))
        self.assertEqual(res.status_code, 200)
        self.assertContains(res, "Global Corp")

        # 2. POST vendor_filter
        res_filter = self.client.post(
            reverse("q_ledger:dashboard"),
            data={"vendor_filter": "V-101 - Global Corp"},
        )
        self.assertEqual(res_filter.status_code, 200)

        # 3. POST upload_masters
        f_gl = SimpleUploadedFile("gl.xlsx", b"dummy", content_type="application/vnd.ms-excel")
        f_sloc = SimpleUploadedFile("sloc.xlsx", b"dummy", content_type="application/vnd.ms-excel")
        res_upload_masters = self.client.post(
            reverse("q_ledger:dashboard"),
            data={"action": "upload_masters", "gl_file": f_gl, "sloc_file": f_sloc},
        )
        self.assertEqual(res_upload_masters.status_code, 200)

    def test_export_current_view_and_reset_data(self):
        cache_dir = Path(settings.MEDIA_ROOT) / "q_ledger_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        filtered_cache = cache_dir / "filtered_df.json"
        df_cache = cache_dir / "df.json"

        # 1. Reset data view
        res_reset = self.client.get(reverse("q_ledger:reset_data"))
        self.assertEqual(res_reset.status_code, 302)
        self.assertEqual(self.client.session.get("selected_vendor", ""), "")

        # 2. Export when no cache exists -> 404
        filtered_cache.unlink(missing_ok=True)
        df_cache.unlink(missing_ok=True)
        res_export_404 = self.client.get(reverse("q_ledger:export_current_view"))
        self.assertEqual(res_export_404.status_code, 404)

        # 3. Export when cache exists -> 200 .xlsx
        sample_df = pd.DataFrame({"Vendor": ["V-101"], "Amount LC": [50000]})
        sample_df.to_json(df_cache, orient="split", date_format="iso")
        res_export_200 = self.client.get(reverse("q_ledger:export_current_view"))
        self.assertEqual(res_export_200.status_code, 200)
        self.assertEqual(
            res_export_200["Content-Type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    @patch("q_ledger.services.process_data")
    @patch("q_ledger.services.process_mara_data")
    @patch("q_ledger.services.dfmain")
    def test_dashboard_view_upload_action(self, mock_dfmain, mock_mara, mock_process):
        sample_df = pd.DataFrame(
            {
                "S/Loc": ["SL01"],
                "Vendor": ["V-101"],
                "Name 1": ["Global Corp"],
                "Vendor Code & Name": ["V-101 - Global Corp"],
                "Creater": ["USER1"],
                "Material": ["M-101"],
                "Material Type": ["ROH"],
                "Material Type.": ["ROH - Raw"],
                "Material Type Description": ["Raw Material"],
                "Description": ["High tensile rod"],
                "Spec": ["IS 2062"],
                "G/L acct": ["410001"],
                "G/L acct.": ["410001"],
                "G/L Acct Long Text": ["Raw material"],
                "Cost Ctr": ["CC-01"],
                "Cost Ctr.": ["CC-01"],
                "PO Date": ["2026-01-01"],
                "Purchase order": ["PO-1001"],
                "PO Currency": ["INR"],
                "Net price": [5000],
                "PO Qty": [10],
                "Pstng Date": ["2026-01-10"],
                "GR Qty": [10],
                "PO Rem": [0],
                "Amount LC": [50000],
            }
        )
        sample_df2 = pd.DataFrame({"Material": ["M-101"], "Material Type": ["ROH"]})

        mock_process.return_value = sample_df
        mock_mara.return_value = sample_df2
        mock_dfmain.return_value = (sample_df, sample_df2)

        f_prpo = SimpleUploadedFile(
            "prpo.xlsx", b"dummy_content", content_type="application/vnd.ms-excel"
        )
        f_mara = SimpleUploadedFile(
            "mara.xlsx", b"dummy_content", content_type="application/vnd.ms-excel"
        )

        res_upload = self.client.post(
            reverse("q_ledger:dashboard"),
            data={"action": "upload", "prpo_file": f_prpo, "mara_file": f_mara},
        )
        self.assertEqual(res_upload.status_code, 200)
        self.assertContains(res_upload, "Global Corp")


class QLedgerDataPreprocessingTests(TestCase):
    def test_get_master_gl_and_sloc_data_defaults(self):
        gl_df = get_master_gl_data()
        self.assertIsInstance(gl_df, pd.DataFrame)
        self.assertIn("G/L acct", gl_df.columns)

        sloc_df = get_master_sloc_data()
        self.assertIsInstance(sloc_df, pd.DataFrame)
        self.assertIn("S/Loc", sloc_df.columns)

    def test_get_master_gl_and_sloc_data_from_model(self):
        # Create temporary excel files for GL and SLoc
        gl_buf = io.BytesIO()
        pd.DataFrame(
            {"G/L acct": [410001], "G/L Acct Long Text": ["Direct Raw Material"]}
        ).to_excel(gl_buf, index=False)
        gl_buf.seek(0)

        sloc_buf = io.BytesIO()
        pd.DataFrame(
            {"Plnt": ["P001"], "S/Loc": ["SL01"], "S/loc Description": ["Central Warehouse"]}
        ).to_excel(sloc_buf, index=False)
        sloc_buf.seek(0)

        f_gl = SimpleUploadedFile(
            "gl.xlsx", gl_buf.getvalue(), content_type="application/vnd.ms-excel"
        )
        f_sloc = SimpleUploadedFile(
            "sloc.xlsx", sloc_buf.getvalue(), content_type="application/vnd.ms-excel"
        )

        cfg = LedgerMasterConfig.objects.create(
            gl_file=f_gl,
            sloc_file=f_sloc,
            is_active=True,
        )

        gl_loaded = get_master_gl_data()
        self.assertFalse(gl_loaded.empty)
        self.assertEqual(gl_loaded.iloc[0]["G/L acct"], 410001)

        sloc_loaded = get_master_sloc_data()
        self.assertFalse(sloc_loaded.empty)
        self.assertEqual(sloc_loaded.iloc[0]["S/Loc"], "SL01")

        # Test corrupt file handle on model
        cfg.gl_file.name = "non_existent_path.xlsx"
        cfg.save()
        gl_fallback = get_master_gl_data()
        self.assertIsInstance(gl_fallback, pd.DataFrame)

    def test_process_data_variations(self):
        # 1. Empty or None files
        self.assertIsNone(process_data([]))
        self.assertIsNone(process_data(None))

        # 2. Corrupt file
        corrupt_buf = io.BytesIO(b"NOT_AN_EXCEL_FILE")
        self.assertIsNone(process_data([corrupt_buf]))

        # 3. Valid file with alternate column names
        valid_buf = io.BytesIO()
        raw_df = pd.DataFrame(
            {
                "Supplier": ["V-8800"],  # Renamed to Vendor
                "Name 1": ["Tech Dynamics"],
                "G/L Acct": [400010],  # Renamed to G/L acct
                "Storage Location": ["SL02"],  # Renamed to S/Loc
                "PO Qty": [50],
                "GR Qty": [20],  # PO Rem should be 30
                "PO Date": ["2026-02-01"],
                "Pstng Date": ["2026-02-10"],
                "Amount LC": [250000.0],
                "Purchase order": ["PO-4501"],
                "Material": ["M-99"],
            }
        )
        raw_df.to_excel(valid_buf, index=False)
        valid_buf.seek(0)

        processed_df = process_data([valid_buf])
        self.assertIsNotNone(processed_df)
        self.assertEqual(len(processed_df), 1)
        self.assertIn("Vendor", processed_df.columns)
        self.assertIn("S/Loc", processed_df.columns)
        self.assertEqual(processed_df.iloc[0]["PO Rem"], 30)
        self.assertEqual(processed_df.iloc[0]["PO Currency"], "<NA>")

    def test_process_mara_data_variations(self):
        # 1. Empty or None
        self.assertIsNone(process_mara_data([]))
        self.assertIsNone(process_mara_data(None))

        # 2. Corrupt file
        corrupt_buf = io.BytesIO(b"INVALID_MARA_BYTES")
        self.assertIsNone(process_mara_data([corrupt_buf]))

        # 3. File with header at row 3 (standard SAP extract format)
        mara_buf = io.BytesIO()
        df_header3 = pd.DataFrame(
            [
                ["Header Info 1", ""],
                ["Header Info 2", ""],
                ["Header Info 3", ""],
                ["Material", "Material Type"],
                ["M-99", "ROH"],
            ]
        )
        df_header3.to_excel(mara_buf, index=False, header=False)
        mara_buf.seek(0)
        mara_res = process_mara_data([mara_buf])
        self.assertIsNotNone(mara_res)
        self.assertEqual(len(mara_res), 1)

        # 4. File with header at row 0 and sufficient rows so header=3 doesn't crash on length
        mara_buf2 = io.BytesIO()
        df_header0 = pd.DataFrame(
            {
                "Material": ["M-101", "M-102", "M-103", "M-104"],
                "Material Type": ["ROH", "HAWA", "VERP", "FERT"],
            }
        )
        df_header0.to_excel(mara_buf2, index=False)
        mara_buf2.seek(0)
        mara_res2 = process_mara_data([mara_buf2])
        self.assertIsNotNone(mara_res2)
        self.assertEqual(len(mara_res2), 4)

    def test_dfmain_enrichment_pipeline(self):
        # 1. First run without background masters
        main_df = pd.DataFrame(
            {
                "PO Date": ["2026-01-15"],
                "Material": ["M-99"],
                "G/L acct": ["410001"],
                "S/Loc": ["SL01"],
                "Vendor": ["V-8800"],
                "Name 1": ["Tech Dynamics"],
                "Cost Ctr": [None],
                "Amount LC": [None],
                "Cost Center name": ["HQ Operations"],
                "G/L Acct Long Text": ["Raw Material Expenses"],
            }
        )
        mara_df = pd.DataFrame({"Material": ["M-99"], "Material Type": ["ROH"]})

        enriched_main, enriched_mara = dfmain(main_df, mara_df)
        self.assertIn("Material Type.", enriched_main.columns)
        self.assertIn("Vendor Code & Name", enriched_main.columns)
        self.assertIn("Cost Ctr.", enriched_main.columns)
        self.assertIn("HQ Operations", enriched_main.iloc[0]["Cost Ctr."])
        self.assertEqual(enriched_main.iloc[0]["G/L acct."], "410001 - N/A")
        self.assertEqual(enriched_main.iloc[0]["Cost Ctr"], "none")
        self.assertEqual(enriched_main.iloc[0]["Amount LC"], 0)

        # 2. Second run with background SLoc master
        sloc_buf = io.BytesIO()
        pd.DataFrame({"S/Loc": ["SL01"], "S/loc Description": ["Warehouse Alpha"]}).to_excel(
            sloc_buf, index=False
        )
        sloc_buf.seek(0)
        f_sloc = SimpleUploadedFile(
            "sloc_active.xlsx", sloc_buf.getvalue(), content_type="application/vnd.ms-excel"
        )
        LedgerMasterConfig.objects.create(sloc_file=f_sloc, is_active=True)

        enriched_with_sloc, _ = dfmain(main_df, mara_df)
        self.assertIn("Warehouse Alpha", enriched_with_sloc.iloc[0]["S/Loc."])


class QLedgerServicesTests(TestCase):
    def test_ingest_master_files_with_real_excel(self):
        from .services import ensure_masters_initialized, ingest_master_files, reset_ledger_cache

        gl_buf = io.BytesIO()
        pd.DataFrame(
            {"G/L acct": [410001, 410002], "G/L Acct Long Text": ["Raw Material", "Packaging"]}
        ).to_excel(gl_buf, index=False)
        gl_buf.seek(0)
        f_gl = SimpleUploadedFile(
            "valid_gl.xlsx", gl_buf.getvalue(), content_type="application/vnd.ms-excel"
        )

        sloc_buf = io.BytesIO()
        pd.DataFrame(
            {"S/Loc": ["SL01", "SL02"], "S/loc Description": ["Plant Store", "Warehouse"]}
        ).to_excel(sloc_buf, index=False)
        sloc_buf.seek(0)
        f_sloc = SimpleUploadedFile(
            "valid_sloc.xlsx", sloc_buf.getvalue(), content_type="application/vnd.ms-excel"
        )

        gl_cnt, sloc_cnt = ingest_master_files(gl_file=f_gl, sloc_file=f_sloc)
        self.assertEqual(gl_cnt, 2)
        self.assertEqual(sloc_cnt, 2)

        config = ensure_masters_initialized()
        self.assertEqual(config.gl_account_count, 2)
        self.assertEqual(config.sloc_count, 2)

        reset_ledger_cache()

    def test_ingest_ledger_datasets_with_real_excel(self):
        from .services import ingest_ledger_datasets

        # Empty prpo returns None, 0
        df_none, cnt_zero = ingest_ledger_datasets(prpo_files=[])
        self.assertIsNone(df_none)
        self.assertEqual(cnt_zero, 0)

        prpo_buf = io.BytesIO()
        pd.DataFrame(
            {
                "S/Loc": ["SL01"],
                "Supplier": ["V-99"],
                "Name 1": ["Seed Supplier"],
                "Creater": ["USER_01"],
                "Material": ["M-99"],
                "Description": ["Component Part"],
                "Spec": ["IS 2062"],
                "Unit": ["EA"],
                "G/L Acct": [410001],
                "Cost Ctr": ["CC-01"],
                "PO Date": ["2026-02-01"],
                "Purchase order": ["PO-9901"],
                "PO Currency": ["INR"],
                "Net price": [1000.0],
                "PO Qty": [20],
                "Pstng Date": ["2026-02-10"],
                "GR Qty": [15],
                "Amount LC": [15000.0],
            }
        ).to_excel(prpo_buf, index=False)
        prpo_buf.seek(0)
        f_prpo = SimpleUploadedFile(
            "prpo_valid.xlsx", prpo_buf.getvalue(), content_type="application/vnd.ms-excel"
        )

        # Ingest with mara_files=None -> exercises fallback MARA generation
        df, count = ingest_ledger_datasets(prpo_files=[f_prpo], mara_files=None)
        self.assertIsNotNone(df)
        self.assertEqual(count, 1)

    def test_ingest_master_files_sloc_error(self):
        from .services import ingest_master_files

        bad_file = SimpleUploadedFile(
            "corrupt_sloc.xlsx", b"not-an-excel", content_type="application/vnd.ms-excel"
        )
        with self.assertRaises(ValueError):
            ingest_master_files(sloc_file=bad_file)

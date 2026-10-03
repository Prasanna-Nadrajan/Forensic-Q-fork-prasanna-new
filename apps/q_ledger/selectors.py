"""
Q-Ledger Forensic Selectors Layer
Read-only queries, data filtering routines, KPI aggregations, Plotly charts,
and forensic checkpoint table generation.
"""

import json
from pathlib import Path
from typing import Any

import pandas as pd
from django.conf import settings
from loguru import logger

from .backend import (
    dif_mat3,
    ersa,
    indian_rupee_format,
    indir_mat,
    mater_list,
    openpo,
    process_data_t7,
    row2_c1,
    row2_c2,
    row2_c3,
    tab66,
)
from .models import LedgerMasterConfig

PERSISTENT_CACHE_DIR = Path(settings.MEDIA_ROOT) / "q_ledger_cache"


def get_master_config() -> LedgerMasterConfig | None:
    """
    Fetches the currently active LedgerMasterConfig record.
    """
    return LedgerMasterConfig.objects.filter(is_active=True).first()


def get_active_dataset() -> tuple[pd.DataFrame | None, pd.DataFrame | None]:
    """
    Reads the cached forensic datasets from disk.
    If not yet cached, triggers initialization via services layer.
    """
    from .services import get_or_load_backend_dataset

    df_cache = PERSISTENT_CACHE_DIR / "df.json"
    df2_cache = PERSISTENT_CACHE_DIR / "df2.json"

    if df_cache.exists() and df2_cache.exists():
        try:
            df = pd.read_json(df_cache, orient="split")
            df2 = pd.read_json(df2_cache, orient="split")
            return df, df2
        except Exception as exc:
            logger.warning("Could not read cached backend dataset in selector: {}", exc)

    return get_or_load_backend_dataset()


def get_vendor_list(df: pd.DataFrame | None) -> list[str]:
    """
    Extracts sorted, unique list of vendor names and codes from active dataset.
    """
    if df is None or df.empty or "Vendor Code & Name" not in df.columns:
        return []

    return sorted(
        [str(v) for v in df["Vendor Code & Name"].dropna().unique().tolist() if str(v).strip()]
    )


def get_filtered_dataset(df: pd.DataFrame | None, selected_vendor: str = "") -> pd.DataFrame | None:
    """
    Filters the dataset by selected vendor and caches the filtered slice for export.
    """
    if df is None or df.empty:
        return None

    filtered_df = df.copy()
    if selected_vendor:
        mask = pd.Series(False, index=filtered_df.index)
        if "Vendor Code & Name" in filtered_df.columns:
            mask = mask | (filtered_df["Vendor Code & Name"] == selected_vendor)
        if "Vendor" in filtered_df.columns:
            mask = mask | (filtered_df["Vendor"].astype(str) == selected_vendor)
        if "Name 1" in filtered_df.columns:
            mask = mask | (filtered_df["Name 1"].astype(str) == selected_vendor)
        filtered_df = filtered_df[mask]

    try:
        filtered_df.to_json(
            PERSISTENT_CACHE_DIR / "filtered_df.json", orient="split", date_format="iso"
        )
    except Exception as exc:
        logger.debug("Failed caching filtered_df: {}", exc)

    return filtered_df


def get_ledger_kpis(filtered_df: pd.DataFrame | None) -> dict[str, Any]:
    """
    Computes top-level forensic procurement KPIs across the active slice.
    """
    if filtered_df is None or filtered_df.empty:
        return {
            "total_amount": "₹ 0",
            "total_amount_raw": 0,
            "vendor_count": 0,
            "material_count": 0,
            "cost_count": 0,
            "gl_count": 0,
            "po_count": 0,
            "creator_count": 0,
        }

    total_spend_raw = filtered_df["Amount LC"].sum() if "Amount LC" in filtered_df.columns else 0

    return {
        "total_amount": indian_rupee_format(total_spend_raw),
        "total_amount_raw": int(total_spend_raw),
        "vendor_count": (filtered_df["Vendor"].nunique() if "Vendor" in filtered_df.columns else 0),
        "material_count": (
            filtered_df["Material"].nunique() if "Material" in filtered_df.columns else 0
        ),
        "cost_count": (
            filtered_df["Cost Ctr"].nunique() if "Cost Ctr" in filtered_df.columns else 0
        ),
        "gl_count": (filtered_df["G/L acct"].nunique() if "G/L acct" in filtered_df.columns else 0),
        "po_count": (
            filtered_df["Purchase order"].nunique()
            if "Purchase order" in filtered_df.columns
            else 0
        ),
        "creator_count": (
            filtered_df["Creater"].nunique() if "Creater" in filtered_df.columns else 0
        ),
    }


def get_top_rankings(
    filtered_df: pd.DataFrame | None, selected_vendor: str = ""
) -> dict[str, list[dict[str, Any]]]:
    """
    Extracts Top 5 rankings for Vendors, G/L Accounts, and Storage Locations.
    """
    if filtered_df is None or filtered_df.empty:
        return {"top_vendors": [], "top_gl": [], "top_sloc": []}

    top_vendors: list[dict[str, Any]] = []
    if (
        not selected_vendor
        and "Vendor" in filtered_df.columns
        and "Name 1" in filtered_df.columns
        and "Amount LC" in filtered_df.columns
    ):
        top_vendor_df = (
            filtered_df.groupby(["Vendor", "Name 1"])["Amount LC"]
            .sum()
            .reset_index()
            .sort_values(by="Amount LC", ascending=False)
            .head(5)
        )
        top_vendor_df["Formatted_Amount"] = top_vendor_df["Amount LC"].apply(indian_rupee_format)
        top_vendor_df = top_vendor_df.rename(
            columns={"Vendor": "vendor_id", "Name 1": "vendor_name"}
        )
        top_vendors = top_vendor_df.to_dict(orient="records")

    top_gl: list[dict[str, Any]] = []
    if "G/L acct" in filtered_df.columns and "Amount LC" in filtered_df.columns:
        top_gl_df = (
            filtered_df.groupby("G/L acct")["Amount LC"]
            .sum()
            .reset_index()
            .sort_values(by="Amount LC", ascending=False)
            .head(5)
        )
        top_gl_df["Formatted_Amount"] = top_gl_df["Amount LC"].apply(indian_rupee_format)
        top_gl_df = top_gl_df.rename(columns={"G/L acct": "gl_account"})
        top_gl = top_gl_df.to_dict(orient="records")

    top_sloc: list[dict[str, Any]] = []
    if "S/Loc" in filtered_df.columns and "Amount LC" in filtered_df.columns:
        top_sloc_df = (
            filtered_df.groupby("S/Loc")["Amount LC"]
            .sum()
            .reset_index()
            .sort_values(by="Amount LC", ascending=False)
            .head(5)
        )
        top_sloc_df["Formatted_Amount"] = top_sloc_df["Amount LC"].apply(indian_rupee_format)
        top_sloc_df = top_sloc_df.rename(columns={"S/Loc": "sloc_code"})
        top_sloc = top_sloc_df.to_dict(orient="records")

    return {
        "top_vendors": top_vendors,
        "top_gl": top_gl,
        "top_sloc": top_sloc,
    }


def get_ledger_charts(filtered_df: pd.DataFrame | None) -> dict[str, str | None]:
    """
    Renders standalone Plotly figures for Vendor spend distribution, Cost Centers, and G/L accounts.
    """
    if filtered_df is None or filtered_df.empty:
        return {"vendor_chart_html": None, "cost_chart_html": None, "gl_chart_html": None}

    vendor_chart_html = None
    cost_chart_html = None
    gl_chart_html = None

    try:
        if (
            "G/L acct" in filtered_df.columns
            and "Cost Ctr" in filtered_df.columns
            and "Amount LC" in filtered_df.columns
        ):
            top_gl_pivot = (
                filtered_df.groupby(["G/L acct", "Cost Ctr"])["Amount LC"].sum().reset_index()
            )
            vendor_fig = row2_c1(top_gl_pivot, filtered_df)
            vendor_chart_html = vendor_fig.to_html(
                full_html=False, include_plotlyjs="cdn", config={"displayModeBar": False}
            )
    except Exception as exc:
        logger.debug("Vendor chart generation error: {}", exc)

    try:
        cost_fig = row2_c2(filtered_df)
        cost_chart_html = cost_fig.to_html(
            full_html=False, include_plotlyjs=False, config={"displayModeBar": False}
        )
    except Exception as exc:
        logger.debug("Cost chart generation error: {}", exc)

    try:
        _, gl_fig = row2_c3(filtered_df)
        gl_chart_html = gl_fig.to_html(
            full_html=False, include_plotlyjs=False, config={"displayModeBar": False}
        )
    except Exception as exc:
        logger.debug("GL chart generation error: {}", exc)

    return {
        "vendor_chart_html": vendor_chart_html,
        "cost_chart_html": cost_chart_html,
        "gl_chart_html": gl_chart_html,
    }


def get_checkpoint_tables(
    filtered_df: pd.DataFrame | None, df2: pd.DataFrame | None
) -> dict[str, dict[str, Any]]:
    """
    Executes forensic anomaly detection routines across all 7 procurement checkpoints.
    """
    if filtered_df is None or filtered_df.empty:
        empty = {"columns": [], "rows": [], "count": 0}
        return {
            "checkpoint_prpo": empty,
            "checkpoint_material": empty,
            "checkpoint_ersa": empty,
            "checkpoint_openpo": empty,
            "checkpoint_unitprice": empty,
            "checkpoint_diffmaterial": empty,
            "checkpoint_receiptgap": empty,
            "checkpoint_receipt1year": empty,
        }

    df2_safe = df2.copy() if df2 is not None else filtered_df.copy()

    # 0. PR/PO List
    try:
        cp_prpo = prepare_table_dict(filtered_df.copy())
    except Exception as exc:
        logger.debug("PRPO table error: {}", exc)
        cp_prpo = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 1. Material
    try:
        mat_df = mater_list(filtered_df.copy(), filtered_df.copy())
        cp_material = prepare_table_dict(mat_df)
    except Exception as exc:
        logger.debug("Material table error: {}", exc)
        cp_material = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 2. ERSA
    try:
        ersa_df = ersa(filtered_df.copy(), df2_safe)
        cp_ersa = prepare_table_dict(ersa_df)
    except Exception as exc:
        logger.debug("ERSA table error: {}", exc)
        cp_ersa = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 3. Open PO
    try:
        openpo_df = openpo(filtered_df.copy())
        cp_openpo = prepare_table_dict(openpo_df)
    except Exception as exc:
        logger.debug("Open PO table error: {}", exc)
        cp_openpo = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 4. Unit Price
    try:
        unitprice_df = indir_mat(filtered_df.copy())
        cp_unitprice = prepare_table_dict(unitprice_df)
    except Exception as exc:
        logger.debug("Unit price table error: {}", exc)
        cp_unitprice = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 5. Diff Material
    try:
        _, _, diffmat_df = dif_mat3(filtered_df.copy(), df2_safe)
        cp_diffmaterial = prepare_table_dict(diffmat_df)
    except Exception as exc:
        logger.debug("Diff material table error: {}", exc)
        cp_diffmaterial = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 6. Receipt Gap
    try:
        receiptgap_df, _ = tab66(filtered_df.copy())
        cp_receiptgap = prepare_table_dict(receiptgap_df)
    except Exception as exc:
        logger.debug("Receipt gap table error: {}", exc)
        cp_receiptgap = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    # 7. Receipt 1 Year
    try:
        receipt1year_df, err = process_data_t7(filtered_df.copy())
        if err:
            cp_receipt1year = {"error": err, "columns": [], "rows": [], "count": 0}
        else:
            cp_receipt1year = prepare_table_dict(receipt1year_df)
    except Exception as exc:
        logger.debug("Receipt 1 year table error: {}", exc)
        cp_receipt1year = {"error": str(exc), "columns": [], "rows": [], "count": 0}

    return {
        "checkpoint_prpo": cp_prpo,
        "checkpoint_material": cp_material,
        "checkpoint_ersa": cp_ersa,
        "checkpoint_openpo": cp_openpo,
        "checkpoint_unitprice": cp_unitprice,
        "checkpoint_diffmaterial": cp_diffmaterial,
        "checkpoint_receiptgap": cp_receiptgap,
        "checkpoint_receipt1year": cp_receipt1year,
    }


def get_export_dataframe(selected_vendor: str = "") -> tuple[pd.DataFrame | None, str]:
    """
    Loads active or filtered dataset from cache and constructs a sanitized export filename.
    """
    file_path = PERSISTENT_CACHE_DIR / "filtered_df.json"
    if not file_path.exists():
        file_path = PERSISTENT_CACHE_DIR / "df.json"
        if not file_path.exists():
            return None, ""

    try:
        df = pd.read_json(file_path, orient="split")
    except Exception as exc:
        logger.error("Failed to load export dataframe: {}", exc)
        return None, ""

    if selected_vendor:
        safe_name = "".join(c if c.isalnum() or c in ("_", "-") else "_" for c in selected_vendor)
        filename = f"QLedger_{safe_name}.xlsx"
    else:
        filename = "QLedger_Consolidated_Vendors.xlsx"

    return df, filename


def prepare_table_dict(df: pd.DataFrame | None, max_rows: int = 500) -> dict[str, Any]:
    """
    Converts a pandas DataFrame into column headers and JSON-serializable row records
    for high-performance Tabulator.js / HTML table rendering.
    """
    if df is None or df.empty:
        return {"columns": "[]", "rows": "[]", "count": 0}

    limited_df = df.head(max_rows).copy()
    limited_df = limited_df.fillna("—")

    # Sanitize column names for Tabulator fields (replace empty with 'unnamed')
    cols = []
    for c in limited_df.columns:
        c_str = str(c).strip()
        if not c_str:
            c_str = "unnamed"
        cols.append(c_str)

    limited_df.columns = cols
    columns = [{"title": col, "field": col} for col in cols]
    records = limited_df.to_dict(orient="records")

    clean_records = []
    for r in records:
        clean_row = {}
        for k, v in r.items():
            if isinstance(v, pd.Timestamp):
                clean_row[str(k)] = v.strftime("%Y-%m-%d")
            elif pd.isna(v):  # Catches NaN, NaT, None
                clean_row[str(k)] = "—"
            else:
                clean_row[str(k)] = str(v) if not isinstance(v, (int, float, bool)) else v
        clean_records.append(clean_row)

    return {
        "columns": json.dumps(columns),
        "rows": json.dumps(clean_records),
        "count": len(df),
    }

"""
Q-Ledger Services Layer (Business Logic & Mutations)
Handles master configuration initialization, SAP PR/PO file ingestion,
and dataset caching under atomic transactions.
"""

from pathlib import Path
from typing import Any

import pandas as pd
from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from loguru import logger

from .backend import dfmain, process_data, process_mara_data
from .models import LedgerDataset, LedgerMasterConfig

BASE_DIR = Path(settings.BASE_DIR)
BACKEND_DATA_DIR = BASE_DIR / "apps" / "q_ledger" / "backend" / "data"
PERSISTENT_CACHE_DIR = Path(settings.MEDIA_ROOT) / "q_ledger_cache"
PERSISTENT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
MASTERS_DIR = Path(settings.MEDIA_ROOT) / "q_ledger" / "masters"
MASTERS_DIR.mkdir(parents=True, exist_ok=True)


@transaction.atomic
def ensure_masters_initialized() -> LedgerMasterConfig:
    """
    Ensures GL Account and SLoc master reference files are stored in the background.
    If no active configuration exists, seeds it from the assets directory.
    """
    config = LedgerMasterConfig.objects.filter(is_active=True).first()
    if config:
        return config

    fallback_gl = (
        BASE_DIR / "apps" / "q_ledger" / "assets" / "GL Acct Data" / "GL account list.xlsx"
    )
    fallback_sloc = BASE_DIR / "apps" / "q_ledger" / "assets" / "SLoc Desc" / "Sloc Desc.xlsx"

    gl_count = 0
    sloc_count = 0

    config = LedgerMasterConfig.objects.create(is_active=True)

    if fallback_gl.exists():  # pragma: no cover
        try:
            df_gl = pd.read_excel(fallback_gl)
            gl_count = len(df_gl)
            with open(fallback_gl, "rb") as f:
                config.gl_file.save("gl_account_list.xlsx", f, save=False)
        except Exception as exc:
            logger.warning("Could not seed GL master file: {}", exc)

    if fallback_sloc.exists():  # pragma: no cover
        try:
            df_sloc = pd.read_excel(fallback_sloc)
            sloc_count = len(df_sloc)
            with open(fallback_sloc, "rb") as f:
                config.sloc_file.save("sloc_desc.xlsx", f, save=False)
        except Exception as exc:
            logger.warning("Could not seed SLoc master file: {}", exc)

    config.gl_account_count = gl_count
    config.sloc_count = sloc_count
    config.save()
    logger.info("Initialized background master config: {} GLs, {} SLocs", gl_count, sloc_count)
    return config


@transaction.atomic
def ingest_master_files(
    *,
    gl_file: Any = None,
    sloc_file: Any = None,
) -> tuple[int, int]:
    """
    Updates GL Account and/or SLoc master reference files and purges persistent cache
    to force dataset re-enrichment against the newly uploaded masters.
    """
    config = ensure_masters_initialized()
    gl_count = config.gl_account_count
    sloc_count = config.sloc_count

    if gl_file:
        try:
            df_gl = pd.read_excel(gl_file)
            gl_count = len(df_gl)
            config.gl_file.save(gl_file.name, gl_file, save=False)
            logger.info("Ingested new G/L Master with {} accounts", gl_count)
        except Exception as exc:
            logger.error("Failed to parse uploaded GL Master: {}", exc)
            raise

    if sloc_file:
        try:
            df_sloc = pd.read_excel(sloc_file)
            sloc_count = len(df_sloc)
            config.sloc_file.save(sloc_file.name, sloc_file, save=False)
            logger.info("Ingested new SLoc Master with {} locations", sloc_count)
        except Exception as exc:
            logger.error("Failed to parse uploaded SLoc Master: {}", exc)
            raise

    config.gl_account_count = gl_count
    config.sloc_count = sloc_count
    config.save()

    # Clear cache so data is re-enriched with new master files
    reset_ledger_cache()

    return gl_count, sloc_count


@transaction.atomic
def ingest_ledger_datasets(
    *,
    prpo_files: list[Any],
    mara_files: list[Any] | None = None,
) -> tuple[pd.DataFrame | None, int]:
    """
    Processes uploaded SAP PR/PO and MARA evidence files, executes enrichment,
    persists cache files to disk, and records an active LedgerDataset entry.
    """
    if not prpo_files:
        return None, 0

    logger.info(
        "Ingesting {} PR/PO files and {} MARA master files",
        len(prpo_files),
        len(mara_files or []),
    )
    df = process_data(prpo_files)
    df2 = process_mara_data(mara_files) if mara_files else None

    if df is None or df.empty:
        return None, 0

    if df2 is None or df2.empty:
        df2 = df[["Material"]].copy()
        df2["Material Type"] = "Not Applicable"
        df2 = df2.drop_duplicates(subset=["Material"])

    df, df2 = dfmain(df, df2)

    # Save to persistent cache storage
    df_cache = PERSISTENT_CACHE_DIR / "df.json"
    df2_cache = PERSISTENT_CACHE_DIR / "df2.json"
    df.to_json(df_cache, orient="split", date_format="iso")
    df2.to_json(df2_cache, orient="split", date_format="iso")

    first_prpo = prpo_files[0]
    first_mara = mara_files[0] if mara_files else None

    dataset = LedgerDataset.objects.create(
        title=getattr(first_prpo, "name", "SAP PR/PO Upload"),
        record_count=len(df),
        total_spend=float(df["Amount LC"].sum()) if "Amount LC" in df.columns else 0.0,
        is_active=True,
    )
    dataset.prpo_file.save(first_prpo.name, first_prpo, save=False)
    if first_mara:
        dataset.mara_file.save(first_mara.name, first_mara, save=False)
    dataset.save()

    logger.info("Successfully ingested and cached {} SAP records", len(df))
    return df, len(df)


def get_or_load_backend_dataset() -> tuple[pd.DataFrame | None, pd.DataFrame | None]:
    """
    Retrieves cached backend dataset or seeds the initial 2 Excel files
    (sample_prpo_extract.xlsx and sample_mara_master.xlsx) from the backend.
    """
    df_cache = PERSISTENT_CACHE_DIR / "df.json"
    df2_cache = PERSISTENT_CACHE_DIR / "df2.json"

    if df_cache.exists() and df2_cache.exists():
        try:
            df = pd.read_json(df_cache, orient="split")
            df2 = pd.read_json(df2_cache, orient="split")
            return df, df2
        except Exception as exc:
            logger.warning("Could not read cached backend dataset: {}", exc)

    prpo_sample = BACKEND_DATA_DIR / "sample_prpo_extract.xlsx"
    mara_sample = BACKEND_DATA_DIR / "sample_mara_master.xlsx"

    if prpo_sample.exists():  # pragma: no cover
        logger.info("Initializing Q-Ledger with backend seed Excel files: {}", prpo_sample)
        with open(prpo_sample, "rb") as f_prpo:
            prpo_content = f_prpo.read()
            df = process_data([ContentFile(prpo_content, name="sample_prpo_extract.xlsx")])

        df2 = None
        if mara_sample.exists():
            with open(mara_sample, "rb") as f_mara:
                mara_content = f_mara.read()
                df2 = process_mara_data([ContentFile(mara_content, name="sample_mara_master.xlsx")])

        if df is not None and not df.empty:
            if df2 is None or df2.empty:
                df2 = df[["Material"]].copy()
                df2["Material Type"] = "Not Applicable"
                df2 = df2.drop_duplicates(subset=["Material"])

            df, df2 = dfmain(df, df2)

            df.to_json(df_cache, orient="split", date_format="iso")
            df2.to_json(df2_cache, orient="split", date_format="iso")

            if not LedgerDataset.objects.filter(is_active=True).exists():
                dataset = LedgerDataset.objects.create(
                    title="Seed SAP ERP Audit Dataset (Hyundai Ecosystem)",
                    record_count=len(df),
                    total_spend=float(df["Amount LC"].sum()) if "Amount LC" in df.columns else 0.0,
                    is_active=True,
                )
                with open(prpo_sample, "rb") as pf:
                    dataset.prpo_file.save("sample_prpo_extract.xlsx", pf, save=False)
                if mara_sample.exists():
                    with open(mara_sample, "rb") as mf:
                        dataset.mara_file.save("sample_mara_master.xlsx", mf, save=False)
                dataset.save()

            return df, df2

    return None, None


def reset_ledger_cache() -> None:
    """
    Purges all cached dataset files from the persistent cache directory.
    """
    for cache_file in PERSISTENT_CACHE_DIR.glob("*.json"):
        try:
            cache_file.unlink()
        except Exception as exc:
            logger.debug("Cache file delete error for {}: {}", cache_file, exc)

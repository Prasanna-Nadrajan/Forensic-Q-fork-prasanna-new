"""
Universal Centralized Fuzzy Search Engine & Keyword File Ingestion Service.
Provides universal RapidFuzz token/sequence matching and keyword file parsers
(.xlsx, .txt, .csv) for forensic text & narration screening across ForensiQ.
"""

import io
import re
from typing import Any

import openpyxl
from django.http import HttpRequest
from loguru import logger
from rapidfuzz import fuzz

HEADER_STOPWORDS = {
    "keyword",
    "keywords",
    "key identifier",
    "key identifiers",
    "identifier",
    "identifiers",
    "target",
    "targets",
    "term",
    "terms",
    "watchlist",
    "watchlists",
    "entity",
    "entities",
    "name",
    "names",
    "search query",
    "search terms",
}


def extract_keywords_from_string(text: str) -> list[str]:
    """
    Extracts clean, deduplicated keywords from space, tab, comma, semicolon, or newline delimited string,
    preserving multi-word phrases enclosed in double or single quotes (e.g. "shell company").
    """
    if not text:
        return []
    # Match quoted strings OR non-delimiter tokens (delimited by space, tab, comma, semicolon, newline)
    pattern = r'"([^"]+)"|\'([^\']+)\'|([^\s,;\t\r\n]+)'
    matches = re.findall(pattern, text)
    seen = set()
    keywords = []
    for m in matches:
        token = m[0] or m[1] or m[2]
        clean = token.strip()
        if clean and clean.lower() not in seen:
            seen.add(clean.lower())
            keywords.append(clean)
    return keywords


def extract_keywords_from_txt(content_or_file: bytes | str | Any) -> list[str]:
    """
    Extracts keywords from plain text file or bytes.
    Ignores comment lines starting with '#' or '//'.
    """
    if hasattr(content_or_file, "read"):
        raw = content_or_file.read()
    else:
        raw = content_or_file

    if isinstance(raw, bytes):
        for enc in ("utf-8", "latin-1", "cp1252"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = raw.decode("utf-8", errors="ignore")
    else:
        text = str(raw)

    lines = text.splitlines()
    clean_lines = []
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("#") or line_str.startswith("//"):
            continue
        clean_lines.append(line_str)

    return extract_keywords_from_string("\n".join(clean_lines))


def extract_keywords_from_xlsx(content_or_file: bytes | Any) -> list[str]:
    """
    Extracts keywords from an Excel workbook (.xlsx).
    If a header row contains a keyword/identifier column, extracts from that column.
    Otherwise, extracts from all cells, skipping header stopwords.
    """
    if hasattr(content_or_file, "read"):
        if hasattr(content_or_file, "seek"):
            content_or_file.seek(0)
        file_bytes = content_or_file.read()
    else:
        file_bytes = content_or_file

    bio = io.BytesIO(file_bytes) if isinstance(file_bytes, bytes) else file_bytes
    wb = openpyxl.load_workbook(bio, data_only=True, read_only=True)

    extracted_tokens = []
    for sheet in wb.worksheets:
        rows = list(sheet.iter_rows(values_only=True))
        if not rows:
            continue

        # Check if first row contains a target column header
        first_row = [str(c).strip().lower() if c is not None else "" for c in rows[0]]
        target_col_indices = [
            idx
            for idx, val in enumerate(first_row)
            if any(term in val for term in ("keyword", "identifier", "target", "term", "watch"))
        ]

        if target_col_indices:
            # Extract specifically from the matched column(s), skipping header
            data_rows = rows[1:]
            for row in data_rows:
                for idx in target_col_indices:
                    if idx < len(row):
                        cell_value = row[idx]
                        if cell_value is None:
                            continue
                        s = str(cell_value).strip()
                        if not s:
                            continue
                        parts = re.split(r"[,;\n\r]+", s)
                        for p in parts:
                            clean_p = p.strip()
                            if clean_p and clean_p.lower() not in HEADER_STOPWORDS:
                                extracted_tokens.append(clean_p)
        else:
            # Check if first row looks like a header (e.g. contains stopwords)
            start_row = 1 if any(val in HEADER_STOPWORDS for val in first_row) else 0
            for row in rows[start_row:]:
                for cell_value in row:
                    if cell_value is None:
                        continue
                    s = str(cell_value).strip()
                    if not s:
                        continue
                    if s.lower() in HEADER_STOPWORDS:
                        continue
                    parts = re.split(r"[,;\n\r]+", s)
                    for p in parts:
                        clean_p = p.strip()
                        if clean_p and clean_p.lower() not in HEADER_STOPWORDS:
                            extracted_tokens.append(clean_p)

    seen = set()
    keywords = []
    for token in extracted_tokens:
        if token.lower() not in seen:
            seen.add(token.lower())
            keywords.append(token)
    return keywords


def extract_keywords_from_file(file_obj: Any, filename: str = "") -> list[str]:
    """
    Auto-detects file type (.xlsx vs .txt) and extracts keywords.
    """
    name = filename or getattr(file_obj, "name", "")
    ext = name.split(".")[-1].lower() if "." in name else ""

    if ext in ("xlsx", "xlsm", "xltx"):
        return extract_keywords_from_xlsx(file_obj)
    elif ext in ("txt", "csv", "log"):
        return extract_keywords_from_txt(file_obj)
    else:
        # Fallback: attempt openpyxl first, then text decode
        try:
            return extract_keywords_from_xlsx(file_obj)
        except Exception:
            if hasattr(file_obj, "seek"):
                file_obj.seek(0)
            return extract_keywords_from_txt(file_obj)


def extract_keywords_from_request(
    request: HttpRequest,
    param_name: str = "keywords",
    file_param: str = "file",
) -> list[str]:
    """
    Extracts keywords comprehensively from both string parameter and uploaded file in request.
    Handles GET query strings, POST form-data, and attached files (.xlsx, .txt, .csv).
    """
    seen = set()
    keywords = []

    # 1. From uploaded file if present
    uploaded_file = (
        request.FILES.get(file_param)
        or request.FILES.get("keywords_file")
        or request.FILES.get("file_upload")
    )
    if uploaded_file:
        try:
            file_kws = extract_keywords_from_file(uploaded_file, uploaded_file.name)
            for kw in file_kws:
                if kw.lower() not in seen:
                    seen.add(kw.lower())
                    keywords.append(kw)
        except Exception as e:
            logger.warning("Failed to extract keywords from file {}: {}", uploaded_file.name, e)

    # 2. From text parameter (POST or GET)
    raw_str = (
        request.POST.get(param_name, "")
        or request.GET.get(param_name, "")
        or request.POST.get("q", "")
        or request.GET.get("q", "")
    ).strip()
    if raw_str:
        str_kws = extract_keywords_from_string(raw_str)
        for kw in str_kws:
            if kw.lower() not in seen:
                seen.add(kw.lower())
                keywords.append(kw)

    return keywords


def score_text_against_keywords(
    text: str,
    keywords: list[str],
    threshold: int = 80,
) -> tuple[bool, int, str]:
    """
    Matches text against a list of keywords using rapidfuzz.
    Returns (is_matched, best_score, matched_keyword).
    """
    if not text or not keywords:
        return False, 0, ""

    text_lower = text.lower()
    text_super_clean = re.sub(r"[^a-z0-9]", "", text_lower)
    text_clean = re.sub(r"[^a-z0-9\s]", " ", text_lower)
    tokens = text_clean.split()

    found = False
    best_score = 0
    matched_keyword = ""

    for kw in keywords:
        kw_clean = re.sub(r"[^a-z0-9]", "", kw.lower())
        if not kw_clean:
            continue

        # 1. Direct Substring Match (100%)
        if kw_clean in text_super_clean:
            return True, 100, kw

        # 2. Partial sequence ratio (substring distance)
        ratio_sub = fuzz.partial_ratio(text_super_clean, kw_clean)
        if ratio_sub >= threshold and ratio_sub > best_score:
            found = True
            best_score = int(ratio_sub)
            matched_keyword = kw

        # 3. Individual token distance match
        for tok in tokens:
            tok_ratio = fuzz.ratio(tok, kw_clean)
            if tok_ratio >= threshold and tok_ratio > best_score:
                found = True
                best_score = int(tok_ratio)
                matched_keyword = kw

    return found, best_score, matched_keyword

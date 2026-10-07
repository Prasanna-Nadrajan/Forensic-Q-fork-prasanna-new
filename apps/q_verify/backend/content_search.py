import re
from pathlib import Path

from loguru import logger


def _extract_text_from_pdf_ocr(file_path: str) -> str:
    """Extracts text from PDF (tries OCR, falls back to PyPDF)."""
    try:
        import pytesseract
        from pdf2image import convert_from_path

        images = convert_from_path(file_path, dpi=200)
        text = ""
        for img in images:
            text += pytesseract.image_to_string(img) + "\n"
        return text
    except Exception as e:
        logger.debug(f"OCR failed for PDF {file_path}: {e}, falling back to PyPDF")
        try:
            from pypdf import PdfReader

            reader = PdfReader(file_path)
            text = ""
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + "\n"
            return text
        except Exception as fallback_e:
            logger.debug(f"PyPDF fallback failed: {fallback_e}")
            return ""


def _extract_text_from_image_ocr(file_path: str) -> str:
    """Extracts text from images using OCR."""
    try:
        import pytesseract
        from PIL import Image

        img = Image.open(file_path)
        return pytesseract.image_to_string(img)
    except Exception as e:
        logger.debug(f"Image OCR failed for {file_path}: {e}")
        return ""


def _extract_text_from_docx(file_path: str) -> str:
    try:
        import docx

        doc = docx.Document(file_path)
        return "\n".join([p.text for p in doc.paragraphs])
    except Exception as e:
        logger.debug(f"Failed to read DOCX {file_path}: {e}")
        return ""


def _extract_text_from_xlsx(file_path: str) -> str:
    try:
        import openpyxl

        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
        text_parts = []
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for cell in row:
                    if cell is not None:
                        text_parts.append(str(cell))
        return " ".join(text_parts)
    except Exception as e:
        logger.debug(f"Failed to read XLSX {file_path}: {e}")
        return ""


def _extract_pages_from_file(storage_path: str, mime_type: str) -> list[tuple[int, str]]:
    """
    Extracts text per page/sheet/section from files.
    Returns a list of (1-indexed page number, text content).
    """
    ext = Path(storage_path).suffix.lower()
    pages: list[tuple[int, str]] = []

    if ext == ".pdf" or mime_type == "application/pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(storage_path)
            for idx, p in enumerate(reader.pages):
                t = p.extract_text() or ""
                pages.append((idx + 1, t))
        except Exception as pdf_e:
            logger.debug(f"PyPDF extraction failed for {storage_path}: {pdf_e}")

        if not pages:
            txt = _extract_text_from_pdf_ocr(storage_path)
            if txt:
                pages.append((1, txt))

    elif ext in [".jpg", ".jpeg", ".png", ".tiff"] or mime_type.startswith("image/"):
        txt = _extract_text_from_image_ocr(storage_path)
        if txt:
            pages.append((1, txt))

    elif ext == ".docx" or "wordprocessingml" in mime_type:
        txt = _extract_text_from_docx(storage_path)
        if txt:
            pages.append((1, txt))

    elif ext == ".xlsx" or "spreadsheetml" in mime_type:
        txt = _extract_text_from_xlsx(storage_path)
        if txt:
            pages.append((1, txt))

    elif ext == ".txt" or mime_type.startswith("text/"):
        try:
            with open(storage_path, encoding="utf-8", errors="ignore") as f:
                pages.append((1, f.read()))
        except Exception as txt_e:
            logger.debug(f"TXT failed for {storage_path}: {txt_e}")

    return pages


def search_keywords_with_pages(
    storage_path: str, mime_type: str, keywords: list[str]
) -> tuple[dict[str, int], dict[str, list[int]]]:
    """
    Searches for keywords across pages in the file.
    Returns:
        (counts_dict, pages_dict)
    """
    if not keywords:
        return {}, {}

    pages = _extract_pages_from_file(storage_path, mime_type)
    counts: dict[str, int] = {}
    pages_map: dict[str, list[int]] = {}

    for kw in set(keywords):
        kw_cleaned = kw.strip()
        if not kw_cleaned:
            continue
        pattern = re.compile(re.escape(kw_cleaned), re.IGNORECASE)
        total_count = 0
        pages_found = []
        for p_num, p_text in pages:
            matches = pattern.findall(p_text)
            if matches:
                total_count += len(matches)
                pages_found.append(p_num)
        counts[kw_cleaned] = total_count
        pages_map[kw_cleaned] = pages_found

    return counts, pages_map


def search_keywords_in_file(
    storage_path: str, mime_type: str, keywords: list[str]
) -> dict[str, int]:
    """
    Reads the file from storage and searches for keywords.
    Returns dict mapping keyword to match count.
    """
    try:
        counts, _ = search_keywords_with_pages(storage_path, mime_type, keywords)
        return counts
    except Exception as e:
        logger.error(f"Error during deep keyword search for {storage_path}: {e}")
        return {}

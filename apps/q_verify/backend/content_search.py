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


def search_keywords_in_file(
    storage_path: str, mime_type: str, keywords: list[str]
) -> dict[str, int]:
    """
    Reads the file from storage and searches for keywords.
    Uses OCR for PDF and images, direct extraction for Office documents.
    """
    if not keywords:
        return {}

    try:
        ext = Path(storage_path).suffix.lower()
        full_text = ""

        if ext == ".pdf" or mime_type == "application/pdf":
            full_text = _extract_text_from_pdf_ocr(storage_path)
        elif ext in [".jpg", ".jpeg", ".png", ".tiff"] or mime_type.startswith("image/"):
            full_text = _extract_text_from_image_ocr(storage_path)
        elif ext == ".docx" or "wordprocessingml" in mime_type:
            full_text = _extract_text_from_docx(storage_path)
        elif ext == ".xlsx" or "spreadsheetml" in mime_type:
            full_text = _extract_text_from_xlsx(storage_path)
        elif ext == ".txt" or mime_type.startswith("text/"):
            with open(storage_path, encoding="utf-8", errors="ignore") as f:
                full_text = f.read()

        if not full_text:
            return {}

        results = {}
        # Case insensitive match using regex
        for kw in set(keywords):
            kw_cleaned = kw.strip()
            if kw_cleaned:
                pattern = re.compile(re.escape(kw_cleaned), re.IGNORECASE)
                matches = pattern.findall(full_text)
                results[kw_cleaned] = len(matches) if matches else 0

        return results
    except Exception as e:
        logger.error(f"Error during deep keyword search for {storage_path}: {e}")
        return {}

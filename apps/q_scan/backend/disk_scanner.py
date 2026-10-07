"""
Q-Scan High-Performance Forensic Filesystem Scanner Engine
========================================================================================
Features:
- Non-recursive stack-based os.scandir() traversal for ultra-fast NTFS/FAT32 iteration
- Windows long path (\\\\?\\) support for deeply nested directory paths
- Zero-buffer streaming CSV output with physical disk fsync (flush + os.fsync)
- Memory-safe chunked binary content scanning with boundary overlap preservation
- Deep inspection of Office archives (.docx, .xlsx, .pptx) & .zip files using pure stdlib
- Configurable directory and file extension exclusion filters
- Extended forensic metadata extraction (Modified Time, Context Snippets, Match Types)
- Resilient exception bypass for locked system files, access denied, and symlink loops
========================================================================================
"""

import csv
import io
import json
import os
import re
import sys
import time
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class HighPerformanceDiskScanner:
    """
    Forensic disk inspection engine designed for high-speed triage across massive filesystems.
    """

    DEFAULT_CONTENT_EXTENSIONS = {
        ".txt",
        ".csv",
        ".log",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".md",
        ".sql",
        ".ini",
        ".env",
        ".py",
        ".bat",
        ".cmd",
        ".ps1",
        ".cfg",
        ".conf",
        ".reg",
        ".html",
        ".htm",
        ".js",
        ".ts",
        ".sh",
        ".vbs",
        ".rtf",
        ".docx",
        ".xlsx",
        ".pptx",
        ".pdf",
        ".zip",
    }

    DEFAULT_EXCLUDE_DIRECTORIES = [
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "$Recycle.Bin",
        "System Volume Information",
        "AppData\\Local\\Temp",
        "AppData\\Local\\Microsoft\\Windows",
        "AppData\\Local\\Packages",
        ".git",
        ".venv",
        "node_modules",
        "__pycache__",
    ]

    DEFAULT_EXCLUDE_EXTENSIONS = [
        ".dll",
        ".sys",
        ".exe",
        ".iso",
        ".vmdk",
        ".bin",
        ".dat",
        ".tmp",
        ".pdb",
        ".msi",
        ".obj",
        ".lib",
        ".node",
        ".pyc",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".mp4",
        ".mp3",
        ".wav",
    ]

    def __init__(
        self,
        target_directories: list[str],
        keywords: list[str],
        search_contents: bool = True,
        content_extensions: set[str] | None = None,
        exclude_directories: list[str] | None = None,
        exclude_extensions: list[str] | None = None,
        output_csv_path: str | Path = "scan_results.csv",
        chunk_size_bytes: int = 2 * 1024 * 1024,  # 2MB
        max_archive_member_bytes: int = 10 * 1024 * 1024,  # 10MB limit per zip member
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.target_directories = [
            str(Path(d).resolve()) for d in target_directories if str(d).strip()
        ]
        self.keywords = [k.strip() for k in keywords if k.strip()]
        self.keywords_lower = [k.lower() for k in self.keywords]
        self.keywords_bytes = [k.lower().encode("utf-8", errors="ignore") for k in self.keywords]
        self.max_keyword_len = max((len(kb) for kb in self.keywords_bytes), default=1)

        self.search_contents = search_contents
        self.content_extensions = (
            {
                ext.lower() if ext.startswith(".") else f".{ext.lower()}"
                for ext in content_extensions
            }
            if content_extensions is not None
            else self.DEFAULT_CONTENT_EXTENSIONS
        )

        raw_exclude_dirs = (
            exclude_directories
            if exclude_directories is not None
            else self.DEFAULT_EXCLUDE_DIRECTORIES
        )
        self.exclude_directories = []
        for d in raw_exclude_dirs:
            d_str = str(d).strip()
            if not d_str:
                continue
            self.exclude_directories.append(d_str.lower())
            try:
                p = Path(d_str)
                if p.is_absolute() or p.exists():
                    resolved = str(p.resolve()).lower()
                    if resolved not in self.exclude_directories:
                        self.exclude_directories.append(resolved)
            except (OSError, ValueError):
                continue

        raw_exclude_exts = (
            exclude_extensions
            if exclude_extensions is not None
            else self.DEFAULT_EXCLUDE_EXTENSIONS
        )
        self.exclude_extensions = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in raw_exclude_exts
            if ext.strip()
        }

        self.output_csv_path = Path(output_csv_path).resolve()
        self.chunk_size_bytes = chunk_size_bytes
        self.max_archive_member_bytes = max_archive_member_bytes
        self.progress_callback = progress_callback

        # Real-time Metrics
        self.total_dirs_scanned = 0
        self.total_files_examined = 0
        self.total_matches_found = 0
        self.total_bytes_scanned = 0
        self.total_errors_bypassed = 0
        self.is_interrupted = False

    @staticmethod
    def format_long_path(path_str: str) -> str:
        """
        Formats path for Windows API to bypass the 260-character MAX_PATH limit.
        """
        if os.name != "nt":
            return path_str

        norm_path = os.path.normpath(path_str)
        if norm_path.startswith("\\\\?\\"):
            return norm_path

        if norm_path.startswith("\\\\"):
            return "\\\\?\\UNC\\" + norm_path[2:]

        return "\\\\?\\" + norm_path

    @staticmethod
    def clean_display_path(path_str: str) -> str:
        """
        Strips Windows long path prefix for readable console display and CSV logging.
        """
        if path_str.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path_str[8:]
        if path_str.startswith("\\\\?\\"):
            return path_str[4:]
        return path_str

    def is_directory_excluded(self, dir_path: str) -> bool:
        """
        Checks if the directory path matches any configured exclusion criteria.
        Explicitly targeted root directories are not excluded.
        """
        clean_dir = self.clean_display_path(dir_path).lower()
        norm_dir = os.path.normpath(clean_dir)

        for target in self.target_directories:
            if norm_dir == os.path.normpath(self.clean_display_path(target).lower()):
                return False

        try:
            resolved_dir = str(Path(norm_dir).resolve()).lower()
        except Exception:
            resolved_dir = norm_dir

        path_parts = {part.lower() for part in Path(norm_dir).parts} | {
            part.lower() for part in Path(resolved_dir).parts
        }

        for exc in self.exclude_directories:
            exc_norm = os.path.normpath(exc)
            try:
                exc_resolved = str(Path(exc_norm).resolve()).lower()
            except Exception:
                exc_resolved = exc_norm

            if (
                norm_dir == exc_norm
                or norm_dir.startswith(exc_norm + os.sep)
                or resolved_dir == exc_resolved
                or resolved_dir.startswith(exc_resolved + os.sep)
            ):
                return True

            if (os.sep + exc_norm + os.sep) in (os.sep + norm_dir + os.sep) or (
                os.sep + exc_resolved + os.sep
            ) in (os.sep + resolved_dir + os.sep):
                return True

            if exc_norm in path_parts or exc_resolved in path_parts:
                return True

        return False

    def is_extension_excluded(self, filename: str) -> bool:
        """
        Checks if file extension is excluded.
        """
        ext = Path(filename).suffix.lower()
        return ext in self.exclude_extensions

    def run_scan(self) -> dict[str, Any]:
        """
        Executes the disk scan and streams matching records directly to CSV.
        """
        start_time = time.time()
        self._init_csv_file()

        with open(self.output_csv_path, "a", encoding="utf-8-sig", newline="") as csv_file:
            writer = csv.writer(csv_file)

            for root_dir in self.target_directories:
                if self.is_interrupted:
                    break
                self._scan_directory_tree(root_dir, writer, csv_file)

        elapsed = time.time() - start_time
        return {
            "dirs_scanned": self.total_dirs_scanned,
            "files_examined": self.total_files_examined,
            "matches_found": self.total_matches_found,
            "bytes_scanned": self.total_bytes_scanned,
            "errors_bypassed": self.total_errors_bypassed,
            "elapsed_seconds": round(elapsed, 2),
            "output_file": str(self.output_csv_path),
        }

    def _init_csv_file(self) -> None:
        """
        Initializes CSV file and writes header if file does not exist or is empty.
        """
        file_exists = self.output_csv_path.exists() and self.output_csv_path.stat().st_size > 0
        if not file_exists:
            self.output_csv_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_csv_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "Timestamp",
                        "File Path",
                        "Matched Keyword",
                        "Match Type",
                        "File Size (Bytes)",
                        "Last Modified Date",
                        "Matching Context/Snippet",
                    ]
                )
                f.flush()
                os.fsync(f.fileno())

    def _scan_directory_tree(self, root_path: str, writer: Any, csv_file: Any) -> None:
        """
        Iterates directory tree using a non-recursive stack with os.scandir().
        """
        if self.is_directory_excluded(root_path):
            return

        stack: list[str] = [self.format_long_path(root_path)]
        last_progress_update = time.time()

        while stack and not self.is_interrupted:
            current_dir = stack.pop()
            self.total_dirs_scanned += 1

            try:
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        if self.is_interrupted:
                            break

                        try:
                            # 1. Directory handling (skip excluded directories and symlinks)
                            if entry.is_dir(follow_symlinks=False):
                                if not self.is_directory_excluded(entry.path):
                                    stack.append(entry.path)
                                continue

                            # 2. File handling
                            if entry.is_file(follow_symlinks=False):
                                if self.is_extension_excluded(entry.name):
                                    continue

                                self.total_files_examined += 1
                                stat_info = entry.stat(follow_symlinks=False)
                                file_size = stat_info.st_size
                                mod_time = datetime.fromtimestamp(
                                    stat_info.st_mtime, tz=UTC
                                ).strftime("%Y-%m-%d %H:%M:%S UTC")
                                self.total_bytes_scanned += file_size

                                self._evaluate_file(entry, file_size, mod_time, writer, csv_file)

                        except (PermissionError, FileNotFoundError, OSError):
                            self.total_errors_bypassed += 1
                            continue

            except (PermissionError, FileNotFoundError, OSError):
                self.total_errors_bypassed += 1
                continue

            # Emit periodic progress callback every 250ms
            now = time.time()
            if self.progress_callback and (now - last_progress_update >= 0.25):
                last_progress_update = now
                self.progress_callback(
                    {
                        "current_dir": self.clean_display_path(current_dir),
                        "dirs_scanned": self.total_dirs_scanned,
                        "files_examined": self.total_files_examined,
                        "matches_found": self.total_matches_found,
                        "errors_bypassed": self.total_errors_bypassed,
                    }
                )

    def _evaluate_file(
        self, entry: os.DirEntry, file_size: int, mod_time: str, writer: Any, csv_file: Any
    ) -> None:
        """
        Tests filename and content against target keyword set.
        """
        cleaned_path = self.clean_display_path(entry.path)
        # Skip the output CSV itself if located within target directory
        if (
            os.path.normcase(cleaned_path) == os.path.normcase(str(self.output_csv_path))
            or entry.name.lower() == self.output_csv_path.name.lower()
        ):
            return

        filename_lower = entry.name.lower()
        ext = Path(entry.name).suffix.lower()

        # 1. Filename keyword inspection
        name_matched = False
        for kw, kw_orig in zip(self.keywords_lower, self.keywords, strict=False):
            if kw in filename_lower:
                snippet = f"Matched in filename: {entry.name}"
                self._record_match(
                    path=cleaned_path,
                    keyword=kw_orig,
                    match_type="FILENAME",
                    file_size=file_size,
                    mod_time=mod_time,
                    snippet=snippet,
                    writer=writer,
                    csv_file=csv_file,
                )
                name_matched = True

        # 2. Content keyword inspection (if enabled, file has size, and extension is eligible)
        if self.search_contents and file_size > 0:
            # Office Document Inspection (.docx, .xlsx, .pptx)
            if ext in {".docx", ".xlsx", ".pptx"}:
                self._scan_office_document(
                    entry.path, cleaned_path, ext, file_size, mod_time, writer, csv_file
                )
            # PDF Document Inspection (.pdf)
            elif ext == ".pdf":
                self._scan_pdf_document(
                    entry.path, cleaned_path, file_size, mod_time, writer, csv_file
                )
            # Zip Archive Inspection
            elif ext == ".zip":
                self._scan_zip_archive(
                    entry.path, cleaned_path, file_size, mod_time, writer, csv_file
                )
            # Text / Source / Config Content Scanning
            elif ext in self.content_extensions and not name_matched:
                self._scan_text_file_contents(
                    entry.path, cleaned_path, file_size, mod_time, writer, csv_file
                )

    def _scan_pdf_document(
        self,
        long_path: str,
        display_path: str,
        file_size: int,
        mod_time: str,
        writer: Any,
        csv_file: Any,
    ) -> None:
        """
        Inspects PDF documents for keyword matches using pypdf with pure-Python stream fallback.
        """
        try:
            text_pages = []
            try:
                from pypdf import PdfReader

                reader = PdfReader(long_path)
                for page in reader.pages:
                    t = page.extract_text()
                    if t:
                        text_pages.append(t)
            except Exception:
                with open(long_path, "rb") as f:
                    raw = f.read(5 * 1024 * 1024)
                    text_pages = [raw.decode("latin-1", errors="ignore")]

            full_text = "\n".join(text_pages)
            text_lower = full_text.lower()
            matched_in_this_file: set[str] = set()

            for kw_lower, kw_orig in zip(self.keywords_lower, self.keywords, strict=False):
                if kw_orig in matched_in_this_file:
                    continue
                pos = text_lower.find(kw_lower)
                if pos != -1:
                    matched_in_this_file.add(kw_orig)
                    snippet = self._extract_snippet_from_str(full_text, pos, len(kw_orig))
                    self._record_match(
                        path=display_path,
                        keyword=kw_orig,
                        match_type="CONTENT_PDF",
                        file_size=file_size,
                        mod_time=mod_time,
                        snippet=snippet,
                        writer=writer,
                        csv_file=csv_file,
                    )
        except Exception:
            self.total_errors_bypassed += 1

    def _scan_text_file_contents(
        self,
        long_path: str,
        display_path: str,
        file_size: int,
        mod_time: str,
        writer: Any,
        csv_file: Any,
    ) -> None:
        """
        Streams text/binary file contents in chunks with boundary overlap to catch split keywords.
        """
        try:
            with open(long_path, "rb") as f:
                overlap_buffer = b""
                matched_in_this_file: set[str] = set()

                while not self.is_interrupted:
                    chunk = f.read(self.chunk_size_bytes)
                    if not chunk:
                        break

                    # Prepend overlap from previous chunk to catch boundary splits
                    data_to_search = (overlap_buffer + chunk).lower()

                    for kw_bytes, kw_orig in zip(self.keywords_bytes, self.keywords, strict=False):
                        if kw_orig in matched_in_this_file:
                            continue

                        pos = data_to_search.find(kw_bytes)
                        if pos != -1:
                            matched_in_this_file.add(kw_orig)
                            snippet = self._extract_snippet_from_bytes(
                                data_to_search, pos, len(kw_bytes)
                            )
                            self._record_match(
                                path=display_path,
                                keyword=kw_orig,
                                match_type="CONTENT_TEXT",
                                file_size=file_size,
                                mod_time=mod_time,
                                snippet=snippet,
                                writer=writer,
                                csv_file=csv_file,
                            )

                    # Update overlap buffer for next chunk
                    if len(chunk) >= self.max_keyword_len:
                        overlap_buffer = chunk[-(self.max_keyword_len - 1) :]
                    else:
                        overlap_buffer = chunk

        except (PermissionError, FileNotFoundError, OSError):
            self.total_errors_bypassed += 1

    def _scan_office_document(
        self,
        long_path: str,
        display_path: str,
        ext: str,
        file_size: int,
        mod_time: str,
        writer: Any,
        csv_file: Any,
    ) -> None:
        """
        Inspects Microsoft Office XML packages (.docx, .xlsx, .pptx) for keywords using pure stdlib zipfile.
        """
        try:
            with zipfile.ZipFile(long_path, "r") as z:
                match_type_label = f"CONTENT_{ext[1:].upper()}"
                matched_in_this_file: set[str] = set()

                target_xml_patterns = {
                    ".docx": [
                        "word/document.xml",
                        "word/header",
                        "word/footer",
                        "word/comments.xml",
                    ],
                    ".xlsx": ["xl/sharedStrings.xml", "xl/worksheets/sheet"],
                    ".pptx": ["ppt/slides/slide", "ppt/notesSlides/notesSlide"],
                }

                patterns = target_xml_patterns.get(ext, [])

                for name in z.namelist():
                    if any(name.startswith(p) or p in name for p in patterns):
                        try:
                            # Read XML entry (protect against decompression bombs)
                            info = z.getinfo(name)
                            if info.file_size > self.max_archive_member_bytes:
                                continue

                            with z.open(name) as xml_file:
                                raw_xml = xml_file.read()

                            # Fast regex to strip XML tags and extract text payload
                            text_content = self._strip_xml_tags(raw_xml)
                            text_lower = text_content.lower()

                            for kw_lower, kw_orig in zip(
                                self.keywords_lower, self.keywords, strict=False
                            ):
                                if kw_orig in matched_in_this_file:
                                    continue

                                pos = text_lower.find(kw_lower)
                                if pos != -1:
                                    matched_in_this_file.add(kw_orig)
                                    snippet = self._extract_snippet_from_str(
                                        text_content, pos, len(kw_orig)
                                    )
                                    self._record_match(
                                        path=f"{display_path} -> [{name}]",
                                        keyword=kw_orig,
                                        match_type=match_type_label,
                                        file_size=file_size,
                                        mod_time=mod_time,
                                        snippet=snippet,
                                        writer=writer,
                                        csv_file=csv_file,
                                    )
                        except (zipfile.BadZipFile, KeyError, RuntimeError, OSError):
                            continue

        except (
            zipfile.BadZipFile,
            PermissionError,
            FileNotFoundError,
            OSError,
            KeyError,
            RuntimeError,
        ):
            self.total_errors_bypassed += 1

    def _scan_zip_archive(
        self,
        long_path: str,
        display_path: str,
        file_size: int,
        mod_time: str,
        writer: Any,
        csv_file: Any,
    ) -> None:
        """
        Inspects .zip archives for keyword matches in member filenames and text/office content.
        """
        try:
            with zipfile.ZipFile(long_path, "r") as z:
                matched_in_this_archive: set[tuple[str, str]] = set()

                for info in z.infolist():
                    if info.is_dir():
                        continue

                    member_name = info.filename
                    member_name_lower = member_name.lower()

                    # 1. Member filename check
                    for kw_lower, kw_orig in zip(self.keywords_lower, self.keywords, strict=False):
                        if kw_lower in member_name_lower:
                            item_key = (kw_orig, member_name)
                            if item_key not in matched_in_this_archive:
                                matched_in_this_archive.add(item_key)
                                snippet = f"Zip archive entry matched: {member_name}"
                                self._record_match(
                                    path=f"{display_path} -> [{member_name}]",
                                    keyword=kw_orig,
                                    match_type="CONTENT_ZIP_ENTRY",
                                    file_size=info.file_size,
                                    mod_time=mod_time,
                                    snippet=snippet,
                                    writer=writer,
                                    csv_file=csv_file,
                                )

                    # 2. Member content check (if text-based and within size limit)
                    member_ext = Path(member_name).suffix.lower()
                    if (
                        self.search_contents
                        and member_ext in self.content_extensions
                        and 0 < info.file_size <= self.max_archive_member_bytes
                    ):
                        try:
                            with z.open(info) as mf:
                                if member_ext in {".docx", ".xlsx", ".pptx"}:
                                    # Nested office file in zip
                                    nested_bytes = mf.read()
                                    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested_z:
                                        for nested_name in nested_z.namelist():
                                            if (
                                                "document.xml" in nested_name
                                                or "sharedStrings.xml" in nested_name
                                                or "slide" in nested_name
                                            ):
                                                with nested_z.open(nested_name) as n_xml:
                                                    nested_text = self._strip_xml_tags(n_xml.read())
                                                    nested_lower = nested_text.lower()
                                                    for kw_lower, kw_orig in zip(
                                                        self.keywords_lower,
                                                        self.keywords,
                                                        strict=False,
                                                    ):
                                                        pos = nested_lower.find(kw_lower)
                                                        if pos != -1:
                                                            snippet = (
                                                                self._extract_snippet_from_str(
                                                                    nested_text, pos, len(kw_orig)
                                                                )
                                                            )
                                                            self._record_match(
                                                                path=f"{display_path} -> [{member_name} / {nested_name}]",
                                                                keyword=kw_orig,
                                                                match_type="CONTENT_ZIP_OFFICE",
                                                                file_size=info.file_size,
                                                                mod_time=mod_time,
                                                                snippet=snippet,
                                                                writer=writer,
                                                                csv_file=csv_file,
                                                            )
                                else:
                                    member_bytes = mf.read().lower()
                                    for kw_bytes, kw_orig in zip(
                                        self.keywords_bytes, self.keywords, strict=False
                                    ):
                                        pos = member_bytes.find(kw_bytes)
                                        if pos != -1:
                                            item_key = (kw_orig, member_name)
                                            if item_key not in matched_in_this_archive:
                                                matched_in_this_archive.add(item_key)
                                                snippet = self._extract_snippet_from_bytes(
                                                    member_bytes, pos, len(kw_bytes)
                                                )
                                                self._record_match(
                                                    path=f"{display_path} -> [{member_name}]",
                                                    keyword=kw_orig,
                                                    match_type="CONTENT_ZIP_ENTRY",
                                                    file_size=info.file_size,
                                                    mod_time=mod_time,
                                                    snippet=snippet,
                                                    writer=writer,
                                                    csv_file=csv_file,
                                                )
                        except (zipfile.BadZipFile, KeyError, RuntimeError, OSError):
                            continue

        except (
            zipfile.BadZipFile,
            PermissionError,
            FileNotFoundError,
            OSError,
            KeyError,
            RuntimeError,
        ):
            self.total_errors_bypassed += 1

    @staticmethod
    def _strip_xml_tags(xml_bytes: bytes) -> str:
        """
        Fast regex to strip XML tags and return clean text.
        """
        try:
            text = xml_bytes.decode("utf-8", errors="ignore")
            clean = re.sub(r"<[^>]+>", " ", text)
            return " ".join(clean.split())
        except Exception:
            return ""

    @staticmethod
    def _extract_snippet_from_bytes(data: bytes, pos: int, kw_len: int, radius: int = 45) -> str:
        """
        Extracts a clean printable text snippet surrounding a byte position.
        """
        start = max(0, pos - radius)
        end = min(len(data), pos + kw_len + radius)
        raw_slice = data[start:end]
        text_slice = raw_slice.decode("utf-8", errors="replace")
        clean_text = " ".join(
            text_slice.replace("\r", " ").replace("\n", " ").replace("\t", " ").split()
        )
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(data) else ""
        return f"{prefix}{clean_text}{suffix}"

    @staticmethod
    def _extract_snippet_from_str(text: str, pos: int, kw_len: int, radius: int = 45) -> str:
        """
        Extracts a clean text snippet surrounding a character position.
        """
        start = max(0, pos - radius)
        end = min(len(text), pos + kw_len + radius)
        raw_slice = text[start:end]
        clean_text = " ".join(
            raw_slice.replace("\r", " ").replace("\n", " ").replace("\t", " ").split()
        )
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        return f"{prefix}{clean_text}{suffix}"

    def _record_match(
        self,
        path: str,
        keyword: str,
        match_type: str,
        file_size: int,
        mod_time: str,
        snippet: str,
        writer: Any,
        csv_file: Any,
    ) -> None:
        """
        Writes match row immediately to disk and forces physical fsync.
        """
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        sanitized_snippet = snippet.replace('"', '""')

        writer.writerow(
            [timestamp, path, keyword, match_type, file_size, mod_time, sanitized_snippet]
        )
        csv_file.flush()
        os.fsync(csv_file.fileno())

        self.total_matches_found += 1

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        size = float(size_bytes)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


def load_or_create_config(config_path: Path) -> dict[str, Any]:
    """
    Loads config.json or auto-generates a clean template if missing.
    """
    if not config_path.exists():
        default_config = {
            "target_directories": ["C:\\"],
            "keywords": [
                "password",
                "confidential",
                "secret",
                "kickback",
                "invoice",
                "ledger",
                "credentials",
                "salary",
                "offshore",
                "audit",
            ],
            "search_contents": True,
            "content_extensions": [
                ".txt",
                ".csv",
                ".log",
                ".json",
                ".xml",
                ".yaml",
                ".yml",
                ".md",
                ".sql",
                ".ini",
                ".env",
                ".py",
                ".bat",
                ".cmd",
                ".ps1",
                ".cfg",
                ".conf",
                ".reg",
                ".html",
                ".js",
                ".docx",
                ".xlsx",
                ".pptx",
                ".zip",
            ],
            "exclude_directories": [
                "C:\\Windows",
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                "$Recycle.Bin",
                "System Volume Information",
                "AppData\\Local\\Temp",
                "AppData\\Local\\Microsoft\\Windows",
                ".git",
                ".venv",
                "node_modules",
            ],
            "exclude_extensions": [
                ".dll",
                ".sys",
                ".exe",
                ".iso",
                ".vmdk",
                ".bin",
                ".dat",
                ".tmp",
                ".pdb",
                ".msi",
                ".pyc",
                ".png",
                ".jpg",
                ".jpeg",
                ".mp4",
            ],
            "chunk_size_mb": 2,
        }
        config_path.write_text(json.dumps(default_config, indent=4), encoding="utf-8")
        return default_config

    try:
        content = config_path.read_text(encoding="utf-8")
        return json.loads(content)
    except Exception as e:
        sys.stderr.write(f"Error reading {config_path.name}: {e}\n")
        raise

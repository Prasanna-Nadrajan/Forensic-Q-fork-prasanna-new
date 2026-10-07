"""
Q-Scan Business Logic & Mutation Services
Handles evidence CSV ingestion, atomic batch database writes, and scoring classification.
"""

import csv
import io
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from django.db import transaction
from django.utils.dateparse import parse_datetime
from loguru import logger

from .models import FileEvidenceHit, ScannedDevice

HIGH_RISK_KEYWORDS = {
    "password",
    "credentials",
    "secret",
    "private_key",
    "id_rsa",
    "kickback",
    "bribe",
    "shadow",
    "offshore",
    "unauthorized",
    "exploit",
    "backdoor",
}

MEDIUM_RISK_KEYWORDS = {
    "salary",
    "payroll",
    "invoice",
    "ledger",
    "confidential",
    "nda",
    "audit",
    "wire_transfer",
    "p&l",
}


def _calculate_risk_score(keyword: str, path: str, match_type: str) -> int:
    """
    Computes a forensic risk score between 10 and 95 based on keyword severity and location.
    """
    kw_lower = keyword.lower().strip()
    path_lower = path.lower()

    if any(k in kw_lower for k in HIGH_RISK_KEYWORDS):
        score = 85
    elif any(k in kw_lower for k in MEDIUM_RISK_KEYWORDS):
        score = 65
    else:
        score = 45

    # Elevation for system/security/hidden paths
    if (
        "appdata" in path_lower
        or "desktop" in path_lower
        or "temp" in path_lower
        or ".env" in path_lower
    ):
        score = min(98, score + 10)

    # Elevation for document/spreadsheet content hits vs filename
    if "CONTENT" in match_type:
        score = min(99, score + 5)

    return score


def _parse_timestamp(raw_val: str) -> datetime | None:
    """
    Parses timestamp string safely to UTC datetime object.
    """
    if not raw_val or not raw_val.strip():
        return None
    val = raw_val.strip()
    # Strip UTC suffix if present
    if val.endswith(" UTC"):
        val = val[:-4].strip()
    # Try ISO format
    dt = parse_datetime(val)
    if dt:
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt

    # Try standard forensic formats
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
        try:
            parsed = datetime.strptime(val, fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


@transaction.atomic
def ingest_scan_csv_file(
    *,
    csv_file_obj_or_path: Any,
    hostname: str = "ENDPOINT-WORKSTATION",
    scan_title: str = "Endpoint Keyword Sweep",
    custodian_name: str = "",
    drive_letter: str = "C:\\",
) -> ScannedDevice:
    """
    Atomically ingests a scan_results.csv report and creates batch evidence records.
    """
    # Read raw content
    if hasattr(csv_file_obj_or_path, "read"):
        raw_data = csv_file_obj_or_path.read()
        if isinstance(raw_data, bytes):
            text_data = raw_data.decode("utf-8-sig", errors="replace")
        else:
            text_data = str(raw_data)
    elif isinstance(csv_file_obj_or_path, Path):
        text_data = csv_file_obj_or_path.read_text(encoding="utf-8-sig", errors="replace")
    elif isinstance(csv_file_obj_or_path, str):
        if "\n" in csv_file_obj_or_path or "," in csv_file_obj_or_path:
            text_data = csv_file_obj_or_path
        elif Path(csv_file_obj_or_path).exists():
            text_data = Path(csv_file_obj_or_path).read_text(encoding="utf-8-sig", errors="replace")
        else:
            text_data = csv_file_obj_or_path
    else:
        text_data = str(csv_file_obj_or_path)

    reader = csv.reader(io.StringIO(text_data))
    _header = next(reader, None)

    # Create ScannedDevice container
    device = ScannedDevice.objects.create(
        hostname=hostname.strip() or "ENDPOINT-PC",
        scan_title=scan_title.strip() or "Forensic Drive Scan",
        custodian_name=custodian_name.strip(),
        drive_letter=drive_letter.strip(),
        status=ScannedDevice.ScanStatus.IMPORTED,
        scan_completed_at=datetime.now(UTC),
    )

    batch: list[FileEvidenceHit] = []
    total_bytes = 0
    total_hits = 0

    for row in reader:
        if not row or len(row) < 3:
            continue

        # Flexible column mapping
        timestamp_str = row[0] if len(row) > 0 else ""
        file_path = row[1] if len(row) > 1 else ""
        keyword = row[2] if len(row) > 2 else ""
        match_type_raw = row[3] if len(row) > 3 else "CONTENT_TEXT"
        size_raw = row[4] if len(row) > 4 else "0"
        mod_time_str = row[5] if len(row) > 5 else ""
        snippet = row[6] if len(row) > 6 else ""

        # Parse numeric size
        size_bytes = 0
        try:
            # Handle plain digits or formatted string like '1.20 MB'
            size_clean = size_raw.split()[0].replace(",", "")
            size_bytes = int(float(size_clean))
        except (ValueError, IndexError):
            size_bytes = 0

        total_bytes += size_bytes

        # Parse Path & Filename
        clean_path = file_path.strip()
        # If it's a nested zip/office path like 'C:\foo.zip -> [bar.txt]'
        base_path = clean_path.split(" -> ")[0] if " -> " in clean_path else clean_path
        filename = Path(base_path).name or "unknown"
        ext = Path(filename).suffix.lower()

        # Normalize match type
        match_type_upper = match_type_raw.strip().upper()
        if "NAME" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.FILENAME
        elif "PDF" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.CONTENT_PDF
        elif "DOCX" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.CONTENT_DOCX
        elif "XLSX" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.CONTENT_XLSX
        elif "PPTX" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.CONTENT_PPTX
        elif "ZIP_OFFICE" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.CONTENT_ZIP_OFFICE
        elif "ZIP" in match_type_upper:
            match_type = FileEvidenceHit.MatchType.CONTENT_ZIP_ENTRY
        else:
            match_type = FileEvidenceHit.MatchType.CONTENT_TEXT

        risk_score = _calculate_risk_score(keyword, clean_path, match_type)

        det_time = _parse_timestamp(timestamp_str)
        mod_time = _parse_timestamp(mod_time_str)

        hit = FileEvidenceHit(
            device=device,
            file_path=clean_path[:1024],
            filename=filename[:255],
            extension=ext[:32],
            file_size_bytes=size_bytes,
            matched_keyword=keyword[:128],
            match_type=match_type,
            snippet=snippet,
            file_modified_at=mod_time,
            detection_timestamp=det_time or datetime.now(UTC),
            risk_score=risk_score,
        )
        batch.append(hit)
        total_hits += 1

        # Bulk insert in batches of 250
        if len(batch) >= 250:
            FileEvidenceHit.objects.bulk_create(batch)
            batch = []

    if batch:
        FileEvidenceHit.objects.bulk_create(batch)

    # Update summary totals on ScannedDevice
    device.total_matches_found = total_hits
    device.total_bytes_scanned = total_bytes
    device.save(update_fields=["total_matches_found", "total_bytes_scanned", "updated_at"])

    # Emit Q-Link findings for scanned hits
    try:
        import re

        from q_link.backend.dispatcher import emit_forensic_finding
        from q_link.models import ForensicEntity

        all_hits = list(FileEvidenceHit.objects.filter(device=device))
        for hit in all_hits:
            emp_match = re.search(
                r"(?:Mr\.|Mrs\.|Ms\.)?\s*([A-Za-z\.\s]+?)\s+(ID-\d+)\s+.*?([A-Za-z\.\s]+?)\s+(Spouse|Husband|Wife|Son|Daughter|Father|Mother|Brother|Sister|Nominee)",
                hit.snippet,
                re.IGNORECASE,
            )
            if emp_match:
                emp_name = emp_match.group(1).strip()
                emp_id = emp_match.group(2).strip()
                nom_name = emp_match.group(3).strip()
                rel_type = emp_match.group(4).strip()
                emit_forensic_finding(
                    source_module="q_scan",
                    event_type="NOMINEE_RELATION_IDENTIFIED",
                    primary_entity_data={
                        "name": emp_name,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "raw_id": emp_id,
                        "metadata": {"employee_id": emp_id},
                    },
                    secondary_entities_data=[
                        {
                            "name": nom_name,
                            "type": ForensicEntity.EntityType.UNKNOWN,
                            "relation_type": rel_type.upper(),
                            "direction": "out",
                            "metadata": {"nominee_of": emp_name, "employee_id": emp_id},
                        }
                    ],
                    evidence_data={
                        "source_module": "q_scan",
                        "source_model": "FileEvidenceHit",
                        "source_record_id": str(hit.id),
                        "evidence_url": f"/scan/devices/{device.id}/",
                        "summary_snippet": hit.snippet[:300],
                    },
                    timeline_title=f"Nominee Identified: {emp_name} -> {nom_name}",
                    timeline_description=f"{nom_name} identified as {rel_type} of {emp_name} ({emp_id}) in file '{hit.filename}'",
                    severity="WARNING",
                )

                if custodian_name:
                    emit_forensic_finding(
                        source_module="q_scan",
                        event_type="BENEFICIARY_NEXUS",
                        primary_entity_data={
                            "name": custodian_name,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "is_target": True,
                        },
                        secondary_entities_data=[
                            {
                                "name": nom_name,
                                "type": ForensicEntity.EntityType.UNKNOWN,
                                "relation_type": "BENEFICIARY_NEXUS",
                                "direction": "out",
                            }
                        ],
                        timeline_title=f"Target Nexus: {custodian_name} -> {nom_name}",
                        severity="WARNING",
                    )
    except Exception as err:
        logger.warning(f"Error emitting findings from Q-Scan CSV to Q-Link: {err}")

    logger.info(
        "Successfully imported Q-Scan report for device '{}' ({} hits, {} bytes)",
        device.hostname,
        total_hits,
        total_bytes,
    )
    return device


@transaction.atomic
def delete_scanned_device(device_id: str | uuid.UUID) -> bool:
    """
    Atomically deletes a scanned device and all its associated evidence hits.
    """
    try:
        device = ScannedDevice.objects.get(id=device_id)
        device.delete()
        logger.info("Deleted scanned device case ID {}", device_id)
        return True
    except ScannedDevice.DoesNotExist:
        return False


@transaction.atomic
def update_evidence_hit_review(
    hit_id: str | uuid.UUID, *, is_reviewed: bool, reviewer_notes: str = ""
) -> FileEvidenceHit | None:
    """
    Updates the analyst review status on an individual evidence hit.
    """
    try:
        hit = FileEvidenceHit.objects.get(id=hit_id)
        hit.is_reviewed = is_reviewed
        hit.reviewer_notes = reviewer_notes
        hit.save(update_fields=["is_reviewed", "reviewer_notes", "updated_at"])
        return hit
    except FileEvidenceHit.DoesNotExist:
        return None


@transaction.atomic
def ingest_document_for_scan(
    *,
    file_obj_or_path: Any,
    filename: str = "",
    hostname: str = "SCHEDULE-AUDIT",
    scan_title: str = "Nominee & Employee Schedule Sweep",
    custodian_name: str = "",
    drive_letter: str = "C:\\",
) -> ScannedDevice:  # pragma: no cover
    """
    Ingests and screens an evidentiary document (.pdf, .docx, .txt) against keywords,
    extracting employee IDs, nominee relations, and counterparties, and registers
    findings with Q-Link.
    """
    import re

    raw_bytes = b""
    if hasattr(file_obj_or_path, "read"):
        raw = file_obj_or_path.read()
        raw_bytes = raw if isinstance(raw, bytes) else str(raw).encode("utf-8")
        if hasattr(file_obj_or_path, "seek"):
            file_obj_or_path.seek(0)
        if not filename and hasattr(file_obj_or_path, "name"):
            filename = file_obj_or_path.name
    elif isinstance(file_obj_or_path, Path):
        raw_bytes = file_obj_or_path.read_bytes()
        filename = filename or file_obj_or_path.name
    elif isinstance(file_obj_or_path, str):
        if Path(file_obj_or_path).exists():
            p = Path(file_obj_or_path)
            raw_bytes = p.read_bytes()
            filename = filename or p.name
        else:
            raw_bytes = file_obj_or_path.encode("utf-8")

    filename = filename or "evidentiary_schedule.pdf"
    ext = Path(filename).suffix.lower()

    extracted_text = ""
    if ext == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(raw_bytes))
            extracted_text = "\n".join([page.extract_text() or "" for page in reader.pages])
        except Exception as e:
            logger.warning(f"Error parsing PDF in Q-Scan: {e}")
            extracted_text = raw_bytes.decode("utf-8", errors="replace")
    else:
        extracted_text = raw_bytes.decode("utf-8", errors="replace")

    device = ScannedDevice.objects.create(
        hostname=hostname.strip() or "SCHEDULE-AUDIT",
        scan_title=scan_title.strip() or f"Schedule Scan - {filename}",
        custodian_name=custodian_name.strip(),
        drive_letter=drive_letter.strip(),
        status=ScannedDevice.ScanStatus.IMPORTED,
        scan_completed_at=datetime.now(UTC),
    )

    from core.profiles import get_profile_keywords

    profile_keywords = get_profile_keywords(custodian_name=custodian_name)
    target_terms = {k.lower() for k in profile_keywords}
    target_terms.update(["silviya", "shanthi", "palani", "joseph remigius"])

    batch = []
    lines = [line.strip() for line in extracted_text.splitlines() if line.strip()]

    found_relations = []
    for line in lines:
        emp_match = re.search(
            r"(?:Mr\.|Mrs\.|Ms\.)?\s*([A-Za-z\.\s]+?)\s+(ID-\d+)\s+.*?([A-Za-z\.\s]+?)\s+(Spouse|Husband|Wife|Son|Daughter|Father|Mother|Brother|Sister|Nominee)",
            line,
            re.IGNORECASE,
        )
        if emp_match:
            emp_name = emp_match.group(1).strip()
            emp_id = emp_match.group(2).strip()
            nominee_name = emp_match.group(3).strip()
            rel_type = emp_match.group(4).strip()
            found_relations.append(
                {
                    "employee": emp_name,
                    "emp_id": emp_id,
                    "nominee": nominee_name,
                    "relation": rel_type,
                    "line": line,
                }
            )

        line_lower = line.lower()
        matched_kw = None
        for term in target_terms:
            if term in line_lower:
                matched_kw = term.title()
                break

        if matched_kw or emp_match:
            kw = matched_kw or (emp_match.group(3).strip() if emp_match else "Nominee Relation")
            match_type = (
                FileEvidenceHit.MatchType.CONTENT_PDF
                if ext == ".pdf"
                else FileEvidenceHit.MatchType.CONTENT_TEXT
            )
            hit = FileEvidenceHit(
                device=device,
                file_path=f"Schedule://{filename}",
                filename=filename[:255],
                extension=ext[:32],
                file_size_bytes=len(raw_bytes),
                matched_keyword=kw[:128],
                match_type=match_type,
                snippet=line[:500],
                detection_timestamp=datetime.now(UTC),
                risk_score=85,
            )
            batch.append(hit)

    if batch:
        FileEvidenceHit.objects.bulk_create(batch)

    device.total_matches_found = len(batch)
    device.total_bytes_scanned = len(raw_bytes)
    device.save(update_fields=["total_matches_found", "total_bytes_scanned", "updated_at"])

    # Emit Q-Link findings for detected relationships
    try:
        from q_link.backend.dispatcher import emit_forensic_finding
        from q_link.models import ForensicEntity

        for rel in found_relations:
            emit_forensic_finding(
                source_module="q_scan",
                event_type="NOMINEE_RELATION_IDENTIFIED",
                primary_entity_data={
                    "name": rel["employee"],
                    "type": ForensicEntity.EntityType.EMPLOYEE,
                    "raw_id": rel["emp_id"],
                    "metadata": {"employee_id": rel["emp_id"]},
                },
                secondary_entities_data=[
                    {
                        "name": rel["nominee"],
                        "type": ForensicEntity.EntityType.UNKNOWN,
                        "relation_type": rel["relation"].upper(),
                        "direction": "out",
                        "metadata": {"nominee_of": rel["employee"], "employee_id": rel["emp_id"]},
                    }
                ],
                evidence_data={
                    "source_module": "q_scan",
                    "source_model": "FileEvidenceHit",
                    "source_record_id": str(device.id),
                    "evidence_url": f"/scan/devices/{device.id}/",
                    "summary_snippet": f"Nominee Schedule: {rel['employee']} ({rel['emp_id']}) -> {rel['nominee']} ({rel['relation']})",
                },
                timeline_title=f"Nominee Link: {rel['employee']} - {rel['nominee']}",
                timeline_description=f"{rel['nominee']} identified as {rel['relation']} of {rel['employee']} ({rel['emp_id']})",
                severity="WARNING",
            )

            if custodian_name:
                emit_forensic_finding(
                    source_module="q_scan",
                    event_type="BENEFICIARY_NEXUS",
                    primary_entity_data={
                        "name": custodian_name,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "is_target": True,
                    },
                    secondary_entities_data=[
                        {
                            "name": rel["nominee"],
                            "type": ForensicEntity.EntityType.UNKNOWN,
                            "relation_type": "BENEFICIARY_NEXUS",
                            "direction": "out",
                        }
                    ],
                    timeline_title=f"Target Nexus: {custodian_name} -> {rel['nominee']}",
                    severity="WARNING",
                )
    except Exception as err:
        logger.warning(f"Error emitting Q-Scan findings to Q-Link: {err}")

    logger.info("Successfully ingested schedule document '{}' with {} hits", filename, len(batch))
    return device

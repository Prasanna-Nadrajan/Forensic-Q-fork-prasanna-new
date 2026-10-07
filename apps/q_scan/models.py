"""
Q-Scan Database Models
Persists endpoint filesystem audit cases, scanned devices, and evidence keyword hits.
"""

from django.db import models

from core.models import ForensicBaseModel


class ScannedDevice(ForensicBaseModel):
    """
    Endpoint device or forensic drive image audited during a Q-Scan campaign.
    """

    class ScanStatus(models.TextChoices):
        COMPLETED = "COMPLETED", "Scan Completed"
        IN_PROGRESS = "IN_PROGRESS", "Scan In Progress"
        PARTIAL = "PARTIAL", "Partial / Interrupted"
        IMPORTED = "IMPORTED", "Evidence CSV Imported"

    hostname = models.CharField(
        max_length=128, db_index=True, help_text="Endpoint Computer / Hostname"
    )
    scan_title = models.CharField(
        max_length=255, blank=True, default="", help_text="Investigation / Audit Label"
    )
    custodian_name = models.CharField(
        max_length=255, blank=True, default="", help_text="Assigned Custodian or User"
    )
    drive_letter = models.CharField(
        max_length=64, blank=True, default="", help_text="Target Root or Drive Letter (e.g., C:\\)"
    )
    file_system = models.CharField(
        max_length=32, blank=True, default="", help_text="File System (NTFS, FAT32, etc.)"
    )
    status = models.CharField(
        max_length=32,
        choices=ScanStatus.choices,
        default=ScanStatus.IMPORTED,
        db_index=True,
    )
    total_files_scanned = models.IntegerField(default=0)
    total_matches_found = models.IntegerField(default=0)
    total_bytes_scanned = models.BigIntegerField(default=0)
    scan_completed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")

    class Meta:
        app_label = "q_scan"
        ordering = ["-created_at"]
        verbose_name = "Scanned Device"
        verbose_name_plural = "Scanned Devices"

    def __str__(self) -> str:
        return f"[{self.hostname}] {self.scan_title or 'Scan Campaign'} ({self.total_matches_found} hits)"


class FileEvidenceHit(ForensicBaseModel):
    """
    Individual keyword or anomaly hit identified on a target endpoint filesystem.
    """

    class MatchType(models.TextChoices):
        FILENAME = "FILENAME", "File Name Match"
        CONTENT_TEXT = "CONTENT_TEXT", "Text Content Match"
        CONTENT_PDF = "CONTENT_PDF", "PDF Document Match"
        CONTENT_DOCX = "CONTENT_DOCX", "Word Document Match"
        CONTENT_XLSX = "CONTENT_XLSX", "Excel Spreadsheet Match"
        CONTENT_PPTX = "CONTENT_PPTX", "PowerPoint Presentation Match"
        CONTENT_ZIP_ENTRY = "CONTENT_ZIP_ENTRY", "Zip Archive Entry Match"
        CONTENT_ZIP_OFFICE = "CONTENT_ZIP_OFFICE", "Zip Nested Document Match"

    device = models.ForeignKey(
        ScannedDevice,
        on_delete=models.CASCADE,
        related_name="hits",
        help_text="Originating Host / Device",
    )
    file_path = models.CharField(max_length=1024, db_index=True)
    filename = models.CharField(max_length=255, db_index=True)
    extension = models.CharField(max_length=32, blank=True, default="", db_index=True)
    file_size_bytes = models.BigIntegerField(default=0)
    matched_keyword = models.CharField(max_length=128, db_index=True)
    match_type = models.CharField(
        max_length=64,
        choices=MatchType.choices,
        default=MatchType.CONTENT_TEXT,
        db_index=True,
    )
    snippet = models.TextField(blank=True, default="", help_text="Surrounding text context snippet")
    file_modified_at = models.DateTimeField(null=True, blank=True)
    detection_timestamp = models.DateTimeField(null=True, blank=True)
    risk_score = models.IntegerField(default=50, help_text="Calculated Risk Score (0-100)")
    is_reviewed = models.BooleanField(default=False)
    reviewer_notes = models.TextField(blank=True, default="")

    class Meta:
        app_label = "q_scan"
        ordering = ["-risk_score", "-created_at"]
        verbose_name = "File Evidence Hit"
        verbose_name_plural = "File Evidence Hits"

    def __str__(self) -> str:
        return f"{self.matched_keyword} in {self.filename} ({self.match_type})"

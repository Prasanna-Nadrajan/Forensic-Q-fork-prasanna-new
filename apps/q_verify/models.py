"""
Q-Verify Database Models
Persists document authenticity records, metadata discrepancy flags, and audit cases.
"""

from django.db import models

from core.models import ForensicBaseModel


class VerificationCase(ForensicBaseModel):
    """
    Audit case container grouping verified documents by custodian or investigation.
    """

    class CaseStatus(models.TextChoices):
        PENDING = "PENDING", "Pending Ingestion"
        PROCESSING = "PROCESSING", "Analyzing Documents"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    case_ref = models.CharField(
        max_length=64, unique=True, db_index=True, help_text="Case Reference Number"
    )
    case_title = models.CharField(max_length=255, help_text="Investigation / Case Title")
    custodian_name = models.CharField(max_length=255, help_text="Target Custodian / Auditee")
    custodian_email = models.EmailField(max_length=255, blank=True, default="")
    custodian_department = models.CharField(max_length=128, blank=True, default="")
    notes = models.TextField(blank=True, default="")

    status = models.CharField(
        max_length=32,
        choices=CaseStatus.choices,
        default=CaseStatus.PENDING,
        db_index=True,
    )

    total_documents = models.IntegerField(default=0)
    authentic_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    tampered_count = models.IntegerField(default=0)
    average_authenticity_score = models.FloatField(default=100.0)

    class Meta:
        app_label = "q_verify"
        ordering = ["-created_at"]
        verbose_name = "Verification Case"
        verbose_name_plural = "Verification Cases"

    def __str__(self) -> str:
        return f"[{self.case_ref}] {self.case_title} ({self.custodian_name})"


class VerifiedDocument(ForensicBaseModel):
    """
    Individual verified document with extracted metadata, discrepancy flags, and authenticity score.
    """

    class RiskLevel(models.TextChoices):
        AUTHENTIC = "AUTHENTIC", "Authentic (Clean)"
        SUSPICIOUS = "SUSPICIOUS", "Suspicious (Discrepancies)"
        HIGH_RISK_TAMPERED = "HIGH_RISK_TAMPERED", "High Risk / Tampered"

    case = models.ForeignKey(
        VerificationCase,
        on_delete=models.CASCADE,
        related_name="documents",
        null=True,
        blank=True,
    )

    filename = models.CharField(max_length=255)
    file_size_bytes = models.BigIntegerField(default=0)
    mime_type = models.CharField(max_length=128, default="application/octet-stream")
    file_extension = models.CharField(max_length=32, blank=True, default="")
    sha256_hash = models.CharField(max_length=64, db_index=True, help_text="Evidence Hash")
    storage_path = models.CharField(max_length=512, blank=True, default="")

    # File System Dates
    file_created_at = models.DateTimeField(null=True, blank=True)
    file_modified_at = models.DateTimeField(null=True, blank=True)

    # Embedded Document Metadata Dates
    meta_created_at = models.DateTimeField(null=True, blank=True, db_index=True)
    meta_modified_at = models.DateTimeField(null=True, blank=True)

    # Author & Application Metadata
    meta_author = models.CharField(max_length=255, blank=True, default="")
    meta_creator = models.CharField(max_length=255, blank=True, default="")
    meta_producer = models.CharField(max_length=255, blank=True, default="")
    meta_software = models.CharField(max_length=255, blank=True, default="")
    meta_company = models.CharField(max_length=255, blank=True, default="")
    meta_title = models.CharField(max_length=512, blank=True, default="")
    meta_subject = models.CharField(max_length=512, blank=True, default="")

    # Structural Forensic Metrics
    incremental_updates_count = models.IntegerField(default=0)
    editing_time_minutes = models.IntegerField(default=0)
    revision_number = models.CharField(max_length=64, blank=True, default="")

    # Authenticity & Anomaly Scoring
    authenticity_score = models.IntegerField(
        default=100, db_index=True, help_text="0 = Highly Tampered, 100 = Authentic"
    )
    risk_level = models.CharField(
        max_length=32,
        choices=RiskLevel.choices,
        default=RiskLevel.AUTHENTIC,
        db_index=True,
    )

    has_timestamp_anomaly = models.BooleanField(default=False, db_index=True)
    has_software_anomaly = models.BooleanField(default=False, db_index=True)
    has_structural_anomaly = models.BooleanField(default=False, db_index=True)

    anomalies = models.JSONField(default=list, help_text="List of detected anomaly flags")
    raw_metadata = models.JSONField(default=dict, help_text="Complete extracted metadata tree")
    matched_keywords = models.JSONField(
        default=dict, help_text="Keywords found in document content"
    )
    summary = models.TextField(blank=True, default="")

    class Meta:
        app_label = "q_verify"
        ordering = ["authenticity_score", "-created_at"]
        indexes = [
            models.Index(fields=["case", "authenticity_score"]),
            models.Index(fields=["case", "risk_level"]),
            models.Index(fields=["case", "mime_type"]),
        ]
        verbose_name = "Verified Document"
        verbose_name_plural = "Verified Documents"

    def __str__(self) -> str:
        return f"{self.filename} ({self.authenticity_score}/100 - {self.risk_level})"

    @property
    def formatted_size(self) -> str:
        size = self.file_size_bytes
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} GB"

import uuid

from django.db import models


class TimeStampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    ``created_at`` and ``updated_at`` fields.
    """

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    """
    An abstract base class model that provides a unique UUID primary key.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class ForensicBaseModel(UUIDModel, TimeStampedModel):
    """
    Combined abstract base model with UUID primary key and timestamp tracking
    for all ForensiQ analytical and forensic entities.
    """

    class Meta:
        abstract = True


class InvestigationProfile(ForensicBaseModel):
    """
    Central Forensic Target / Investigation Subject Profile.
    Unified across all Q-Apps (Q-Bank, Q-Voice, Q-Verify, Q-Ledger, Q-Mail, Q-Chat).
    Represents an auditee, target custodian, employee, or subject of inquiry.
    """

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active Investigation"
        MONITORING = "MONITORING", "Under Monitoring"
        CLEARED = "CLEARED", "Cleared / Closed"
        FLAGGED = "FLAGGED", "High Risk / Flagged"

    full_name = models.CharField(
        max_length=255, db_index=True, help_text="Target / Auditee Full Name"
    )
    employee_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="Employee ID or Case Reference",
    )
    department = models.CharField(
        max_length=128, blank=True, default="", help_text="Department / Division"
    )
    designation = models.CharField(
        max_length=128, blank=True, default="", help_text="Designation / Position"
    )
    email = models.EmailField(blank=True, default="", help_text="Official / Primary Email")
    phone = models.CharField(max_length=32, blank=True, default="", help_text="Contact Phone")
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    is_substantiated = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether allegations/findings against this auditee/target are substantiated",
    )
    notes = models.TextField(
        blank=True,
        default="",
        help_text="Investigative hypothesis, case background, or notes",
    )
    avatar_color = models.CharField(
        max_length=32,
        default="indigo",
        help_text="UI Accent color tag",
    )
    keywords = models.JSONField(
        default=list,
        blank=True,
        help_text="Search and flag investigation keywords associated with this auditee / target.",
    )

    class Meta:
        app_label = "core"
        ordering = ["full_name"]
        verbose_name = "Investigation Profile"
        verbose_name_plural = "Investigation Profiles"

    def __str__(self) -> str:
        dept_str = f" • {self.department}" if self.department else ""
        return f"{self.full_name}{dept_str}"

    @property
    def display_name(self) -> str:
        if self.department:
            return f"{self.full_name} ({self.department})"
        return self.full_name

    @property
    def initials(self) -> str:
        parts = self.full_name.strip().split()
        if not parts:
            return "Q"
        if len(parts) == 1:
            return parts[0][:2].upper()
        return f"{parts[0][0]}{parts[-1][0]}".upper()

    def to_dict(self) -> dict[str, object]:
        audits_info = []
        if self.pk:
            try:
                audits_info = [
                    {"id": str(a.id), "name": a.name, "title": a.title, "status": a.status}
                    for a in self.audits.all()
                ]
            except Exception:
                audits_info = []

        return {
            "id": str(self.id),
            "full_name": self.full_name,
            "employee_id": self.employee_id,
            "department": self.department,
            "designation": self.designation,
            "email": self.email,
            "phone": self.phone,
            "status": self.status,
            "is_substantiated": self.is_substantiated,
            "initials": self.initials,
            "display_name": self.display_name,
            "avatar_color": self.avatar_color,
            "keywords": self.keywords or [],
            "audits": audits_info,
        }


class Audit(ForensicBaseModel):
    """
    Forensic Audit Entity.
    Identified by an auto-generated unique reference: YYYY-WB-XX (e.g. 2026-WB-01).
    Groups and maps investigation profiles (auditees/targets) under a single audit mandate.
    """

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        IN_PROGRESS = "IN_PROGRESS", "In Progress"
        COMPLETED = "COMPLETED", "Completed"
        ARCHIVED = "ARCHIVED", "Archived"

    name = models.CharField(
        max_length=32,
        unique=True,
        db_index=True,
        help_text="Auto-generated unique Audit ID (e.g. YYYY-WB-XX)",
    )
    title = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Audit Title or Investigative Objective",
    )
    description = models.TextField(
        blank=True,
        default="",
        help_text="Investigation scope, allegations, or background notes",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    profiles = models.ManyToManyField(
        InvestigationProfile,
        related_name="audits",
        blank=True,
        help_text="Investigation profiles mapped under this audit",
    )

    class Meta:
        app_label = "core"
        ordering = ["-name"]
        verbose_name = "Audit"
        verbose_name_plural = "Audits"

    def __str__(self) -> str:
        if self.title:
            return f"{self.name} - {self.title}"
        return self.name

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "profiles_count": self.profiles.count(),
            "profile_ids": [str(p.id) for p in self.profiles.all()],
            "profiles": [p.to_dict() for p in self.profiles.all()],
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M") if self.created_at else "",
        }

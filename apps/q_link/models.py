"""
Q-Link Database Models
Forensic Knowledge Graph, Entity Resolution, Relationships, Evidence Pointers,
Timelines, and Automated Cross-Module Intelligence Alerts.
"""

from django.db import models

from core.models import ForensicBaseModel


class ForensicEntity(ForensicBaseModel):
    """
    Master standardized forensic entity (Person, Company, Bank Account, PO, etc.)
    aggregated across all investigative modules.
    """

    class EntityType(models.TextChoices):
        EMPLOYEE = "EMPLOYEE", "Employee / Target Custodian"
        VENDOR = "VENDOR", "Vendor / Supplier"
        CUSTOMER = "CUSTOMER", "Customer / Client"
        COMPANY = "COMPANY", "Company / Corporate Entity"
        BANK_ACCOUNT = "BANK_ACCOUNT", "Bank Account"
        EMAIL_ID = "EMAIL_ID", "Email Address"
        PHONE = "PHONE", "Phone Number"
        PO = "PO", "Purchase Order"
        INVOICE = "INVOICE", "Invoice"
        DOCUMENT = "DOCUMENT", "Document / File"
        UNKNOWN = "UNKNOWN", "Unclassified Entity"

    entity_type = models.CharField(
        max_length=32,
        choices=EntityType.choices,
        default=EntityType.UNKNOWN,
        db_index=True,
    )
    identifier = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Normalized canonical identifier (e.g. EMAIL:foo@bar.com, ACC:HDFC:12345)",
    )
    display_name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Human-readable label or entity name",
    )
    category = models.CharField(
        max_length=64,
        blank=True,
        default="General",
        help_text="Classification category (e.g. Individual, Corporate, Procurement)",
    )
    risk_rating = models.IntegerField(
        default=0,
        help_text="Calculated risk score (0-100)",
    )
    is_target = models.BooleanField(
        default=False,
        help_text="Whether this entity is a prime auditee/suspect",
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Arbitrary entity metadata (attributes, tags, address, etc.)",
    )

    class Meta:
        app_label = "q_link"
        ordering = ["-risk_rating", "display_name"]
        verbose_name = "Forensic Entity"
        verbose_name_plural = "Forensic Entities"

    def __str__(self) -> str:
        return f"[{self.entity_type}] {self.display_name} ({self.identifier})"

    @property
    def tags(self) -> list[str]:
        """Returns entity tags including Substantiated, External, and functional tags."""
        raw_tags = list(self.metadata.get("tags") or [])
        if self.metadata.get("is_substantiated") and "Substantiated" not in raw_tags:
            raw_tags.append("Substantiated")
        if self.metadata.get("is_external") and "External" not in raw_tags:
            raw_tags.append("External")
        return raw_tags

    @property
    def is_external(self) -> bool:
        """Indicates whether this entity originates outside the active audit."""
        return bool(self.metadata.get("is_external", False))


class EntityAlias(ForensicBaseModel):
    """
    Alternative representations, former names, or variations linked to a master entity.
    Supports fuzzy and LLM-assisted entity resolution.
    """

    class MatchSource(models.TextChoices):
        EXACT = "EXACT", "Exact Key Match"
        RAPIDFUZZ = "RAPIDFUZZ", "Fuzzy Token Match"
        LLM_INFERRED = "LLM_INFERRED", "LLM Semantic Inference"
        MANUAL = "MANUAL", "Investigator Manual Link"

    entity = models.ForeignKey(
        ForensicEntity,
        on_delete=models.CASCADE,
        related_name="aliases",
        help_text="Associated master canonical entity",
    )
    alias_name = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Raw or variant name string",
    )
    match_source = models.CharField(
        max_length=32,
        choices=MatchSource.choices,
        default=MatchSource.EXACT,
    )
    confidence = models.FloatField(
        default=1.0,
        help_text="Match confidence score (0.0 to 1.0)",
    )

    class Meta:
        app_label = "q_link"
        ordering = ["-confidence", "alias_name"]
        verbose_name = "Entity Alias"
        verbose_name_plural = "Entity Aliases"

    def __str__(self) -> str:
        return f"Alias '{self.alias_name}' -> {self.entity.display_name} ({self.confidence:.2f})"


class EntityRelationship(ForensicBaseModel):
    """
    Directed relationship / edge connecting two forensic entities across evidence sources.
    """

    class RelationType(models.TextChoices):
        EMAILED = "EMAILED", "Emailed / Communicated"
        TRANSFERRED_FUNDS = "TRANSFERRED_FUNDS", "Transferred Funds"
        ISSUED_PO = "ISSUED_PO", "Issued Purchase Order"
        APPROVED_BY = "APPROVED_BY", "Approved By"
        SHARED_IDENTIFIER = "SHARED_IDENTIFIER", "Shared Identifier (Address/Phone/PAN)"
        CONDUIT_TO = "CONDUIT_TO", "Pass-Through Conduit"
        DIRECTOR_OF = "DIRECTOR_OF", "Director / Beneficial Owner"
        MENTIONED_IN = "MENTIONED_IN", "Mentioned in Evidence / Call"
        ASSOCIATE = "ASSOCIATE", "Known Associate / Co-Auditee"

    source_entity = models.ForeignKey(
        ForensicEntity,
        on_delete=models.CASCADE,
        related_name="out_relations",
        help_text="Originating entity",
    )
    target_entity = models.ForeignKey(
        ForensicEntity,
        on_delete=models.CASCADE,
        related_name="in_relations",
        help_text="Destination entity",
    )
    relation_type = models.CharField(
        max_length=64,
        choices=RelationType.choices,
        default=RelationType.ASSOCIATE,
        db_index=True,
    )
    confidence_score = models.FloatField(
        default=1.0,
        help_text="Confidence rating (0.0 to 1.0)",
    )
    weight = models.FloatField(
        default=1.0,
        help_text="Edge weight (e.g. monetary amount or interaction count)",
    )
    source_module = models.CharField(
        max_length=32,
        db_index=True,
        help_text="Originating tool (q_bank, q_trail, q_mail, q_ledger, etc.)",
    )
    is_direct = models.BooleanField(
        default=True,
        help_text="True for direct connection, False for multi-hop inferred",
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Edge attributes (dates, channel, transaction IDs, etc.)",
    )

    class Meta:
        app_label = "q_link"
        ordering = ["-weight", "-created_at"]
        verbose_name = "Entity Relationship"
        verbose_name_plural = "Entity Relationships"

    def __str__(self) -> str:
        arrow = "-->" if self.is_direct else "-~->"
        return f"{self.source_entity.display_name} {arrow} [{self.relation_type}] {arrow} {self.target_entity.display_name}"


class EvidencePointer(ForensicBaseModel):
    """
    Direct granular link anchoring an entity relationship to its original evidence record
    in upstream forensic modules (Q-Bank transaction, Q-Ledger PO, Q-Mail message, etc.).
    """

    relationship = models.ForeignKey(
        EntityRelationship,
        on_delete=models.CASCADE,
        related_name="evidence_pointers",
        help_text="Associated relationship edge",
    )
    source_module = models.CharField(
        max_length=32,
        db_index=True,
        help_text="Originating forensic module name",
    )
    source_model = models.CharField(
        max_length=64,
        help_text="Model class name (e.g. BankTransaction, PurchaseOrder, EmailMessage)",
    )
    source_record_id = models.CharField(
        max_length=128,
        db_index=True,
        help_text="Primary key or reference identifier in originating table",
    )
    evidence_url = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Clickable URL to inspect evidence in the primary tool",
    )
    summary_snippet = models.TextField(
        blank=True,
        default="",
        help_text="Human-readable evidence summary or finding text",
    )
    occurred_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Timestamp when the forensic event took place",
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Raw payload or contextual snapshot from originating finding",
    )

    class Meta:
        app_label = "q_link"
        ordering = ["-occurred_at", "-created_at"]
        verbose_name = "Evidence Pointer"
        verbose_name_plural = "Evidence Pointers"

    def __str__(self) -> str:
        return f"Evidence [{self.source_module}:{self.source_model}#{self.source_record_id}]"


class ForensicTimelineEvent(ForensicBaseModel):
    """
    Chronological event record for reconstructed cross-module timelines.
    """

    entity = models.ForeignKey(
        ForensicEntity,
        on_delete=models.CASCADE,
        related_name="timeline_events",
        help_text="Primary entity involved in this event",
    )
    relationship = models.ForeignKey(
        EntityRelationship,
        on_delete=models.SET_NULL,
        related_name="timeline_events",
        null=True,
        blank=True,
        help_text="Optional linked relationship edge",
    )
    event_title = models.CharField(
        max_length=255,
        help_text="Brief headline (e.g. 'PO-2026-88 Issued', 'Transfer ₹5,00,000')",
    )
    event_description = models.TextField(
        blank=True,
        default="",
        help_text="Detailed description of the forensic interaction",
    )
    event_timestamp = models.DateTimeField(
        db_index=True,
        help_text="Exact date and time of the event",
    )
    source_module = models.CharField(
        max_length=32,
        db_index=True,
        help_text="Module reporting this event",
    )
    severity = models.CharField(
        max_length=16,
        default="INFO",
        help_text="Severity flag (INFO, WARNING, CRITICAL)",
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Contextual metadata for timeline playback",
    )

    class Meta:
        app_label = "q_link"
        ordering = ["event_timestamp"]
        verbose_name = "Forensic Timeline Event"
        verbose_name_plural = "Forensic Timeline Events"

    def __str__(self) -> str:
        return f"[{self.event_timestamp:%Y-%m-%d}] [{self.source_module}] {self.event_title}"


class RelationshipAlert(ForensicBaseModel):
    """
    Proactive investigative alert generated when new relationships, syndicate patterns,
    or historical entity resurfacings are discovered.
    """

    class AlertLevel(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    title = models.CharField(
        max_length=255,
        help_text="Alert headline (e.g. 'New Relationship: Vendor ABC connected to Employee X')",
    )
    alert_level = models.CharField(
        max_length=16,
        choices=AlertLevel.choices,
        default=AlertLevel.MEDIUM,
        db_index=True,
    )
    primary_entity = models.ForeignKey(
        ForensicEntity,
        on_delete=models.CASCADE,
        related_name="alerts",
        help_text="Central entity triggering the alert",
    )
    related_entities = models.JSONField(
        default=list,
        blank=True,
        help_text="Array of connected entity IDs, names, and roles",
    )
    risk_score = models.IntegerField(
        default=50,
        help_text="Calculated risk score (0-100)",
    )
    trigger_reason = models.TextField(
        blank=True,
        default="",
        help_text="Rule or threshold that triggered this alert",
    )
    ai_summary = models.TextField(
        blank=True,
        default="",
        help_text="LLM-synthesized narrative explaining the connection and investigative significance",
    )
    is_acknowledged = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether an auditor has acknowledged this notification",
    )

    class Meta:
        app_label = "q_link"
        ordering = ["-risk_score", "-created_at"]
        verbose_name = "Relationship Alert"
        verbose_name_plural = "Relationship Alerts"

    def __str__(self) -> str:
        return f"[{self.alert_level}] {self.title} (Risk: {self.risk_score})"

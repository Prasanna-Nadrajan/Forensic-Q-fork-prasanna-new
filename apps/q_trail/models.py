"""
Q-Trail Multi-Bank Money Trail & Fund Flow Database Models
=============================================================================
Defines forensic dossier cases, stitched multi-hop fund trail paths, and
pass-through nodes for intermediary conduits and circular round-tripping.
Conforms to SCHEMA.md and dbdiagram.io specifications.
=============================================================================
"""

from decimal import Decimal

from django.db import models

from core.models import ForensicBaseModel


class CaseDossier(ForensicBaseModel):
    """
    Forensic investigation case dossier tracking money trail campaigns across auditees.
    """

    case_number = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="Unique Case Reference (e.g. TR-2026-001)",
    )
    title = models.CharField(max_length=255, help_text="Investigation Dossier Title")
    lead_investigator = models.CharField(
        max_length=128, blank=True, default="", help_text="Assigned Senior Auditor"
    )
    status = models.CharField(max_length=32, default="Active", db_index=True)

    class Meta:
        app_label = "q_trail"
        ordering = ["-created_at"]
        verbose_name = "Case Dossier"
        verbose_name_plural = "Case Dossiers"

    def __str__(self) -> str:
        return f"{self.case_number} - {self.title}"


class FundTrailPath(ForensicBaseModel):
    """
    Stitched multi-hop fund flow path connecting source and destination auditees
    via direct transfers or intermediate conduit entities.
    """

    case = models.ForeignKey(
        CaseDossier,
        on_delete=models.CASCADE,
        related_name="fund_trails",
        null=True,
        blank=True,
        help_text="Linked Case Dossier",
    )
    source_entity = models.CharField(
        max_length=255, db_index=True, help_text="Originating Person / Account"
    )
    source_bank = models.CharField(
        max_length=64, blank=True, default="", help_text="Source Bank Institution"
    )
    intermediate_hops = models.JSONField(
        default=list, blank=True, help_text="Array of conduit entity names, timestamps, and amounts"
    )
    destination_entity = models.CharField(
        max_length=255, db_index=True, help_text="Recipient Person / Account"
    )
    destination_bank = models.CharField(
        max_length=64, blank=True, default="", help_text="Destination Bank Institution"
    )
    total_amount = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
        help_text="Total Funds Transferred (INR)",
    )
    hop_count = models.IntegerField(default=1, help_text="1 for direct, 2 for 1-hop conduit, etc.")
    is_circular = models.BooleanField(
        default=False, db_index=True, help_text="True if funds loop back to originator"
    )
    velocity_hours = models.FloatField(default=0.0, help_text="Pass-through speed in hours")
    risk_score = models.IntegerField(
        default=0, db_index=True, help_text="Calculated Trail Risk Score (0-100)"
    )

    class Meta:
        app_label = "q_trail"
        ordering = ["-total_amount", "-created_at"]
        verbose_name = "Fund Trail Path"
        verbose_name_plural = "Fund Trail Paths"

    def __str__(self) -> str:
        return f"{self.source_entity} -> {self.destination_entity} (₹{self.total_amount})"


class PassThroughNode(ForensicBaseModel):
    """
    Detailed ledger entry for an intermediate conduit node (Person X)
    within a multi-hop money trail.
    """

    trail = models.ForeignKey(
        FundTrailPath,
        on_delete=models.CASCADE,
        related_name="pass_through_nodes",
        help_text="Parent Fund Trail Path",
    )
    entity_name = models.CharField(max_length=255, db_index=True, help_text="Conduit Person / VPA")
    inflow_amount = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
        help_text="Amount received from originator",
    )
    outflow_amount = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
        help_text="Amount passed to recipient",
    )
    retention_pct = models.FloatField(default=0.0, help_text="Percentage retained by conduit")
    inflow_time = models.DateTimeField(null=True, blank=True, help_text="Timestamp of fund receipt")
    outflow_time = models.DateTimeField(
        null=True, blank=True, help_text="Timestamp of fund dispatch"
    )

    class Meta:
        app_label = "q_trail"
        ordering = ["-created_at"]
        verbose_name = "Pass-Through Node"
        verbose_name_plural = "Pass-Through Nodes"

    def __str__(self) -> str:
        return f"{self.entity_name} (₹{self.inflow_amount} -> ₹{self.outflow_amount})"

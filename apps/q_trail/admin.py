"""
Q-Trail Admin Configuration
Registers forensic case dossiers, fund trails, and pass-through conduit nodes.
"""

from django.contrib import admin

from .models import CaseDossier, FundTrailPath, PassThroughNode


@admin.register(CaseDossier)
class CaseDossierAdmin(admin.ModelAdmin):
    list_display = ("case_number", "title", "lead_investigator", "status", "created_at")
    search_fields = ("case_number", "title", "lead_investigator")
    list_filter = ("status", "created_at")


@admin.register(FundTrailPath)
class FundTrailPathAdmin(admin.ModelAdmin):
    list_display = (
        "source_entity",
        "destination_entity",
        "total_amount",
        "hop_count",
        "is_circular",
        "risk_score",
        "created_at",
    )
    search_fields = ("source_entity", "destination_entity")
    list_filter = ("hop_count", "is_circular")


@admin.register(PassThroughNode)
class PassThroughNodeAdmin(admin.ModelAdmin):
    list_display = ("entity_name", "inflow_amount", "outflow_amount", "retention_pct", "trail")
    search_fields = ("entity_name",)

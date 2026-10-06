from django.apps import AppConfig


class QVerifyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "q_verify"
    verbose_name = "Q-Verify"

    # Forensic Module Metadata
    module_num = "06"
    module_category = "DOCUMENT"
    module_name = "Verify"
    module_tag = "LIVE"
    module_accent = "rose"
    module_tagline = "Document Metadata Forensic Analyzer"
    module_url = "/verify/"
    module_order = 6

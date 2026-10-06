from django.apps import AppConfig


class QLinkConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "q_link"
    verbose_name = "Q-Link"

    # Forensic Module Metadata
    module_num = "05"
    module_category = "CORRELATOR"
    module_name = "Link"
    module_tag = "LIVE"
    module_accent = "orange"
    module_tagline = "Cross-Source Evidence Correlation & Intelligence Engine"
    module_url = "/link/"
    module_order = 5

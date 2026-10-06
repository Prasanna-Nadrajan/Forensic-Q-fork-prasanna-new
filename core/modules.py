import importlib
import inspect

from django.apps import AppConfig
from django.conf import settings

# Default catalog for known Forensic-Q analytical modules
DEFAULT_MODULE_SPECS = {
    "q_bank": {
        "num": "01",
        "category": "TRANSACTION",
        "name": "Bank",
        "tag": "LIVE",
        "accent": "orange",
        "tagline": "Multi-Bank Forensic Analyzer",
        "href": "/bank/",
        "order": 1,
    },
    "q_trail": {
        "num": "02",
        "category": "TRANSACTION",
        "name": "Trail",
        "tag": "LIVE",
        "accent": "gold",
        "tagline": "End-to-End Money Trail Mapper",
        "href": "/trail/",
        "order": 2,
    },
    "q_mail": {
        "num": "03",
        "category": "COMMUNICATIONS",
        "name": "Mail",
        "tag": "LIVE",
        "accent": "purple",
        "tagline": "Email Forensic Intelligence Analyzer",
        "href": "/mail/",
        "order": 3,
    },
    "q_scan": {
        "num": "04",
        "category": "DESKTOP",
        "name": "Scan",
        "tag": "LIVE",
        "accent": "teal",
        "tagline": "Computer Evidence Discovery Tool",
        "href": "/scan/",
        "order": 4,
    },
    "q_link": {
        "num": "05",
        "category": "CORRELATOR",
        "name": "Link",
        "tag": "LIVE",
        "accent": "orange",
        "tagline": "Cross-Source Evidence Correlation & Intelligence Engine",
        "href": "/link/",
        "order": 5,
    },
    "q_verify": {
        "num": "06",
        "category": "DOCUMENT",
        "name": "Verify",
        "tag": "LIVE",
        "accent": "rose",
        "tagline": "Document Metadata Forensic Analyzer",
        "href": "/verify/",
        "order": 6,
    },
    "q_voice": {
        "num": "07",
        "category": "VOICE",
        "name": "Voice",
        "tag": "LIVE",
        "accent": "indigo",
        "tagline": "Voice Transcript Intelligence Analyzer",
        "href": "/voice/",
        "order": 7,
    },
    "q_ledger": {
        "num": "08",
        "category": "ERP / RECORDS",
        "name": "Ledger",
        "tag": "LIVE",
        "accent": "copper",
        "tagline": "SAP ERP & Procurement Forensic Analyzer",
        "href": "/ledger/",
        "order": 8,
    },
    "q_chat": {
        "num": "09",
        "category": "COMMUNICATIONS",
        "name": "Chat",
        "tag": "LIVE",
        "accent": "steel",
        "tagline": "Corporate Chat Forensic Analyzer",
        "href": "/chat/",
        "order": 9,
    },
}

EXCLUDED_MODULES = {"q_timeline", "timeline"}

ACCENT_ROTATION = ["orange", "gold", "purple", "teal", "rose", "amber", "steel", "copper"]


def get_discovered_modules():
    """
    Dynamically scans BASE_DIR / 'apps' for all app directories and builds
    module cards based on app configuration, AppConfig metadata, and default specs.
    Explicitly excludes q_timeline.
    """
    apps_dir = settings.BASE_DIR / "apps"
    if not apps_dir.exists():
        return []

    modules = []
    app_folders = [d for d in apps_dir.iterdir() if d.is_dir() and (d / "__init__.py").exists()]

    for idx, folder in enumerate(sorted(app_folders, key=lambda f: f.name)):
        app_name = folder.name

        # Explicit exclusion rule
        if app_name in EXCLUDED_MODULES:
            continue

        config = None

        # Try to dynamically load the AppConfig class
        apps_py = folder / "apps.py"
        if apps_py.exists():
            try:
                module_obj = importlib.import_module(f"{app_name}.apps")
                for attr_name in dir(module_obj):
                    attr = getattr(module_obj, attr_name)
                    if (
                        inspect.isclass(attr)
                        and issubclass(attr, AppConfig)
                        and attr is not AppConfig
                    ):
                        config = attr
                        break
            except (ImportError, AttributeError, ValueError):
                config = None

        # Check default catalog
        default_spec = DEFAULT_MODULE_SPECS.get(app_name, {})

        # Extract attributes with fallback hierarchy: AppConfig > default_spec > auto-generated
        clean_name = app_name.replace("q_", "").replace("_", " ").title()
        accent = (
            getattr(config, "module_accent", None)
            or default_spec.get("accent")
            or ACCENT_ROTATION[idx % len(ACCENT_ROTATION)]
        )

        # num can be empty string for BUILDING modules
        if hasattr(config, "module_num"):
            num = config.module_num
        elif "num" in default_spec:
            num = default_spec["num"]
        else:
            num = f"{idx + 1:02d}"

        category = (
            getattr(config, "module_category", None) or default_spec.get("category") or "FORENSIC"
        )
        name = getattr(config, "module_name", None) or default_spec.get("name") or clean_name
        tag = getattr(config, "module_tag", None) or default_spec.get("tag") or "LIVE"
        tagline = (
            getattr(config, "module_tagline", None)
            or default_spec.get("tagline")
            or f"Forensic analysis and investigation engine for {clean_name}."
        )

        if hasattr(config, "module_features"):
            features = config.module_features
        elif "features" in default_spec:
            features = default_spec["features"]
        else:
            features = []

        href = getattr(config, "module_url", None) or default_spec.get("href") or "/demo/tabulator/"
        order = getattr(config, "module_order", None) or default_spec.get("order") or idx + 1

        modules.append(
            {
                "app_name": app_name,
                "num": num,
                "category": category,
                "name": name,
                "tag": tag,
                "accent": accent,
                "tagline": tagline,
                "features": features,
                "href": href,
                "order": order,
            }
        )

    # Sort modules by designated order and num
    modules.sort(key=lambda m: (m["order"], str(m["num"])))
    return modules

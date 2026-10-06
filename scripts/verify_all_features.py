# ruff: noqa: E402
"""
End-to-end verification script for Forensic-Q
Tests all features:
- Authentication & login
- Audit auto-generation (YYYY-WB-XX)
- Profile mapping/unmapping
- Active audit session state & API
- Global context processor scoping
- Q-Trail audit scoping & toggle (audit vs all)
- Q-Link audit scoping & toggle (audit vs all)
- Q-Bank, Q-Mail, Q-Voice, Q-Verify, Q-Scan, Q-Chat audit scoping
"""

import json
import os
import sys
from pathlib import Path

# Setup Django environment
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")

import django

django.setup()

from django.test import Client, RequestFactory
from django.urls import reverse

from core.audits import (
    create_audit,
    generate_next_audit_name,
)
from core.context_processors import global_profiles_context
from core.models import InvestigationProfile


def run_verification():
    print("=" * 70)
    print("  FORENSIC-Q SYSTEMATIC FEATURE VERIFICATION")
    print("=" * 70)

    client = Client()
    passed_checks = []
    failed_checks = []

    def check(name, condition, extra_info=""):
        if condition:
            print(f"  [PASS] {name} {extra_info}")
            passed_checks.append(name)
        else:
            print(f"  [FAIL] {name} {extra_info}")
            failed_checks.append(name)

    # 1. Master Login Authentication
    print("\n--- 1. Authentication & Security ---")
    res_unauth = client.get("/")
    check(
        "Unauthenticated redirect to /login/",
        res_unauth.status_code == 302 and "/login/" in res_unauth.url,
    )

    res_wrong_pw = client.post("/login/", {"password": "wrongpassword"})
    check(
        "Reject incorrect portal key",
        res_wrong_pw.status_code == 200 and "Invalid" in res_wrong_pw.content.decode(),
    )

    from django.conf import settings

    expected_password = getattr(settings, "PORTAL_ACCESS_PASSWORD", "forensiq2026")

    res_login = client.post("/login/", {"password": expected_password})
    check(
        f"Accept master portal key ({expected_password})",
        res_login.status_code == 302 and res_login.url == "/",
    )

    res_auth = client.get("/")
    check("Authenticated access to Landing Page (200 OK)", res_auth.status_code == 200)

    # 2. Sequential Audit Generation (YYYY-WB-XX)
    print("\n--- 2. Sequential Audit Creation & Auto-Naming ---")
    next_name = generate_next_audit_name(year=2026)
    check(
        "Next audit name format matches YYYY-WB-XX",
        "-WB-" in next_name and len(next_name) >= 10,
        f"({next_name})",
    )

    # Ensure we have at least 3 test profiles
    p1, _ = InvestigationProfile.objects.get_or_create(
        full_name="Arun Kumar",
        defaults={
            "department": "Strategic Sourcing",
            "designation": "General Manager",
            "is_substantiated": True,
        },
    )
    p2, _ = InvestigationProfile.objects.get_or_create(
        full_name="Rajesh Sharma",
        defaults={
            "department": "Commercial Sourcing",
            "designation": "Deputy General Manager",
            "is_substantiated": False,
        },
    )
    p3, _ = InvestigationProfile.objects.get_or_create(
        full_name="Suresh Raina",
        defaults={
            "department": "Procurement Operations",
            "designation": "Senior Manager",
            "is_substantiated": False,
        },
    )
    check(
        "Investigation profiles available",
        InvestigationProfile.objects.count() >= 3,
        f"({InvestigationProfile.objects.count()} total)",
    )

    # Create test audit with 2 profiles
    audit = create_audit(
        title="Verification Test Audit",
        description="Automated feature testing audit",
        profile_ids=[str(p1.id), str(p2.id)],
    )
    check(
        "Audit created with auto-sequential name",
        bool(audit.name) and "-WB-" in audit.name,
        f"({audit.name})",
    )
    check("Audit profiles properly mapped (2 mapped)", audit.profiles.count() == 2)
    mapped_ids = [str(p.id) for p in audit.profiles.all()]
    check(
        "Profile 1 and 2 mapped, Profile 3 excluded",
        str(p1.id) in mapped_ids and str(p2.id) in mapped_ids and str(p3.id) not in mapped_ids,
    )

    # 3. Active Audit Session & API
    print("\n--- 3. Active Audit Switching & APIs ---")
    res_set = client.post(
        reverse("set_active_audit"),
        data=json.dumps({"audit_id": str(audit.id)}),
        content_type="application/json",
    )
    check(
        "Set active audit endpoint (/audits/active/)",
        res_set.status_code == 200 and res_set.json()["status"] == "success",
    )
    check(
        "Active audit in response matches created audit",
        res_set.json()["active_audit"]["name"] == audit.name,
    )

    # Context Processor scoping
    factory = RequestFactory()
    req = factory.get("/")
    req.session = client.session
    ctx = global_profiles_context(req)
    check("Context processor detects active audit", ctx["is_audit_active"] is True)
    check(
        "Context processor scopes investigation_profiles to mapped profiles",
        len(ctx["investigation_profiles"]) == 2,
    )
    check(
        "Context processor preserves all_investigation_profiles",
        len(ctx["all_investigation_profiles"]) >= 3,
    )

    # 4. Landing Page UI Elements
    print("\n--- 4. Landing Page Template & Modals ---")
    res_landing = client.get("/")
    html_landing = res_landing.content.decode()
    check("Landing page contains Audits Directory button", "landing-audits-btn" in html_landing)
    check("Landing page contains Profiles Directory button", "landing-profiles-btn" in html_landing)
    check(
        "Landing page contains App Launch Intercept Modal",
        "showLaunchModal" in html_landing and "Select Audit Workspace" in html_landing,
    )
    check(
        "Landing page contains promptLaunchModule handler on cards",
        "promptLaunchModule" in html_landing,
    )

    # 5. Q-Trail: Audit Scoping and Toggle Switch
    print("\n--- 5. Q-Trail Multi-Bank Trail Scoping & Toggle ---")
    # Scope: audit (default)
    res_trail_audit = client.get(reverse("q_trail:dashboard") + "?scope=audit")
    check("Q-Trail loads with scope=audit (200 OK)", res_trail_audit.status_code == 200)
    html_trail = res_trail_audit.content.decode()
    audit_checkbox_count = html_trail.count('name="profile_ids"')
    check(
        "Q-Trail renders exactly 2 audit-scoped profiles in HTML",
        audit_checkbox_count == 2,
        f"({audit_checkbox_count} checkboxes)",
    )
    check(
        "Q-Trail displays segmented toggle button in HTML",
        "Audit:" in html_trail and "All Profiles (" in html_trail,
    )
    check("Q-Trail preserves scope in hidden form field", 'name="scope"' in html_trail)

    # Scope: all
    res_trail_all = client.get(reverse("q_trail:dashboard") + "?scope=all")
    check("Q-Trail loads with scope=all (200 OK)", res_trail_all.status_code == 200)
    html_trail_all = res_trail_all.content.decode()
    all_checkbox_count = html_trail_all.count('name="profile_ids"')
    check(
        "Q-Trail renders all profiles in HTML when scope=all",
        all_checkbox_count >= 3,
        f"({all_checkbox_count} checkboxes)",
    )

    # 6. Q-Link: Knowledge Graph Scoping and Toggle Switch
    print("\n--- 6. Q-Link Relationship Engine Scoping & Toggle ---")
    res_link_audit = client.get(reverse("q_link:dashboard") + "?scope=audit")
    check("Q-Link loads with scope=audit (200 OK)", res_link_audit.status_code == 200)
    html_link = res_link_audit.content.decode()
    check(
        "Q-Link displays segmented toggle in action bar",
        "Audit:" in html_link and "All Profiles (" in html_link,
    )
    check(
        "Q-Link active toggle reflects scope=audit",
        "bg-amber-500 text-slate-950 font-bold" in html_link,
    )

    res_link_all = client.get(reverse("q_link:dashboard") + "?scope=all")
    check("Q-Link loads with scope=all (200 OK)", res_link_all.status_code == 200)
    html_link_all = res_link_all.content.decode()
    check("Q-Link displays toggle with scope=all active", 'href="?scope=all"' in html_link_all)

    # 7. Other Analytical Applications (Q-Bank, Q-Mail, Q-Voice, Q-Verify, Q-Scan, Q-Chat)
    print("\n--- 7. Application Directory Scoping Verification ---")
    apps_to_test = [
        ("Q-Bank", "/bank/"),
        ("Q-Mail", "/mail/"),
        ("Q-Voice", "/voice/"),
        ("Q-Verify", "/verify/"),
        ("Q-Scan", "/scan/"),
        ("Q-Chat", "/chat/"),
    ]

    for app_name, url in apps_to_test:
        res_app = client.get(url)
        check(f"{app_name} loads (200 OK)", res_app.status_code == 200)
        html_app = res_app.content.decode()
        check(
            f"{app_name} renders active audit pill in header ({audit.name})", audit.name in html_app
        )

    # 8. Audit Switcher in Header Modal & Global Mode
    print("\n--- 8. Header Audit Switcher & Global Mode ---")
    # Clear active audit
    res_clear = client.post(
        reverse("set_active_audit"),
        data=json.dumps({"audit_id": ""}),
        content_type="application/json",
    )
    check(
        "Clear active audit (/audits/active/ with empty ID)",
        res_clear.status_code == 200 and res_clear.json()["active_audit"] is None,
    )

    req.session = client.session
    ctx_cleared = global_profiles_context(req)
    check("Global mode active (is_audit_active=False)", ctx_cleared["is_audit_active"] is False)
    check(
        "Global mode shows all profiles",
        len(ctx_cleared["investigation_profiles"]) == ctx_cleared["total_profiles_count"],
    )

    # Verify header reflects cleared audit
    res_cleared_page = client.get("/trail/")
    html_cleared = res_cleared_page.content.decode()
    check(
        "Header reflects unrestricted mode (Select Audit / All Profiles)",
        "Select Audit" in html_cleared,
    )

    print("\n" + "=" * 70)
    print(f"  VERIFICATION RESULTS: {len(passed_checks)} PASSED, {len(failed_checks)} FAILED")
    print("=" * 70)

    if failed_checks:
        sys.exit(1)
    else:
        print("  ALL FORENSIC-Q FEATURES FUNCTIONING FLAWLESSLY!\n")
        sys.exit(0)


if __name__ == "__main__":
    run_verification()

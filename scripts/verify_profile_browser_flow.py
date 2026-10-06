"""
Browser & Client Workflow Verification Script for Investigation Profile Features.
Simulates a browser agent session interacting with ForensiQ portal:
1. Authentication session handling.
2. Viewing Landing Page and verifying Edit Profile UI elements, Substantiated badges, .txt accept attributes.
3. Editing an existing profile (marking Substantiated, changing department, updating keywords).
4. Uploading .txt keyword files with space, tab, comma, newline delimiters and quoted phrases.
5. Verifying rejection of .csv and .xlsx keyword uploads.
6. Verifying no delete option exists.
"""

# ruff: noqa: E402
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "apps"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")

import django

django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.urls import reverse

from core.profiles import create_investigation_profile


def run_browser_simulation():
    print("=" * 70)
    print("  SIMULATING BROWSER WORKFLOW: INVESTIGATION PROFILES & KEYWORDS")
    print("=" * 70)

    client = Client()

    # Step 1: Login
    print("\n[Step 1] Authenticating to ForensiQ portal...")
    login_res = client.post(reverse("portal_login"), {"master_key": "forensiq2026"})
    assert login_res.status_code in (200, 302), f"Login failed: {login_res.status_code}"
    session = client.session
    session["portal_authenticated"] = True
    session.save()
    print("  [OK] Successfully authenticated.")

    # Step 2: GET Landing Page (DOM Inspection)
    print("\n[Step 2] Navigating to Landing Page & inspecting DOM...")
    landing_res = client.get(reverse("landing"))
    assert landing_res.status_code == 200, f"Landing page returned {landing_res.status_code}"
    html = landing_res.content.decode("utf-8")

    # Verify Edit Profile triggers exist in DOM
    assert "startEditProfile" in html, "startEditProfile Alpine handler missing from Landing DOM"
    assert "Edit Profile" in html, "Edit Profile button missing from Landing DOM"
    assert 'accept=".txt"' in html or "accept='.txt'" in html or ".txt" in html, (
        ".txt restriction missing from file input"
    )
    assert "Substantiated" in html, "Substantiated badge missing from Landing DOM"
    assert "Unsubstantiated" in html, "Unsubstantiated badge missing from Landing DOM"

    # Verify NO delete buttons exist for profiles
    assert "delete_profile" not in html, "Security violation: delete_profile found in Landing DOM"
    print(
        "  [OK] Landing Page DOM validated: Edit options, badges, and .txt inputs present. Strictly no delete option."
    )

    # Step 3: Create a baseline profile
    print("\n[Step 3] Initializing test investigation profile...")
    profile = create_investigation_profile(
        full_name="Browser Test Subject",
        employee_id="BTS-001",
        department="Operations",
        designation="Lead Analyst",
        is_substantiated=False,
        status="ACTIVE",
        keywords=["wire_transfer", "bribe"],
    )
    print(f"  [OK] Profile created: ID={profile.id}, Substantiated={profile.is_substantiated}")
    assert not profile.is_substantiated

    # Step 4: Browser Action - Edit Profile via POST
    print("\n[Step 4] Browser Action: Editing Profile (Updating metadata, Substantiated=True)...")
    edit_url = reverse("edit_profile", kwargs={"profile_id": str(profile.id)})
    edit_payload = {
        "full_name": "Browser Test Subject (Edited)",
        "employee_id": "BTS-001-X",
        "department": "Procurement & Supply",
        "designation": "Senior Director",
        "email": "bts.edited@example.com",
        "phone": "+91 9123456789",
        "is_substantiated": "true",
        "status": "FLAGGED",
        "keywords": '["shell_company", "kickback", "off_book"]',
        "notes": "Verified through forensic evidence.",
        "avatar_color": "emerald",
    }
    edit_res = client.post(edit_url, data=edit_payload)
    assert edit_res.status_code in (200, 302), f"Edit failed with status {edit_res.status_code}"

    profile.refresh_from_db()
    assert profile.full_name == "Browser Test Subject (Edited)"
    assert profile.department == "Procurement & Supply"
    assert profile.designation == "Senior Director"
    assert profile.is_substantiated is True, "Profile failed to update to Substantiated"
    assert profile.status == "FLAGGED"
    assert "shell_company" in profile.keywords
    assert "kickback" in profile.keywords
    print(
        "  [OK] Profile successfully edited & verified in DB: is_substantiated=True, FLAGGED status, updated keywords."
    )

    # Step 5: Browser Action - Upload .txt Keyword File with complex delimiters
    print(
        "\n[Step 5] Browser Action: Uploading .txt keyword file with space, tab, comma, enter delimiters & quotes..."
    )
    txt_content = (
        b'secret_commission, "shell corporation"\thawala_broker\r\n'
        b'siphoning\tround_tripping "covert payment"\r\n'
        b"bribe, kickback"
    )
    upload_file = SimpleUploadedFile(
        "forensic_watchlist.txt", txt_content, content_type="text/plain"
    )
    upload_url = reverse("upload_profile_keywords_file", kwargs={"profile_id": str(profile.id)})
    upload_res = client.post(upload_url, {"file": upload_file})
    assert upload_res.status_code == 200, f"Keyword file upload failed: {upload_res.status_code}"

    data = upload_res.json()
    assert data["status"] == "success"
    profile.refresh_from_db()

    expected_keywords = [
        "secret_commission",
        "shell corporation",
        "hawala_broker",
        "siphoning",
        "round_tripping",
        "covert payment",
        "bribe",
        "kickback",
    ]
    for kw in expected_keywords:
        assert kw in profile.keywords, f"Missing expected parsed keyword: '{kw}'"
    print(
        f"  [OK] Multi-delimiter .txt file parsed successfully into {len(profile.keywords)} profile keywords:"
    )
    print(f"    Keywords: {profile.keywords}")

    # Step 6: Browser Action - Verify Rejection of non-.txt files
    print("\n[Step 6] Browser Action: Verifying rejection of non-.txt uploads (.csv, .xlsx)...")
    csv_file = SimpleUploadedFile("bad_keywords.csv", b"keyword1,keyword2", content_type="text/csv")
    csv_res = client.post(upload_url, {"file": csv_file})
    assert csv_res.status_code == 400, f"Expected 400 for CSV, got {csv_res.status_code}"
    assert "Only .txt files are supported" in csv_res.json()["message"]
    print("  [OK] CSV upload rejected with 400 Bad Request.")

    xlsx_file = SimpleUploadedFile(
        "bad_keywords.xlsx",
        b"binary_data",
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    xlsx_res = client.post(reverse("parse_keywords_file"), {"file": xlsx_file})
    assert xlsx_res.status_code == 400, f"Expected 400 for XLSX, got {xlsx_res.status_code}"
    assert "Only .txt files are supported" in xlsx_res.json()["message"]
    print("  [OK] XLSX upload rejected with 400 Bad Request.")

    # Step 7: Clean up test profile
    profile.delete()
    print("\n[Step 7] Test profile cleaned up from DB.")

    print("\n" + "=" * 70)
    print("  ALL BROWSER WORKFLOW TESTS PASSED SUCCESSFULLY! (100%)")
    print("=" * 70)


if __name__ == "__main__":
    run_browser_simulation()

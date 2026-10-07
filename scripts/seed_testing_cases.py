"""
ForensiQ Real Sample Test Cases Seeder
=============================================================================
Flushes previous sample/dummy data and uploads the 4 real test cases
from C:\\Users\\VikashG\\Downloads\\Testing into the ForensiQ investigation engine.

Cases Seeded:
  - Case 1: Mr. V Bank Statement -> Shanthi & Silviya + Q-Scan Nominee Schedule
  - Case 1.b: Mr. V Rapid Layering with Palani + Q-Chat WhatsApp Vendor Export
  - Case 2: Maharajan Partnership Deed -> Dhanasekaran (Substantiated Tag)
  - Case 3: Kaviarasan Multi-Hop -> Indhumathi -> Kumar & Sathees + Q-Voice Intercept
=============================================================================
"""

# ruff: noqa: E402
import os
import sys
from pathlib import Path

import django

# Setup Django Environment
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ForensiQ.settings")
django.setup()

from q_bank.services import (
    get_or_create_audited_person_from_profile,
    ingest_bank_statement_file,
)
from q_chat.services import ingest_chat_export_file
from q_link.backend.sync_all import sync_all_modules
from q_link.models import EntityRelationship, ForensicEntity, RelationshipAlert
from q_scan.services import ingest_document_for_scan
from q_trail.services import analyze_profiles_money_trail
from q_voice.services import ingest_audio_recording

from core.audits import create_audit
from core.models import InvestigationProfile
from core.profiles import attach_document_to_profile

TESTING_ROOT = Path(r"C:\Users\VikashG\Downloads\Testing")


def seed_real_test_cases():
    print("=" * 75)
    print("  FORENSIQ SAMPLE CASES SEEDER: CASES 1, 1.B, 2, 3")
    print("=" * 75)
    print(f"[*] Source directory: {TESTING_ROOT}\n")

    if not TESTING_ROOT.exists():
        print(f"[!] Error: {TESTING_ROOT} does not exist!")
        return False

    # -------------------------------------------------------------------------
    # 1. SETUP INVESTIGATION PROFILES
    # -------------------------------------------------------------------------
    print("[1/6] Registering Core Investigation Profiles...")

    # Profile 1: Mr. V (Veeramani Velmurugan)
    prof_v, _ = InvestigationProfile.objects.get_or_create(
        full_name="Veeramani Velmurugan",
        defaults={
            "employee_id": "HYU-OPS-042",
            "department": "Operations",
            "designation": "Operations Lead",
            "keywords": [
                "Palani",
                "Shanthi",
                "Silviya",
                "Operations",
                "IMPS",
                "Turnaround",
                "Rapid Layering",
            ],
            "is_substantiated": False,
            "notes": "Target custodian under investigation for third-party disbursements and vendor nexus.",
        },
    )
    print(f"  [✓] Profile created: {prof_v.full_name} ({prof_v.employee_id})")

    # Profile 2: Maharajan
    prof_maha, _ = InvestigationProfile.objects.get_or_create(
        full_name="Maharajan",
        defaults={
            "employee_id": "HYU-ENG-108",
            "department": "Engineering",
            "designation": "Senior Project Lead",
            "keywords": [
                "Partnership",
                "Sri Mirra",
                "Contract",
                "Deed",
                "Chennai",
                "Second Part",
            ],
            "is_substantiated": False,
            "notes": "Target engineer associated with external engineering entity Sri Mirra Engineers.",
        },
    )
    print(f"  [✓] Profile created: {prof_maha.full_name} ({prof_maha.employee_id})")

    # Profile 3: Dhanasekaran (SUBSTANTIATED)
    prof_dhana, _ = InvestigationProfile.objects.get_or_create(
        full_name="Dhanasekaran",
        defaults={
            "employee_id": "HYU-PROC-205",
            "department": "Procurement",
            "designation": "Commercial Vendor Coordinator",
            "keywords": [
                "Sri Mirra",
                "Partner",
                "Substantiated",
                "Engineers",
                "Chennai",
            ],
            "is_substantiated": True,
            "notes": "Signatory and partner in Sri Mirra Engineers partnership deed. Verified and substantiated.",
        },
    )
    prof_dhana.is_substantiated = True
    prof_dhana.save()
    print(
        f"  [✓] Profile created: {prof_dhana.full_name} ({prof_dhana.employee_id}) [SUBSTANTIATED]"
    )

    # Profile 4: Kaviarasan (Kavi)
    prof_kavi, _ = InvestigationProfile.objects.get_or_create(
        full_name="Kaviarasan",
        defaults={
            "employee_id": "HYU-ENG-312",
            "department": "Engineering",
            "designation": "Engineering Specialist",
            "keywords": [
                "Indhumathi",
                "Sathees",
                "Kumar",
                "Metec",
                "Design",
                "Multi-Hop",
            ],
            "is_substantiated": False,
            "notes": "Originator of multi-hop fund trail to Metec design contractors.",
        },
    )
    print(f"  [✓] Profile created: {prof_kavi.full_name} ({prof_kavi.employee_id})")

    # Profile 5: Indhumathi
    prof_indhu, _ = InvestigationProfile.objects.get_or_create(
        full_name="Indhumathi",
        defaults={
            "employee_id": "MET-HR-009",
            "department": "Human Resources",
            "designation": "Design HR - Metec",
            "keywords": [
                "Design",
                "HR",
                "Metec",
                "Rapid Layering Hub",
                "Payroll",
                "Onboarding",
            ],
            "is_substantiated": False,
            "notes": "Identified in audio intercepts as Design HR coordinator at Metec.",
        },
    )
    print(f"  [✓] Profile created: {prof_indhu.full_name} ({prof_indhu.employee_id})")

    # Profile 6: Emor Palani
    prof_palani, _ = InvestigationProfile.objects.get_or_create(
        full_name="Emor Palani",
        defaults={
            "employee_id": "VND-PAL-099",
            "department": "Vendor Services",
            "designation": "Vendor Representative",
            "keywords": [
                "Vendor",
                "Rapid Layering",
                "Invoice",
                "Field Vendor Discussion",
            ],
            "is_substantiated": False,
            "notes": "Contractor and vendor flagged for rapid turnaround transfers with Mr. V.",
        },
    )
    print(f"  [✓] Profile created: {prof_palani.full_name} ({prof_palani.employee_id})")

    # Profile 7 & 8: Kumar & Sathees (Contractors)
    prof_kumar, _ = InvestigationProfile.objects.get_or_create(
        full_name="Kumar",
        defaults={
            "employee_id": "CON-KUM-114",
            "department": "Contractor Services",
            "designation": "Design Contractor",
            "keywords": ["Design Contractor", "Metec", "Commission"],
            "is_substantiated": False,
        },
    )
    prof_sathees, _ = InvestigationProfile.objects.get_or_create(
        full_name="Sathees",
        defaults={
            "employee_id": "CON-SAT-115",
            "department": "Contractor Services",
            "designation": "Design Contractor",
            "keywords": ["Design Contractor", "Metec", "Commission"],
            "is_substantiated": False,
        },
    )
    print(f"  [✓] Profiles created: {prof_kumar.full_name}, {prof_sathees.full_name}")

    all_profiles = [
        prof_v,
        prof_maha,
        prof_dhana,
        prof_kavi,
        prof_indhu,
        prof_palani,
        prof_kumar,
        prof_sathees,
    ]

    # -------------------------------------------------------------------------
    # 2. CREATE MASTER AUDIT & ASSOCIATE PROFILES
    # -------------------------------------------------------------------------
    print("\n[2/6] Setting Up Master Audit (2026-WB-01)...")
    profile_ids = [str(p.id) for p in all_profiles]
    master_audit = create_audit(
        title="Hyundai Forensic Investigation - Active Cases (1, 1.b, 2, 3)",
        description=(
            "Primary investigative audit correlating Mr. V banking & nominee trail, "
            "Palani rapid layering, Maharajan partnership deed, and Kavi-Indhumathi multi-hop fund flow."
        ),
        profile_ids=profile_ids,
    )
    print(
        f"  [✓] Audit created: {master_audit.name} - '{master_audit.title}' with {master_audit.profiles.count()} profiles."
    )

    # -------------------------------------------------------------------------
    # 3. CASE 1 & CASE 1.B: INGEST MR. V BANK STATEMENT, NOMINEE SCAN, & CHAT
    # -------------------------------------------------------------------------
    print("\n[3/6] Ingesting Case 1 & Case 1.b Data (Mr. V & Palani)...")

    # 3.a Bank Statement (Federal Bank)
    stmt_pdf = TESTING_ROOT / "case 1" / "Federal_Bank_Account_Statement.pdf"
    if stmt_pdf.exists():
        ap_v = get_or_create_audited_person_from_profile(prof_v)
        with open(stmt_pdf, "rb") as f:
            acc_v = ingest_bank_statement_file(
                file_obj_or_path=f,
                filename=stmt_pdf.name,
                account_holder=prof_v.full_name,
                person_id=ap_v.id,
            )
        print(
            f"  [✓] Ingested Federal Bank Statement for {prof_v.full_name}: {acc_v.transactions.count()} transactions."
        )
    else:
        print(f"  [!] Missing file: {stmt_pdf}")

    # 3.b Nominee Schedule Screening (Q-Scan)
    schedule_pdf = TESTING_ROOT / "case 1" / "Sanitized_Employee_and_Nominee_Schedule.pdf"
    if schedule_pdf.exists():
        device = ingest_document_for_scan(
            file_obj_or_path=schedule_pdf,
            filename=schedule_pdf.name,
            hostname="SCHEDULE-AUDIT-CASE1",
            scan_title="Nominee Schedule Forensic Screening",
            custodian_name=prof_v.full_name,
        )
        print(
            f"  [✓] Screened Nominee Schedule via Q-Scan: {device.total_matches_found} hit(s) matched."
        )
    else:
        print(f"  [!] Missing file: {schedule_pdf}")

    # 3.c WhatsApp Chat Export (Q-Chat)
    chat_txt = TESTING_ROOT / "case 1.b" / "WhatsApp_Chat_Export.txt"
    if chat_txt.exists():
        with open(chat_txt, "rb") as f:
            chat_ch = ingest_chat_export_file(
                file_obj_or_content=f,
                filename=chat_txt.name,
                platform="WHATSAPP",
                channel_name="Field Vendor Discussion",
                custodian_name=prof_v.full_name,
            )
        print(
            f"  [✓] Ingested WhatsApp Chat Export: {chat_ch.total_messages} messages parsed in '{chat_ch.channel_name}'."
        )
    else:
        print(f"  [!] Missing file: {chat_txt}")

    # -------------------------------------------------------------------------
    # 4. CASE 2: ATTACH PARTNERSHIP DEED TO MAHARAJAN
    # -------------------------------------------------------------------------
    print("\n[4/6] Ingesting Case 2 Data (Maharajan & Dhanasekaran)...")
    deed_pdf = TESTING_ROOT / "case 2" / "Partnership_Deed.pdf"
    if deed_pdf.exists():
        with open(deed_pdf, "rb") as f:
            doc = attach_document_to_profile(
                profile_id=prof_maha.id,
                file_obj=f,
                filename=deed_pdf.name,
                description="Partnership Deed of Sri Mirra Engineers",
            )
        print(
            f"  [✓] Attached Partnership Deed to {prof_maha.full_name}: {doc.filename} ({len(doc.extracted_text)} chars extracted)."
        )
    else:
        print(f"  [!] Missing file: {deed_pdf}")

    # -------------------------------------------------------------------------
    # 5. CASE 3: INGEST KAVI BANK STATEMENT & Q-VOICE INTERCEPT
    # -------------------------------------------------------------------------
    print("\n[5/6] Ingesting Case 3 Data (Kaviarasan, Indhumathi, Kumar, Sathees)...")

    # 5.a Bank Statement (Combined XLSX)
    excel_stmt = TESTING_ROOT / "case 3" / "Bank_Statement_Combined.xlsx"
    if excel_stmt.exists():
        ap_kavi = get_or_create_audited_person_from_profile(prof_kavi)
        with open(excel_stmt, "rb") as f:
            acc_kavi = ingest_bank_statement_file(
                file_obj_or_path=f,
                filename=excel_stmt.name,
                account_holder=prof_kavi.full_name,
                person_id=ap_kavi.id,
            )
        print(
            f"  [✓] Ingested Bank Statement for {prof_kavi.full_name}: {acc_kavi.transactions.count()} transactions."
        )
    else:
        print(f"  [!] Missing file: {excel_stmt}")

    # 5.b Audio Recording (Q-Voice)
    audio_wav = TESTING_ROOT / "case 3" / "South%20Avenue%20Road%208.wav"
    if not audio_wav.exists():
        audio_wav = TESTING_ROOT / "case 3" / "South Avenue Road 8.wav"

    if audio_wav.exists():
        with open(audio_wav, "rb") as f:
            rec, _ = ingest_audio_recording(
                audio_file=f,
                call_title="South Avenue Road 8 Call Intercept",
                custodian_name=prof_kavi.full_name,
            )
        print(
            f"  [✓] Ingested Audio Intercept via Q-Voice: '{rec.call_title}' ({rec.segments.count()} segments, status={rec.transcription_status})."
        )
    else:
        print(f"  [!] Missing file: {audio_wav}")

    # Prime Q-Trail Money Trail Analytics
    print("  [*] Running Money Trail Rapid Layering analysis for Mr. V and Kavi...")
    analyze_profiles_money_trail([str(prof_v.id)])
    analyze_profiles_money_trail([str(prof_kavi.id)])

    # -------------------------------------------------------------------------
    # 6. SYNCHRONIZE ALL MODULES INTO Q-LINK
    # -------------------------------------------------------------------------
    print("\n[6/6] Synchronizing Cross-Module Findings into Q-Link Knowledge Graph...")
    sync_stats = sync_all_modules()
    print(f"  [✓] Q-Link Cross-Tool Sync Complete: {sync_stats}")

    total_entities = ForensicEntity.objects.count()
    total_rels = EntityRelationship.objects.count()
    total_alerts = RelationshipAlert.objects.count()

    print("\n" + "=" * 75)
    print("  FORENSIQ DATABASE SUCCESSFULLY SEEDED WITH REAL TEST CASES!")
    print("=" * 75)
    print(f"  Active Master Audit : {master_audit.name} ({master_audit.title})")
    print(f"  Profiles Created    : {InvestigationProfile.objects.count()}")
    print(f"  Forensic Entities   : {total_entities}")
    print(f"  Correlated Edges    : {total_rels}")
    print(f"  Active Risk Alerts  : {total_alerts}")
    print("=" * 75)
    return True


if __name__ == "__main__":
    success = seed_real_test_cases()
    sys.exit(0 if success else 1)

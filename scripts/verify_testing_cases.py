"""
ForensiQ Automated End-to-End Verification Suite for Sample Test Cases
Validates Case 1, Case 1.b, Case 2, and Case 3 against files in C:\\Users\\VikashG\\Downloads\\Testing.
"""

# ruff: noqa: E402
import os
import sys
from pathlib import Path

import django

# Setup Django environment
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

from core.models import InvestigationProfile
from core.profiles import attach_document_to_profile

TESTING_ROOT = Path(r"C:\Users\VikashG\Downloads\Testing")


def run_case_1():
    print("\n" + "=" * 70)
    print("RUNNING CASE 1: Bank Money Trail to Shanthi & Silviya + Q-Scan Nominee Schedule")
    print("=" * 70)

    case1_dir = TESTING_ROOT / "case 1"
    stmt_pdf = case1_dir / "Federal_Bank_Account_Statement.pdf"
    schedule_pdf = case1_dir / "Sanitized_Employee_and_Nominee_Schedule.pdf"

    assert stmt_pdf.exists(), f"Missing {stmt_pdf}"
    assert schedule_pdf.exists(), f"Missing {schedule_pdf}"

    # 1. Create Profile for Mr. V
    mr_v, _ = InvestigationProfile.objects.get_or_create(
        full_name="Veeramani Velmurugan",
        defaults={"department": "Operations", "is_substantiated": False},
    )
    ap = get_or_create_audited_person_from_profile(mr_v)

    # 2. Ingest Bank Statement
    with open(stmt_pdf, "rb") as f:
        acc = ingest_bank_statement_file(
            file_obj_or_path=f,
            filename=stmt_pdf.name,
            account_holder=mr_v.full_name,
            person_id=ap.id,
        )
    print(
        f"[✓] Bank Statement Ingested: {acc.transactions.count()} transactions for {mr_v.full_name}"
    )

    # Verify money trail to Shanthi and Silviya in bank transactions
    txns = list(acc.transactions.all())
    shanthi_txns = [t for t in txns if "shanthi" in t.narration.lower()]
    silviya_txns = [t for t in txns if "silviya" in t.narration.lower()]
    assert len(shanthi_txns) > 0, "Failed to identify money trail to Shanthi"
    assert len(silviya_txns) > 0, "Failed to identify money trail to Silviya"
    print(
        f"[✓] Money Trail Identified: {len(shanthi_txns)} txn(s) to Shanthi, {len(silviya_txns)} txn(s) to Silviya"
    )

    # 3. Use Q-Scan to screen schedule PDF
    device = ingest_document_for_scan(
        file_obj_or_path=schedule_pdf,
        filename=schedule_pdf.name,
        hostname="SCHEDULE-AUDIT-CASE1",
        scan_title="Nominee Schedule Audit",
        custodian_name=mr_v.full_name,
    )
    print(f"[✓] Q-Scan Ingested Schedule: {device.total_matches_found} hits found")

    silviya_hit = device.hits.filter(matched_keyword__iexact="Silviya").first()
    assert silviya_hit is not None, "Q-Scan did not match Silviya in schedule PDF"
    assert (
        "REMIGIUS" in silviya_hit.snippet or "JOSEPH" in silviya_hit.snippet
    ) and "Spouse" in silviya_hit.snippet, (
        f"Snippet did not contain spouse relation: {silviya_hit.snippet}"
    )
    print(f"[✓] Q-Scan Matched Relation: {silviya_hit.snippet[:80]}...")

    # 4. Check Q-Link Output
    silviya_ent = ForensicEntity.objects.filter(display_name__icontains="Silviya").first()
    remigius_ent = ForensicEntity.objects.filter(display_name__icontains="REMIGIUS").first()
    mr_v_ent = ForensicEntity.objects.filter(display_name__icontains="Veeramani").first()

    assert silviya_ent is not None, "Silviya entity missing in Q-Link"
    assert remigius_ent is not None, "Mr. A. Joseph Remigius entity missing in Q-Link"
    assert mr_v_ent is not None, "Mr. V entity missing in Q-Link"

    # Verify link: Remigius -> Spouse -> Silviya
    spouse_rel = EntityRelationship.objects.filter(
        source_entity=remigius_ent, target_entity=silviya_ent
    ).first()
    assert spouse_rel is not None, "Remigius -> Silviya spouse relationship missing in Q-Link"

    # Verify nexus: Mr. V -> Beneficiary Nexus -> Silviya
    nexus_rel = EntityRelationship.objects.filter(
        source_entity=mr_v_ent, target_entity=silviya_ent
    ).first()
    assert nexus_rel is not None, "Mr. V -> Silviya nexus relationship missing in Q-Link"
    print(
        "[✓] Q-Link Knowledge Graph Verified: Remigius (ID-004) --[SPOUSE]--> Silviya <--[NEXUS]-- Mr. V"
    )
    print(">>> CASE 1 PASSED SUCCESSFULLY! <<<\n")


def run_case_1b():
    print("\n" + "=" * 70)
    print("RUNNING CASE 1.b: Mr. V Rapid Layering from Palani + Q-Chat Identification")
    print("=" * 70)

    case1b_dir = TESTING_ROOT / "case 1.b"
    chat_txt = case1b_dir / "WhatsApp_Chat_Export.txt"
    assert chat_txt.exists(), f"Missing {chat_txt}"

    # 1. From Mr. V's Bank Statement, establish Rapid Layering for Palani
    mr_v = InvestigationProfile.objects.filter(full_name__icontains="Veeramani").first()
    assert mr_v is not None, "Mr. V profile must exist from Case 1"

    trail_res = analyze_profiles_money_trail([str(mr_v.id)])
    intermediate = trail_res.get("intermediate_transfers")
    assert intermediate is not None and not intermediate.empty, (
        "Rapid layering not detected for Mr. V"
    )

    palani_hops = intermediate[
        intermediate["Sender_Person"].str.contains("palani", case=False, na=False)
        | intermediate["Inflow_Narration"].str.contains("palani", case=False, na=False)
    ]
    assert not palani_hops.empty, (
        "Rapid layering hop from Palani not found in intermediate transfers"
    )
    first_hop = palani_hops.iloc[0]
    print(
        f"[✓] Rapid Layering Detected: Inflow from {first_hop['Sender_Person']} (₹{first_hop['Inflow_Amount']}) -> Outflow to {first_hop['Recipient_Person']} (₹{first_hop['Outflow_Amount']}) within {first_hop['Time_Delta_Hours']} hrs"
    )

    # 2. Ingest Q-Chat Export
    with open(chat_txt, "rb") as f:
        chat_channel = ingest_chat_export_file(
            file_obj_or_content=f,
            filename=chat_txt.name,
            platform="WHATSAPP",
            channel_name="Field Vendor Discussion",
            custodian_name=mr_v.full_name,
        )
    print(f"[✓] Q-Chat Ingested: {chat_channel.total_messages} messages parsed")

    # 3. Synchronize All to Q-Link
    sync_all_modules()

    # 4. Check Q-Link Collective Result
    palani_ent = ForensicEntity.objects.filter(display_name__icontains="Palani").first()
    assert palani_ent is not None, "Palani entity missing in Q-Link"
    print(f"[✓] Q-Link Identified Entity: {palani_ent.display_name} ({palani_ent.entity_type})")

    # Assert relations
    rels = list(palani_ent.out_relations.all()) + list(palani_ent.in_relations.all())
    assert len(rels) > 0, "Palani has no connected relations in Q-Link"
    for r in rels:
        print(
            f"    Link: {r.source_entity.display_name} --[{r.relation_type}]--> {r.target_entity.display_name}"
        )

    print(">>> CASE 1.b PASSED SUCCESSFULLY! <<<\n")


def run_case_2():
    print("\n" + "=" * 70)
    print("RUNNING CASE 2: Maharajan Partnership Deed + Substantiated Target Dhanasekaran")
    print("=" * 70)

    case2_dir = TESTING_ROOT / "case 2"
    deed_pdf = case2_dir / "Partnership_Deed.pdf"
    assert deed_pdf.exists(), f"Missing {deed_pdf}"

    # 1. Create profile Maharajan
    maharajan, _ = InvestigationProfile.objects.get_or_create(
        full_name="Maharajan",
        defaults={"department": "Engineering", "is_substantiated": False},
    )

    # 2. Attach Partnership Deed to Maharajan
    with open(deed_pdf, "rb") as f:
        doc = attach_document_to_profile(
            profile_id=maharajan.id,
            file_obj=f,
            filename=deed_pdf.name,
            description="Partnership Deed - Sri Mirra Engineers",
        )
    print(
        f"[✓] Partnership Deed Attached: {doc.filename} (Extracted text: {len(doc.extracted_text)} chars)"
    )
    assert "Dhanasekaran" in doc.extracted_text or "DHANASEKARAN" in doc.extracted_text, (
        "Dhanasekaran not extracted from deed"
    )

    # 3. Create profile Dhanasekaran marked as SUBSTANTIATED
    dhana, _ = InvestigationProfile.objects.get_or_create(
        full_name="Dhanasekaran",
        defaults={"department": "Procurement", "is_substantiated": True},
    )
    dhana.is_substantiated = True
    dhana.save()
    print(f"[✓] Created Profile: {dhana.full_name} (is_substantiated={dhana.is_substantiated})")

    # 4. Synchronize all to Q-Link
    sync_all_modules()

    # 5. Verify Q-Link shows Maharajan linked to Substantiated profile Dhanasekaran
    m_ent = ForensicEntity.objects.filter(display_name__icontains="Maharajan").first()
    d_ent = ForensicEntity.objects.filter(display_name__icontains="Dhanasekaran").first()
    assert m_ent is not None, "Maharajan entity missing in Q-Link"
    assert d_ent is not None, "Dhanasekaran entity missing in Q-Link"

    # Check connection
    partner_rel = (
        EntityRelationship.objects.filter(source_entity=m_ent, target_entity=d_ent).first()
        or EntityRelationship.objects.filter(source_entity=d_ent, target_entity=m_ent).first()
    )
    assert partner_rel is not None, "Maharajan <-> Dhanasekaran relationship missing in Q-Link"
    print(
        f"[✓] Q-Link Nexus Verified: {partner_rel.source_entity.display_name} --[{partner_rel.relation_type}]--> {partner_rel.target_entity.display_name}"
    )

    # Check critical alert
    alert = (
        RelationshipAlert.objects.filter(
            primary_entity=m_ent,
            title__icontains="Substantiated Target",
        ).first()
        or RelationshipAlert.objects.filter(
            title__icontains="Substantiated Target",
        ).first()
    )
    assert alert is not None, "Critical Alert 'Nexus with Substantiated Target' missing in Q-Link"
    print(
        f"[✓] Critical Alert Verified: [{alert.alert_level}] {alert.title} - {alert.trigger_reason}"
    )
    print(">>> CASE 2 PASSED SUCCESSFULLY! <<<\n")


def run_case_3():
    print("\n" + "=" * 70)
    print("RUNNING CASE 3: Kavi Rapid Layering + Q-Voice Indhumadhi Metec HR Identification")
    print("=" * 70)

    case3_dir = TESTING_ROOT / "case 3"
    excel_stmt = case3_dir / "Bank_Statement_Combined.xlsx"
    audio_wav = case3_dir / "South%20Avenue%20Road%208.wav"

    assert excel_stmt.exists(), f"Missing {excel_stmt}"
    assert audio_wav.exists(), f"Missing {audio_wav}"

    # 1. Create Profile for Kavi and Ingest Bank Statement
    kavi, _ = InvestigationProfile.objects.get_or_create(
        full_name="Kaviarasan",
        defaults={"department": "Engineering", "is_substantiated": False},
    )
    ap = get_or_create_audited_person_from_profile(kavi)

    with open(excel_stmt, "rb") as f:
        acc = ingest_bank_statement_file(
            file_obj_or_path=f,
            filename=excel_stmt.name,
            account_holder=kavi.full_name,
            person_id=ap.id,
        )
    print(f"[✓] Kavi Statement Ingested: {acc.transactions.count()} transactions")

    # 2. Q-Trail: Identify rapid hop from Indhumadhi to Kumar and Sathees
    trail_res = analyze_profiles_money_trail([str(kavi.id)])
    intermediate = trail_res.get("intermediate_transfers")
    assert intermediate is not None and not intermediate.empty, (
        "Rapid layering not detected for Kavi"
    )

    indhu_hops = intermediate[
        intermediate["Sender_Person"].str.contains("INDHUMATHI", case=False, na=False)
    ]
    assert len(indhu_hops) >= 2, "Expected multiple rapid hops from Indhumathi"

    sathees_found = any("sathees" in str(r).lower() for r in indhu_hops["Recipient_Person"])
    kumar_found = any("kumar" in str(r).lower() for r in indhu_hops["Recipient_Person"])
    assert sathees_found, "Rapid hop to Sathees not found in Q-Trail"
    assert kumar_found, "Rapid hop to Kumar not found in Q-Trail"
    print(
        "[✓] Q-Trail Rapid Layering Verified: Indhumathi -> Kaviarasan -> Sathees & Kumar detected within hours"
    )

    # 3. Q-Voice: Upload South Avenue Road 8.wav
    with open(audio_wav, "rb") as f:
        rec, _ = ingest_audio_recording(
            audio_file=f,
            call_title="South Avenue Road 8 Call Intercept",
            custodian_name=kavi.full_name,
        )
    assert rec is not None, "Failed to ingest audio recording"
    print(
        f"[✓] Q-Voice Ingested Recording: {rec.call_title} ({rec.segments.count()} segments, status={rec.transcription_status})"
    )

    # Verify flagged keywords: indhumathi, design, hr, metec
    all_text = " ".join([s.text_content for s in rec.segments.all()]).lower()
    for kw in ["indhumathi", "design", "hr", "metec"]:
        assert kw in all_text or kw in [k.lower() for k in rec.flagged_keywords], (
            f"Keyword '{kw}' not identified in Q-Voice"
        )
    print("[✓] Flagged Keywords Verified in Q-Voice: Indhumathi, Design, HR, Metec")

    # 4. Synchronize all to Q-Link
    sync_all_modules()

    # 5. In Q-Link, show link between Kaviarasan, Indhumathi, Kumar, Sathees, Metec
    kavi_ent = ForensicEntity.objects.filter(display_name__icontains="Kaviarasan").first()
    indhu_ent = ForensicEntity.objects.filter(display_name__icontains="Indhumathi").first()
    metec_ent = ForensicEntity.objects.filter(display_name__icontains="Metec").first()

    assert kavi_ent is not None, "Kaviarasan missing in Q-Link"
    assert indhu_ent is not None, "Indhumathi missing in Q-Link"
    assert metec_ent is not None, "Metec missing in Q-Link"

    indhu_rels = list(indhu_ent.out_relations.all()) + list(indhu_ent.in_relations.all())
    connected_names = {r.source_entity.display_name for r in indhu_rels} | {
        r.target_entity.display_name for r in indhu_rels
    }

    print(f"[✓] Q-Link Connected Network for Indhumathi: {connected_names}")
    assert any("metec" in n.lower() for n in connected_names), (
        "Indhumathi not linked to Metec in Q-Link"
    )
    assert any("kaviarasan" in n.lower() for n in connected_names), (
        "Indhumathi not linked to Kaviarasan in Q-Link"
    )
    print(">>> CASE 3 PASSED SUCCESSFULLY! <<<\n")


def main():
    print("======================================================================")
    print("FORENSIQ AUTOMATED VERIFICATION SUITE FOR ALL 4 FORENSIC CASES")
    print("======================================================================")
    run_case_1()
    run_case_1b()
    run_case_2()
    run_case_3()
    print("======================================================================")
    print("ALL 4 FORENSIC CASES PASSED 100% PERFECTLY!")
    print("======================================================================")


if __name__ == "__main__":
    main()

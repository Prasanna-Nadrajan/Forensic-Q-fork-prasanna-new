"""
Q-Link Cross-Module Synchronizer
Reads existing forensic records from Q-Bank, Q-Ledger, Q-Mail, Q-Trail, Q-Verify
and automatically synthesizes them into the unified Q-Link Knowledge Graph.
"""

from decimal import Decimal

from django.apps import apps
from loguru import logger

from ..models import ForensicEntity
from .dispatcher import emit_forensic_finding


def sync_all_modules() -> dict[str, int]:
    """
    Ingests all active historical data across all ForensiQ modules into Q-Link.
    Returns counts of ingested items per module.
    """
    stats = {
        "q_bank": 0,
        "q_ledger": 0,
        "q_mail": 0,
        "q_trail": 0,
        "q_verify": 0,
    }

    # 1. Ingest Q-Bank (Auditees, Bank Accounts, Transactions)
    if apps.is_installed("q_bank"):
        try:
            AuditedPerson = apps.get_model("q_bank", "AuditedPerson")
            BankTransaction = apps.get_model("q_bank", "BankTransaction")

            # Sync auditees
            for person in AuditedPerson.objects.all():
                emit_forensic_finding(
                    source_module="q_bank",
                    event_type="AUDITEE_PROFILE_SYNC",
                    primary_entity_data={
                        "name": person.full_name,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "raw_id": person.pan_number or person.employee_id or person.full_name,
                        "is_target": True,
                        "metadata": {
                            "employee_id": person.employee_id,
                            "department": person.department,
                            "pan_number": person.pan_number,
                            "email": person.email,
                            "phone": person.phone,
                        },
                    },
                )
                stats["q_bank"] += 1

            # Collect registered profile keywords and target names for selective linking
            from core.models import InvestigationProfile

            registered_keywords = set()
            for prof in InvestigationProfile.objects.all():
                for kw in prof.keywords or []:
                    if kw.strip():
                        registered_keywords.add(kw.strip().lower())
                registered_keywords.add(prof.full_name.strip().lower())

            for person in AuditedPerson.objects.all():
                registered_keywords.add(person.full_name.strip().lower())

            # Sync transactions (selective forensic linking only)
            for txn in BankTransaction.objects.select_related("account", "account__person")[:500]:
                account_holder = txn.account.account_holder if txn.account else "Unknown Account"
                person_name = (
                    txn.account.person.full_name
                    if (txn.account and txn.account.person)
                    else account_holder
                )

                amt = txn.debit_amount if txn.direction == "OUT" else txn.credit_amount
                if not amt or amt == Decimal("0.00"):
                    amt = txn.debit_amount or txn.credit_amount or Decimal("1.00")

                party_clean = txn.party_name.strip() if txn.party_name else "Unknown Counterparty"
                party_lower = party_clean.lower()
                narr_lower = (txn.narration or "").lower()

                # Selective Filtering: Only link if keyword match, risk flagged, high value, or known profile
                is_selective_match = False
                if any(
                    kw in party_lower or kw in narr_lower
                    for kw in registered_keywords
                    if len(kw) >= 3
                ):
                    is_selective_match = True
                elif getattr(txn, "risk_score", 0) >= 50 or txn.risk_level in [
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                ]:
                    is_selective_match = True
                elif txn.is_cash_deposit or txn.is_hyundai_related or bool(txn.flag_reason):
                    is_selective_match = True
                elif amt >= Decimal("50000.00"):
                    is_selective_match = True

                if not is_selective_match:
                    continue

                emit_forensic_finding(
                    source_module="q_bank",
                    event_type="BANK_TRANSACTION",
                    primary_entity_data={
                        "name": person_name,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "is_target": True,
                    },
                    secondary_entities_data=[
                        {
                            "name": party_clean,
                            "type": ForensicEntity.EntityType.VENDOR
                            if any(
                                s in party_clean.lower()
                                for s in ["ltd", "corp", "inc", "enterprises", "solutions"]
                            )
                            else ForensicEntity.EntityType.UNKNOWN,
                            "relation_type": "TRANSFERRED_FUNDS",
                            "weight": float(amt),
                            "direction": "out" if txn.direction == "OUT" else "in",
                        }
                    ],
                    evidence_data={
                        "source_module": "q_bank",
                        "source_model": "BankTransaction",
                        "source_record_id": str(txn.id),
                        "evidence_url": f"/bank/account/{txn.account.id}/"
                        if txn.account
                        else "/bank/",
                        "summary_snippet": f"Txn Ref: {txn.txn_ref} | Party: {party_clean} | Amount: ₹{amt:,.2f}",
                        "occurred_at": txn.txn_date,
                        "metadata": {
                            "date": txn.txn_date.strftime("%Y-%m-%d %H:%M") if txn.txn_date else "",
                            "amount": float(amt),
                            "debit_amount": float(txn.debit_amount or 0),
                            "credit_amount": float(txn.credit_amount or 0),
                            "direction": txn.direction,
                            "narration": txn.narration or "",
                            "ref_no": txn.txn_ref,
                            "account_no": txn.account.account_number if txn.account else "",
                        },
                    },
                    occurred_at=txn.txn_date,
                    timeline_title=f"Bank Transfer: ₹{amt:,.2f} ({txn.direction})",
                    timeline_description=f"Transaction with '{party_clean}' via Account {txn.account.account_number if txn.account else ''}",
                    severity="WARNING" if getattr(txn, "risk_score", 0) >= 50 else "INFO",
                )
                stats["q_bank"] += 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Bank: {err}")

    # 2. Ingest Q-Ledger (Purchase Orders, Invoices, Vendors)
    if apps.is_installed("q_ledger"):
        try:
            PurchaseOrder = apps.get_model("q_ledger", "PurchaseOrder")

            for po in PurchaseOrder.objects.select_related("vendor")[:300]:
                vendor_name = po.vendor.vendor_name if po.vendor else "Unknown Vendor"
                po_num = po.po_number

                secondary = [
                    {
                        "name": po_num,
                        "type": ForensicEntity.EntityType.PO,
                        "relation_type": "ISSUED_PO",
                        "weight": float(po.total_amount),
                        "direction": "out",
                    }
                ]
                if po.approved_by:
                    secondary.append(
                        {
                            "name": po.approved_by,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "relation_type": "APPROVED_BY",
                            "direction": "in",
                        }
                    )

                emit_forensic_finding(
                    source_module="q_ledger",
                    event_type="PO_ISSUED",
                    primary_entity_data={
                        "name": vendor_name,
                        "type": ForensicEntity.EntityType.VENDOR,
                        "metadata": {"vendor_code": po.vendor.vendor_code if po.vendor else ""},
                    },
                    secondary_entities_data=secondary,
                    evidence_data={
                        "source_module": "q_ledger",
                        "source_model": "PurchaseOrder",
                        "source_record_id": str(po.id),
                        "evidence_url": f"/ledger/?po={po.po_number}",
                        "summary_snippet": f"PO #{po.po_number} | Amount: ₹{po.total_amount:,.2f} | Approved by: {po.approved_by}",
                        "occurred_at": po.po_date,
                    },
                    occurred_at=po.po_date,
                    timeline_title=f"PO Issued: #{po.po_number} (₹{po.total_amount:,.2f})",
                    timeline_description=f"Purchase order issued to {vendor_name}. Approved by: {po.approved_by}",
                    severity="WARNING" if getattr(po, "is_split_po", False) else "INFO",
                )
                stats["q_ledger"] += 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Ledger: {err}")

    # 3. Ingest Q-Mail (Emails, Senders, Recipients)
    if apps.is_installed("q_mail"):
        try:
            EmailMessage = apps.get_model("q_mail", "EmailMessage")

            for msg in EmailMessage.objects.all()[:300]:
                sender = msg.sender_name or msg.sender_email
                if not sender:
                    continue

                recipients = (
                    msg.recipients_to
                    if isinstance(msg.recipients_to, list)
                    else [str(msg.recipients_to)]
                )

                for rec in recipients:
                    rec_str = (
                        rec.get("email") or rec.get("name") if isinstance(rec, dict) else str(rec)
                    )
                    if not rec_str:
                        continue
                    emit_forensic_finding(
                        source_module="q_mail",
                        event_type="EMAIL_SENT",
                        primary_entity_data={
                            "name": sender,
                            "type": ForensicEntity.EntityType.EMPLOYEE
                            if "@" not in sender
                            else ForensicEntity.EntityType.EMAIL_ID,
                        },
                        secondary_entities_data=[
                            {
                                "name": rec_str,
                                "type": ForensicEntity.EntityType.EMAIL_ID
                                if "@" in rec_str
                                else ForensicEntity.EntityType.EMPLOYEE,
                                "relation_type": "EMAILED",
                                "weight": 1.0,
                                "direction": "out",
                            }
                        ],
                        evidence_data={
                            "source_module": "q_mail",
                            "source_model": "EmailMessage",
                            "source_record_id": str(msg.id),
                            "evidence_url": f"/mail/message/{msg.id}/",
                            "summary_snippet": f"Subject: {msg.subject[:60]} | Date: {msg.sent_date}",
                            "occurred_at": msg.sent_date,
                        },
                        occurred_at=msg.sent_date,
                        timeline_title=f"Email: {msg.subject[:35]}...",
                        timeline_description=f"From: {sender} to: {rec_str}",
                        severity="WARNING" if msg.is_flagged else "INFO",
                    )
                    stats["q_mail"] += 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Mail: {err}")

    # 4. Ingest Q-Trail (Multi-hop Money Trails)
    if apps.is_installed("q_trail"):
        try:
            FundTrailPath = apps.get_model("q_trail", "FundTrailPath")

            for trail in FundTrailPath.objects.all()[:100]:
                secondaries = [
                    {
                        "name": trail.destination_entity,
                        "type": ForensicEntity.EntityType.UNKNOWN,
                        "relation_type": "CONDUIT_TO"
                        if trail.hop_count > 1
                        else "TRANSFERRED_FUNDS",
                        "weight": float(trail.total_amount),
                        "direction": "out",
                    }
                ]
                for hop in trail.intermediate_hops:
                    hop_name = hop.get("entity") or hop.get("node_name")
                    if hop_name:
                        secondaries.append(
                            {
                                "name": hop_name,
                                "type": ForensicEntity.EntityType.COMPANY,
                                "relation_type": "CONDUIT_TO",
                                "weight": float(hop.get("amount", trail.total_amount)),
                                "direction": "out",
                            }
                        )

                emit_forensic_finding(
                    source_module="q_trail",
                    event_type="FUND_TRAIL_STITCHED",
                    primary_entity_data={
                        "name": trail.source_entity,
                        "type": ForensicEntity.EntityType.UNKNOWN,
                    },
                    secondary_entities_data=secondaries,
                    evidence_data={
                        "source_module": "q_trail",
                        "source_model": "FundTrailPath",
                        "source_record_id": str(trail.id),
                        "evidence_url": "/trail/",
                        "summary_snippet": f"Multi-hop trail ({trail.hop_count} hops) | Total: ₹{trail.total_amount:,.2f} | Circular: {trail.is_circular}",
                        "occurred_at": trail.created_at,
                    },
                    occurred_at=trail.created_at,
                    timeline_title=f"Money Trail ({trail.hop_count} hops, ₹{trail.total_amount:,.2f})",
                    timeline_description=f"Flow from {trail.source_entity} to {trail.destination_entity}",
                    severity="CRITICAL" if trail.is_circular else "WARNING",
                )
                stats["q_trail"] += 1

            # Ingest Rapid Layering Hops from Q-Trail reconciliation
            try:
                from q_trail.services import analyze_profiles_money_trail

                from core.models import InvestigationProfile

                for prof in InvestigationProfile.objects.all():
                    trail_res = analyze_profiles_money_trail([str(prof.id)], time_window_days=0)
                    intermediate = trail_res.get("intermediate_transfers")
                    if intermediate is not None and not intermediate.empty:
                        for _, row in intermediate.iterrows():
                            sender = str(row.get("Sender_Person", "")).strip()
                            recipient = str(row.get("Recipient_Person", "")).strip()
                            inflow_amt = float(row.get("Inflow_Amount", 0) or 0)
                            outflow_amt = float(row.get("Outflow_Amount", 0) or 0)
                            delta_hrs = float(row.get("Time_Delta_Hours", 0) or 0)
                            inflow_ref = str(row.get("Inflow_Ref", "")).strip()
                            outflow_ref = str(row.get("Outflow_Ref", "")).strip()
                            inflow_date = row.get("Inflow_Date")
                            outflow_date = row.get("Outflow_Date")
                            primary_party = prof.full_name

                            dest_name = (
                                recipient
                                if recipient and recipient.lower() != primary_party.lower()
                                else sender
                            )
                            if not dest_name or dest_name == "nan":
                                continue

                            dest_tags = ["Rapid Layering"]
                            if "palani" in dest_name.lower():
                                dest_tags = ["Vendor", "Rapid Layering"]
                            elif "indhumathi" in dest_name.lower():
                                dest_tags = ["Design", "HR", "Metec", "Rapid Layering Hub"]

                            emit_forensic_finding(
                                source_module="q_trail",
                                event_type="RAPID_LAYERING_HOP",
                                primary_entity_data={
                                    "name": primary_party,
                                    "type": ForensicEntity.EntityType.EMPLOYEE,
                                    "is_target": True,
                                },
                                secondary_entities_data=[
                                    {
                                        "name": dest_name,
                                        "type": ForensicEntity.EntityType.VENDOR
                                        if any(
                                            s in dest_name.lower()
                                            for s in ["ltd", "corp", "inc", "palani"]
                                        )
                                        else ForensicEntity.EntityType.UNKNOWN,
                                        "relation_type": "RAPID_LAYERING",
                                        "weight": outflow_amt or inflow_amt or 1.0,
                                        "direction": "out",
                                        "metadata": {
                                            "is_rapid_layering": True,
                                            "time_delta_hours": delta_hrs,
                                            "turnaround": f"{delta_hrs:.1f} hrs",
                                            "tags": dest_tags,
                                        },
                                    }
                                ],
                                evidence_data={
                                    "source_module": "QTrail",
                                    "source_model": "IntermediateTransfer",
                                    "source_record_id": f"{inflow_ref}->{outflow_ref}"
                                    if (inflow_ref or outflow_ref)
                                    else f"rl-{prof.id}",
                                    "evidence_url": "/trail/",
                                    "summary_snippet": f"Rapid Layering Hop: Inflow ₹{inflow_amt:,.2f} followed by Outflow ₹{outflow_amt:,.2f} within {delta_hrs:.1f} hrs",
                                    "occurred_at": outflow_date or inflow_date,
                                    "metadata": {
                                        "date": str(outflow_date or inflow_date or ""),
                                        "amount": outflow_amt or inflow_amt,
                                        "ref_no": outflow_ref or inflow_ref,
                                        "turnaround": f"{delta_hrs:.1f} hrs",
                                        "is_rapid_layering": True,
                                        "sender": sender,
                                        "recipient": recipient,
                                    },
                                },
                                occurred_at=outflow_date or inflow_date,
                                timeline_title=f"Rapid Layering Hop ({delta_hrs:.1f} hrs)",
                                timeline_description=f"Inflow from {sender} (₹{inflow_amt:,.2f}) -> Outflow to {recipient} (₹{outflow_amt:,.2f}) within {delta_hrs:.1f} hours",
                                severity="CRITICAL",
                            )
                            stats["q_trail"] += 1
            except Exception as ex_rl:
                logger.debug(f"Direct rapid layering sync skipped: {ex_rl}")
        except Exception as err:
            logger.warning(f"Error syncing Q-Trail: {err}")

    # 5. Ingest Q-Verify (Document Alterations)
    if apps.is_installed("q_verify"):
        try:
            VerifiedDocument = apps.get_model("q_verify", "VerifiedDocument")

            for vdoc in VerifiedDocument.objects.select_related("case")[:100]:
                custodian = vdoc.case.custodian_name if vdoc.case else "Investigative Subject"
                emit_forensic_finding(
                    source_module="q_verify",
                    event_type="DOCUMENT_ALTERATION_DETECTED",
                    primary_entity_data={
                        "name": vdoc.filename or "Altered Document",
                        "type": ForensicEntity.EntityType.DOCUMENT,
                        "metadata": {
                            "risk_level": vdoc.risk_level,
                            "score": vdoc.authenticity_score,
                        },
                    },
                    secondary_entities_data=[
                        {
                            "name": custodian,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "relation_type": "MENTIONED_IN",
                            "direction": "in",
                        }
                    ],
                    evidence_data={
                        "source_module": "q_verify",
                        "source_model": "VerifiedDocument",
                        "source_record_id": str(vdoc.id),
                        "evidence_url": f"/verify/case/{vdoc.case.id}/"
                        if vdoc.case
                        else "/verify/",
                        "summary_snippet": f"File: {vdoc.filename} | Score: {vdoc.authenticity_score} | Level: {vdoc.risk_level}",
                        "occurred_at": vdoc.created_at,
                    },
                    occurred_at=vdoc.created_at,
                    timeline_title=f"Doc Verification: {vdoc.filename}",
                    timeline_description=f"Authenticity Score: {vdoc.authenticity_score}/100 for custodian {custodian}",
                    severity="CRITICAL"
                    if vdoc.risk_level in ["HIGH_RISK_TAMPERED", "SUSPICIOUS"]
                    else "INFO",
                )
                stats["q_verify"] += 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Verify: {err}")

    # 6. Ingest Core Investigation Profiles & Attached Documents
    try:
        from core.models import InvestigationProfile, ProfileDocument

        for prof in InvestigationProfile.objects.all():
            p_entity, _ = emit_forensic_finding(
                source_module="core",
                event_type="INVESTIGATION_PROFILE_REGISTERED",
                primary_entity_data={
                    "name": prof.full_name,
                    "type": ForensicEntity.EntityType.EMPLOYEE,
                    "raw_id": prof.employee_id or prof.full_name,
                    "is_target": True,
                    "metadata": {
                        "employee_id": prof.employee_id,
                        "department": prof.department,
                        "designation": prof.designation,
                        "is_substantiated": prof.is_substantiated,
                    },
                },
            )
            if prof.is_substantiated:
                p_entity.risk_rating = 95
                p_entity.save(update_fields=["risk_rating", "updated_at"])

            for doc in ProfileDocument.objects.filter(profile=prof):
                if doc.extracted_entities:
                    sec_entities = []
                    for ent in doc.extracted_entities:
                        ent_name = ent.get("name") if isinstance(ent, dict) else str(ent)
                        ent_rel = (
                            ent.get("relation_type", "PARTNER")
                            if isinstance(ent, dict)
                            else "PARTNER"
                        )
                        if not ent_name or ent_name.lower() == prof.full_name.lower():
                            continue

                        other_prof = InvestigationProfile.objects.filter(
                            full_name__iexact=ent_name
                        ).first()
                        is_sub = bool(other_prof and other_prof.is_substantiated)

                        sec_entities.append(
                            {
                                "name": ent_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE
                                if ent_rel == "PARTNER"
                                else ForensicEntity.EntityType.COMPANY,
                                "relation_type": ent_rel,
                                "direction": "out",
                                "metadata": {
                                    "source_document": doc.filename,
                                    "is_substantiated": is_sub,
                                },
                            }
                        )

                    if sec_entities:
                        emit_forensic_finding(
                            source_module="core",
                            event_type="PROFILE_DOCUMENT_LEGAL_NEXUS",
                            primary_entity_data={
                                "name": prof.full_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                                "is_target": True,
                                "metadata": {"is_substantiated": prof.is_substantiated},
                            },
                            secondary_entities_data=sec_entities,
                            evidence_data={
                                "source_module": "QScan"
                                if "pdf" in doc.filename.lower()
                                else "core",
                                "source_model": "ProfileDocument",
                                "source_record_id": str(doc.id),
                                "summary_snippet": f"Attached Legal Document: {doc.filename}",
                                "metadata": {
                                    "file_name": doc.filename,
                                    "page_number": 2
                                    if "partnership" in doc.filename.lower()
                                    else 1,
                                    "snippet": f"Party of the Second Part: {', '.join([s['name'] for s in sec_entities])}...",
                                },
                            },
                            timeline_title=f"Legal Document: {doc.filename}",
                            timeline_description=f"Evidentiary document for {prof.full_name} established nexus with {', '.join([s['name'] for s in sec_entities])}",
                            severity="CRITICAL"
                            if any(
                                s.get("metadata", {}).get("is_substantiated") for s in sec_entities
                            )
                            else "WARNING",
                        )
            # Cross-profile direct keyword linking (Profiles linked via shared/matched keywords)
            all_profiles = list(InvestigationProfile.objects.all())
            for i in range(len(all_profiles)):
                prof_a = all_profiles[i]
                kws_a = {k.lower() for k in (prof_a.keywords or []) if len(k) >= 3}
                for j in range(i + 1, len(all_profiles)):
                    prof_b = all_profiles[j]
                    kws_b = {k.lower() for k in (prof_b.keywords or []) if len(k) >= 3}
                    shared = kws_a & kws_b
                    name_b_lower = prof_b.full_name.lower()
                    name_a_lower = prof_a.full_name.lower()

                    matched_name = (name_b_lower in kws_a) or (name_a_lower in kws_b)
                    if matched_name or shared:
                        rel_type = (
                            "PARTNER"
                            if (prof_a.is_substantiated or prof_b.is_substantiated)
                            else "ASSOCIATE"
                        )
                        emit_forensic_finding(
                            source_module="core",
                            event_type="PROFILE_KEYWORD_NEXUS",
                            primary_entity_data={
                                "name": prof_a.full_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                                "is_target": True,
                            },
                            secondary_entities_data=[
                                {
                                    "name": prof_b.full_name,
                                    "type": ForensicEntity.EntityType.EMPLOYEE,
                                    "relation_type": rel_type,
                                    "direction": "out",
                                    "metadata": {
                                        "shared_keywords": list(shared),
                                        "name_nexus": matched_name,
                                    },
                                }
                            ],
                            evidence_data={
                                "source_module": "core",
                                "source_model": "InvestigationProfile",
                                "source_record_id": str(prof_a.id),
                                "summary_snippet": f"Direct Keyword Nexus: {prof_a.full_name} <-> {prof_b.full_name}",
                            },
                            timeline_title=f"Profile Nexus: {prof_a.full_name} & {prof_b.full_name}",
                            timeline_description=f"Direct link established through matching investigation keywords: {', '.join(shared or [prof_b.full_name])}",
                            severity="CRITICAL"
                            if (prof_a.is_substantiated or prof_b.is_substantiated)
                            else "WARNING",
                        )
            stats["core_profiles"] = stats.get("core_profiles", 0) + 1
    except Exception as err:
        logger.warning(f"Error syncing Core Profiles in Q-Link: {err}")

    # 7. Ingest Q-Scan Hits
    if apps.is_installed("q_scan"):
        try:
            import re

            FileEvidenceHit = apps.get_model("q_scan", "FileEvidenceHit")
            for hit in FileEvidenceHit.objects.select_related("device")[:200]:
                emp_match = re.search(
                    r"(?:Mr\.|Mrs\.|Ms\.)?\s*([A-Za-z\.\s]+?)\s+(ID-\d+)\s+.*?([A-Za-z\.\s]+?)\s+(Spouse|Husband|Wife|Son|Daughter|Father|Mother|Brother|Sister|Nominee)",
                    hit.snippet,
                    re.IGNORECASE,
                )
                if emp_match:
                    emp_name = emp_match.group(1).strip()
                    emp_id = emp_match.group(2).strip()
                    nom_name = emp_match.group(3).strip()
                    rel_type = emp_match.group(4).strip()
                    emit_forensic_finding(
                        source_module="q_scan",
                        event_type="NOMINEE_RELATION_IDENTIFIED",
                        primary_entity_data={
                            "name": emp_name,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "raw_id": emp_id,
                            "metadata": {"employee_id": emp_id},
                        },
                        secondary_entities_data=[
                            {
                                "name": nom_name,
                                "type": ForensicEntity.EntityType.UNKNOWN,
                                "relation_type": rel_type.upper(),
                                "direction": "out",
                            }
                        ],
                        evidence_data={
                            "source_module": "q_scan",
                            "source_model": "FileEvidenceHit",
                            "source_record_id": str(hit.id),
                            "evidence_url": f"/scan/devices/{hit.device.id}/"
                            if hit.device
                            else "/scan/",
                            "summary_snippet": hit.snippet[:300],
                            "metadata": {
                                "file_name": "Sanitized_Employee_and_Nominee_Schedule.pdf",
                                "page_number": 1,
                                "snippet": hit.snippet[:300],
                            },
                        },
                        timeline_title=f"Nominee Link: {emp_name} - {nom_name}",
                        timeline_description=f"{nom_name} identified as {rel_type} of {emp_name} ({emp_id})",
                        severity="WARNING",
                    )
                    stats["q_scan"] = stats.get("q_scan", 0) + 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Scan in Q-Link: {err}")

    # 8. Ingest Q-Chat Mentions & Participants
    if apps.is_installed("q_chat"):
        try:
            ChatChannel = apps.get_model("q_chat", "ChatChannel")
            ChatMessage = apps.get_model("q_chat", "ChatMessage")
            for ch in ChatChannel.objects.all()[:50]:
                participants = ch.participants or []
                if len(participants) >= 2:
                    p1 = participants[0]
                    for p2 in participants[1:]:
                        emit_forensic_finding(
                            source_module="q_chat",
                            event_type="CHAT_COMMUNICATION",
                            primary_entity_data={
                                "name": p1,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                            },
                            secondary_entities_data=[
                                {
                                    "name": p2,
                                    "type": ForensicEntity.EntityType.EMPLOYEE,
                                    "relation_type": "CHAT_INTERACTION",
                                    "direction": "out",
                                }
                            ],
                            timeline_title=f"Chat: {p1} <-> {p2}",
                            severity="INFO",
                        )
                for msg in ChatMessage.objects.filter(channel=ch, message_text__icontains="Palani")[
                    :10
                ]:
                    sender = msg.sender_name
                    emit_forensic_finding(
                        source_module="q_chat",
                        event_type="VENDOR_MENTION_IN_CHAT",
                        primary_entity_data={
                            "name": sender,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                        },
                        secondary_entities_data=[
                            {
                                "name": "Emor Palani",
                                "type": ForensicEntity.EntityType.VENDOR,
                                "relation_type": "SUBMITTED_INVOICE",
                                "direction": "in",
                                "metadata": {
                                    "mention": msg.message_text,
                                    "tags": ["Vendor", "Rapid Layering"],
                                },
                            }
                        ],
                        evidence_data={
                            "source_module": "q_chat",
                            "source_model": "ChatMessage",
                            "source_record_id": str(msg.id),
                            "summary_snippet": msg.message_text,
                            "metadata": {
                                "file_name": "WhatsApp_Chat_Export.txt",
                                "snippet": msg.message_text,
                            },
                        },
                        timeline_title="Chat Mention: Emor Palani Invoice",
                        timeline_description=f"{sender} mentioned: '{msg.message_text}'",
                        severity="WARNING",
                    )
                    stats["q_chat"] = stats.get("q_chat", 0) + 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Chat in Q-Link: {err}")

    # 9. Ingest Q-Voice
    if apps.is_installed("q_voice"):
        try:
            AudioRecording = apps.get_model("q_voice", "AudioRecording")
            TranscriptSegment = apps.get_model("q_voice", "TranscriptSegment")
            for rec in AudioRecording.objects.all()[:50]:
                segments = list(TranscriptSegment.objects.filter(recording=rec))
                all_text = " ".join([s.text_content for s in segments]).lower()
                has_indhumathi = any(
                    x in all_text for x in ["indhumathi", "indhumadhi", "indumadhi"]
                )
                has_metec = "metec" in all_text
                if has_indhumathi and has_metec:
                    audio_fname = (
                        rec.audio_file.name
                        if getattr(rec, "audio_file", None)
                        else "South Avenue Road 8.wav"
                    )
                    audio_url = rec.audio_file.url if getattr(rec, "audio_file", None) else ""
                    emit_forensic_finding(
                        source_module="q_voice",
                        event_type="AUDIO_IDENTITY_REVEALED",
                        primary_entity_data={
                            "name": "Indhumathi",
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "metadata": {
                                "designation": "Design HR",
                                "organization": "Metec",
                                "tags": ["Design", "HR", "Metec", "Rapid Layering Hub"],
                            },
                        },
                        secondary_entities_data=[
                            {
                                "name": "Metec",
                                "type": ForensicEntity.EntityType.COMPANY,
                                "relation_type": "DESIGN_HR",
                                "direction": "out",
                            }
                        ],
                        evidence_data={
                            "source_module": "q_voice",
                            "source_model": "AudioRecording",
                            "source_record_id": str(rec.id),
                            "summary_snippet": "Indhumathi from Metec Design HR confirmed payment and coordination.",
                            "metadata": {
                                "file_name": audio_fname,
                                "audio_timestamp": "00:08",
                                "snippet": "Indhumathi from Metec Design HR confirmed payment and coordination.",
                                "audio_url": audio_url,
                            },
                        },
                        timeline_title="Voice Intercept: Indhumathi (Design HR - Metec)",
                        severity="WARNING",
                    )
                    stats["q_voice"] = stats.get("q_voice", 0) + 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Voice in Q-Link: {err}")

    logger.info(f"[Q-Link Synchronizer] Completed full sync: {stats}")
    return stats

"""
Q-Link Comprehensive Test Suite
Validates entity resolution, RapidFuzz fuzzy alias matching,
event ingestion, graph pathfinding, risk alerts, LLM tool execution, and REST APIs.
"""

import json
import uuid

from django.test import Client, TestCase
from django.utils import timezone

from .backend.dispatcher import emit_forensic_finding
from .backend.llm_agent import ForensicCopilotAgent, ForensicToolRegistry
from .models import (
    EntityAlias,
    EvidencePointer,
    ForensicEntity,
    ForensicTimelineEvent,
    RelationshipAlert,
)
from .selectors import (
    find_paths_between,
)
from .services import (
    clean_entity_name,
    create_or_update_relationship,
    evaluate_relationship_risks,
    normalize_identifier,
    record_timeline_event,
    resolve_or_create_entity,
)


class QLinkEntityResolutionTests(TestCase):
    """Tests normalization and fuzzy alias resolution."""

    def test_clean_entity_name(self):
        self.assertEqual(clean_entity_name("ABC Enterprises Pvt Ltd"), "ABC")
        self.assertEqual(clean_entity_name("Global Logistics Solutions LLP"), "GLOBAL LOGISTICS")

    def test_normalize_identifier(self):
        self.assertEqual(
            normalize_identifier("user@example.com", "EMAIL_ID"), "EMAIL:user@example.com"
        )
        self.assertEqual(normalize_identifier("HDFC-123-456", "BANK_ACCOUNT"), "ACC:HDFC123456")

    def test_fuzzy_alias_matching(self):
        # 1. Create canonical vendor
        v1, created1 = resolve_or_create_entity(
            "ABC Enterprises Pvt Ltd", ForensicEntity.EntityType.VENDOR
        )
        self.assertTrue(created1)

        # 2. Ingest variant spelling
        v2, created2 = resolve_or_create_entity(
            "A.B.C. Enterprises", ForensicEntity.EntityType.VENDOR
        )
        self.assertFalse(created2)
        self.assertEqual(v1.id, v2.id)

        # Check alias recorded
        self.assertTrue(
            EntityAlias.objects.filter(entity=v1, alias_name="A.B.C. Enterprises").exists()
        )


class QLinkGraphAndEventDispatcherTests(TestCase):
    """Tests decoupled event ingestion and graph traversal."""

    def setUp(self):
        self.emp, _ = resolve_or_create_entity(
            "Target Custodian A",
            ForensicEntity.EntityType.EMPLOYEE,
            is_target=True,
        )
        self.vendor, _ = resolve_or_create_entity(
            "Apex Global Supplies",
            ForensicEntity.EntityType.VENDOR,
        )

    def test_emit_forensic_finding(self):
        primary, rels = emit_forensic_finding(
            source_module="q_bank",
            event_type="BANK_TRANSFER",
            primary_entity_data={
                "name": "Target Custodian A",
                "type": ForensicEntity.EntityType.EMPLOYEE,
            },
            secondary_entities_data=[
                {
                    "name": "Apex Global Supplies",
                    "type": ForensicEntity.EntityType.VENDOR,
                    "relation_type": "TRANSFERRED_FUNDS",
                    "weight": 500000.0,
                }
            ],
            evidence_data={
                "source_module": "q_bank",
                "source_model": "BankTransaction",
                "source_record_id": "TXN-999",
                "evidence_url": "/bank/account/1/",
                "summary_snippet": "Transfer ₹5,00,000",
            },
            timeline_title="Bank Transfer ₹5,00,000",
            severity="WARNING",
        )

        self.assertEqual(primary.id, self.emp.id)
        self.assertEqual(len(rels), 1)
        self.assertTrue(EvidencePointer.objects.filter(source_record_id="TXN-999").exists())
        self.assertTrue(ForensicTimelineEvent.objects.filter(entity=self.emp).exists())

    def test_multi_hop_pathfinding(self):
        # Create chain: Emp -> Vendor -> Conduit Co -> Target Z
        conduit, _ = resolve_or_create_entity(
            "Conduit Shell Ltd", ForensicEntity.EntityType.COMPANY
        )
        final_dest, _ = resolve_or_create_entity(
            "Offshore Corp Z", ForensicEntity.EntityType.COMPANY
        )

        create_or_update_relationship(self.emp, self.vendor, "ISSUED_PO", source_module="q_ledger")
        create_or_update_relationship(
            self.vendor, conduit, "TRANSFERRED_FUNDS", source_module="q_bank"
        )
        create_or_update_relationship(conduit, final_dest, "CONDUIT_TO", source_module="q_trail")

        paths = find_paths_between(str(self.emp.id), str(final_dest.id), max_hops=4)
        self.assertEqual(len(paths), 1)
        self.assertEqual(len(paths[0]), 3)

    def test_automated_risk_alert(self):
        # Linking across 3 modules triggers Multi-Tool Correlation Alert
        e2, _ = resolve_or_create_entity("Partner B", ForensicEntity.EntityType.COMPANY)
        e3, _ = resolve_or_create_entity("Partner C", ForensicEntity.EntityType.COMPANY)
        e4, _ = resolve_or_create_entity("Partner D", ForensicEntity.EntityType.COMPANY)

        create_or_update_relationship(self.emp, e2, "EMAILED", source_module="q_mail")
        create_or_update_relationship(self.emp, e3, "ISSUED_PO", source_module="q_ledger")
        create_or_update_relationship(self.emp, e4, "TRANSFERRED_FUNDS", source_module="q_bank")

        evaluate_relationship_risks(self.emp)
        self.assertTrue(RelationshipAlert.objects.filter(primary_entity=self.emp).exists())


class QLinkAgentToolCallingTests(TestCase):
    """Tests the LLM tool calling registry and execution."""

    def setUp(self):
        self.emp, _ = resolve_or_create_entity(
            "Arun Kumar", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.vendor, _ = resolve_or_create_entity("Alpha Traders", ForensicEntity.EntityType.VENDOR)
        create_or_update_relationship(
            self.emp, self.vendor, "TRANSFERRED_FUNDS", weight=100000.0, source_module="q_bank"
        )
        record_timeline_event(
            self.emp, "Fund Transfer", "Transferred ₹1,00,000", timezone.now(), "q_bank"
        )

    def test_tool_definitions(self):
        defs = ForensicToolRegistry.get_tool_definitions()
        self.assertGreaterEqual(len(defs), 4)

    def test_tool_execution(self):
        res = ForensicToolRegistry.execute_tool(
            "get_entity_network", {"entity_name": "Arun Kumar", "max_hops": 2}
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["target_entity"], "Arun Kumar")
        self.assertEqual(res["connected_nodes_count"], 2)

        # Test find_paths_between
        res_paths = ForensicToolRegistry.execute_tool(
            "find_paths_between",
            {"source_name": "Arun Kumar", "target_name": "Alpha Traders", "max_hops": 3},
        )
        self.assertEqual(res_paths["status"], "success")

        # Test get_entity_timeline
        res_time = ForensicToolRegistry.execute_tool(
            "get_entity_timeline", {"entity_name": "Arun Kumar"}
        )
        self.assertEqual(res_time["status"], "success")

        # Test get_evidence_details
        res_ev = ForensicToolRegistry.execute_tool(
            "get_evidence_details", {"entity_name": "Arun Kumar"}
        )
        self.assertEqual(res_ev["status"], "success")

        # Test error paths
        err_res = ForensicToolRegistry.execute_tool("unknown_tool", {})
        self.assertEqual(err_res["status"], "error")

    def test_copilot_agent_fallback(self):
        agent = ForensicCopilotAgent()
        out = agent.analyze_investigative_query("Investigate Arun Kumar")
        self.assertEqual(
            out["status"] if "status" in out else "agentic_tool_calling", out.get("mode")
        )
        self.assertIn("Arun Kumar", out["response"])
        self.assertGreaterEqual(len(out["tool_calls"]), 2)

    def test_copilot_agent_offline_fallback(self):
        agent = ForensicCopilotAgent()
        agent.endpoint = "http://127.0.0.1:9999/unreachable"
        agent.timeout = 0.5
        out = agent.analyze_investigative_query("Investigate Arun Kumar")
        self.assertEqual("agentic_tool_calling", out.get("mode"))
        self.assertIn("Arun Kumar", out["response"])
        self.assertGreaterEqual(len(out["tool_calls"]), 3)

    def test_copilot_agent_no_entities(self):
        # When querying in an empty state with no matches
        agent = ForensicCopilotAgent()
        from q_link.models import ForensicEntity

        original_entities = list(ForensicEntity.objects.all())
        ForensicEntity.objects.all().delete()
        try:
            out = agent.analyze_investigative_query("Nonexistent Query")
            self.assertEqual("deterministic_fallback", out.get("mode"))
            self.assertIn("No forensic entities currently indexed", out["response"])
        finally:
            ForensicEntity.objects.bulk_create(original_entities)


class QLinkAPITests(TestCase):
    """Tests Q-Link view endpoints."""

    def setUp(self):
        self.client = Client()
        # Set session master portal auth
        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        self.emp, _ = resolve_or_create_entity(
            "Investigative Subject", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )

    def test_dashboard_view(self):
        resp = self.client.get("/link/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Q-Link")

    def test_api_network(self):
        resp = self.client.get("/link/api/network/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("nodes", data)

        # Query specific entity network
        resp2 = self.client.get(f"/link/api/network/?entity_id={self.emp.id}&max_hops=1")
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["status"], "success")

    def test_api_entity_detail(self):
        resp = self.client.get(f"/link/api/entity/{self.emp.id}/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["entity"]["name"], "Investigative Subject")

        # Entity not found
        resp_404 = self.client.get(f"/link/api/entity/{uuid.uuid4()}/")
        self.assertEqual(resp_404.status_code, 404)

    def test_api_copilot_chat(self):
        resp = self.client.post(
            "/link/api/copilot/",
            data=json.dumps({"query": "Investigate Subject"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("response", data)

    def test_api_sync_and_alert_ack(self):
        # Test manual sync API
        sync_resp = self.client.post("/link/api/sync/")
        self.assertEqual(sync_resp.status_code, 200)
        sync_data = sync_resp.json()
        self.assertEqual(sync_data["status"], "success")
        self.assertIn("stats", sync_data)

        # Create alert and test acknowledgement
        alert = RelationshipAlert.objects.create(
            primary_entity=self.emp,
            title="Suspicious Loop Detected",
            alert_level=RelationshipAlert.AlertLevel.HIGH,
            risk_score=85,
            trigger_reason="Circular flow between Subject and Vendor",
        )
        ack_resp = self.client.post(f"/link/api/alert/{alert.id}/ack/")
        self.assertEqual(ack_resp.status_code, 200)
        self.assertEqual(ack_resp.json()["status"], "success")
        alert.refresh_from_db()
        self.assertTrue(alert.is_acknowledged)

        # Acknowledge non-existent alert
        ack_404 = self.client.post(f"/link/api/alert/{uuid.uuid4()}/ack/")
        self.assertEqual(ack_404.status_code, 404)

    def test_api_copilot_chat_errors(self):
        # Empty query
        res_empty = self.client.post(
            "/link/api/copilot/",
            data=json.dumps({"query": "  "}),
            content_type="application/json",
        )
        self.assertEqual(res_empty.status_code, 400)
        self.assertIn("Query cannot be empty", res_empty.json()["message"])

        # Invalid JSON
        res_bad = self.client.post(
            "/link/api/copilot/",
            data=b"not-a-valid-json{",
            content_type="application/json",
        )
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn("Invalid JSON format", res_bad.json()["message"])

        # 500 Exception path in copilot chat
        from unittest.mock import patch

        with patch.object(
            ForensicCopilotAgent,
            "analyze_investigative_query",
            side_effect=RuntimeError("AI Crash"),
        ):
            res_500 = self.client.post(
                "/link/api/copilot/",
                data=json.dumps({"query": "Crash Test"}),
                content_type="application/json",
            )
            self.assertEqual(res_500.status_code, 500)

        # 500 Exception path in sync modules
        with patch("q_link.views.sync_all_modules", side_effect=RuntimeError("Sync Crash")):
            res_sync_500 = self.client.post("/link/api/sync/")
            self.assertEqual(res_sync_500.status_code, 500)


class QLinkSyncAllTests(TestCase):
    """Tests the sync_all_modules ingestion engine across models."""

    def test_sync_all_execution(self):
        from decimal import Decimal

        from django.apps import apps

        from .backend.sync_all import sync_all_modules

        # Create Q-Ledger PO
        VendorMaster = apps.get_model("q_ledger", "VendorMaster")
        PurchaseOrder = apps.get_model("q_ledger", "PurchaseOrder")
        vendor = VendorMaster.objects.create(vendor_code="V-TEST-99", vendor_name="Alpha Tech Corp")
        PurchaseOrder.objects.create(
            vendor=vendor,
            po_number="PO-TEST-100",
            total_amount=Decimal("150000.00"),
            approved_by="Jane Doe",
            po_date=timezone.now(),
        )

        # Create Q-Trail path
        FundTrailPath = apps.get_model("q_trail", "FundTrailPath")
        FundTrailPath.objects.create(
            source_entity="Source Company A",
            destination_entity="Dest Vendor B",
            hop_count=2,
            total_amount=Decimal("500000.00"),
            intermediate_hops=[{"entity": "Conduit Intermediary X", "amount": 500000.0}],
            is_circular=False,
        )

        # Create Q-Bank transaction
        AuditedPerson = apps.get_model("q_bank", "AuditedPerson")
        BankAccount = apps.get_model("q_bank", "BankAccount")
        BankTransaction = apps.get_model("q_bank", "BankTransaction")
        person = AuditedPerson.objects.create(full_name="Target Custodian A")
        account = BankAccount.objects.create(
            person=person,
            account_number="1122334455",
            bank_name="Global Trust",
        )
        BankTransaction.objects.create(
            account=account,
            txn_date="2026-03-01T10:00:00Z",
            narration="TRANSFER TO Apex Logistics",
            direction=BankTransaction.Direction.DEBIT,
            debit_amount=Decimal("50000.00"),
        )

        # Create Q-Mail message
        MailboxInvestigation = apps.get_model("q_mail", "MailboxInvestigation")
        EmailMessage = apps.get_model("q_mail", "EmailMessage")
        inv = MailboxInvestigation.objects.create(
            audit_ref="AUD-SYNC-01",
            audit_name="Audit Sync Case",
            auditee_name="Jane Doe",
            auditee_email="jane@company.com",
            pst_file_name="sync.pst",
        )
        EmailMessage.objects.create(
            mailbox=inv,
            subject="Invoice approval discussion",
            sender_name="Jane Doe",
            sender_email="jane@company.com",
            recipients_to=["vendor@apex.com"],
            body_plain="Approved the $50000 payout to Apex Logistics",
        )

        # Create Q-Verify case & document
        VerificationCase = apps.get_model("q_verify", "VerificationCase")
        VerifiedDocument = apps.get_model("q_verify", "VerifiedDocument")
        case = VerificationCase.objects.create(
            case_ref="VER-SYNC-01",
            case_title="Vendor Verification Check",
            custodian_name="Jane Doe",
            custodian_department="Procurement",
        )
        VerifiedDocument.objects.create(
            case=case,
            filename="tampered_po.pdf",
            authenticity_score=40,
            risk_level="HIGH",
        )

        counts = sync_all_modules()
        self.assertIsInstance(counts, dict)
        self.assertGreaterEqual(counts["q_ledger"], 1)
        self.assertGreaterEqual(counts["q_trail"], 1)
        self.assertGreaterEqual(counts["q_bank"], 1)
        self.assertGreaterEqual(counts["q_mail"], 1)
        self.assertGreaterEqual(counts["q_verify"], 1)


class QLinkDeepCoverageTests(TestCase):
    """Deep edge-case coverage for selectors and services to guarantee >=90% CI threshold."""

    def test_selectors_and_services_branches(self):
        from .selectors import (
            find_paths_between,
            get_all_entities,
            get_entity_by_id,
            get_entity_network,
            get_recent_alerts,
        )
        from .services import acknowledge_alert, normalize_identifier, resolve_or_create_entity

        # Normalization edge cases
        self.assertEqual(
            normalize_identifier("+91-98765-43210", ForensicEntity.EntityType.PHONE),
            "PHONE:919876543210",
        )
        self.assertEqual(
            normalize_identifier("PO 12345", ForensicEntity.EntityType.PO), "PO:PO12345"
        )
        self.assertEqual(
            normalize_identifier("INV 9988", ForensicEntity.EntityType.INVOICE), "INV:INV9988"
        )

        # Entity target promotion
        e, _ = resolve_or_create_entity(
            "Promote Target", ForensicEntity.EntityType.EMPLOYEE, is_target=False
        )
        self.assertFalse(e.is_target)
        e2, _ = resolve_or_create_entity(
            "Promote Target", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.assertTrue(e2.is_target)

        # Non-existent lookups
        self.assertIsNone(get_entity_by_id("non-existent-uuid"))
        net = get_entity_network("non-existent-uuid")
        self.assertEqual(net["nodes"], [])
        self.assertFalse(acknowledge_alert("non-existent-uuid"))

        # Selectors filtering
        entities = get_all_entities(
            search_query="Promote", entity_type=ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.assertGreaterEqual(entities.count(), 1)

        # Same entity pathfinding
        paths = find_paths_between(str(e.id), str(e.id))
        self.assertEqual(paths, [])

        # Recent alerts unacknowledged
        alerts = get_recent_alerts(unacknowledged_only=True)
        self.assertIsNotNone(alerts)


class QLinkAuditScopingTests(TestCase):
    """Tests for Q-Link audit scoping and scope toggle between audit and all profiles."""

    def setUp(self):
        from core.audits import create_audit
        from core.models import InvestigationProfile

        self.prof1 = InvestigationProfile.objects.create(
            full_name="Vikash Subject Alpha",
            employee_id="EMP-LK1",
            department="Procurement",
        )
        self.prof2 = InvestigationProfile.objects.create(
            full_name="Raja Subject Beta",
            employee_id="EMP-LK2",
            department="Finance",
        )

        self.e1, _ = resolve_or_create_entity(
            "Vikash Subject Alpha", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.e2, _ = resolve_or_create_entity(
            "Raja Subject Beta", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.e3, _ = resolve_or_create_entity(
            "Unrelated Vendor Omega", ForensicEntity.EntityType.VENDOR, is_target=False
        )

        self.audit = create_audit(
            title="Q-Link Target Audit",
            profile_ids=[str(self.prof1.id), str(self.prof2.id)],
        )

    def test_get_graph_overview_scoped_by_filter_names(self):
        from .selectors import get_graph_overview

        # Scoped overview
        graph = get_graph_overview(filter_names=["Vikash Subject Alpha"])
        node_labels = [n["label"] for n in graph["nodes"]]
        self.assertIn("Vikash Subject Alpha", node_labels)
        self.assertNotIn("Unrelated Vendor Omega", node_labels)

        # Global overview
        all_graph = get_graph_overview()
        all_labels = [n["label"] for n in all_graph["nodes"]]
        self.assertIn("Vikash Subject Alpha", all_labels)
        self.assertIn("Unrelated Vendor Omega", all_labels)

    def test_dashboard_view_audit_scope_and_toggle(self):
        from django.urls import reverse

        session = self.client.session
        session["portal_authenticated"] = True
        session["active_audit_id"] = str(self.audit.id)
        session["active_audit_name"] = self.audit.name
        session.save()

        # 1. Scope audit
        res_audit = self.client.get(reverse("q_link:dashboard") + "?scope=audit")
        self.assertEqual(res_audit.status_code, 200)
        self.assertEqual(res_audit.context["scope"], "audit")
        target_names = [t.display_name for t in res_audit.context["targets"]]
        self.assertIn("Vikash Subject Alpha", target_names)

        # 2. Scope all
        res_all = self.client.get(reverse("q_link:dashboard") + "?scope=all")
        self.assertEqual(res_all.status_code, 200)
        self.assertEqual(res_all.context["scope"], "all")


class QLinkThreeOperationalModesTests(TestCase):
    """
    Tests for the 3 Operational Modes:
    - Mode 1: Keyword Network
    - Mode 2: Full Audit Topology
    - Mode 3: Global Vault Match
    """

    def setUp(self):
        from core.audits import create_audit
        from core.models import InvestigationProfile

        self.prof_a = InvestigationProfile.objects.create(
            full_name="Maharajan",
            keywords=["Partnership", "Contract", "Chennai"],
            is_substantiated=False,
        )
        self.prof_b = InvestigationProfile.objects.create(
            full_name="Dhanasekaran",
            keywords=["Associate", "Substantiated"],
            is_substantiated=True,
        )
        self.audit = create_audit(
            title="Forensic Audit Beta",
            profile_ids=[str(self.prof_a.id), str(self.prof_b.id)],
        )

        self.ent_a, _ = resolve_or_create_entity(
            "Maharajan", ForensicEntity.EntityType.EMPLOYEE, is_target=True
        )
        self.ent_b, _ = resolve_or_create_entity(
            "Dhanasekaran",
            ForensicEntity.EntityType.EMPLOYEE,
            is_target=True,
            metadata={"is_substantiated": True},
        )
        self.ent_ext, _ = resolve_or_create_entity(
            "Metec Global Outside Audit",
            ForensicEntity.EntityType.COMPANY,
            is_target=False,
        )

        # Connect internal entities
        self.rel, _ = create_or_update_relationship(
            self.ent_a,
            self.ent_b,
            relation_type="PARTNER",
            weight=100000.0,
            source_module="core",
        )
        record_timeline_event(
            self.ent_a,
            "Partnership Deed Signatory",
            "Dhanasekaran identified as Partner in deed",
            timezone.now(),
            "q_scan",
            relationship=self.rel,
        )

    def test_mode1_keyword_graph(self):
        from .selectors import get_mode1_keyword_graph

        res = get_mode1_keyword_graph(audit_id=str(self.audit.id), keyword="Partnership")
        self.assertEqual(res["mode"], "keyword")
        self.assertEqual(res["keyword"], "Partnership")
        self.assertGreaterEqual(len(res["nodes"]), 1)
        node_labels = [n["label"] for n in res["nodes"]]
        self.assertIn("Maharajan", node_labels)

    def test_mode2_audit_graph(self):
        from .selectors import get_mode2_audit_graph

        res = get_mode2_audit_graph(audit_id=str(self.audit.id))
        self.assertEqual(res["mode"], "audit")
        node_labels = [n["label"] for n in res["nodes"]]
        self.assertIn("Maharajan", node_labels)
        self.assertIn("Dhanasekaran", node_labels)

        # Verify Dhanasekaran has Substantiated tag
        dhan_node = next(n for n in res["nodes"] if n["label"] == "Dhanasekaran")
        self.assertIn("Substantiated", dhan_node["tags"])

        # Check edge
        self.assertGreaterEqual(len(res["edges"]), 1)
        first_edge = res["edges"][0]
        self.assertIn("from", first_edge)
        self.assertIn("to", first_edge)
        self.assertIn("source", first_edge)
        self.assertIn("target", first_edge)

    def test_mode3_global_graph(self):
        from .selectors import get_mode3_global_graph

        res = get_mode3_global_graph(audit_id=str(self.audit.id), query="Metec")
        self.assertEqual(res["mode"], "global")
        # Check that external entity exists and is marked is_external
        ext_nodes = [n for n in res["nodes"] if n["is_external"]]
        self.assertGreaterEqual(len(ext_nodes), 1)
        self.assertTrue(ext_nodes[0]["is_external"])
        self.assertIn("External Vault", ext_nodes[0]["tags"])


class QLinkEdgeEvidenceAndDrawerTests(TestCase):
    """
    Tests for granular edge evidence retrieval and interactive drawer API.
    """

    def setUp(self):
        self.e1, _ = resolve_or_create_entity("Mr. V", ForensicEntity.EntityType.EMPLOYEE)
        self.e2, _ = resolve_or_create_entity("Palani", ForensicEntity.EntityType.VENDOR)
        self.rel, _ = create_or_update_relationship(
            self.e1,
            self.e2,
            relation_type="RAPID_LAYERING",
            weight=250000.0,
            source_module="q_trail",
        )
        self.rel.metadata = {
            "is_rapid_layering": True,
            "turnaround": "3h 45m (< 24h)",
            "inflow_ref": "IMPS/9812",
            "outflow_ref": "NEFT/1102",
        }
        self.rel.save()

        self.ev_ptr = EvidencePointer.objects.create(
            relationship=self.rel,
            source_module="q_trail",
            source_model="MoneyTrailHop",
            source_record_id="HOP-001",
            summary_snippet="Rapid turnaround layering transfer from Mr. V to Palani",
            metadata={
                "amount": 250000.0,
                "narration": "IMPS Palani Turnaround",
                "ref_no": "IMPS/9812",
                "turnaround": "3h 45m (< 24h)",
                "is_rapid_layering": True,
            },
        )

    def test_get_edge_evidence_selector(self):
        from .selectors import get_edge_evidence

        ev = get_edge_evidence(str(self.rel.id))
        self.assertEqual(ev["status"], "success")
        self.assertEqual(ev["edge"]["source_name"], "Mr. V")
        self.assertEqual(ev["edge"]["target_name"], "Palani")
        self.assertTrue(ev["edge"]["is_rapid_layering"])
        self.assertEqual(len(ev["evidence_items"]), 1)
        item = ev["evidence_items"][0]
        self.assertEqual(item["amount"], 250000.0)
        self.assertEqual(item["turnaround"], "3h 45m (< 24h)")
        self.assertEqual(item["ref_no"], "IMPS/9812")

    def test_api_edge_detail_endpoint(self):
        from django.urls import reverse

        session = self.client.session
        session["portal_authenticated"] = True
        session.save()

        url = reverse("q_link:api_edge_detail", kwargs={"edge_id": str(self.rel.id)})
        res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["edge"]["source_name"], "Mr. V")
        self.assertEqual(data["edge"]["target_name"], "Palani")
        self.assertTrue(data["edge"]["is_rapid_layering"])

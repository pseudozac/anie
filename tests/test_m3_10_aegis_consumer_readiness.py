"""Integration tests for Milestone M3.10 Phase C: AEGIS Consumer Integration Readiness."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from anie.consumer_contract import (
    CONSUMER_CONTRACT_VERSION_V1,
    CONSUMER_CONTRACT_VERSION_V2,
    FINDINGS_FEED_SCHEMA_V2,
    IOC_FEED_SCHEMA,
    AnieIntelligenceClient,
)
from anie.cross_vector_correlation import (
    CrossVectorCorrelator,
    VectorObservationSummary,
)
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore
from examples.aegis_consumer_v2_example import run_consumer_demo


def _make_telemetry_records(
    domain: str,
    ip: str = "104.21.48.12",
    observed_at: str = "2026-11-21T10:00:00Z",
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_payload = f"raw_dns_wire_{domain}_{ip}_{observed_at}".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=observed_at,
        target_endpoint="https://cloudflare-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity="cloudflare",
        wire_rcode="NOERROR",
        raw_evidence_status="captured",
    )
    event = RealCollectionEvent(
        request=req,
        response_code="ANSWER",
        raw_sha256=raw_hash,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id="first_party:doh:cloudflare",
        observed_at=observed_at,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=observed_at,
        values=(ip,),
        status="ok",
        source_id="first_party:doh:cloudflare",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    return event, obs


class TestM310AegisConsumerReadiness(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.db_path = self.base_path / "telemetry.db"
        self.store = RealObservationStore(self.db_path)
        self.client = AnieIntelligenceClient.from_database_path(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_consumer_contract_v2_frozen_fixture_validation(self):
        """Validate that the frozen V2 fixture strictly complies with Consumer Contract V2."""
        fixture_path = Path(__file__).resolve().parent / "fixtures" / "aegis_consumer_contract_v2_fixture.json"
        self.assertTrue(fixture_path.is_file(), f"Fixture file not found: {fixture_path}")

        fixture_data = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(fixture_data["contract_version"], CONSUMER_CONTRACT_VERSION_V2)
        self.assertEqual(fixture_data["schema"], FINDINGS_FEED_SCHEMA_V2)
        self.assertEqual(fixture_data["publisher"], "anie-first-party")
        self.assertIn("Uncalibrated heuristic scores", fixture_data["disclaimer"])
        self.assertGreaterEqual(fixture_data["total_findings"], 1)

        allowed_layers = {"FACT", "DERIVED", "HYPOTHESIS", "VALIDATED"}
        for f in fixture_data["findings"]:
            self.assertEqual(f["schema"], "anie.cross-vector-finding.v2")
            self.assertTrue(f["finding_id"].startswith("finding_"))
            self.assertTrue(f["subject_uri"].startswith("anie:entity:"))
            self.assertIn(f["epistemic_layer"], allowed_layers)
            self.assertEqual(f["state"], "ACTIVE")

            # Validate temporal correlation vs causation
            temp_corr = f["temporal_correlation_vs_causation"]
            self.assertFalse(temp_corr["causation_inferred"])
            self.assertIn("competing hypotheses", temp_corr["analysis"])

            # Validate abstention state
            abst = f["abstention_state"]
            self.assertIn("abstained", abst)
            self.assertIsInstance(abst["participating_vectors"], list)

            # Validate competing hypotheses
            hyps = f.get("competing_hypotheses", [])
            self.assertGreaterEqual(len(hyps), 1)
            for h in hyps:
                self.assertIn(h["status"], {"FAVORED", "VIABLE", "CONTRADICTED", "INCONCLUSIVE"})
                self.assertIsInstance(h["heuristic_score"], float)
                self.assertGreaterEqual(h["heuristic_score"], 0.0)
                self.assertLessEqual(h["heuristic_score"], 1.0)
                self.assertTrue(h["falsifiability_condition"])

    def test_aegis_client_query_cross_vector_findings_and_pagination(self):
        """Verify client cursor-based pagination and filtering across cross-vector findings."""
        correlator = CrossVectorCorrelator(self.store)

        # Ingest 5 findings across domains
        for i in range(5):
            domain = f"app-{i}.example.org"
            time_str = f"2026-11-21T10:0{i}:00Z"
            ev, obs = _make_telemetry_records(domain, f"104.21.48.{10+i}", time_str)
            self.store.insert_record(ev, obs)

            findings = correlator.correlate_records(
                domain=domain,
                vectors={
                    "dns": VectorObservationSummary(
                        vector="dns",
                        observed_at=time_str,
                        evidence_id=ev.event_id,
                        evidence_hash=ev.raw_sha256,
                        values=[f"104.21.48.{10+i}"],
                    ),
                    "http": VectorObservationSummary(
                        vector="http",
                        observed_at=time_str,
                        evidence_id=ev.event_id,
                        evidence_hash=ev.raw_sha256,
                        values=["cloudflare"],
                        metadata={"server": "cloudflare"},
                    ),
                },
            )
            for f in findings:
                self.store.insert_cross_vector_finding(f)

        # 1. Query with pagination (limit=2)
        page1 = self.client.query_cross_vector_findings(limit=2)
        self.assertEqual(len(page1.items), 2)
        self.assertTrue(page1.has_more)
        self.assertIsNotNone(page1.next_cursor)

        page2 = self.client.query_cross_vector_findings(limit=2, cursor=page1.next_cursor)
        self.assertEqual(len(page2.items), 2)
        self.assertTrue(page2.has_more)
        self.assertIsNotNone(page2.next_cursor)

        page3 = self.client.query_cross_vector_findings(limit=2, cursor=page2.next_cursor)
        self.assertEqual(len(page3.items), 1)
        self.assertFalse(page3.has_more)

        # Confirm all 5 unique findings were retrieved in descending order
        all_ids = [f["finding_id"] for f in page1.items + page2.items + page3.items]
        self.assertEqual(len(all_ids), 5)
        self.assertEqual(len(set(all_ids)), 5)

        # 2. Filter by subject_uri
        target_subject = "anie:entity:domain:app-2.example.org"
        filt_page = self.client.query_cross_vector_findings(subject_uri=target_subject)
        self.assertEqual(len(filt_page.items), 1)
        self.assertEqual(filt_page.items[0]["subject_uri"], target_subject)

        # 3. Filter by state
        active_page = self.client.query_cross_vector_findings(state="ACTIVE")
        self.assertEqual(len(active_page.items), 5)

        # 4. Filter by finding_type
        cdn_page = self.client.query_cross_vector_findings(finding_type="CDN_PROVIDER_MIGRATION")
        self.assertEqual(len(cdn_page.items), 5)

    def test_epistemic_layer_integrity_and_uncalibrated_disclaimer(self):
        """Verify that findings carry epistemic labels, disclaimers, and authoritative evidence grounding."""
        domain = "grounded-host.net"
        ev, obs = _make_telemetry_records(domain, "104.21.48.99", "2026-11-21T10:00:00Z")
        self.store.insert_record(ev, obs)

        correlator = CrossVectorCorrelator(self.store)
        # 1. Single-vector yields epistemic layer FACT with abstention
        single_findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev.event_id,
                    evidence_hash=ev.raw_sha256,
                    values=["104.21.48.99"],
                ),
            },
        )
        self.assertEqual(single_findings[0].epistemic_layer, "FACT")
        self.assertTrue(single_findings[0].abstention_state.abstained)

        # 2. Multi-vector correlation yields epistemic layer HYPOTHESIS
        multi_findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev.event_id,
                    evidence_hash=ev.raw_sha256,
                    values=["104.21.48.99"],
                ),
                "http": VectorObservationSummary(
                    vector="http",
                    observed_at="2026-11-21T10:01:00Z",
                    evidence_id=ev.event_id,
                    evidence_hash=ev.raw_sha256,
                    values=["cloudflare"],
                    metadata={"server": "cloudflare"},
                ),
            },
        )
        self.assertEqual(multi_findings[0].epistemic_layer, "HYPOTHESIS")
        self.assertFalse(multi_findings[0].abstention_state.abstained)

        self.store.insert_cross_vector_finding(multi_findings[0])

        feed = self.client.export_normalized_findings_feed()
        self.assertEqual(feed.contract_version, CONSUMER_CONTRACT_VERSION_V2)
        self.assertIn("uncalibrated rule-based metrics", feed.notice)
        self.assertEqual(feed.total_findings, 1)

        finding = feed.findings[0]
        self.assertEqual(finding["epistemic_layer"], "HYPOTHESIS")
        self.assertIn("uncalibrated", finding["disclaimer"].lower())

        # Verify evidence grounding
        ev_res = self.client.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertTrue(ev_res["is_authoritative"])
        self.assertEqual(ev_res["status"], "AUTHORITATIVE_VERIFIED")
        self.assertEqual(ev_res["source_id"], "first_party:doh:cloudflare")

    def test_v1_v2_compatibility_and_reference_client_demo(self):
        """Verify V1 backward compatibility and production reference client execution."""
        domain = "compat-demo.org"
        ev, obs = _make_telemetry_records(domain, "104.21.48.55", "2026-11-21T10:00:00Z")
        self.store.insert_record(ev, obs)

        correlator = CrossVectorCorrelator(self.store)
        findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev.event_id,
                    evidence_hash=ev.raw_sha256,
                    values=["104.21.48.55"],
                ),
                "http": VectorObservationSummary(
                    vector="http",
                    observed_at="2026-11-21T10:01:00Z",
                    evidence_id=ev.event_id,
                    evidence_hash=ev.raw_sha256,
                    values=["cloudflare"],
                    metadata={"server": "cloudflare"},
                ),
            },
        )
        self.store.insert_cross_vector_finding(findings[0])

        # Test V1 IOC feed export alongside V2 findings feed
        v1_ioc_feed = self.client.export_canonical_ioc_feed(publisher_id="compat-tester")
        self.assertEqual(v1_ioc_feed.schema, IOC_FEED_SCHEMA)
        self.assertEqual(v1_ioc_feed.contract_version, CONSUMER_CONTRACT_VERSION_V1)

        v2_findings_feed = self.client.export_normalized_findings_feed(publisher_id="compat-tester")
        self.assertEqual(v2_findings_feed.schema, FINDINGS_FEED_SCHEMA_V2)
        self.assertEqual(v2_findings_feed.contract_version, CONSUMER_CONTRACT_VERSION_V2)

        # Test reference consumer demo output
        stdout_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf):
            run_consumer_demo(self.db_path)

        output = stdout_buf.getvalue()
        self.assertIn("ANIE -> AEGIS Consumer Contract V2 Integration Demo", output)
        self.assertIn("Contract Version: anie.consumer-contract.v2", output)
        self.assertIn("Retrieved 1 findings", output)
        self.assertIn("[AUTHENTICATED]", output)
        self.assertIn("Integration check successful: AEGIS consumer contract V2 ready for production handoff.", output)


if __name__ == "__main__":
    unittest.main()

"""Tests for AnieIntelligenceClient and Consumer Contract (Phase 3.5)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.canonical_entities import (
    canonical_domain_uri,
    canonical_ipv4_uri,
    canonical_resolver_uri,
)
from anie.consumer_contract import (
    AnieIntelligenceClient,
    decode_cursor,
    encode_cursor,
)
from anie.intelligence_evaluator import IntelligenceEvaluator
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore


def _make_record(subject: str, ip: str, observed_at: str = "2026-11-20T12:00:00Z") -> tuple[RealObservation, RealCollectionEvent]:
    raw_payload = f"raw_{subject}_{ip}".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=subject,
        observed_at=observed_at,
        target_endpoint="https://cloudflare-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
    factual = FactualVerification(
        dnssec_status="indeterminate",
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
        subject=subject,
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
    return obs, event


class TestConsumerContract(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_intel.db"
        self.store = RealObservationStore(self.db_path)

        # Populate store, claims, discrepancies using IntelligenceEvaluator
        evaluator = IntelligenceEvaluator(self.store)
        evaluator.evaluate()

        self.client = AnieIntelligenceClient(self.store)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_cursor_encoding_and_decoding(self):
        cursor = encode_cursor(offset=50, sort_key="example.com")
        self.assertIsInstance(cursor, str)
        offset, sort_key = decode_cursor(cursor)
        self.assertEqual(offset, 50)
        self.assertEqual(sort_key, "example.com")

        # Invalid cursor returns (0, None)
        self.assertEqual(decode_cursor("invalid_base64_string!!!"), (0, None))
        self.assertEqual(decode_cursor(None), (0, None))

    def test_query_entities_pagination(self):
        page1 = self.client.query_entities(limit=5)
        self.assertEqual(len(page1["items"]), 5)
        self.assertIsNotNone(page1["next_cursor"])

        page2 = self.client.query_entities(limit=5, cursor=page1["next_cursor"])
        self.assertTrue(len(page2["items"]) > 0)

        # Verify no overlap between page 1 and page 2
        p1_uris = {item["uri"] for item in page1["items"]}
        p2_uris = {item["uri"] for item in page2["items"]}
        self.assertTrue(p1_uris.isdisjoint(p2_uris))

    def test_query_entities_filtering(self):
        domains = self.client.query_entities(entity_type="domain", limit=100)
        for d in domains["items"]:
            self.assertEqual(d["entity_type"], "domain")
            self.assertTrue(d["uri"].startswith("domain:"))

        ips = self.client.query_entities(entity_type="ipv4", limit=100)
        for ip in ips["items"]:
            self.assertEqual(ip["entity_type"], "ipv4")
            self.assertTrue(ip["uri"].startswith("ipv4:"))

    def test_query_claims_filtering(self):
        # All claims
        all_claims = self.client.query_claims(limit=100)
        self.assertTrue(len(all_claims["items"]) > 0)

        # Confidence filter
        high_conf = self.client.query_claims(min_confidence=0.85, limit=100)
        for claim in high_conf["items"]:
            self.assertGreaterEqual(claim["confidence"], 0.85)

        # Entity URI filter
        domain_uri = canonical_domain_uri("botnet-flux.example.org")
        entity_claims = self.client.query_claims(entity_uri=domain_uri, limit=100)
        self.assertTrue(len(entity_claims["items"]) > 0)
        for c in entity_claims["items"]:
            self.assertEqual(c["subject_uri"], domain_uri)

        # Layer filter
        hypotheses = self.client.query_claims(layer="HYPOTHESIS", limit=100)
        for c in hypotheses["items"]:
            self.assertEqual(c["layer"], "HYPOTHESIS")

    def test_query_relationships(self):
        domain_uri = canonical_domain_uri("cdn-rotator.example.com")
        rels = self.client.query_relationships(domain_uri, direction="BOTH", limit=100)
        self.assertTrue(len(rels["items"]) > 0)
        for r in rels["items"]:
            self.assertTrue(
                r["source_uri"] == domain_uri or r["target_uri"] == domain_uri,
                f"Relationship {r} must touch {domain_uri}"
            )

    def test_get_entity_provenance(self):
        domain_uri = canonical_domain_uri("cdn-rotator.example.com")
        prov = self.client.get_entity_provenance(domain_uri)

        self.assertEqual(prov["entity_uri"], domain_uri)
        self.assertEqual(prov["schema"], "anie.entity-provenance-bundle.v1")
        self.assertTrue(len(prov["observations"]) > 0)
        self.assertTrue(len(prov["raw_evidence_events"]) > 0)

        # Check evidence hash linkage
        for ev in prov["raw_evidence_events"]:
            self.assertTrue("raw_sha256" in ev)
            self.assertTrue("subject" in ev)
            self.assertTrue("response_code" in ev)

    def test_export_canonical_ioc_feed(self):
        feed = self.client.export_canonical_ioc_feed(min_confidence=0.7)

        self.assertEqual(feed["feed_schema"], "anie.canonical-ioc-feed.v1")
        self.assertIn("disclaimer", feed)
        self.assertIn("accuracy_vs_confidence_note", feed)
        self.assertIsInstance(feed["indicators"], list)
        self.assertTrue(feed["total_indicators"] > 0)

        # Check structure of indicators
        for ind in feed["indicators"]:
            self.assertIn("entity_uri", ind)
            self.assertIn("entity_type", ind)
            self.assertIn("claim_type", ind)
            self.assertIn("indicator_category", ind)
            self.assertIn("maliciousness_inferred", ind)
            self.assertFalse(ind["maliciousness_inferred"])
            self.assertGreaterEqual(ind["confidence"], 0.7)

    def test_provenance_isolation_apex_vs_subdomain(self):
        # Insert records for apex and subdomain
        obs_apex, evt_apex = _make_record("example.com", "93.184.216.34")
        obs_sub, evt_sub = _make_record("sub.example.com", "192.0.2.1")
        self.store.insert_record(evt_apex, obs_apex)
        self.store.insert_record(evt_sub, obs_sub)

        # Provenance for apex domain MUST NOT include subdomain observations
        prov_apex = self.client.get_entity_provenance("domain:example.com")
        subjects_apex = {o["subject"] for o in prov_apex["observations"]}
        self.assertIn("example.com", subjects_apex)
        self.assertNotIn("sub.example.com", subjects_apex)

        # Provenance for subdomain MUST NOT include apex observations
        prov_sub = self.client.get_entity_provenance("domain:sub.example.com")
        subjects_sub = {o["subject"] for o in prov_sub["observations"]}
        self.assertIn("sub.example.com", subjects_sub)
        self.assertNotIn("example.com", subjects_sub)

    def test_provenance_isolation_similar_domains(self):
        # Insert records for similar domain names (substring match hazard)
        obs_co, evt_co = _make_record("test.co", "198.51.100.1")
        obs_com, evt_com = _make_record("test.com", "198.51.100.2")
        self.store.insert_record(evt_co, obs_co)
        self.store.insert_record(evt_com, obs_com)

        # Provenance for test.co MUST NOT include test.com
        prov_co = self.client.get_entity_provenance("domain:test.co")
        subjects_co = {o["subject"] for o in prov_co["observations"]}
        self.assertIn("test.co", subjects_co)
        self.assertNotIn("test.com", subjects_co)

    def test_provenance_isolation_ip_substring_collision(self):
        # Insert records where one IP is a string prefix of another
        obs_1, evt_1 = _make_record("host-a.org", "10.0.0.1")
        obs_10, evt_10 = _make_record("host-b.org", "10.0.0.10")
        self.store.insert_record(evt_1, obs_1)
        self.store.insert_record(evt_10, obs_10)

        # Provenance for 10.0.0.1 MUST NOT include host-b.org (resolving to 10.0.0.10)
        prov_ip1 = self.client.get_entity_provenance("ipv4:10.0.0.1")
        subjects_ip1 = {o["subject"] for o in prov_ip1["observations"]}
        self.assertIn("host-a.org", subjects_ip1)
        self.assertNotIn("host-b.org", subjects_ip1)

    def test_export_canonical_ioc_feed_pagination_and_semantics(self):
        # Page 1 with limit=2
        page1 = self.client.export_canonical_ioc_feed(limit=2)
        self.assertEqual(len(page1.indicators), 2)
        self.assertTrue(page1.has_more)
        self.assertIsNotNone(page1.next_cursor)

        # Page 2 using cursor
        page2 = self.client.export_canonical_ioc_feed(limit=2, cursor=page1.next_cursor)
        self.assertTrue(len(page2.indicators) > 0)
        p1_ids = {ind["indicator_id"] for ind in page1.indicators}
        p2_ids = {ind["indicator_id"] for ind in page2.indicators}
        self.assertTrue(p1_ids.isdisjoint(p2_ids))

        # fetch_all=True returns all indicators
        all_feed = self.client.export_canonical_ioc_feed(fetch_all=True)
        self.assertFalse(all_feed.has_more)
        self.assertIsNone(all_feed.next_cursor)
        self.assertGreaterEqual(len(all_feed.indicators), 2)
        self.assertEqual(all_feed.total_indicators, len(all_feed.indicators))



if __name__ == "__main__":
    unittest.main()

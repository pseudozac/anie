"""Tests for AnieIntelligenceClient and Consumer Contract (Phase 3.5)."""
from __future__ import annotations

from datetime import datetime, timezone
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
from anie.real_store import RealObservationStore


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
            self.assertGreaterEqual(ind["confidence"], 0.7)


if __name__ == "__main__":
    unittest.main()

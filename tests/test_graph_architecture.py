"""Unit tests for ANIE M3.3.1 Graph-Native Architecture, Epistemic Hierarchy, and Profiling."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from anie.discrepancy_models import (
    DiscrepancyVerdict,
    DivergenceCategory,
    RealDiscrepancyReport,
)
from anie.graph_engine import GraphEngine
from anie.graph_models import (
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    IntelligenceClaim,
    NodeType,
    RelationType,
    format_node_id,
)
from anie.profiling import get_process_rss, profile_execution
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_publish import (
    AegisReleaseConsumer,
    RealReleaseTrust,
    ReleaseSequenceTracker,
)
from anie.real_store import CURRENT_SCHEMA_VERSION, RealObservationStore


def make_sample_event_and_obs(
    domain: str = "example.com",
    resolver: str = "cloudflare",
    ips: tuple[str, ...] = ("93.184.216.34",),
    observed_at: str = "2026-11-20T10:00:00Z",
) -> tuple[RealCollectionEvent, RealObservation]:
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=observed_at,
        target_endpoint=f"https://{resolver}.net/dns-query",
        pinned_ip="192.0.2.1",
    )
    raw_payload = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    raw_sha = sha256(raw_payload).hexdigest()

    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity=resolver,
        wire_rcode="NOERROR",
        raw_evidence_status="captured",
        resolver_ad_claim=True,
    )

    ev = RealCollectionEvent(
        request=req,
        response_code="NOERROR",
        raw_sha256=raw_sha,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id=f"oracle-collector-01:{resolver}",
        observed_at=observed_at,
        raw_payload=raw_payload,
    )

    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=observed_at,
        values=ips,
        status="ok",
        source_id=f"oracle-collector-01:{resolver}",
        method="dns",
        synthetic=False,
        evidence_id=ev.event_id,
        factual_verification=factual,
        ttl_seconds=300,
    )
    return ev, obs


class TestGraphModels(unittest.TestCase):
    """Test typed entity models, URIs, and epistemic layers."""

    def test_node_uri_formatting(self):
        self.assertEqual(format_node_id(NodeType.DOMAIN, "Example.COM"), "anie:entity:domain:example.com")
        self.assertEqual(format_node_id(NodeType.IP, "93.184.216.34"), "anie:entity:ip:93.184.216.34")
        self.assertEqual(format_node_id(NodeType.RESOLVER, "Cloudflare"), "anie:entity:resolver:cloudflare")
        self.assertEqual(format_node_id(NodeType.ASN, "AS15133"), "anie:entity:asn:15133")

    def test_node_creation_and_serialization(self):
        node = GraphNode.create(
            node_type=NodeType.DOMAIN,
            canonical_name="example.com",
            layer=EpistemicLayer.FACT,
            observed_at="2026-11-20T10:00:00Z",
            properties={"environment": "production"},
        )
        self.assertEqual(node.node_id, "anie:entity:domain:example.com")
        self.assertEqual(node.layer, "FACT")

        d = node.to_dict()
        reconstructed = GraphNode.from_dict(d)
        self.assertEqual(reconstructed.node_id, node.node_id)
        self.assertEqual(reconstructed.properties, node.properties)

    def test_edge_creation_and_deterministic_hash(self):
        edge = GraphEdge.create(
            source_id="anie:entity:domain:example.com",
            target_id="anie:entity:ip:93.184.216.34",
            relation_type=RelationType.RESOLVES_TO,
            layer=EpistemicLayer.DERIVED,
            observed_at="2026-11-20T10:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            valid_until="2026-11-20T10:05:00Z",
            confidence=1.0,
            evidence_hashes=["4ffd1e091d02e6a62fd48ddd52e129db50f631991a51895e0410a11dd68c9c23"],
        )
        self.assertTrue(edge.edge_id.startswith("edge_"))
        self.assertEqual(len(edge.edge_id), 69)

        d = edge.to_dict()
        reconstructed = GraphEdge.from_dict(d)
        self.assertEqual(reconstructed.edge_id, edge.edge_id)
        self.assertEqual(reconstructed.evidence_hashes, edge.evidence_hashes)

    def test_intelligence_claim_creation(self):
        claim = IntelligenceClaim(
            subject_uri="anie:entity:domain:example.com",
            claim_type="ANYCAST_CDN_ROTATION",
            layer=EpistemicLayer.HYPOTHESIS.value,
            asserted_at="2026-11-20T10:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            ruleset_version="anie.cluster-rules.v1",
            explanation="Domain IP rotated within verified Cloudflare Anycast edge pool.",
            confidence=0.95,
            supporting_evidence_hashes=("4ffd1e091d02e6a62fd48ddd52e129db50f631991a51895e0410a11dd68c9c23",),
            supporting_node_ids=("anie:entity:ip:104.16.12.34",),
        )
        self.assertTrue(claim.claim_id.startswith("claim_"))
        d = claim.to_dict()
        reconstructed = IntelligenceClaim.from_dict(d)
        self.assertEqual(reconstructed.claim_id, claim.claim_id)
        self.assertEqual(reconstructed.confidence, 0.95)


class TestGraphEngineAndQueries(unittest.TestCase):
    """Test graph extraction, SQLite storage, and graph queries."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_graph.sqlite"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_schema_version_is_v3(self):
        self.assertEqual(self.store.schema_version, 3)
        self.assertEqual(CURRENT_SCHEMA_VERSION, 3)

    def test_graph_extraction_from_observation(self):
        ev, obs = make_sample_event_and_obs("example.com", "cloudflare", ("93.184.216.34",))
        self.store.insert_record(ev, obs)

        node_count, edge_count = self.store.sync_observation_to_graph(ev, obs)
        self.assertEqual(node_count, 3)  # domain, resolver, ip
        self.assertEqual(edge_count, 2)  # QUERIED_VIA, RESOLVES_TO

        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            hood = engine.get_k_hop_neighborhood("anie:entity:domain:example.com", max_depth=1)
            self.assertEqual(len(hood["nodes"]), 3)
            self.assertEqual(len(hood["edges"]), 2)

    def test_co_hosted_domains_query(self):
        ev1, obs1 = make_sample_event_and_obs("alpha.com", "cloudflare", ("198.51.100.5",))
        ev2, obs2 = make_sample_event_and_obs("beta.com", "cloudflare", ("198.51.100.5",))
        self.store.insert_record(ev1, obs1)
        self.store.insert_record(ev2, obs2)
        self.store.sync_observation_to_graph(ev1, obs1)
        self.store.sync_observation_to_graph(ev2, obs2)

        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            co_hosted = engine.find_co_hosted_domains("198.51.100.5")
            self.assertEqual(co_hosted, ["alpha.com", "beta.com"])

    def test_evidence_lineage_tracing(self):
        ev, obs = make_sample_event_and_obs("example.com", "cloudflare", ("93.184.216.34",))
        self.store.insert_record(ev, obs)
        self.store.sync_observation_to_graph(ev, obs)

        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            hashes = engine.trace_evidence_lineage("anie:entity:domain:example.com")
            self.assertEqual(len(hashes), 1)
            self.assertEqual(hashes[0], ev.raw_sha256)

    def test_obsidian_markdown_export(self):
        ev, obs = make_sample_event_and_obs("example.com", "cloudflare", ("93.184.216.34",))
        self.store.insert_record(ev, obs)
        self.store.sync_observation_to_graph(ev, obs)

        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            md = engine.export_obsidian_markdown("example.com")
            self.assertIn("---", md)
            self.assertIn("[[anie:entity:ip:93.184.216.34|93.184.216.34]]", md)
            self.assertIn("RESOLVES_TO", md)
            self.assertIn(ev.raw_sha256, md)

    def test_claims_persistence(self):
        claim = IntelligenceClaim(
            subject_uri="anie:entity:domain:example.com",
            claim_type="VERIFIED_BENIGN_PILOT",
            layer=EpistemicLayer.VALIDATED.value,
            asserted_at="2026-11-20T10:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            ruleset_version="anie.analyst-review.v1",
            explanation="Manually verified benign test domain.",
            confidence=1.0,
            supporting_evidence_hashes=("4ffd1e091d02e6a62fd48ddd52e129db50f631991a51895e0410a11dd68c9c23",),
            supporting_node_ids=(),
            analyst_identity="operator-key-1",
        )
        self.store.insert_claim(claim)
        fetched = self.store.get_claim(claim.claim_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.analyst_identity, "operator-key-1")

        by_subj = self.store.claims_for_subject("anie:entity:domain:example.com")
        self.assertEqual(len(by_subj), 1)


class TestAegisConsumerAtomicityGuard(unittest.TestCase):
    """Test AegisReleaseConsumer defense-in-depth on boolean persist_callback return."""

    def test_persist_callback_returning_false_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            state_file = tmp_p / "tracker.json"
            tracker = ReleaseSequenceTracker(state_file, auto_init=True)
            trust = RealReleaseTrust(trusted_keys={})
            consumer = AegisReleaseConsumer(trust, sequence_tracker=tracker)

            # Define a callback returning False
            def failing_callback(obs, evs, discs):
                return False

            import io
            # Even if verify_real_release were called, returning False must raise RuntimeError
            # Test directly with mock
            with self.assertRaises(RuntimeError):
                with patch("anie.real_publish.verify_real_release") as mock_verify:
                    mock_verify.return_value = {
                        "release_sequence": 1,
                        "publisher_identity": "test-pub",
                        "manifest_sha256": "abc",
                    }
                    with patch("gzip.open") as mock_gz:
                        mock_gz.return_value.__enter__.return_value = io.BytesIO(b"")
                        consumer.verify_and_load(tmp_p, persist_callback=failing_callback)


class TestProfilingUtilities(unittest.TestCase):
    """Test OS process RSS measurement and execution profiling."""

    def test_get_process_rss(self):
        rss = get_process_rss()
        self.assertIn("current_rss_bytes", rss)
        self.assertIn("peak_rss_bytes", rss)
        self.assertGreater(rss["current_rss_bytes"], 1024 * 1024)  # At least 1 MB
        self.assertGreaterEqual(rss["peak_rss_bytes"], rss["current_rss_bytes"])

    def test_profile_execution(self):
        def sample_work():
            return sum(i * i for i in range(10000))

        result, profile = profile_execution(sample_work)
        self.assertEqual(result, 333283335000)
        self.assertIn("elapsed_wall_ms", profile)
        self.assertIn("peak_rss_mb", profile)
        self.assertGreater(profile["peak_rss_mb"], 0.0)


if __name__ == "__main__":
    unittest.main()

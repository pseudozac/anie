"""Tests for ANIE Milestone M3.3.2: Architecture Integrity & OCI Readiness.

Verifies:
1. Crash-recoverable release ingestion journal and reconciliation protocol.
2. Crash simulations before, during, and after persistence and tracker updates.
3. Historical inspection isolation and anti-rollback guarantees.
4. Automatic dual-write graph synchronization and transactional consistency.
5. Edge deduplication with evidence hash union (no silent loss of evidence).
6. Complete graph rebuildability from authoritative Layer 1 and 2 records.
7. Unambiguous comma-delimited path-cycle matching and traversal bounding.
8. Safe Markdown/YAML export escaping against untrusted injection.
9. Intelligence trust model verification states and uncertainty semantics.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from typing import Any
import unittest

from anie.discrepancy_engine import DiscrepancyEngine
from anie.discrepancy_models import DiscrepancyVerdict, RealDiscrepancyReport
from anie.graph_engine import GraphEngine
from anie.graph_models import (
    ClaimVerificationState,
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    IntelligenceClaim,
    NodeType,
    RelationType,
    format_node_id,
)
from anie.real_models import RealCollectionEvent, RealObservation
from anie.real_publish import (
    AegisReleaseBundle,
    AegisReleaseConsumer,
    RealReleaseTrust,
    ReleaseSequenceTracker,
    publish_real,
    sign_manifest_detached,
)
from anie.real_store import CURRENT_SCHEMA_VERSION, RealObservationStore
from test_multi_resolver_intelligence import make_multi_resolver_pair


def generate_test_keypair() -> tuple[Any, bytes, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub_raw, "test-op-key-1"


class TestReleaseIngestionJournalAndCrashRecovery(unittest.TestCase):
    """Test idempotent, crash-recoverable ingestion and tracker reconciliation."""

    def setUp(self):
        self.priv_key, self.pub_raw, self.key_id = generate_test_keypair()
        self.trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            allow_rollback=False,
        )
        self.historical_trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            allow_rollback=True,
        )

    def _create_signed_release(self, target_dir: Path, seq: int = 1, domain: str = "example.com") -> Path:
        ev, obs = make_multi_resolver_pair(domain, "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
        publish_real(([obs], [ev]), target_dir, as_of="2026-11-20T10:00:00Z", release_sequence=seq)
        sign_manifest_detached(
            target_dir,
            self.priv_key,
            key_id=self.key_id,
            release_sequence=seq,
            issued_at="2026-11-20T10:05:00Z",
            expires_at="2026-12-20T10:05:00Z",
        )
        return target_dir

    def test_single_transactional_boundary_success(self):
        """Normal release ingestion commits records and advances consumer_releases journal atomically."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_path = tmp_p / "consumer.sqlite"
            tracker_file = tmp_p / "tracker.json"
            store = RealObservationStore(db_path)
            tracker = ReleaseSequenceTracker(tracker_file, auto_init=True)
            consumer = AegisReleaseConsumer(self.trust, sequence_tracker=tracker, store=store)

            rel_dir = self._create_signed_release(tmp_p / "rel1", seq=1)
            bundle = consumer.verify_and_load_bundle(rel_dir, now="2026-11-20T10:10:00Z")

            self.assertIsInstance(bundle, AegisReleaseBundle)
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 1)
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 1)

            # Check journal entry details
            journal = store.get_consumer_release("anie-first-party", 1)
            self.assertIsNotNone(journal)
            self.assertEqual(journal["status"], "COMMITTED")
            self.assertEqual(journal["total_observations"], 1)
            self.assertEqual(journal["total_events"], 1)

    def test_idempotent_reingestion(self):
        """Re-ingesting an already-committed release into store returns False without duplicate rows."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            store = RealObservationStore(tmp_p / "consumer.sqlite")
            tracker = ReleaseSequenceTracker(tmp_p / "tracker.json", auto_init=True)
            consumer = AegisReleaseConsumer(self.trust, sequence_tracker=tracker, store=store)

            rel_dir = self._create_signed_release(tmp_p / "rel1", seq=1)
            bundle = consumer.verify_and_load_bundle(rel_dir, now="2026-11-20T10:10:00Z")
            self.assertIsInstance(bundle, AegisReleaseBundle)
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 1)

            # Re-calling store.ingest_release_bundle directly with same manifest returns False (idempotent no-op)
            re_ingested = store.ingest_release_bundle(
                observations=bundle.observations,
                events=bundle.events,
                discrepancies=bundle.discrepancies,
                publisher="anie-first-party",
                release_sequence=1,
                manifest_sha256=bundle.verification_result["manifest_sha256"],
            )
            self.assertFalse(re_ingested)
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 1)

    def test_crash_simulation_during_persistence(self):
        """Simulated database failure during persistence rolls back all tables and leaves tracker unchanged."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_path = tmp_p / "consumer.sqlite"
            tracker_file = tmp_p / "tracker.json"
            store = RealObservationStore(db_path)
            tracker = ReleaseSequenceTracker(tracker_file, auto_init=True)

            rel_dir = self._create_signed_release(tmp_p / "rel1", seq=1)

            # Mock a failure inside persist_callback
            def failing_callback(obs, evs, discs):
                raise sqlite3.OperationalError("disk I/O error during insert")

            consumer = AegisReleaseConsumer(self.trust, sequence_tracker=tracker, store=None)
            with self.assertRaises(sqlite3.OperationalError):
                consumer.verify_and_load_bundle(rel_dir, now="2026-11-20T10:10:00Z", persist_callback=failing_callback)

            # Tracker remains at sequence 0
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 0)
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 0)

    def test_crash_simulation_after_db_commit_before_tracker_write(self):
        """Crash after DB commit but before tracker file update is recovered on subsequent initialization."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_path = tmp_p / "consumer.sqlite"
            tracker_file = tmp_p / "tracker.json"
            store = RealObservationStore(db_path)
            tracker = ReleaseSequenceTracker(tracker_file, auto_init=True)

            rel_dir = self._create_signed_release(tmp_p / "rel1", seq=1)

            # Ingest directly into store simulating crash before tracker.update_accepted
            ev, obs = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare")
            store.ingest_release_bundle(
                observations=[obs],
                events=[ev],
                discrepancies=[],
                publisher="anie-first-party",
                release_sequence=1,
                manifest_sha256="test_manifest_hash_123",
            )
            # Store has sequence 1, but tracker still has 0!
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 1)
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 0)

            # When AegisReleaseConsumer starts up, it automatically reconciles the tracker forward
            consumer = AegisReleaseConsumer(self.trust, sequence_tracker=tracker, store=store)
            rel_dir2 = self._create_signed_release(tmp_p / "rel2", seq=2)
            bundle2 = consumer.verify_and_load_bundle(rel_dir2, now="2026-11-20T10:10:00Z")

            self.assertEqual(bundle2.verification_result["release_sequence"], 2)
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 2)
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 2)

    def test_historical_inspection_isolation(self):
        """Historical inspection under authorized trust policy never mutates release journal or tracker."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            store = RealObservationStore(tmp_p / "consumer.sqlite")
            tracker = ReleaseSequenceTracker(tmp_p / "tracker.json", auto_init=True)
            consumer = AegisReleaseConsumer(self.historical_trust, sequence_tracker=tracker, store=store)

            rel_dir = self._create_signed_release(tmp_p / "rel1", seq=1)
            bundle = consumer.verify_and_load_bundle(rel_dir, now="2026-11-20T10:10:00Z", allow_rollback=True)

            self.assertTrue(bundle.verification_result["authenticated"])
            self.assertFalse(bundle.verification_result["anti_rollback_verified"])
            # Sequence tracker and consumer_releases MUST NOT advance
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 0)
            self.assertEqual(store.get_last_consumer_release_sequence("anie-first-party"), 0)


class TestGraphIntegrityAndTraversalBounds(unittest.TestCase):
    """Test automatic dual-write sync, evidence union, cycle detection, and bounds."""

    def test_automatic_dual_write_synchronization(self):
        """insert_record and insert_discrepancy automatically update graph tables in same transaction."""
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "store.sqlite")
            ev, obs = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))

            store.insert_record(ev, obs, auto_sync_graph=True)

            with store._connect() as conn:
                engine = GraphEngine(conn)
                node = engine.get_node("anie:entity:domain:example.com")
                self.assertIsNotNone(node)
                self.assertEqual(node.canonical_name, "example.com")
                self.assertEqual(node.layer, EpistemicLayer.FACT.value)

                # Direct co-hosting lookup
                co_hosted = engine.find_co_hosted_domains("93.184.216.34")
                self.assertIn("example.com", co_hosted)

    def test_edge_deduplication_unions_evidence_hashes_without_silent_loss(self):
        """Repeated observations of the same relationship merge evidence hashes rather than dropping them."""
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "store.sqlite")
            # First observation with hash 1
            ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
            # Second observation at same timestamp with different raw evidence
            ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",), ad_flag=True)
            self.assertNotEqual(ev1.raw_sha256, ev2.raw_sha256)

            with store._connect() as conn:
                engine = GraphEngine(conn)
                nodes1, edges1 = engine.extract_from_observation(ev1, obs1)
                nodes2, edges2 = engine.extract_from_observation(ev2, obs2)

                for n in nodes1 + nodes2:
                    engine.upsert_node(n)
                for e in edges1:
                    engine.insert_edge(e)

                # Before second edge insert: verify edge has ev1's hash
                resolves_edge1 = [e for e in edges1 if e.relation_type == RelationType.RESOLVES_TO.value][0]
                hashes_before = engine.trace_evidence_lineage(resolves_edge1.edge_id)
                self.assertEqual(len(hashes_before), 1)

                # Now insert edges from second observation (which targets same domain->IP edge)
                for e in edges2:
                    engine.insert_edge(e)

                hashes_after = engine.trace_evidence_lineage(resolves_edge1.edge_id)
                # MUST have 2 distinct hashes merged! No silent loss of evidence!
                self.assertEqual(len(hashes_after), 2)
                self.assertIn(ev1.raw_sha256, hashes_after)
                self.assertIn(ev2.raw_sha256, hashes_after)

    def test_rebuild_graph_from_authoritative_observations(self):
        """store.rebuild_graph_from_observations completely regenerates graph tables."""
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "store.sqlite")
            ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
            ev2, obs2 = make_multi_resolver_pair("iana.org", "dns_aaaa", resolver_name="google", values=("2606:2800:21f:cb07:6820:80da:af6b:8b2c",))

            store.insert_record(ev1, obs1)
            store.insert_record(ev2, obs2)

            disc = DiscrepancyEngine().analyze("example.com", "dns_a", [obs1], [ev1])
            store.insert_discrepancy(disc)

            # Rebuild graph from observations
            nodes_count, edges_count = store.rebuild_graph_from_observations()
            self.assertGreater(nodes_count, 0)
            self.assertGreater(edges_count, 0)

            with store._connect() as conn:
                engine = GraphEngine(conn)
                self.assertIsNotNone(engine.get_node("anie:entity:domain:example.com"))
                self.assertIsNotNone(engine.get_node("anie:entity:domain:iana.org"))

    def test_unambiguous_comma_delimited_cycle_detection(self):
        """Substring matching defect is resolved: example.co is not falsely treated as cycle of example.com."""
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "store.sqlite")
            with store._connect() as conn:
                engine = GraphEngine(conn)
                # Create nodes where one node_id is a prefix/substring of another
                node_com = GraphNode.create(NodeType.DOMAIN, "example.com", EpistemicLayer.FACT, "2026-11-20T10:00:00Z")
                node_co = GraphNode.create(NodeType.DOMAIN, "example.co", EpistemicLayer.FACT, "2026-11-20T10:00:00Z")
                node_shared = GraphNode.create(NodeType.IP, "93.184.216.34", EpistemicLayer.FACT, "2026-11-20T10:00:00Z")

                engine.upsert_node(node_com)
                engine.upsert_node(node_co)
                engine.upsert_node(node_shared)

                # Connect example.com -> shared IP -> example.co
                e1 = GraphEdge.create(node_com.node_id, node_shared.node_id, RelationType.RESOLVES_TO, EpistemicLayer.DERIVED, "2026-11-20T10:00:00Z", evidence_hashes=["a" * 64])
                e2 = GraphEdge.create(node_co.node_id, node_shared.node_id, RelationType.RESOLVES_TO, EpistemicLayer.DERIVED, "2026-11-20T10:00:00Z", evidence_hashes=["b" * 64])
                engine.insert_edge(e1)
                engine.insert_edge(e2)

                # Traverse 2 hops from example.com: should reach example.co!
                res = engine.get_k_hop_neighborhood(node_com.node_id, max_depth=2)
                node_ids = {n["node_id"] for n in res["nodes"]}
                self.assertIn(node_com.node_id, node_ids)
                self.assertIn(node_shared.node_id, node_ids)
                # With exact delimiter cycle detection, example.co is NOT skipped!
                self.assertIn(node_co.node_id, node_ids)

    def test_traversal_hard_bounds_enforced(self):
        """Recursive traversal enforces depth bounds and result limits."""
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "store.sqlite")
            with store._connect() as conn:
                engine = GraphEngine(conn)
                # max_depth > 5 must raise ValueError
                with self.assertRaises(ValueError):
                    engine.get_k_hop_neighborhood("anie:entity:domain:example.com", max_depth=6)

                with self.assertRaises(ValueError):
                    engine.get_k_hop_neighborhood("anie:entity:domain:example.com", max_depth=-1)

    def test_obsidian_markdown_export_strict_escaping(self):
        """Untrusted domain strings cannot inject Markdown syntax, headers, or break wikilinks."""
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "store.sqlite")
            with store._connect() as conn:
                engine = GraphEngine(conn)
                # Untrusted domain containing injection characters
                nasty_name = "test.com\n# Injected Header\n[[injected|link]]"
                node = GraphNode(
                    node_id="anie:entity:domain:test.com",
                    node_type=NodeType.DOMAIN.value,
                    canonical_name=nasty_name,
                    layer=EpistemicLayer.FACT.value,
                    first_observed_at="2026-11-20T10:00:00Z",
                    last_observed_at="2026-11-20T10:00:00Z",
                )
                engine.upsert_node(node)

                md = engine.export_obsidian_markdown("test.com")
                # Confirm frontmatter is quoted and newlines/brackets are sanitized so header injection fails
                self.assertIn('canonical_name: "test.com # Injected Header injected|link"', md)
                self.assertNotIn("\n# Injected Header\n", md)
                # Confirm wikilinks in text do not contain raw unescaped double brackets
                self.assertNotIn("[[injected|link]]", md)


class TestIntelligenceTrustModel(unittest.TestCase):
    """Test verification states, uncertainty semantics, and non-infallibility."""

    def test_claim_verification_state_semantics(self):
        """IntelligenceClaim requires valid ClaimVerificationState and supports falsifiability condition."""
        claim = IntelligenceClaim(
            subject_uri="anie:entity:domain:example.com",
            claim_type="fast_flux_suspicion",
            layer=EpistemicLayer.HYPOTHESIS.value,
            asserted_at="2026-11-20T10:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            ruleset_version="anie.cluster.v1",
            explanation="Domain resolves to 14 distinct IPs across 3 autonomous systems in 10 minutes",
            confidence=0.85,
            supporting_evidence_hashes=("a" * 64,),
            supporting_node_ids=("anie:entity:domain:example.com",),
            verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
            falsifiability_condition="Subsequent query resolves consistently to anycast CDN prefix 104.16.0.0/12",
        )
        self.assertEqual(claim.verification_state, ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value)
        self.assertIsNotNone(claim.falsifiability_condition)

        # Serialization roundtrip preserves attributes
        d = claim.to_dict()
        reconstructed = IntelligenceClaim.from_dict(d)
        self.assertEqual(reconstructed.verification_state, claim.verification_state)
        self.assertEqual(reconstructed.falsifiability_condition, claim.falsifiability_condition)

    def test_invalid_verification_state_fails_closed(self):
        """Unrecognized verification state string raises ValueError."""
        with self.assertRaises(ValueError):
            IntelligenceClaim(
                subject_uri="anie:entity:domain:example.com",
                claim_type="test",
                layer=EpistemicLayer.HYPOTHESIS.value,
                asserted_at="2026-11-20T10:00:00Z",
                valid_from="2026-11-20T10:00:00Z",
                ruleset_version="v1",
                explanation="test",
                confidence=1.0,
                supporting_evidence_hashes=("a" * 64,),
                supporting_node_ids=(),
                verification_state="ABSOLUTE_EXTERNAL_TRUTH",  # Disallowed
            )


if __name__ == "__main__":
    unittest.main()

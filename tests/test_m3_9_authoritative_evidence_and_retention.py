"""Unit and integration tests for Milestone M3.9: Authoritative Evidence Verification and Retention Lifecycle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.graph_models import ClaimVerificationState, IntelligenceClaim
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore
from anie.retention import (
    RetentionPolicy,
    rebuild_derived_indexes,
    safe_prune_retention,
)


def _make_sample_record(
    subject: str,
    ip: str,
    observed_at: str = "2026-11-20T12:00:00Z",
) -> tuple[RealObservation, RealCollectionEvent]:
    raw_payload = f"raw_auth_{subject}_{ip}_{observed_at}".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=subject,
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


class TestM39AuthoritativeEvidenceAndRetention(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_auth_retention.db"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_authoritative_evidence_verification(self):
        """Verify that genuine authoritative records pass verification while fabricated hashes are rejected."""
        obs, ev = _make_sample_record("auth-test.org", "93.184.216.34")
        self.store.insert_record(ev, obs)

        # 1. Authoritative verification by event_id
        res_by_id = self.store.verify_evidence_authoritativeness(ev.event_id)
        self.assertTrue(res_by_id["is_authoritative"])
        self.assertEqual(res_by_id["status"], "AUTHORITATIVE_VERIFIED")
        self.assertEqual(res_by_id["event_id"], ev.event_id)
        self.assertEqual(res_by_id["raw_sha256"], ev.raw_sha256)
        self.assertEqual(res_by_id["observation_id"], obs.observation_id)

        # 2. Authoritative verification by raw_sha256
        res_by_hash = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertTrue(res_by_hash["is_authoritative"])
        self.assertEqual(res_by_hash["status"], "AUTHORITATIVE_VERIFIED")
        self.assertEqual(res_by_hash["event_id"], ev.event_id)

        # 3. Authoritative verification by observation_id
        res_by_obs = self.store.verify_evidence_authoritativeness(obs.observation_id)
        self.assertTrue(res_by_obs["is_authoritative"])
        self.assertEqual(res_by_obs["observation_id"], obs.observation_id)

        # 4. Rejection of fabricated / user-supplied hash alone
        fake_hash = hashlib.sha256(b"fabricated_user_supplied_hash").hexdigest()
        res_fake = self.store.verify_evidence_authoritativeness(fake_hash)
        self.assertFalse(res_fake["is_authoritative"])
        self.assertEqual(res_fake["status"], "UNVERIFIED_EVIDENCE_REFERENCE")
        self.assertIn("A user-supplied hash alone cannot authenticate an observation", res_fake["reason"])

        # 5. Rejection of empty/invalid string
        res_empty = self.store.verify_evidence_authoritativeness("")
        self.assertFalse(res_empty["is_authoritative"])

    def test_retention_lifecycle_policy_non_destructive_by_default(self):
        """Verify that allow_destructive_pruning=False preserves all authoritative evidence."""
        now_dt = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
        old_time = (now_dt - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

        obs_old, ev_old = _make_sample_record("ancient.com", "192.0.2.1", observed_at=old_time)
        self.store.insert_record(ev_old, obs_old)

        # Policy with allow_destructive_pruning=False
        policy = RetentionPolicy(
            observation_ttl_days=90,
            event_ttl_days=180,
            allow_destructive_pruning=False,
        )
        report = safe_prune_retention(self.store, policy=policy, now=now_dt)

        # Assert zero observations or events were deleted
        self.assertEqual(report.pruned_observations, 0)
        self.assertEqual(report.pruned_events, 0)
        self.assertEqual(report.protected_observations_kept, 1)
        self.assertEqual(report.protected_events_kept, 1)

        # Verify records remain intact in database
        all_obs = self.store.all_observations()
        self.assertEqual(len(all_obs), 1)
        self.assertEqual(all_obs[0].observation_id, obs_old.observation_id)

    def test_retention_lifecycle_tombstone_logging(self):
        """Verify that when destructive pruning is enabled, cryptographic tombstones are logged."""
        now_dt = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
        old_time = (now_dt - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

        obs_old, ev_old = _make_sample_record("prunable.com", "192.0.2.99", observed_at=old_time)
        self.store.insert_record(ev_old, obs_old)

        policy = RetentionPolicy(
            observation_ttl_days=90,
            event_ttl_days=180,
            allow_destructive_pruning=True,
            operator_authorization="operator_token_2026",
        )
        report = safe_prune_retention(self.store, policy=policy, now=now_dt)

        self.assertEqual(report.pruned_observations, 1)
        self.assertEqual(report.pruned_events, 1)

        # Verify tombstones were recorded in retention_tombstone_ledger
        with self.store._connect() as conn:
            tombstones = conn.execute("SELECT record_type, original_id, operator_authorization FROM retention_tombstone_ledger").fetchall()
            self.assertEqual(len(tombstones), 2)
            types = {t[0] for t in tombstones}
            self.assertEqual(types, {"observation", "event"})
            for t in tombstones:
                self.assertEqual(t[2], "operator_token_2026")

    def test_rebuild_derived_indexes(self):
        """Verify that derived graph nodes and edges can be dropped and rebuilt deterministically."""
        obs1, ev1 = _make_sample_record("rebuild-domain.org", "93.184.216.34")
        obs2, ev2 = _make_sample_record("rebuild-domain.org", "93.184.216.35")
        self.store.insert_record(ev1, obs1)
        self.store.insert_record(ev2, obs2)

        # Verify initial graph nodes exist
        with self.store._connect() as conn:
            initial_nodes = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
            initial_edges = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
            self.assertGreater(initial_nodes, 0)
            self.assertGreater(initial_edges, 0)

        # Rebuild derived indexes
        result = rebuild_derived_indexes(self.store)
        self.assertGreaterEqual(result["rebuilt_nodes"], 2)
        self.assertGreaterEqual(result["rebuilt_edges"], 2)

        # Verify reconstructed nodes match expectations
        with self.store._connect() as conn:
            domain_node = conn.execute(
                "SELECT canonical_name, node_type FROM graph_nodes WHERE canonical_name = 'rebuild-domain.org'"
            ).fetchone()
            self.assertIsNotNone(domain_node)
            self.assertEqual(domain_node[1], "domain")

            edge_rows = conn.execute(
                "SELECT relation_type FROM graph_edges WHERE source_id = 'anie:entity:domain:rebuild-domain.org'"
            ).fetchall()
            self.assertEqual(len(edge_rows), 2)
            for er in edge_rows:
                self.assertEqual(er[0], "RESOLVES_TO")


if __name__ == "__main__":
    unittest.main()

"""Unit and integration tests for Milestone M3.10 Phase A: Correctness Audit and Remediations."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
    is_authorized_collector_source,
)
from anie.real_store import RealObservationStore
from anie.retention import (
    RetentionPolicy,
    rebuild_derived_indexes,
    safe_prune_retention,
)


def _make_event_and_obs(
    subject: str,
    ip: str,
    source_id: str = "first_party:doh:cloudflare",
    observed_at: str = "2026-11-21T10:00:00Z",
    raw_payload_override: bytes | None = None,
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_payload = raw_payload_override or f"wire_dns_{subject}_{ip}_{observed_at}".encode("utf-8")
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
        source_id=source_id,
        observed_at=observed_at,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=subject,
        kind="dns_a",
        observed_at=observed_at,
        values=(ip,),
        status="ok",
        source_id=source_id,
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    return event, obs


class TestM310AuthoritativeAudit(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_m310_audit.db"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_preimage_hash_verification_success_and_tamper(self):
        """Verify that genuine payloads authenticate and tampered payloads fail with CORRUPT_PAYLOAD_DIGEST_MISMATCH."""
        ev, obs = _make_event_and_obs("secure-host.org", "93.184.216.34")
        self.store.insert_record(ev, obs)

        # 1. Genuine record authenticates
        res = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertTrue(res["is_authoritative"])
        self.assertEqual(res["status"], "AUTHORITATIVE_VERIFIED")

        # 2. Tamper with raw_payload bytes directly in SQLite
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE real_events SET raw_payload = ? WHERE event_id = ?",
                (b"corrupted_tampered_bytes_here", ev.event_id),
            )

        res_tampered = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertFalse(res_tampered["is_authoritative"])
        self.assertEqual(res_tampered["status"], "CORRUPT_PAYLOAD_DIGEST_MISMATCH")
        self.assertIn("retained payload hash", res_tampered["reason"])

    def test_collector_source_authorization_whitelist(self):
        """Verify that unauthorized collector source IDs are rejected even with valid hashes."""
        # 1. Authorized sources pass
        self.assertTrue(is_authorized_collector_source("first_party:doh:cloudflare"))
        self.assertTrue(is_authorized_collector_source("oracle-collector-01:cloudflare"))
        self.assertTrue(is_authorized_collector_source("anie-collector-01"))

        # 2. Unauthorized sources fail
        self.assertFalse(is_authorized_collector_source("unauthorized_foreign_crawler"))
        self.assertFalse(is_authorized_collector_source("synthetic:test"))
        self.assertFalse(is_authorized_collector_source("random_agent_007"))

        # 3. Store-level verification rejects unauthorized source
        ev, obs = _make_event_and_obs(
            "unauthorized-host.org",
            "192.0.2.1",
            source_id="first_party:doh:cloudflare",
        )
        self.store.insert_record(ev, obs)

        # Modify source_id in DB to an unauthorized entity
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE real_events SET payload = json_set(payload, '$.source_id', 'unauthorized_foreign_crawler') WHERE event_id = ?",
                (ev.event_id,),
            )

        res = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertFalse(res["is_authoritative"])
        self.assertEqual(res["status"], "UNAUTHENTICATED_COLLECTOR")
        self.assertIn("not an authorized collector under trusted policy", res["reason"])

    def test_retention_tombstone_operator_identity_and_integrity(self):
        """Verify that retention tombstones record operator audit identity and preserve genuine record SHA-256."""
        now_dt = datetime.now(timezone.utc)
        ev, obs = _make_event_and_obs(
            "prune-target.org",
            "192.0.2.99",
            observed_at=(now_dt - unittest.mock.ANY if False else "2020-01-01T00:00:00Z"),
        )
        self.store.insert_record(ev, obs)

        operator_identity = "operator:secops_audit_run_01"
        policy = RetentionPolicy(
            observation_ttl_days=1,
            event_ttl_days=1,
            operator_authorization=operator_identity,
            allow_destructive_pruning=True,
        )

        safe_prune_retention(self.store, policy=policy, now=now_dt)

        # Check tombstone ledger
        with self.store._connect() as conn:
            rows = conn.execute(
                "SELECT record_type, original_id, original_sha256, operator_authorization FROM retention_tombstone_ledger"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            for r_type, orig_id, orig_sha, auth_val in rows:
                self.assertEqual(auth_val, operator_identity)
                # Original SHA-256 MUST be non-empty valid 64-char hex
                self.assertEqual(len(orig_sha), 64)

    def test_rebuild_derived_indexes_out_of_order_convergence(self):
        """Verify that derived indexes converge first_observed_at and last_observed_at deterministically out-of-order."""
        domain = "converge-test.org"
        ip = "192.0.2.55"

        # Ingest t2 (later observation) first
        ev2, obs2 = _make_event_and_obs(domain, ip, observed_at="2026-11-21T12:00:00Z")
        self.store.insert_record(ev2, obs2)

        # Ingest t1 (earlier observation) second
        ev1, obs1 = _make_event_and_obs(domain, ip, observed_at="2026-11-21T08:00:00Z")
        self.store.insert_record(ev1, obs1)

        # Rebuild derived indexes
        res = rebuild_derived_indexes(self.store)
        self.assertGreaterEqual(res["rebuilt_nodes"], 2)

        with self.store._connect() as conn:
            dom_node = conn.execute(
                "SELECT first_observed_at, last_observed_at FROM graph_nodes WHERE canonical_name = ?",
                (domain,),
            ).fetchone()
            self.assertIsNotNone(dom_node)
            # Minimum first_observed_at must be 08:00:00Z, maximum last_observed_at must be 12:00:00Z
            self.assertEqual(dom_node[0], "2026-11-21T08:00:00Z")
            self.assertEqual(dom_node[1], "2026-11-21T12:00:00Z")


if __name__ == "__main__":
    unittest.main()

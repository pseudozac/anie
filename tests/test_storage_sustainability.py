"""Tests for evidence-preserving retention and storage sustainability (Phase 3.5)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
    PROFILE_PILOT,
    PROFILE_PRODUCTION,
    PROFILE_SCALE,
    RetentionPolicy,
    StorageGrowthModel,
    collect_protected_evidence_identifiers,
    safe_prune_retention,
)


def _create_record(
    subject: str,
    observed_at: str,
    ip: str = "93.184.216.34",
    resolver: str = "cloudflare",
) -> tuple[RealObservation, RealCollectionEvent]:
    raw_payload = f"raw_wire_{subject}_{observed_at}_{resolver}".encode("utf-8")
    import hashlib
    raw_hash = hashlib.sha256(raw_payload).hexdigest()

    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=subject,
        observed_at=observed_at,
        target_endpoint=f"https://{resolver}-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
    factual = FactualVerification(
        dnssec_status="indeterminate",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity=resolver,
        wire_rcode="NOERROR",
        raw_evidence_status="captured",
    )
    event = RealCollectionEvent(
        request=req,
        response_code="ANSWER",
        raw_sha256=raw_hash,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id=f"first_party:doh:{resolver}",
        observed_at=observed_at,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=subject,
        kind="dns_a",
        observed_at=observed_at,
        values=(ip,),
        status="ok",
        source_id=f"first_party:doh:{resolver}",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    return obs, event


class TestStorageSustainability(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_retention.db"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_safe_prune_preserves_claim_evidence(self):
        now_dt = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
        # 100 days old (exceeds default 90-day observation TTL)
        old_time = (now_dt - timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 10 days old (within retention window)
        recent_time = (now_dt - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Record 1: Old and unreferenced -> Should be pruned
        obs_old_unref, evt_old_unref = _create_record("old-unref.com", old_time, ip="192.0.2.1")
        self.store.insert_record(evt_old_unref, obs_old_unref)

        # Record 2: Old but referenced by an Intelligence Claim -> Must be PROTECTED
        obs_old_ref, evt_old_ref = _create_record("old-ref.com", old_time, ip="192.0.2.2")
        self.store.insert_record(evt_old_ref, obs_old_ref)

        # Record 3: Recent record -> Must be KEPT by TTL
        obs_recent, evt_recent = _create_record("recent.com", recent_time, ip="192.0.2.3")
        self.store.insert_record(evt_recent, obs_recent)

        # Create intelligence claim binding Record 2's evidence hash and observation ID
        claim = IntelligenceClaim(
            subject_uri="anie:entity:domain:old-ref.com",
            claim_type="INFRASTRUCTURE_TRANSITION",
            layer="HYPOTHESIS",
            asserted_at=now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            valid_from=old_time,
            valid_until=None,
            confidence=0.9,
            ruleset_version="anie.rules.v1",
            explanation="Test preservation claim",
            supporting_evidence_hashes=(evt_old_ref.raw_sha256,),
            supporting_node_ids=("anie:entity:domain:old-ref.com",),
            verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
        )
        self.store.insert_claim(claim)

        # Verify initial count
        all_obs = self.store.all_observations()
        self.assertEqual(len(all_obs), 3)

        # Execute safe pruning with reference time
        policy = RetentionPolicy(observation_ttl_days=90, event_ttl_days=180, compact_vacuum=True)
        summary = safe_prune_retention(self.store, policy=policy, now=now_dt)

        self.assertEqual(summary["pruned_observations"], 1)
        self.assertEqual(summary["protected_observations_kept"], 1)
        self.assertTrue(summary["foreign_key_check_passed"])

        # Check remaining observations in store
        remaining_obs = self.store.all_observations()
        remaining_ids = {o.observation_id for o in remaining_obs}

        self.assertNotIn(obs_old_unref.observation_id, remaining_ids)
        self.assertIn(obs_old_ref.observation_id, remaining_ids)
        self.assertIn(obs_recent.observation_id, remaining_ids)

        # Verify the protected claim still exists and is fully intact
        claims = self.store.claims_for_subject("anie:entity:domain:old-ref.com")
        self.assertEqual(len(claims), 1)
        self.assertTrue(claims[0].claim_id.startswith("claim_"))

    def test_event_pruning_and_referential_integrity(self):
        now_dt = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
        # 200 days old (exceeds default 180-day raw event TTL)
        very_old_time = (now_dt - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Record with very old event, but observation is NOT pruned yet (e.g. obs TTL set to 300 days)
        obs, evt = _create_record("active-old.com", very_old_time)
        self.store.insert_record(evt, obs)

        # Policy where event TTL is exceeded (180 days) but obs TTL is not (300 days)
        # Fail-closed check: event must NOT be deleted because active observation still references it!
        policy = RetentionPolicy(observation_ttl_days=300, event_ttl_days=180, compact_vacuum=False)
        summary = safe_prune_retention(self.store, policy=policy, now=now_dt)

        self.assertEqual(summary["pruned_events"], 0)
        self.assertEqual(summary["protected_events_kept"], 1)
        self.assertTrue(summary["foreign_key_check_passed"])

    def test_storage_growth_model_projections(self):
        for profile in [PROFILE_PILOT, PROFILE_PRODUCTION, PROFILE_SCALE]:
            for days in [30, 90, 180, 365]:
                proj = StorageGrowthModel.project_growth(profile, days=days)
                self.assertEqual(proj["profile_name"], profile)
                self.assertEqual(proj["days"], days)
                self.assertGreater(proj["total_observations"], 0)
                self.assertGreater(proj["estimated_db_mb"], 0.0)
                self.assertGreater(proj["estimated_wal_peak_mb"], 0.0)
                self.assertGreater(proj["estimated_backup_mb"], 0.0)
                self.assertGreater(proj["estimated_release_gzip_mb"], 0.0)

        # Scaling monotonicity check: 365 days > 30 days
        p30 = StorageGrowthModel.project_growth(PROFILE_PILOT, days=30)
        p365 = StorageGrowthModel.project_growth(PROFILE_PILOT, days=365)
        self.assertGreater(p365["estimated_db_mb"], p30["estimated_db_mb"])
        self.assertGreater(p365["total_observations"], p30["total_observations"])


if __name__ == "__main__":
    unittest.main()

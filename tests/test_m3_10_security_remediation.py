"""Security remediation test suite for Milestone M3.10 Independent Security Review.

Covers:
1. Priority 0: Retention policy fail-closed defaults (allow_destructive_pruning=False).
2. Priority 0: Requiring explicit authorized intent and non-empty operator authorization.
3. Priority 0: Transactional crash consistency and tombstone/deletion atomicity under fault injection.
4. Priority 1: Evidence authorization rejecting prefix matching and missing source_id fallbacks.
5. Priority 1: Differentiating hash-verified raw evidence, unauthenticated collectors, and unavailable raw bytes.
6. Priority 1: Multi-vector evidence binding rejecting mismatched vector-to-event relationships.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from anie.cross_vector_correlation import (
    CrossVectorCorrelator,
    VectorObservationSummary,
)
from anie.real_models import (
    DEFAULT_TRUSTED_COLLECTORS,
    CollectorIdentityPolicy,
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
    TrustedCollectorPolicy,
    is_authorized_collector_source,
)
from anie.real_publish import (
    publish_real,
    verify_real_release,
)
from anie.real_store import RealObservationStore
from anie.retention import (
    RetentionPolicy,
    safe_prune_retention,
    validate_operator_audit_id,
)


def _make_telemetry_event_and_obs(
    subject: str,
    ip: str = "93.184.216.34",
    kind: str = "dns_a",
    source_id: str = "first_party:doh:cloudflare",
    observed_at: str = "2026-11-21T10:00:00Z",
    raw_payload_override: bytes | None = None,
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_payload = raw_payload_override or f"wire_payload_{kind}_{subject}_{ip}_{observed_at}".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind=kind,
        subject=subject,
        observed_at=observed_at,
        target_endpoint=f"https://collector.example.net/{kind}",
        pinned_ip="1.1.1.1",
    )
    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity="first_party",
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
        kind=kind,
        observed_at=observed_at,
        values=(ip,),
        status="ok",
        source_id=source_id,
        method="dns" if kind.startswith("dns") else ("http" if kind.startswith("http") else "tls"),
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    return event, obs


class TestM310SecurityRemediation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.db_path = self.base_path / "security_audit.db"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    # --------------------------------------------------------------------------
    # Priority 0: Destructive Retention Default & Intent Authorization
    # --------------------------------------------------------------------------

    def test_priority_0_retention_policy_default_safe_no_deletion(self):
        """Verify that default RetentionPolicy has allow_destructive_pruning=False and deletes zero records."""
        policy = RetentionPolicy()
        self.assertFalse(policy.allow_destructive_pruning, "Default policy MUST be non-destructive (fail-closed)")

        # Ingest expired records (300 days old, well past 90-day / 180-day TTL)
        now_dt = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
        expired_time = (now_dt - timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%SZ")

        for i in range(5):
            ev, obs = _make_telemetry_event_and_obs(f"expired-{i}.org", observed_at=expired_time)
            self.store.insert_record(ev, obs)

        # Execute safe_prune_retention with default policy
        report = safe_prune_retention(self.store, policy=policy, now=now_dt)

        self.assertEqual(report.pruned_observations, 0, "Default pruning MUST NOT delete observations")
        self.assertEqual(report.pruned_events, 0, "Default pruning MUST NOT delete events")
        self.assertEqual(report.protected_observations_kept, 5)
        self.assertEqual(report.protected_events_kept, 5)

        # Database remains 100% intact
        self.assertEqual(len(self.store.all_observations()), 5)

    def test_priority_0_destructive_pruning_requires_explicit_authorization(self):
        """Verify that allow_destructive_pruning=True requires explicit, non-empty operator_audit_id."""
        # 1. Missing operator_audit_id
        policy_missing = RetentionPolicy(allow_destructive_pruning=True, operator_audit_id=None)
        with self.assertRaises(ValueError) as ctx:
            safe_prune_retention(self.store, policy=policy_missing)
        self.assertIn("explicit operator audit identity", str(ctx.exception))

        # 2. Empty string operator_audit_id
        policy_empty = RetentionPolicy(allow_destructive_pruning=True, operator_audit_id="")
        with self.assertRaises(ValueError) as ctx:
            safe_prune_retention(self.store, policy=policy_empty)
        self.assertIn("explicit operator audit identity", str(ctx.exception))

        # 3. Whitespace string operator_audit_id
        policy_whitespace = RetentionPolicy(allow_destructive_pruning=True, operator_audit_id="   ")
        with self.assertRaises(ValueError) as ctx:
            safe_prune_retention(self.store, policy=policy_whitespace)
        self.assertIn("explicit operator audit identity", str(ctx.exception))

        # 4. Backward-compatible operator_authorization alias accepted
        policy_compat = RetentionPolicy(allow_destructive_pruning=True, operator_authorization="ops-compat-user")
        self.assertEqual(policy_compat.get_operator_audit_id(), "ops-compat-user")

    def test_priority_0_operator_audit_id_validation_rejects_credentials_and_secrets(self):
        """Verify that operator_audit_id strictly rejects bearer tokens, passwords, and sensitive credentials."""
        sensitive_samples = [
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "bearer abc1234567890",
            "token secret_api_key_value",
            "secret top_secret_retention_password",
            "jwt:eyJhbGciOi...",
            "eyJh...",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "sk_live_1234567890abcdef",
            "pwd:SuperSecretPassword123",
            "operator with whitespace",
            "operator\ninjection",
        ]
        for sample in sensitive_samples:
            with self.assertRaises(ValueError) as ctx:
                validate_operator_audit_id(sample)
            self.assertTrue(
                "must not contain secret tokens" in str(ctx.exception)
                or "whitespace" in str(ctx.exception)
                or "invalid operator_audit_id" in str(ctx.exception),
                f"Failed to reject sensitive sample: {sample}",
            )

        # Valid clean operator identifiers must pass
        valid_samples = [
            "operator:alice",
            "ops-retention-runner",
            "sys:cron_job_1",
            "admin@anie.local",
            "ops/cluster-01",
        ]
        for sample in valid_samples:
            self.assertEqual(validate_operator_audit_id(sample), sample)

    def test_priority_0_transactional_rollback_validation_under_fault_injection(self):
        """Verify transactional rollback validation under SQLite error injection: aborting row deletion preserves database state and records zero partial tombstones."""
        now_dt = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
        expired_time = (now_dt - timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%SZ")

        ev, obs = _make_telemetry_event_and_obs("atomic-target.org", observed_at=expired_time)
        self.store.insert_record(ev, obs)

        policy = RetentionPolicy(
            observation_ttl_days=1,
            event_ttl_days=1,
            allow_destructive_pruning=True,
            operator_audit_id="operator:fault_injection_test",
        )

        # Inject failure by adding a trigger on real_observations that forbids DELETE
        with self.store._connect() as conn:
            conn.execute("""
                CREATE TRIGGER test_abort_deletion
                BEFORE DELETE ON real_observations
                BEGIN
                    SELECT RAISE(ABORT, 'Fault injection: simulated crash during deletion');
                END;
            """)

        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            safe_prune_retention(self.store, policy=policy, now=now_dt)
        self.assertIn("simulated crash during deletion", str(ctx.exception))

        # Verify TRANSACTIONAL ROLLBACK VALIDATION:
        # Neither records were deleted, NOR were partial tombstones committed
        with self.store._connect() as conn:
            obs_count = conn.execute("SELECT COUNT(*) FROM real_observations").fetchone()[0]
            evt_count = conn.execute("SELECT COUNT(*) FROM real_events").fetchone()[0]
            tomb_count = conn.execute("SELECT COUNT(*) FROM retention_tombstone_ledger").fetchone()[0]

            self.assertEqual(obs_count, 1, "Observation must remain intact after aborted prune")
            self.assertEqual(evt_count, 1, "Event must remain intact after aborted prune")
            self.assertEqual(tomb_count, 0, "Zero partial tombstones must exist after rollback")

    # --------------------------------------------------------------------------
    # Priority 1: Evidence Authorization & Fallback Rejection
    # --------------------------------------------------------------------------

    def test_priority_1_evidence_authorization_rejects_untrusted_collector(self):
        """Verify that unknown/untrusted collectors fail authorization even if prefix matches an arbitrary pattern."""
        custom_policy = TrustedCollectorPolicy(
            trusted_collector_ids=frozenset({"first_party:doh:cloudflare"}),
            custom_allowed_collectors=frozenset(),
        )

        # Source not in trusted_collector_ids
        ev, obs = _make_telemetry_event_and_obs("untrusted-source.org", source_id="first_party:rogue:sensor")
        self.store.insert_record(ev, obs)

        res = self.store.verify_evidence_authoritativeness(ev.raw_sha256, collector_policy=custom_policy)
        self.assertFalse(res["is_authoritative"])
        self.assertEqual(res["status"], "UNAUTHENTICATED_COLLECTOR")
        self.assertIn("not an authorized collector under trusted policy", res["reason"])

    def test_priority_1_evidence_authorization_rejects_missing_source_id(self):
        """Verify that records with missing/empty source_id fail closed (no permissive first_party fallback)."""
        ev, obs = _make_telemetry_event_and_obs("missing-source.org", source_id="first_party:doh:cloudflare")
        self.store.insert_record(ev, obs)

        # Strip source_id from event payload directly in SQLite
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE real_events SET payload = json_remove(payload, '$.source_id') WHERE event_id = ?",
                (ev.event_id,),
            )

        res = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertFalse(res["is_authoritative"])
        self.assertEqual(res["status"], "MISSING_COLLECTOR_IDENTITY")
        self.assertIn("fallback to first_party is prohibited", res["reason"])

    def test_priority_1_differentiates_raw_bytes_unavailable_vs_corrupt(self):
        """Verify explicit differentiation between verified raw bytes, unavailable raw bytes, and corrupt payload bytes."""
        ev, obs = _make_telemetry_event_and_obs("differentiation.org", source_id="first_party:doh:cloudflare")
        self.store.insert_record(ev, obs)

        # 1. Authentic record with verified raw payload bytes
        res_auth = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertTrue(res_auth["is_authoritative"])
        self.assertEqual(res_auth["status"], "AUTHORITATIVE_VERIFIED")
        self.assertEqual(res_auth["evidence_quality"], "RAW_PAYLOAD_HASH_VERIFIED")

        # 2. Unavailable raw payload bytes (raw_payload set to NULL in DB)
        with self.store._connect() as conn:
            conn.execute("UPDATE real_events SET raw_payload = NULL WHERE event_id = ?", (ev.event_id,))

        # Under default policy (require_retained_raw_payload=True) -> Fails closed
        res_unavail = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertFalse(res_unavail["is_authoritative"])
        self.assertEqual(res_unavail["status"], "EVIDENCE_RAW_BYTES_UNAVAILABLE")
        self.assertEqual(res_unavail["evidence_quality"], "EVIDENCE_RAW_BYTES_UNAVAILABLE")

        # Under legacy metadata-only policy (require_retained_raw_payload=False)
        legacy_policy = TrustedCollectorPolicy(require_retained_raw_payload=False)
        res_legacy = self.store.verify_evidence_authoritativeness(ev.raw_sha256, collector_policy=legacy_policy)
        self.assertTrue(res_legacy["is_authoritative"])
        self.assertEqual(res_legacy["status"], "AUTHORITATIVE_METADATA_ONLY")
        self.assertEqual(res_legacy["evidence_quality"], "EVIDENCE_RAW_BYTES_UNAVAILABLE")

        # 3. Corrupt / Tampered raw payload bytes
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE real_events SET raw_payload = ? WHERE event_id = ?",
                (b"tampered_bitflipped_bytes", ev.event_id),
            )
        res_corrupt = self.store.verify_evidence_authoritativeness(ev.raw_sha256)
        self.assertFalse(res_corrupt["is_authoritative"])
        self.assertEqual(res_corrupt["status"], "CORRUPT_PAYLOAD_DIGEST_MISMATCH")

    # --------------------------------------------------------------------------
    # Priority 1: Multi-Vector Evidence Binding
    # --------------------------------------------------------------------------

    def test_priority_1_correlator_rejects_mismatched_vector_evidence(self):
        """Verify that CrossVectorCorrelator rejects vector summaries referencing mismatched evidence kinds."""
        domain = "mismatch-test.com"
        # Create a DNS event (kind="dns_a")
        ev_dns, obs_dns = _make_telemetry_event_and_obs(domain, kind="dns_a", source_id="first_party:doh:cloudflare")
        self.store.insert_record(ev_dns, obs_dns)

        correlator = CrossVectorCorrelator(self.store)

        # Attempt to bind HTTP vector to DNS evidence event
        with self.assertRaises(ValueError) as ctx:
            correlator.correlate_records(
                domain=domain,
                vectors={
                    "dns": VectorObservationSummary(
                        vector="dns",
                        observed_at="2026-11-21T10:00:00Z",
                        evidence_id=ev_dns.event_id,
                        evidence_hash=ev_dns.raw_sha256,
                        values=["93.184.216.34"],
                    ),
                    "http": VectorObservationSummary(
                        vector="http",
                        observed_at="2026-11-21T10:01:00Z",
                        evidence_id=ev_dns.event_id,       # MISMATCH: DNS event used for HTTP
                        evidence_hash=ev_dns.raw_sha256,
                        values=["cloudflare"],
                    ),
                },
            )
        self.assertIn("Mismatched vector evidence: vector 'http' cannot bind to evidence of kind 'dns_a'", str(ctx.exception))

    def test_priority_1_release_verifier_rejects_mismatched_vector_evidence(self):
        """Verify that verify_real_release fails closed if findings partition contains mismatched vector evidence."""
        release_path = self.base_path / "release_mismatch"
        domain = "release-mismatch.org"

        # Create authentic DNS and HTTP events
        ev_dns, obs_dns = _make_telemetry_event_and_obs(domain, kind="dns_a", source_id="first_party:doh:cloudflare")
        ev_http, obs_http = _make_telemetry_event_and_obs(domain, kind="http_metadata", source_id="first_party:http:direct")
        self.store.insert_record(ev_dns, obs_dns)
        self.store.insert_record(ev_http, obs_http)

        # Correlate authentic finding
        correlator = CrossVectorCorrelator(self.store)
        findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev_dns.event_id,
                    evidence_hash=ev_dns.raw_sha256,
                    values=["93.184.216.34"],
                ),
                "http": VectorObservationSummary(
                    vector="http",
                    observed_at="2026-11-21T10:01:00Z",
                    evidence_id=ev_http.event_id,
                    evidence_hash=ev_http.raw_sha256,
                    values=["cloudflare"],
                ),
            },
        )
        self.store.insert_cross_vector_finding(findings[0])

        # Publish release candidate
        publish_real(self.store, output_dir=release_path, as_of="2026-11-21T12:00:00Z", include_findings=True)

        # Candidate is valid initially
        cand = verify_real_release(release_path, integrity_only=True)
        self.assertTrue(cand["evidence_integrity_valid"])

        # Tamper findings partition to replace HTTP evidence hash with DNS evidence hash
        findings_gz = release_path / "real_findings.jsonl.gz"
        with gzip.open(findings_gz, "rt", encoding="utf-8") as f_in:
            data = json.loads(f_in.readline())
        data["vectors"]["http"]["evidence_hash"] = ev_dns.raw_sha256
        data["vectors"]["http"]["evidence_id"] = ev_dns.event_id

        # Recompress tampered partition and update manifest file hash
        tampered_bytes = json.dumps(data).encode("utf-8") + b"\n"
        with gzip.open(findings_gz, "wb") as f_out:
            f_out.write(tampered_bytes)
        new_hash = hashlib.sha256(findings_gz.read_bytes()).hexdigest()

        manifest_path = release_path / "manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        for f_entry in manifest_data["files"]:
            if f_entry["file"] == "real_findings.jsonl.gz":
                f_entry["sha256"] = new_hash
                f_entry["bytes"] = len(findings_gz.read_bytes())
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        # Now verify_real_release MUST fail with mismatched evidence kind
        with self.assertRaises(ValueError) as ctx:
            verify_real_release(release_path, integrity_only=True)
        self.assertIn("references mismatched evidence", str(ctx.exception))
        self.assertIn("of kind 'dns_a'", str(ctx.exception))

    def test_priority_1_release_verifier_mandatory_vector_evidence_resolution(self):
        """Verify that verify_real_release fails closed on missing evidence_id, missing evidence_hash, unknown IDs/hashes, or conflicting ID/hash pairs."""
        release_path = self.base_path / "mandatory_evidence_test"
        domain = "mandatory-ev.org"

        ev_dns, obs_dns = _make_telemetry_event_and_obs(domain, kind="dns_a", source_id="first_party:doh:cloudflare")
        ev_http, obs_http = _make_telemetry_event_and_obs(domain, kind="http_metadata", source_id="first_party:http:direct")
        self.store.insert_record(ev_dns, obs_dns)
        self.store.insert_record(ev_http, obs_http)

        correlator = CrossVectorCorrelator(self.store)
        findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev_dns.event_id,
                    evidence_hash=ev_dns.raw_sha256,
                    values=["93.184.216.34"],
                ),
                "http": VectorObservationSummary(
                    vector="http",
                    observed_at="2026-11-21T10:01:00Z",
                    evidence_id=ev_http.event_id,
                    evidence_hash=ev_http.raw_sha256,
                    values=["cloudflare"],
                ),
            },
        )
        self.store.insert_cross_vector_finding(findings[0])
        publish_real(self.store, output_dir=release_path, as_of="2026-11-21T12:00:00Z", include_findings=True)

        findings_gz = release_path / "real_findings.jsonl.gz"
        with gzip.open(findings_gz, "rt", encoding="utf-8") as f_in:
            base_finding = json.loads(f_in.readline())

        def _rewrite_findings_and_verify(mutator_fn):
            import copy
            data = copy.deepcopy(base_finding)
            mutator_fn(data)
            tampered_bytes = json.dumps(data).encode("utf-8") + b"\n"
            with gzip.open(findings_gz, "wb") as f_out:
                f_out.write(tampered_bytes)
            new_hash = hashlib.sha256(findings_gz.read_bytes()).hexdigest()

            manifest_path = release_path / "manifest.json"
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            for f_entry in manifest_data["files"]:
                if f_entry["file"] == "real_findings.jsonl.gz":
                    f_entry["sha256"] = new_hash
                    f_entry["bytes"] = len(findings_gz.read_bytes())
            manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
            return verify_real_release(release_path, integrity_only=True)

        # 1. Missing evidence_id
        def mut_missing_id(d):
            d["vectors"]["dns"]["evidence_id"] = ""
        with self.assertRaises(ValueError) as ctx:
            _rewrite_findings_and_verify(mut_missing_id)
        self.assertIn("missing mandatory evidence_id", str(ctx.exception))

        # 2. Missing evidence_hash
        def mut_missing_hash(d):
            d["vectors"]["dns"]["evidence_hash"] = ""
        with self.assertRaises(ValueError) as ctx:
            _rewrite_findings_and_verify(mut_missing_hash)
        self.assertIn("missing mandatory evidence_hash", str(ctx.exception))

        # 3. Unknown event_id
        def mut_unknown_id(d):
            d["vectors"]["dns"]["evidence_id"] = "event_unknown_does_not_exist"
        with self.assertRaises(ValueError) as ctx:
            _rewrite_findings_and_verify(mut_unknown_id)
        self.assertIn("references unknown event_id", str(ctx.exception))

        # 4. Unknown evidence_hash
        def mut_unknown_hash(d):
            d["vectors"]["dns"]["evidence_hash"] = "0" * 64
        with self.assertRaises(ValueError) as ctx:
            _rewrite_findings_and_verify(mut_unknown_hash)
        self.assertIn("references unknown evidence_hash", str(ctx.exception))

        # 5. Conflicting ID/hash pair (event_id exists, but evidence_hash is set to a different valid event's hash)
        def mut_conflicting_pair(d):
            d["vectors"]["dns"]["evidence_hash"] = ev_http.raw_sha256  # valid hash in release, but belongs to ev_http, not ev_dns
        with self.assertRaises(ValueError) as ctx:
            _rewrite_findings_and_verify(mut_conflicting_pair)
        self.assertIn("Conflicting evidence ID/hash pair", str(ctx.exception))

    def test_priority_1_collector_identity_policy_clarification(self):
        """Verify CollectorIdentityPolicy functions as an identity allowlist and maintains backward compatibility with TrustedCollectorPolicy."""
        self.assertIs(TrustedCollectorPolicy, CollectorIdentityPolicy)

        policy = CollectorIdentityPolicy(trusted_collector_ids=frozenset({"first_party:doh:cloudflare"}))
        self.assertTrue(policy.is_trusted_collector("first_party:doh:cloudflare"))
        self.assertFalse(policy.is_trusted_collector("first_party:unlisted:probe"))
        self.assertFalse(policy.is_trusted_collector("synthetic:sensor"))
        self.assertFalse(policy.is_trusted_collector(None))


if __name__ == "__main__":
    unittest.main()

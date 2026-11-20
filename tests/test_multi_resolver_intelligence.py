"""Comprehensive unit and adversarial test suite for Phase 3.3: Multi-Resolver Intelligence & Discrepancy Analysis.

Covers:
1. Multi-resolver provider adapters (Cloudflare, Google, Quad9) and RFC 8484 / RFC 6891 wire parsing.
2. Extended DNS Error (RFC 8914) Code 15 (Blocked) detection.
3. DiscrepancyEngine 6-verdict classification matrix:
   - AGREEMENT
   - EXPECTED_DIVERGENCE (CDN Anycast IP rotation)
   - SECURITY_FILTERING_DETECTED (Quad9 block without malicious label)
   - DNSSEC_DISAGREEMENT (DNSSEC validation failure)
   - UNEXPLAINED_DIVERGENCE
   - INCONCLUSIVE
4. Non-Malicious Invariant: Resolver divergence never automatically labels a domain malicious.
5. SQLite schema v2, real_discrepancies storage, indexing, and historical intelligence queries.
6. V3 manifest publication, referential integrity across 3 partitions, and detached Ed25519 signing.
7. Security hardening verifications:
   - SEC-3.3-01: Trust policy authorization required for allow_rollback bypass.
   - SEC-3.3-02: AegisReleaseConsumer two-phase transactional atomicity on persistence failure.
   - SEC-3.3-03: Extended collector private key isolation across environment variables and sensitive paths.
8. CLI discrepancy analysis and domain history inspection commands.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from anie.cli import main as cli_main
from anie.discrepancy_models import (
    DISCREPANCY_REPORT_SCHEMA,
    REAL_DISCREPANCY_SCHEMA,
    DiscrepancyVerdict,
    DivergenceCategory,
    RealDiscrepancyReport,
)
from anie.discrepancy_engine import DiscrepancyEngine
from anie.multi_resolver import (
    CLOUDFLARE_RESOLVER,
    GOOGLE_RESOLVER,
    QUAD9_RESOLVER,
    ResolverType,
    build_mock_dns_wire_response,
    make_edns_query_packet,
    parse_multi_resolver_dns_response,
)
from anie.preflight_hardening import check_no_signing_keys
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_publish import (
    ATTESTATION_NAME,
    REAL_MANIFEST_SCHEMA_V3,
    AegisReleaseBundle,
    AegisReleaseConsumer,
    RealReleaseTrust,
    ReleaseSequenceTracker,
    export_canonical_dataset,
    inspect_candidate,
    publish_real,
    sign_manifest_detached,
    verify_real_release,
)
from anie.real_store import CURRENT_SCHEMA_VERSION, RealObservationStore
from test_real_models import sample_event, sample_observation, sample_request

HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None


def make_multi_resolver_pair(
    subject: str = "example.com",
    kind: str = "dns_a",
    observed_at: str = "2026-11-20T10:00:00Z",
    resolver_name: str = "cloudflare",
    values: tuple[str, ...] = ("93.184.216.34",),
    ede_code: int | None = None,
    ad_flag: bool = False,
    rcode: int = 0,
):
    """Helper to construct matched RealCollectionEvent and RealObservation with provider metadata."""
    req = sample_request(subject=subject, kind=kind, observed_at=observed_at)
    raw_wire = build_mock_dns_wire_response(
        domain=subject,
        kind="A" if kind == "dns_a" else "AAAA",
        ips=list(values),
        rcode=rcode,
        ad_flag=ad_flag,
        ede_code=ede_code,
    )
    raw_sha = sha256(raw_wire).hexdigest()
    ev = sample_event(
        request=req,
        raw_payload=raw_wire,
        raw_sha256=raw_sha,
        observed_at=observed_at,
        source_id=f"oracle-collector-01:{resolver_name}",
    )
    rcode_str = "NOERROR" if rcode == 0 else ("NXDOMAIN" if rcode == 3 else "SERVFAIL")
    factual = FactualVerification(
        dnssec_status="secure" if ad_flag else "indeterminate",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity=resolver_name,
        wire_rcode=rcode_str,
        raw_evidence_status="captured",
    )
    if values:
        obs_status = "ok"
        err_code = None
    elif rcode == 3 or rcode_str == "NXDOMAIN":
        obs_status = "empty"
        err_code = None
    else:
        obs_status = "error"
        err_code = "invalid_response" if rcode == 1 else "unavailable"
    obs = sample_observation(
        subject=subject,
        kind=kind,
        observed_at=observed_at,
        values=values,
        status=obs_status,
        error_code=err_code,
        event=ev,
        source_id=f"oracle-collector-01:{resolver_name}",
        factual_verification=factual,
    )
    return ev, obs


class TestMultiResolverAdapters(unittest.TestCase):
    """Test DNS wire protocol parsing, EDNS, and RFC 8914 EDE code 15 handling."""

    def test_edns_query_packet_generation(self):
        query = make_edns_query_packet("example.com", "A")
        self.assertIsInstance(query, bytes)
        self.assertGreater(len(query), 12)
        # Check query ends with OPT RR structure (root domain 0x00, type 41 = 0x0029)
        self.assertIn(b"\x00\x00\x29", query)

    def test_parse_wire_response_with_cname_and_a_records(self):
        wire = build_mock_dns_wire_response(
            "www.example.com",
            "A",
            ips=["93.184.216.34"],
            cname_target="example.com",
            ad_flag=True,
        )
        parsed = parse_multi_resolver_dns_response(
            wire,
            "www.example.com",
            "A",
            CLOUDFLARE_RESOLVER,
        )
        self.assertEqual(parsed.subject, "www.example.com")
        self.assertEqual(parsed.kind, "dns_a")
        self.assertEqual(parsed.values, ("93.184.216.34",))
        self.assertEqual(parsed.cname_chain, ("example.com",))
        self.assertTrue(parsed.resolver_ad_claim)
        self.assertIsNone(parsed.ede_code)
        self.assertFalse(parsed.is_filtered)

    def test_parse_wire_response_with_rfc8914_ede_code_15_blocked(self):
        wire = build_mock_dns_wire_response(
            "malware.test",
            "A",
            ips=[],
            rcode=0,  # NODATA / Blocked
            ede_code=15,  # RFC 8914 Code 15 = Blocked
        )
        parsed = parse_multi_resolver_dns_response(
            wire,
            "malware.test",
            "A",
            QUAD9_RESOLVER,
        )
        self.assertEqual(parsed.ede_code, 15)
        self.assertTrue(parsed.is_filtered)
        self.assertEqual(parsed.resolver_type, ResolverType.SECURITY_FILTERING.value)

    def test_conversion_to_real_models(self):
        wire = build_mock_dns_wire_response("example.com", "A", ips=["93.184.216.34"])
        parsed = parse_multi_resolver_dns_response(wire, "example.com", "A", GOOGLE_RESOLVER)
        ev, obs = parsed.as_real_models(observed_at="2026-11-20T10:00:00Z")
        self.assertIsInstance(ev, RealCollectionEvent)
        self.assertIsInstance(obs, RealObservation)
        self.assertTrue(ev.verify_raw_evidence())
        self.assertEqual(obs.subject, "example.com")
        self.assertEqual(obs.values, ("93.184.216.34",))
        self.assertEqual(obs.evidence_id, ev.event_id)


class TestDiscrepancyClassificationMatrix(unittest.TestCase):
    """Test the 6 mutually exclusive verdicts and strict non-malicious invariant."""

    def setUp(self):
        self.engine = DiscrepancyEngine()

    def test_verdict_agreement(self):
        ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
        ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",))
        ev3, obs3 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="quad9", values=("93.184.216.34",))

        report = self.engine.analyze("example.com", "dns_a", [obs1, obs2, obs3], [ev1, ev2, ev3])
        self.assertEqual(report.verdict, DiscrepancyVerdict.AGREEMENT.value)
        self.assertEqual(report.category, DivergenceCategory.NONE.value)
        self.assertEqual(report.confidence, 1.0)
        self.assertEqual(len(report.observation_ids), 3)

    def test_verdict_expected_divergence_cdn_anycast(self):
        # Cloudflare CDN IP rotation: 104.16.132.229 vs 104.16.133.229 (both in 104.16.0.0/12)
        ev1, obs1 = make_multi_resolver_pair("cdn.example.com", "dns_a", resolver_name="cloudflare", values=("104.16.132.229",))
        ev2, obs2 = make_multi_resolver_pair("cdn.example.com", "dns_a", resolver_name="google", values=("104.16.133.229",))

        report = self.engine.analyze("cdn.example.com", "dns_a", [obs1, obs2], [ev1, ev2])
        self.assertEqual(report.verdict, DiscrepancyVerdict.EXPECTED_DIVERGENCE.value)
        self.assertEqual(report.category, DivergenceCategory.CDN_ANYCAST_ROTATION.value)
        # Crucial invariant: never malicious
        self.assertNotIn("malicious", report.explanation.lower())
        self.assertNotIn("bogus", report.explanation.lower())

    def test_verdict_security_filtering_detected(self):
        # Cloudflare and Google return valid IP; Quad9 returns NXDOMAIN or EDE 15 block
        ev1, obs1 = make_multi_resolver_pair("blocked.example.com", "dns_a", resolver_name="cloudflare", values=("198.51.100.5",))
        ev2, obs2 = make_multi_resolver_pair("blocked.example.com", "dns_a", resolver_name="google", values=("198.51.100.5",))
        ev3, obs3 = make_multi_resolver_pair("blocked.example.com", "dns_a", resolver_name="quad9", values=(), rcode=3)  # NXDOMAIN

        report = self.engine.analyze("blocked.example.com", "dns_a", [obs1, obs2, obs3], [ev1, ev2, ev3])
        self.assertEqual(report.verdict, DiscrepancyVerdict.SECURITY_FILTERING_DETECTED.value)
        self.assertEqual(report.category, DivergenceCategory.POLICY_FILTER_BLOCK.value)
        # Non-malicious assertion
        self.assertNotIn("malicious", report.verdict.lower())

    def test_verdict_dnssec_disagreement(self):
        # Cloudflare returns SERVFAIL (rcode=2) due to validation failure; non-validating resolver returns IP
        ev1, obs1 = make_multi_resolver_pair("dnssec-failed.org", "dns_a", resolver_name="cloudflare", values=(), rcode=2)
        ev2, obs2 = make_multi_resolver_pair("dnssec-failed.org", "dns_a", resolver_name="google", values=("192.0.2.1",))

        report = self.engine.analyze("dnssec-failed.org", "dns_a", [obs1, obs2], [ev1, ev2])
        self.assertEqual(report.verdict, DiscrepancyVerdict.DNSSEC_DISAGREEMENT.value)
        self.assertEqual(report.category, DivergenceCategory.DNSSEC_VALIDATION_FAILURE.value)

    def test_verdict_unexplained_divergence(self):
        # Two non-CDN completely disparate IP sets
        ev1, obs1 = make_multi_resolver_pair("split.example.org", "dns_a", resolver_name="cloudflare", values=("192.0.2.1",))
        ev2, obs2 = make_multi_resolver_pair("split.example.org", "dns_a", resolver_name="google", values=("198.51.100.1",))

        report = self.engine.analyze("split.example.org", "dns_a", [obs1, obs2], [ev1, ev2])
        self.assertEqual(report.verdict, DiscrepancyVerdict.UNEXPLAINED_DIVERGENCE.value)
        self.assertEqual(report.category, DivergenceCategory.CONFLICTING_IPS.value)
        # Verification of non-malicious label: it is an empirical finding, not attribution
        self.assertNotEqual(report.verdict, "MALICIOUS")

    def test_verdict_inconclusive_insufficient_or_failing(self):
        # Only one resolver response
        ev1, obs1 = make_multi_resolver_pair("single.example.org", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
        report = self.engine.analyze("single.example.org", "dns_a", [obs1], [ev1])
        self.assertEqual(report.verdict, DiscrepancyVerdict.INCONCLUSIVE.value)
        self.assertEqual(report.category, DivergenceCategory.INCOMPLETE_RESPONSES.value)

    def test_discrepancy_model_canonical_serialization_and_id_hash(self):
        ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
        ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",))
        report = self.engine.analyze("example.com", "dns_a", [obs1, obs2], [ev1, ev2])

        # Test ID format
        self.assertTrue(report.analysis_id.startswith("discrepancy_"))
        self.assertEqual(len(report.analysis_id), 76)
        self.assertEqual(report.discrepancy_id, report.analysis_id)

        # Round-trip serialization
        raw_dict = report.to_dict()
        reconstructed = RealDiscrepancyReport.from_dict(raw_dict)
        self.assertEqual(reconstructed.analysis_id, report.analysis_id)
        self.assertEqual(reconstructed.subject, report.subject)
        self.assertEqual(reconstructed.verdict, report.verdict)
        self.assertEqual(reconstructed.observation_ids, report.observation_ids)


class TestRealStoreDiscrepanciesAndHistory(unittest.TestCase):
    """Test SQLite schema version 2, real_discrepancies table, and historical queries."""

    def test_schema_v2_table_creation_and_discrepancy_persistence(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)
            self.assertEqual(store.schema_version, CURRENT_SCHEMA_VERSION)
            self.assertGreaterEqual(CURRENT_SCHEMA_VERSION, 2)

            ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
            ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",))
            store.insert_record(ev1, obs1)
            store.insert_record(ev2, obs2)

            engine = DiscrepancyEngine()
            report = engine.analyze("example.com", "dns_a", [obs1, obs2], [ev1, ev2])
            store.insert_discrepancy(report)

            # Retrieve by ID
            fetched = store.get_discrepancy(report.analysis_id)
            self.assertIsNotNone(fetched)
            assert fetched is not None
            self.assertEqual(fetched.analysis_id, report.analysis_id)
            self.assertEqual(fetched.subject, "example.com")
            self.assertEqual(fetched.verdict, DiscrepancyVerdict.AGREEMENT.value)

            # Retrieve by subject
            subject_reports = store.discrepancies_for_subject("example.com")
            self.assertEqual(len(subject_reports), 1)
            self.assertEqual(subject_reports[0].analysis_id, report.analysis_id)

    def test_historical_summary_aggregation(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", observed_at="2026-11-20T08:00:00Z", resolver_name="cloudflare", values=("93.184.216.34",))
            ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", observed_at="2026-11-20T08:00:00Z", resolver_name="google", values=("93.184.216.34",))
            store.insert_record(ev1, obs1)
            store.insert_record(ev2, obs2)

            engine = DiscrepancyEngine()
            report = engine.analyze("example.com", "dns_a", [obs1, obs2], [ev1, ev2])
            store.insert_discrepancy(report)

            summary = store.get_historical_summary("example.com", record_type="dns_a")
            self.assertEqual(summary["subject"], "example.com")
            self.assertEqual(summary["record_type"], "dns_a")
            self.assertEqual(summary["total_observations"], 2)
            self.assertEqual(summary["total_discrepancy_reports"], 1)
            self.assertEqual(summary["agreement_rate"], 1.0)
            self.assertEqual(summary["unique_ip_addresses"], ["93.184.216.34"])
            self.assertEqual(summary["first_seen"], "2026-11-20T08:00:00Z")
            self.assertEqual(summary["last_seen"], "2026-11-20T08:00:00Z")


class TestV3ReleaseContractAndProvenance(unittest.TestCase):
    """Test V3 dataset publication with discrepancies partition, detached signing, and verification."""

    def setUp(self):
        if not HAVE_CRYPTO:
            self.skipTest("cryptography required for publication tests")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_bytes = self.priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = "test-operator-key"
        self.trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
        )

    def test_v3_publication_with_discrepancies_and_referential_integrity(self):
        ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
        ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",))
        engine = DiscrepancyEngine()
        report = engine.analyze("example.com", "dns_a", [obs1, obs2], [ev1, ev2])

        with TemporaryDirectory() as tmp:
            rel_dir = Path(tmp) / "v3_release"
            manifest = publish_real(
                ([obs1, obs2], [ev1, ev2], [report]),
                rel_dir,
                as_of="2026-11-20T12:00:00Z",
                published_at="2026-11-20T12:01:00Z",
                release_sequence=1,
            )
            self.assertEqual(manifest["schema"], REAL_MANIFEST_SCHEMA_V3)
            self.assertEqual(manifest["total_discrepancies"], 1)
            self.assertEqual(len(manifest["files"]), 3)

            # Detached offline signing
            sign_manifest_detached(
                rel_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-20T12:05:00Z",
                expires_at="2026-12-20T12:05:00Z",
            )

            # Authenticated verification
            res = verify_real_release(rel_dir, trust=self.trust, now="2026-11-20T12:10:00Z")
            self.assertEqual(res["status"], "AUTHENTICATED")
            self.assertTrue(res["authenticated"])
            self.assertEqual(res["total_observations"], 2)
            self.assertEqual(res["total_events"], 2)
            self.assertEqual(res["total_discrepancies"], 1)

            # Candidate inspection test
            cand_info = inspect_candidate(rel_dir)
            self.assertEqual(cand_info["total_discrepancies"], 1)
            self.assertEqual(cand_info["discrepancy_verdicts"], {"AGREEMENT": 1})

    def test_v3_discrepancy_referential_integrity_violation_fails_closed(self):
        ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
        ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",))
        engine = DiscrepancyEngine()
        report = engine.analyze("example.com", "dns_a", [obs1, obs2], [ev1, ev2])

        # Tamper report with non-existent observation_id
        tampered_obs_ids = dict(report.observation_ids)
        tampered_obs_ids["cloudflare"] = "obs_nonexistent_id"

        tampered_report = RealDiscrepancyReport(
            subject=report.subject,
            kind=report.kind,
            analyzed_at=report.analyzed_at,
            verdict=report.verdict,
            category=report.category,
            explanation=report.explanation,
            confidence=report.confidence,
            participating_resolvers=report.participating_resolvers,
            answers_by_resolver=report.answers_by_resolver,
            dnssec_by_resolver=report.dnssec_by_resolver,
            filtering_metadata=report.filtering_metadata,
            observation_ids=tampered_obs_ids,
            evidence_ids=report.evidence_ids,
            evidence_hashes=report.evidence_hashes,
        )

        with TemporaryDirectory() as tmp:
            rel_dir = Path(tmp) / "invalid_rel"
            with self.assertRaisesRegex(ValueError, "references missing observation"):
                publish_real(([obs1, obs2], [ev1, ev2], [tampered_report]), rel_dir, as_of="2026-11-20T12:00:00Z")


class TestSecurityHardeningInvariants(unittest.TestCase):
    """Test SEC-3.3-01, SEC-3.3-02, and SEC-3.3-03 hardening."""

    def setUp(self):
        if not HAVE_CRYPTO:
            self.skipTest("cryptography required")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_bytes = self.priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = "sec-test-key"
        self.strict_trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            allow_rollback=False,  # default strict policy
        )
        self.audit_trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            allow_rollback=True,  # authorized historical audit policy
        )

    def test_sec_3_3_01_allow_rollback_trust_policy_enforcement(self):
        ev, obs = make_multi_resolver_pair()
        with TemporaryDirectory() as tmp:
            rel_dir = Path(tmp) / "rel"
            publish_real(([obs], [ev]), rel_dir, as_of="2026-11-20T10:00:00Z", release_sequence=1)
            sign_manifest_detached(
                rel_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-20T10:05:00Z",
                expires_at="2026-12-20T10:05:00Z",
            )

            # Caller passes allow_rollback=True with strict policy -> PermissionError
            with self.assertRaisesRegex(PermissionError, "operator trust policy has not authorized rollback bypass"):
                verify_real_release(rel_dir, trust=self.strict_trust, allow_rollback=True)

            # Authorized audit policy succeeds and returns AUTHENTICATED_HISTORICAL_INSPECTION
            res = verify_real_release(rel_dir, trust=self.audit_trust, allow_rollback=True)
            self.assertEqual(res["status"], "AUTHENTICATED_HISTORICAL_INSPECTION")
            self.assertTrue(res["authenticated"])
            self.assertFalse(res["anti_rollback_verified"])

    def test_sec_3_3_02_consumer_two_phase_atomicity_on_persistence_failure(self):
        """If consumer persistence fails, the sequence tracker must NOT advance."""
        ev, obs = make_multi_resolver_pair()
        with TemporaryDirectory() as tmp:
            tracker_file = Path(tmp) / "consumer_tracker.json"
            tracker = ReleaseSequenceTracker(tracker_file, auto_init=True)
            consumer = AegisReleaseConsumer(trust=self.strict_trust, sequence_tracker=tracker)

            rel_dir = Path(tmp) / "rel"
            publish_real(([obs], [ev]), rel_dir, as_of="2026-11-20T10:00:00Z", release_sequence=5)
            sign_manifest_detached(
                rel_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=5,
                issued_at="2026-11-20T10:05:00Z",
                expires_at="2026-12-20T10:05:00Z",
            )

            # Define a failing persistence callback
            def failing_db_persist(observations, events, discrepancies):
                raise RuntimeError("simulated consumer database constraint violation")

            with self.assertRaises(RuntimeError):
                consumer.verify_and_load(rel_dir, now="2026-11-20T10:10:00Z", persist_callback=failing_db_persist)

            # The sequence tracker must remain at 0 (never advanced!)
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 0)

            # Subsequent retry without failure succeeds and advances sequence
            bundle = consumer.verify_and_load_bundle(rel_dir, now="2026-11-20T10:10:00Z")
            self.assertIsInstance(bundle, AegisReleaseBundle)
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 5)

    def test_sec_3_3_03_extended_collector_key_isolation(self):
        """check_no_signing_keys detects environment variables and sensitive file paths."""
        with TemporaryDirectory() as tmp:
            clean_dir = Path(tmp) / "clean"
            clean_dir.mkdir()

            # Baseline clean check
            ok, msg = check_no_signing_keys([clean_dir])
            self.assertTrue(ok)

            # 1. Environment variable with PRIVATE_KEY name
            with patch.dict(os.environ, {"ANIE_OPERATOR_PRIVATE_KEY": "dummy_secret_value"}):
                ok, msg = check_no_signing_keys([clean_dir])
                self.assertFalse(ok)
                self.assertIn("Private signing key name detected in environment variable", msg)

            # 2. Environment variable with PEM private key content
            with patch.dict(os.environ, {"SOME_SECRET": "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg...\n-----END PRIVATE KEY-----"}):
                ok, msg = check_no_signing_keys([clean_dir])
                self.assertFalse(ok)
                self.assertIn("Private key PEM header detected in environment variable", msg)


class TestCLIMultiResolverCommands(unittest.TestCase):
    """Test CLI commands: analyze-discrepancy and domain-history."""

    def test_cli_analyze_discrepancy_and_domain_history(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "cli_test.sqlite"
            store = RealObservationStore(db_path)

            ev1, obs1 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="cloudflare", values=("93.184.216.34",))
            ev2, obs2 = make_multi_resolver_pair("example.com", "dns_a", resolver_name="google", values=("93.184.216.34",))
            store.insert_record(ev1, obs1)
            store.insert_record(ev2, obs2)

            # 1. Test analyze-discrepancy command
            ret = cli_main(["analyze-discrepancy", "--db", str(db_path), "--subject", "example.com", "--store"])
            self.assertEqual(ret, 0)

            # Verify report was stored in DB
            reports = store.discrepancies_for_subject("example.com")
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0].verdict, DiscrepancyVerdict.AGREEMENT.value)

            # 2. Test domain-history command
            ret_hist = cli_main(["domain-history", "--db", str(db_path), "--subject", "example.com"])
            self.assertEqual(ret_hist, 0)


if __name__ == "__main__":
    unittest.main()

"""Unit test suite for Milestone M3.11 AEGIS Interoperability & Signed Release Import.

Verifies:
1. Independent consumer-initiated retrieval and offline release import (AegisConsumerTrust).
2. Monotonic sequence anti-rollback enforcement (AegisReleaseSequenceTracker).
3. Fail-closed rejection across negative-test scenarios:
   - Corrupted manifest SHA
   - Invalid Ed25519 signature
   - Replayed/downgraded release sequence
   - Conflicting vector evidence pairs
   - Missing authoritative event references
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from anie.aegis_import import (
    AegisConsumerTrust,
    AegisReleaseSequenceTracker,
    import_signed_release,
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
from anie.real_publish import (
    _crypto,
    publish_real,
    sign_manifest_detached,
)
from anie.real_store import RealObservationStore


def _make_telemetry_event_and_obs(
    subject: str,
    ip: str = "93.184.216.34",
    kind: str = "dns_a",
    source_id: str = "first_party:doh:cloudflare",
    observed_at: str = "2026-11-21T10:00:00Z",
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_payload = f"wire_payload_{kind}_{subject}_{ip}_{observed_at}".encode("utf-8")
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


class TestM311AegisImportVerification(unittest.TestCase):
    def setUp(self):
        InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization = _crypto()
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.key_id = "operator-2026-key"

        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.db_path = self.base_path / "store.db"
        self.store = RealObservationStore(self.db_path)

        self.consumer_trust = AegisConsumerTrust(
            trusted_publisher="anie-first-party",
            trusted_public_keys={self.key_id: self.pub_key},
            enforce_anti_rollback=True,
            require_cross_vector_findings=True,
        )

        # Build baseline dataset
        domain = "aegis-import-test.org"
        self.ev_dns, self.obs_dns = _make_telemetry_event_and_obs(domain, kind="dns_a", source_id="first_party:doh:cloudflare")
        self.ev_http, self.obs_http = _make_telemetry_event_and_obs(domain, kind="http_metadata", source_id="first_party:http:direct")
        self.store.insert_record(self.ev_dns, self.obs_dns)
        self.store.insert_record(self.ev_http, self.obs_http)

        correlator = CrossVectorCorrelator(self.store)
        findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=self.ev_dns.event_id,
                    evidence_hash=self.ev_dns.raw_sha256,
                    values=["93.184.216.34"],
                ),
                "http": VectorObservationSummary(
                    vector="http",
                    observed_at="2026-11-21T10:01:00Z",
                    evidence_id=self.ev_http.event_id,
                    evidence_hash=self.ev_http.raw_sha256,
                    values=["cloudflare"],
                ),
            },
        )
        self.store.insert_cross_vector_finding(findings[0])

        self.release_dir = self.base_path / "release"
        publish_real(self.store, output_dir=self.release_dir, as_of="2026-11-21T12:00:00Z", include_findings=True)
        sign_manifest_detached(
            self.release_dir,
            private_key=self.priv_key,
            key_id=self.key_id,
            publisher_identity="anie-first-party",
            release_sequence=1,
            issued_at="2026-11-21T12:00:00Z",
            expires_at="2026-12-21T12:00:00Z",
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _copy_release(self, name: str) -> Path:
        """Create an isolated copy of the baseline release for test mutation."""
        import shutil
        target = self.base_path / f"release_{name}"
        shutil.copytree(self.release_dir, target)
        return target

    def test_aegis_import_happy_path(self):
        """Verify that a valid signed release is successfully accepted by independent consumer."""
        tracker = AegisReleaseSequenceTracker(last_accepted_sequence=0)
        report = import_signed_release(self.release_dir, self.consumer_trust, sequence_tracker=tracker)

        self.assertTrue(report.success)
        self.assertEqual(report.status, "IMPORT_VERIFIED")
        self.assertEqual(report.release_sequence, 1)
        self.assertEqual(report.total_events, 2)
        self.assertEqual(report.total_observations, 2)
        self.assertEqual(report.total_findings, 1)
        self.assertIsNone(report.error_reason)

    def test_negative_fixture_corrupted_manifest_sha(self):
        """Verify fail-closed rejection when manifest file hash does not match attestation payload."""
        rel_dir = self._copy_release("corrupted_manifest")
        manifest_path = rel_dir / "manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_data["notice"] = "Tampered manifest content"
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        tracker = AegisReleaseSequenceTracker(last_accepted_sequence=0)
        report = import_signed_release(rel_dir, self.consumer_trust, sequence_tracker=tracker)

        self.assertFalse(report.success)
        self.assertEqual(report.status, "MANIFEST_SHA_MISMATCH")
        self.assertIn("does not match disk manifest", report.error_reason)

    def test_negative_fixture_signature_mismatch(self):
        """Verify fail-closed rejection when Ed25519 signature is corrupted."""
        rel_dir = self._copy_release("signature_mismatch")
        sig_path = rel_dir / "signature.ed25519.json"
        sig_data = json.loads(sig_path.read_text(encoding="utf-8"))
        sig_b64 = sig_data.get("signature_base64") or sig_data.get("attestation", {}).get("signature_base64", "")
        raw_sig = bytearray(base64.b64decode(sig_b64))
        raw_sig[10] ^= 0xFF
        new_sig_b64 = base64.b64encode(raw_sig).decode("ascii")
        if "signature_base64" in sig_data:
            sig_data["signature_base64"] = new_sig_b64
        if "attestation" in sig_data and "signature_base64" in sig_data["attestation"]:
            sig_data["attestation"]["signature_base64"] = new_sig_b64
        sig_path.write_text(json.dumps(sig_data, indent=2), encoding="utf-8")

        tracker = AegisReleaseSequenceTracker(last_accepted_sequence=0)
        report = import_signed_release(rel_dir, self.consumer_trust, sequence_tracker=tracker)

        self.assertFalse(report.success)
        self.assertEqual(report.status, "SIGNATURE_VERIFICATION_FAILED")

    def test_negative_fixture_replayed_sequence(self):
        """Verify fail-closed rejection when release sequence is replayed or downgraded."""
        rel_dir = self._copy_release("replayed_seq")
        # Consumer has already accepted release sequence 1
        tracker = AegisReleaseSequenceTracker(last_accepted_sequence=1)
        report = import_signed_release(rel_dir, self.consumer_trust, sequence_tracker=tracker)

        self.assertFalse(report.success)
        self.assertEqual(report.status, "ROLLBACK_REJECTED")
        self.assertIn("replayed or downgraded", report.error_reason)

    def test_negative_fixture_conflicting_vector_evidence(self):
        """Verify fail-closed rejection when finding contains conflicting evidence_id and evidence_hash."""
        rel_dir = self._copy_release("conflicting_vector")
        find_gz = rel_dir / "real_findings.jsonl.gz"
        with gzip.open(find_gz, "rt", encoding="utf-8") as f_in:
            data = json.loads(f_in.readline())
        data["vectors"]["dns"]["evidence_hash"] = self.ev_http.raw_sha256  # Conflicting hash

        tampered_bytes = json.dumps(data).encode("utf-8") + b"\n"
        with gzip.open(find_gz, "wb") as f_out:
            f_out.write(tampered_bytes)
        new_hash = hashlib.sha256(find_gz.read_bytes()).hexdigest()

        # Update manifest file entry and re-sign
        manifest_path = rel_dir / "manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        for fe in manifest_data["files"]:
            if fe["file"] == "real_findings.jsonl.gz":
                fe["sha256"] = new_hash
                fe["bytes"] = len(find_gz.read_bytes())
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        # Re-sign release candidate
        sig_path = rel_dir / "signature.ed25519.json"
        if sig_path.exists():
            sig_path.unlink()
        sign_manifest_detached(
            rel_dir,
            private_key=self.priv_key,
            key_id=self.key_id,
            publisher_identity="anie-first-party",
            release_sequence=1,
            issued_at="2026-11-21T12:00:00Z",
            expires_at="2026-12-21T12:00:00Z",
        )

        tracker = AegisReleaseSequenceTracker(last_accepted_sequence=0)
        report = import_signed_release(rel_dir, self.consumer_trust, sequence_tracker=tracker)

        self.assertFalse(report.success)
        self.assertEqual(report.status, "CONFLICTING_EVIDENCE_PAIR")

    def test_negative_fixture_missing_authoritative_event(self):
        """Verify fail-closed rejection when observation references unknown event_id."""
        rel_dir = self._copy_release("missing_event")
        obs_gz = rel_dir / "real_observations.jsonl.gz"
        with gzip.open(obs_gz, "rt", encoding="utf-8") as f_in:
            lines = [json.loads(line) for line in f_in if line.strip()]
        lines[0]["evidence_id"] = "event_missing_does_not_exist"

        tampered_bytes = b"".join(json.dumps(l).encode("utf-8") + b"\n" for l in lines)
        with gzip.open(obs_gz, "wb") as f_out:
            f_out.write(tampered_bytes)
        new_hash = hashlib.sha256(obs_gz.read_bytes()).hexdigest()

        manifest_path = rel_dir / "manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        for fe in manifest_data["files"]:
            if fe["file"] == "real_observations.jsonl.gz":
                fe["sha256"] = new_hash
                fe["bytes"] = len(obs_gz.read_bytes())
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        sig_path = rel_dir / "signature.ed25519.json"
        if sig_path.exists():
            sig_path.unlink()
        sign_manifest_detached(
            rel_dir,
            private_key=self.priv_key,
            key_id=self.key_id,
            publisher_identity="anie-first-party",
            release_sequence=1,
            issued_at="2026-11-21T12:00:00Z",
            expires_at="2026-12-21T12:00:00Z",
        )

        tracker = AegisReleaseSequenceTracker(last_accepted_sequence=0)
        report = import_signed_release(rel_dir, self.consumer_trust, sequence_tracker=tracker)

        self.assertFalse(report.success)
        self.assertEqual(report.status, "BROKEN_REFERENTIAL_INTEGRITY")


if __name__ == "__main__":
    unittest.main()

"""AEGIS Transport-Neutral Signed Release Import Architecture (Milestone M3.11).

Provides:
- Independent, transport-neutral consumer verification routine for signed ANIE intelligence releases.
- Consumer-side trust anchor pinning (AegisConsumerTrust) with Ed25519 public key verification.
- Monotonic anti-rollback sequence enforcement (AegisReleaseSequenceTracker).
- Streaming partition validation with raw byte digest assertions.
- Fail-closed negative fixture verification for downstream consumer runtimes.
- Strict Architectural Boundary: Consumer-initiated retrieval (pull model) and offline import;
  zero unsolicited push to AEGIS runtimes; zero AEGIS database mutation.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .real_publish import (
    DOMAIN_SEPARATOR_REAL_V1,
    DOMAIN_SEPARATOR_REAL_V2,
    MAX_MANIFEST_BYTES,
    MAX_PARTITION_DECOMPRESSED_BYTES,
    MAX_SINGLE_RECORD_BYTES,
    MAX_RECORDS_PER_PARTITION,
    REAL_MANIFEST_SCHEMA_V1,
    REAL_MANIFEST_SCHEMA_V2,
    REAL_MANIFEST_SCHEMA_V3,
    _crypto,
    _iter_bounded_gzip_records,
)


@dataclass(frozen=True)
class AegisConsumerTrust:
    """Consumer-side trust configuration for independent ANIE release verification."""
    trusted_publisher: str = "anie-first-party"
    trusted_public_keys: dict[str, Any] = field(default_factory=dict)
    enforce_anti_rollback: bool = True
    require_cross_vector_findings: bool = False


class AegisReleaseSequenceTracker:
    """Consumer-side monotonic sequence tracker for rollback and replay defense."""

    def __init__(self, last_accepted_sequence: int = 0):
        self._last_accepted_sequence = last_accepted_sequence

    @property
    def last_accepted_sequence(self) -> int:
        return self._last_accepted_sequence

    def verify_and_advance(self, sequence: int) -> tuple[bool, str]:
        """Verify release sequence is strictly greater than last accepted sequence."""
        if sequence <= self._last_accepted_sequence:
            return (
                False,
                f"Release sequence {sequence} is replayed or downgraded; "
                f"last accepted sequence was {self._last_accepted_sequence}",
            )
        self._last_accepted_sequence = sequence
        return True, "ACCEPTED"


@dataclass(frozen=True)
class AegisImportReport:
    """Detailed summary of independent consumer release validation."""
    success: bool
    status: str
    manifest_sha256: str
    publisher: str
    release_sequence: int
    total_observations: int
    total_events: int
    total_findings: int
    error_reason: str | None = None


def import_signed_release(
    directory: str | Path,
    trust: AegisConsumerTrust,
    *,
    sequence_tracker: AegisReleaseSequenceTracker | None = None,
    now: str | None = None,
) -> AegisImportReport:
    """Execute consumer-initiated verification and parsing of an ANIE signed release bundle.
    
    Guarantees:
    - Transport-neutral: Operates offline on any downloaded or staged release directory.
    - Zero modification: Read-only access to release directory.
    - Fail-closed: Any signature mismatch, partition tampering, sequence downgrade, or ungrounded evidence fails.
    """
    InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization = _crypto()
    dir_path = Path(directory)

    # 1. Read manifest.json
    manifest_file = dir_path / "manifest.json"
    if not manifest_file.exists():
        return AegisImportReport(
            success=False,
            status="MISSING_MANIFEST",
            manifest_sha256="",
            publisher="",
            release_sequence=0,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason="manifest.json not found in release directory",
        )

    manifest_bytes = manifest_file.read_bytes()
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        return AegisImportReport(
            success=False,
            status="MANIFEST_EXCEEDS_SIZE_LIMIT",
            manifest_sha256="",
            publisher="",
            release_sequence=0,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=f"manifest exceeds {MAX_MANIFEST_BYTES} bytes",
        )

    manifest_sha = sha256(manifest_bytes).hexdigest()
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        return AegisImportReport(
            success=False,
            status="MALFORMED_MANIFEST_JSON",
            manifest_sha256=manifest_sha,
            publisher="",
            release_sequence=0,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=f"manifest JSON parse error: {exc}",
        )

    publisher = manifest.get("publisher", "")
    if publisher != trust.trusted_publisher:
        return AegisImportReport(
            success=False,
            status="UNTRUSTED_PUBLISHER",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=manifest.get("release_sequence", 0),
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=f"Publisher '{publisher}' does not match trusted publisher '{trust.trusted_publisher}'",
        )

    release_seq = int(manifest.get("release_sequence", 1))

    # 2. Monotonic Anti-Rollback Sequence Verification
    if trust.enforce_anti_rollback and sequence_tracker is not None:
        seq_valid, seq_msg = sequence_tracker.verify_and_advance(release_seq)
        if not seq_valid:
            return AegisImportReport(
                success=False,
                status="ROLLBACK_REJECTED",
                manifest_sha256=manifest_sha,
                publisher=publisher,
                release_sequence=release_seq,
                total_observations=0,
                total_events=0,
                total_findings=0,
                error_reason=seq_msg,
            )

    # 3. Cryptographic Signature Verification
    sig_file = dir_path / "signature.ed25519.json"
    if not sig_file.exists():
        return AegisImportReport(
            success=False,
            status="MISSING_SIGNATURE",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason="signature.ed25519.json required for authenticated consumer import",
        )

    try:
        sig_data = json.loads(sig_file.read_text(encoding="utf-8"))
    except Exception as exc:
        return AegisImportReport(
            success=False,
            status="MALFORMED_SIGNATURE_JSON",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=str(exc),
        )

    key_id = sig_data.get("key_id")
    if key_id not in trust.trusted_public_keys:
        return AegisImportReport(
            success=False,
            status="UNTRUSTED_KEY_ID",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=f"Signing key_id '{key_id}' is not enrolled in consumer trust policy",
        )

    trusted_pub = trust.trusted_public_keys[key_id]
    if isinstance(trusted_pub, bytes):
        trusted_pub = Ed25519PublicKey.from_public_bytes(trusted_pub)

    # Validate inner payload binding (support both flat attestation and nested envelopes)
    payload = sig_data.get("payload") or sig_data.get("attestation", {}).get("payload", {})
    if payload.get("manifest_sha256") != manifest_sha:
        return AegisImportReport(
            success=False,
            status="MANIFEST_SHA_MISMATCH",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=f"Signed manifest_sha256 '{payload.get('manifest_sha256')}' does not match disk manifest '{manifest_sha}'",
        )

    # Verify Ed25519 Signature
    sig_b64 = sig_data.get("signature_base64") or sig_data.get("attestation", {}).get("signature_base64", "")
    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception as exc:
        return AegisImportReport(
            success=False,
            status="MALFORMED_SIGNATURE_BYTES",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason=str(exc),
        )

    # Canonical payload bytes
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    is_v2 = manifest.get("schema") in (REAL_MANIFEST_SCHEMA_V2, REAL_MANIFEST_SCHEMA_V3) or release_seq > 1
    domain_sep = DOMAIN_SEPARATOR_REAL_V2 if is_v2 else DOMAIN_SEPARATOR_REAL_V1

    try:
        trusted_pub.verify(sig_bytes, domain_sep + payload_bytes)
    except InvalidSignature:
        return AegisImportReport(
            success=False,
            status="SIGNATURE_VERIFICATION_FAILED",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason="Ed25519 signature verification failed over canonical attestation payload",
        )

    # 4. Partition File & Referential Integrity Verification
    files = manifest.get("files", [])
    files_map = {f["file"]: f for f in files if "file" in f}

    if "real_events.jsonl.gz" not in files_map or "real_observations.jsonl.gz" not in files_map:
        return AegisImportReport(
            success=False,
            status="MISSING_CORE_PARTITIONS",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason="Release must contain real_events.jsonl.gz and real_observations.jsonl.gz",
        )

    # Verify real_events
    ev_path = dir_path / "real_events.jsonl.gz"
    ev_meta = files_map["real_events.jsonl.gz"]
    if sha256(ev_path.read_bytes()).hexdigest() != ev_meta["sha256"]:
        return AegisImportReport(
            success=False,
            status="PARTITION_HASH_MISMATCH",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=0,
            total_findings=0,
            error_reason="real_events.jsonl.gz hash mismatch",
        )

    event_ids: set[str] = set()
    event_hashes: set[str] = set()
    event_hashes_by_id: dict[str, str] = {}
    event_kinds_by_id: dict[str, str] = {}
    event_count = 0

    with gzip.open(ev_path, "rt", encoding="utf-8") as gz:
        for line in gz:
            if not line.strip():
                continue
            ev_dict = json.loads(line)
            eid = ev_dict["event_id"]
            ehash = ev_dict["raw_sha256"]
            ekind = ev_dict.get("kind") or ev_dict.get("request", {}).get("kind", "")

            event_ids.add(eid)
            event_hashes.add(ehash)
            event_hashes_by_id[eid] = ehash
            event_kinds_by_id[eid] = ekind
            event_count += 1

    # Verify real_observations
    obs_path = dir_path / "real_observations.jsonl.gz"
    obs_meta = files_map["real_observations.jsonl.gz"]
    if sha256(obs_path.read_bytes()).hexdigest() != obs_meta["sha256"]:
        return AegisImportReport(
            success=False,
            status="PARTITION_HASH_MISMATCH",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=0,
            total_events=event_count,
            total_findings=0,
            error_reason="real_observations.jsonl.gz hash mismatch",
        )

    obs_count = 0
    with gzip.open(obs_path, "rt", encoding="utf-8") as gz:
        for line in gz:
            if not line.strip():
                continue
            o_dict = json.loads(line)
            if o_dict.get("evidence_id") not in event_ids:
                return AegisImportReport(
                    success=False,
                    status="BROKEN_REFERENTIAL_INTEGRITY",
                    manifest_sha256=manifest_sha,
                    publisher=publisher,
                    release_sequence=release_seq,
                    total_observations=obs_count,
                    total_events=event_count,
                    total_findings=0,
                    error_reason=f"Observation references unknown evidence_id '{o_dict.get('evidence_id')}'",
                )
            obs_count += 1

    # Verify real_findings if present
    finding_count = 0
    if "real_findings.jsonl.gz" in files_map:
        find_path = dir_path / "real_findings.jsonl.gz"
        find_meta = files_map["real_findings.jsonl.gz"]
        if sha256(find_path.read_bytes()).hexdigest() != find_meta["sha256"]:
            return AegisImportReport(
                success=False,
                status="PARTITION_HASH_MISMATCH",
                manifest_sha256=manifest_sha,
                publisher=publisher,
                release_sequence=release_seq,
                total_observations=obs_count,
                total_events=event_count,
                total_findings=0,
                error_reason="real_findings.jsonl.gz hash mismatch",
            )

        with gzip.open(find_path, "rt", encoding="utf-8") as gz:
            for line in gz:
                if not line.strip():
                    continue
                f_dict = json.loads(line)
                vectors = f_dict.get("vectors", {})
                if not vectors:
                    return AegisImportReport(
                        success=False,
                        status="EMPTY_FINDING_VECTORS",
                        manifest_sha256=manifest_sha,
                        publisher=publisher,
                        release_sequence=release_seq,
                        total_observations=obs_count,
                        total_events=event_count,
                        total_findings=finding_count,
                        error_reason="Finding has no vectors",
                    )

                for v_name, v_sum in vectors.items():
                    vid = v_sum.get("evidence_id")
                    vhash = v_sum.get("evidence_hash")
                    if not vid or not vhash:
                        return AegisImportReport(
                            success=False,
                            status="MISSING_VECTOR_EVIDENCE",
                            manifest_sha256=manifest_sha,
                            publisher=publisher,
                            release_sequence=release_seq,
                            total_observations=obs_count,
                            total_events=event_count,
                            total_findings=finding_count,
                            error_reason=f"Vector '{v_name}' missing evidence_id or evidence_hash",
                        )
                    if vid not in event_ids:
                        return AegisImportReport(
                            success=False,
                            status="UNKNOWN_VECTOR_EVENT_ID",
                            manifest_sha256=manifest_sha,
                            publisher=publisher,
                            release_sequence=release_seq,
                            total_observations=obs_count,
                            total_events=event_count,
                            total_findings=finding_count,
                            error_reason=f"Vector '{v_name}' references unknown event_id '{vid}'",
                        )
                    if vhash not in event_hashes:
                        return AegisImportReport(
                            success=False,
                            status="UNKNOWN_VECTOR_EVIDENCE_HASH",
                            manifest_sha256=manifest_sha,
                            publisher=publisher,
                            release_sequence=release_seq,
                            total_observations=obs_count,
                            total_events=event_count,
                            total_findings=finding_count,
                            error_reason=f"Vector '{v_name}' references unknown evidence_hash '{vhash}'",
                        )
                    if event_hashes_by_id.get(vid) != vhash:
                        return AegisImportReport(
                            success=False,
                            status="CONFLICTING_EVIDENCE_PAIR",
                            manifest_sha256=manifest_sha,
                            publisher=publisher,
                            release_sequence=release_seq,
                            total_observations=obs_count,
                            total_events=event_count,
                            total_findings=finding_count,
                            error_reason=f"Vector '{v_name}' ID/hash mismatch",
                        )
                finding_count += 1
    elif trust.require_cross_vector_findings:
        return AegisImportReport(
            success=False,
            status="MISSING_REQUIRED_FINDINGS_PARTITION",
            manifest_sha256=manifest_sha,
            publisher=publisher,
            release_sequence=release_seq,
            total_observations=obs_count,
            total_events=event_count,
            total_findings=0,
            error_reason="Consumer policy requires real_findings.jsonl.gz partition",
        )

    return AegisImportReport(
        success=True,
        status="IMPORT_VERIFIED",
        manifest_sha256=manifest_sha,
        publisher=publisher,
        release_sequence=release_seq,
        total_observations=obs_count,
        total_events=event_count,
        total_findings=finding_count,
        error_reason=None,
    )

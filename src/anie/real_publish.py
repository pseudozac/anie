"""Deterministic publication, detached Ed25519 signing, and integrity verification

for ANIE first-party real-world intelligence datasets.

Part of ANIE Phase 2 PR 4 (Authenticated First-Party Intelligence Publication).

Security & Invariant Boundaries:
1. Strict Pipeline Isolation: Unconditionally rejects synthetic observations,
   synthetic methods, or synthetic source IDs.
2. Bounded & Reproducible Serialization: Uses canonical JSON formatting and
   reproducible gzip archives (mtime=0, compresslevel=9) to guarantee byte-for-byte
   reproducibility across independent publication builds.
3. Air-Gapped Detached Signing: The primary Ed25519 private key never resides on the
   collector VM (anie-collector-01). The collector produces an unsigned candidate
   release; detached signing takes place in an isolated operator environment.
4. Cryptographic Provenance Authentication: The Ed25519 signature authenticates the
   publisher's release integrity and sequence; it does not claim absolute external truth
   for third-party DNS endpoints.
5. Anti-Replay & Rollback Protection: Stateless signature verification alone cannot
   prevent replay of previously signed historical releases. Genuine rollback protection
   is enforced via monotonic sequences and persistent verifier high-water mark tracking.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Iterator
import uuid

from .observations import canonical_json, utc_iso
from .real_models import (
    REAL_EVENT_SCHEMA,
    REAL_OBSERVATION_SCHEMA,
    RealCollectionEvent,
    RealObservation,
)
from .real_store import RealObservationStore

# --- Schema & Identifier Constants ---
REAL_MANIFEST_SCHEMA = "anie.real-dataset-manifest.v1"
DATASET_TYPE_REAL = "first_party_intelligence"
REAL_SIGNATURE_SCHEMA = "anie.real-ed25519-attestation.v1"
REAL_PAYLOAD_SCHEMA = "anie.real-release-attestation.v1"
ATTESTATION_NAME = "signature.ed25519.json"
DOMAIN_SEPARATOR_REAL = b"ANIE-REAL-ED25519-RELEASE-V1\x00"

REAL_PARTITION_FILES = frozenset({"real_observations.jsonl.gz", "real_events.jsonl.gz"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# Maximum Resource & Decompression Bomb Protection Limits
MAX_MANIFEST_BYTES = 65536  # 64 KiB
MAX_ATTESTATION_BYTES = 16384  # 16 KiB
MAX_PARTITION_COMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MiB
MAX_PARTITION_DECOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MiB
MAX_RECORDS_PER_PARTITION = 100000
MAX_SINGLE_RECORD_BYTES = 500000  # 500 KiB


def _crypto():
    """Import cryptographic primitives only when signing or verifying signatures."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 release signing and signature verification requires cryptography: "
            "pip install 'anie-intelligence[signing]'"
        ) from exc
    return InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization


def _dt(value: str) -> datetime:
    """Parse UTC ISO string into timezone-aware datetime."""
    try:
        return datetime.fromisoformat(utc_iso(value).replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"invalid UTC timestamp: {value!r}") from exc


def key_fingerprint(public_key_raw: bytes) -> str:
    """Compute SHA-256 hex digest of raw 32-byte Ed25519 public key."""
    if not isinstance(public_key_raw, bytes) or len(public_key_raw) != 32:
        raise ValueError("expected a 32-byte raw Ed25519 public key")
    return sha256(public_key_raw).hexdigest()


def _public_key_raw(private_key: object) -> bytes:
    """Extract raw 32 bytes from an Ed25519PrivateKey instance."""
    _, Ed25519PrivateKey, _, serialization = _crypto()
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("expected an in-memory Ed25519PrivateKey instance")
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _write_deterministic_gzip(path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Write records to gzip archive with fixed metadata for byte-for-byte reproducibility."""
    payload = b"".join((canonical_json(r) + "\n").encode("utf-8") for r in records)
    if len(payload) > MAX_PARTITION_DECOMPRESSED_BYTES:
        raise ValueError(
            f"partition payload ({len(payload)} bytes) exceeds maximum bound "
            f"of {MAX_PARTITION_DECOMPRESSED_BYTES} bytes"
        )
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
            stream.write(payload)

    file_bytes = path.stat().st_size
    if file_bytes > MAX_PARTITION_COMPRESSED_BYTES:
        raise ValueError(
            f"compressed partition '{path.name}' ({file_bytes} bytes) exceeds limit "
            f"of {MAX_PARTITION_COMPRESSED_BYTES} bytes"
        )

    file_sha = sha256(path.read_bytes()).hexdigest()
    return {
        "file": path.name,
        "sha256": file_sha,
        "records": len(records),
        "bytes": file_bytes,
    }


def export_canonical_dataset(
    store: RealObservationStore,
    as_of: str,
    limit: int = MAX_RECORDS_PER_PARTITION,
) -> tuple[list[RealObservation], list[RealCollectionEvent]]:
    """Export a consistent SQLite snapshot of real observations and referenced events.
    
    Guarantees:
    - Observations ordered by (observed_at ASC, observation_id ASC).
    - Events ordered by (observed_at ASC, event_id ASC).
    - Referential integrity: all observation evidence_id references exist in events.
    - Raw evidence hashes verified for all exported events.
    - Rejects any synthetic record unconditionally.
    """
    as_of_iso = utc_iso(as_of)
    with store._connect() as conn:
        obs_rows = conn.execute(
            """
            SELECT payload FROM real_observations
            WHERE observed_at <= ?
            ORDER BY observed_at ASC, observation_id ASC
            LIMIT ?
            """,
            (as_of_iso, limit),
        ).fetchall()

    if not obs_rows:
        raise ValueError(f"no real observations found at or before as_of cutoff '{as_of_iso}'")

    observations: list[RealObservation] = []
    needed_evidence_ids: set[str] = set()

    for (obs_json,) in obs_rows:
        raw_obs = json.loads(obs_json)
        # Strict anti-contamination verification
        if raw_obs.get("synthetic") is not False:
            raise PermissionError("synthetic observation found in real database: publication aborted")
        if raw_obs.get("method") == "synthetic":
            raise PermissionError("synthetic collection method found in real database: publication aborted")
        if str(raw_obs.get("source_id", "")).startswith("synthetic:"):
            raise PermissionError("synthetic source_id found in real database: publication aborted")

        obs = RealObservation.from_dict(raw_obs)
        observations.append(obs)
        needed_evidence_ids.add(obs.evidence_id)

    # Fetch corresponding collection events
    events: list[RealCollectionEvent] = []
    with store._connect() as conn:
        ev_rows = conn.execute(
            """
            SELECT event_id, payload, raw_payload, raw_sha256, raw_evidence_status
            FROM real_events
            WHERE observed_at <= ?
            ORDER BY observed_at ASC, event_id ASC
            LIMIT ?
            """,
            (as_of_iso, limit),
        ).fetchall()

    for event_id, payload_json, raw_blob, raw_sha, status in ev_rows:
        store._verify_stored_raw_hash(event_id, raw_blob, raw_sha, status)
        ev_dict = json.loads(payload_json)
        if str(ev_dict.get("source_id", "")).startswith("synthetic:"):
            raise PermissionError("synthetic source_id found in real event: publication aborted")
        event = RealCollectionEvent.from_dict(ev_dict)
        if not event.verify_raw_evidence():
            raise ValueError(f"raw evidence verification failed for event '{event_id}'")
        events.append(event)

    # Referential integrity check
    event_ids = {e.event_id for e in events}
    missing_evidence = needed_evidence_ids - event_ids
    if missing_evidence:
        raise ValueError(
            f"broken referential integrity: observations reference {len(missing_evidence)} "
            f"missing collection events (sample: {sorted(missing_evidence)[:3]})"
        )

    return observations, events


def publish_real(
    store_or_data: RealObservationStore | tuple[list[RealObservation], list[RealCollectionEvent]],
    output_dir: str | Path,
    as_of: str,
    *,
    publisher_identity: str = "anie-first-party",
    release_sequence: int = 1,
    source_commit: str | None = None,
    limit: int = MAX_RECORDS_PER_PARTITION,
) -> dict[str, Any]:
    """Publish a deterministic, canonical real-world intelligence dataset.
    
    Creates unsigned candidate release artifacts with atomic generation.
    """
    output_path = Path(output_dir)
    if output_path.exists() and any(output_path.iterdir()):
        raise FileExistsError(
            f"output directory '{output_path}' must be empty; overwriting previous releases is prohibited"
        )

    if not isinstance(release_sequence, int) or release_sequence < 1:
        raise ValueError(f"release_sequence must be a positive integer >= 1: got {release_sequence}")

    as_of_iso = utc_iso(as_of)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    if isinstance(store_or_data, RealObservationStore):
        observations, events = export_canonical_dataset(store_or_data, as_of_iso, limit=limit)
    elif isinstance(store_or_data, tuple) and len(store_or_data) == 2:
        observations, events = store_or_data
    else:
        raise TypeError("store_or_data must be RealObservationStore or (observations, events) tuple")

    if not observations:
        raise ValueError("cannot publish empty observation dataset")
    if not events:
        raise ValueError("cannot publish empty event dataset")

    # Strict sorting and anti-contamination validation
    observations = sorted(observations, key=lambda o: (o.observed_at, o.observation_id))
    events = sorted(events, key=lambda e: (e.observed_at, e.event_id))

    for o in observations:
        if o.synthetic is not False or o.method == "synthetic" or o.source_id.startswith("synthetic:"):
            raise PermissionError("synthetic observation rejected by real-data publication engine")

    event_ids = set()
    for e in events:
        if e.source_id.startswith("synthetic:"):
            raise PermissionError("synthetic event rejected by real-data publication engine")
        if not e.verify_raw_evidence():
            raise ValueError(f"corrupted raw evidence in event '{e.event_id}'")
        event_ids.add(e.event_id)

    # Referential integrity check
    for o in observations:
        if o.evidence_id not in event_ids:
            raise ValueError(f"observation '{o.observation_id}' references missing evidence '{o.evidence_id}'")

    # Atomic publication via temporary staging directory
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path = output_path.parent / f".staging_{uuid.uuid4().hex}"
    staging_path.mkdir(parents=True, exist_ok=True)

    try:
        obs_records = [o.to_dict() for o in observations]
        obs_meta = _write_deterministic_gzip(staging_path / "real_observations.jsonl.gz", obs_records)

        ev_records = [e.to_dict() for e in events]
        ev_meta = _write_deterministic_gzip(staging_path / "real_events.jsonl.gz", ev_records)

        manifest = {
            "schema": REAL_MANIFEST_SCHEMA,
            "dataset_type": DATASET_TYPE_REAL,
            "publisher": publisher_identity,
            "release_sequence": release_sequence,
            "as_of": as_of_iso,
            "published_at": now_iso,
            "source_commit": source_commit or ("0" * 40),
            "files": [obs_meta, ev_meta],
            "total_observations": len(observations),
            "total_events": len(events),
            "integrity": "unsigned_candidate_manifest",
            "notice": (
                "First-party empirical intelligence observations collected under strict "
                "policy governance. Authenticates publisher provenance, not absolute external truth."
            ),
        }

        manifest_path = staging_path / "manifest.json"
        manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")

        # Pre-publication integrity self-verification
        verify_real_release(staging_path, trust=None)

        # Atomic move to destination directory
        staging_path.rename(output_path)
        return manifest
    except Exception:
        if staging_path.exists():
            shutil.rmtree(staging_path, ignore_errors=True)
        raise


def _read_and_validate_manifest(directory: Path) -> tuple[bytes, str, dict[str, Any]]:
    """Read and validate candidate or signed manifest.json."""
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError(f"missing or unsafe manifest in '{directory}'")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest size exceeds limit of {MAX_MANIFEST_BYTES} bytes")

    raw_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(raw_bytes.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"invalid manifest JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    if manifest.get("schema") != REAL_MANIFEST_SCHEMA:
        raise ValueError(f"unsupported manifest schema: {manifest.get('schema')!r}")
    if manifest.get("dataset_type") != DATASET_TYPE_REAL:
        raise ValueError(f"unsupported dataset_type: {manifest.get('dataset_type')!r}")

    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 2:
        raise ValueError("manifest must specify exactly 2 partition files")
    found_files = {f.get("file") for f in files}
    if found_files != REAL_PARTITION_FILES:
        raise ValueError(f"unexpected manifest partition files: {found_files}")

    manifest_sha = sha256(raw_bytes).hexdigest()
    return raw_bytes, manifest_sha, manifest


def sign_manifest_detached(
    directory: str | Path,
    private_key: object,
    *,
    key_id: str,
    release_sequence: int,
    issued_at: str,
    expires_at: str,
    publisher_identity: str = "anie-first-party",
    source_commit: str | None = None,
) -> dict[str, Any]:
    """Sign an exported manifest in a detached operator environment.
    
    The private key never resides on the collector VM and is never persisted to disk.
    Existing attestation files cannot be overwritten.
    """
    _, Ed25519PrivateKey, _, _ = _crypto()
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an instance of cryptography Ed25519PrivateKey")

    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError(f"invalid key_id: {key_id!r}")
    if not isinstance(release_sequence, int) or release_sequence < 1:
        raise ValueError(f"release_sequence must be >= 1: got {release_sequence}")

    dir_path = Path(directory)
    _, manifest_sha, manifest = _read_and_validate_manifest(dir_path)

    if manifest.get("release_sequence") != release_sequence:
        raise ValueError(
            f"release sequence mismatch: manifest specifies {manifest.get('release_sequence')}, "
            f"signing requested {release_sequence}"
        )

    issued_dt = _dt(issued_at)
    expires_dt = _dt(expires_at)
    if issued_dt >= expires_dt:
        raise ValueError("issued_at must be strictly before expires_at")
    if (expires_dt - issued_dt).total_seconds() > 90 * 86400:
        raise ValueError("signature validity period cannot exceed 90 days")

    as_of_dt = _dt(manifest["as_of"])
    if issued_dt < as_of_dt:
        raise ValueError("signature issuance cannot predate dataset as_of cutoff")

    raw_public = _public_key_raw(private_key)
    fingerprint = key_fingerprint(raw_public)

    payload = {
        "schema": REAL_PAYLOAD_SCHEMA,
        "publisher": publisher_identity,
        "key_id": key_id,
        "key_fingerprint": fingerprint,
        "dataset_type": DATASET_TYPE_REAL,
        "manifest_sha256": manifest_sha,
        "release_sequence": release_sequence,
        "source_commit": source_commit or manifest.get("source_commit", "0" * 40),
        "issued_at": utc_iso(issued_at),
        "expires_at": utc_iso(expires_at),
    }

    message = DOMAIN_SEPARATOR_REAL + canonical_json(payload).encode("utf-8")
    sig_bytes = private_key.sign(message)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    attestation = {
        "schema": REAL_SIGNATURE_SCHEMA,
        "key_id": key_id,
        "key_fingerprint": fingerprint,
        "payload": payload,
        "signature_base64": sig_b64,
    }

    attestation_path = dir_path / ATTESTATION_NAME
    # Atomic creation: cannot overwrite existing signature
    with attestation_path.open("x", encoding="utf-8") as f:
        f.write(canonical_json(attestation) + "\n")

    return attestation


@dataclass(frozen=True)
class TrustedKey:
    """An operator-pinned Ed25519 public key with defined validity boundaries."""
    key_id: str
    public_key_raw: bytes
    valid_from: str
    valid_until: str

    def __post_init__(self):
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.fullmatch(self.key_id):
            raise ValueError(f"invalid key_id: {self.key_id!r}")
        key_fingerprint(self.public_key_raw)
        if _dt(self.valid_from) >= _dt(self.valid_until):
            raise ValueError("valid_from must be strictly before valid_until")


@dataclass(frozen=True)
class RealReleaseTrust:
    """Operator-pinned trust configuration supporting key rotation and revocation."""
    trusted_keys: dict[str, TrustedKey]  # key_id -> TrustedKey
    expected_publisher: str = "anie-first-party"
    expected_source_commit: str | None = None
    min_sequence: int = 1
    max_age_seconds: int = 90 * 86400
    revoked_fingerprints: frozenset[str] = field(default_factory=frozenset)
    revoked_key_ids: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_single_key(
        cls,
        key_id: str,
        public_key_raw: bytes,
        valid_from: str,
        valid_until: str,
        **kwargs,
    ) -> "RealReleaseTrust":
        key = TrustedKey(
            key_id=key_id,
            public_key_raw=public_key_raw,
            valid_from=valid_from,
            valid_until=valid_until,
        )
        return cls(trusted_keys={key_id: key}, **kwargs)


class ReleaseSequenceTracker:
    """Persistent verifier state tracking accepted release sequences for rollback protection."""

    def __init__(self, state_path: str | Path):
        self.state_path = Path(state_path)

    def get_last_accepted_sequence(self, publisher: str) -> int:
        if not self.state_path.exists():
            return 0
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return int(data.get("sequences", {}).get(publisher, 0))
        except (OSError, ValueError, TypeError):
            return 0

    def update_accepted_sequence(self, publisher: str, sequence: int) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        sequences = data.setdefault("sequences", {})
        current = int(sequences.get(publisher, 0))
        if sequence > current:
            sequences[publisher] = sequence
            tmp = self.state_path.with_suffix(f".tmp.{uuid.uuid4().hex}")
            tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.state_path)


def verify_real_release(
    directory: str | Path,
    trust: RealReleaseTrust | None = None,
    *,
    now: str | None = None,
    allow_rollback: bool = False,
    sequence_tracker: ReleaseSequenceTracker | None = None,
) -> dict[str, Any]:
    """Verify integrity, referential consistency, raw evidence hashes, and signatures.
    
    Stateless signature verification alone cannot prevent replay or rollback attacks;
    sequence_tracker enforces persistent monotonicity against accepted sequences.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir() or dir_path.is_symlink():
        raise ValueError(f"release path '{dir_path}' must be a genuine directory")

    raw_manifest, manifest_sha, manifest = _read_and_validate_manifest(dir_path)

    # 1. Verify partition files
    files_map = {f["file"]: f for f in manifest["files"]}
    decompressed_data: dict[str, list[dict[str, Any]]] = {}

    for fname in sorted(REAL_PARTITION_FILES):
        fpath = dir_path / fname
        if not fpath.is_file() or fpath.is_symlink():
            raise ValueError(f"missing or unsafe partition file: '{fname}'")

        fbytes = fpath.stat().st_size
        if fbytes > MAX_PARTITION_COMPRESSED_BYTES:
            raise ValueError(f"partition '{fname}' exceeds compressed size limit")

        expected_meta = files_map[fname]
        if fbytes != expected_meta.get("bytes"):
            raise ValueError(f"size mismatch for partition '{fname}'")

        actual_sha = sha256(fpath.read_bytes()).hexdigest()
        if actual_sha != expected_meta.get("sha256"):
            raise ValueError(f"SHA-256 integrity mismatch for partition '{fname}'")

        # Decompression with stream bounding
        decompressed_chunks = bytearray()
        with gzip.open(fpath, "rb") as gz:
            while True:
                chunk = gz.read(65536)
                if not chunk:
                    break
                decompressed_chunks.extend(chunk)
                if len(decompressed_chunks) > MAX_PARTITION_DECOMPRESSED_BYTES:
                    raise ValueError(f"partition '{fname}' exceeded decompression limit (potential bomb)")

        lines = bytes(decompressed_chunks).splitlines()
        if len(lines) != expected_meta.get("records"):
            raise ValueError(f"record count mismatch for '{fname}': expected {expected_meta.get('records')}, got {len(lines)}")
        if len(lines) > MAX_RECORDS_PER_PARTITION:
            raise ValueError(f"record count exceeds maximum allowed {MAX_RECORDS_PER_PARTITION}")

        records = []
        for line_num, line in enumerate(lines, 1):
            if len(line) > MAX_SINGLE_RECORD_BYTES:
                raise ValueError(f"record #{line_num} in '{fname}' exceeds single record byte limit")
            try:
                records.append(json.loads(line.decode("utf-8")))
            except (ValueError, UnicodeError) as exc:
                raise ValueError(f"malformed JSON in '{fname}' line #{line_num}: {exc}") from exc

        decompressed_data[fname] = records

    # 2. Verify Observations
    obs_list = decompressed_data["real_observations.jsonl.gz"]
    if manifest.get("total_observations") != len(obs_list):
        raise ValueError(
            f"manifest total_observations ({manifest.get('total_observations')}) "
            f"does not match actual record count ({len(obs_list)})"
        )
    obs_ids: set[str] = set()
    referenced_evidence_ids: set[str] = set()

    for idx, r in enumerate(obs_list):
        if not isinstance(r, dict):
            raise ValueError(f"observation #{idx} must be a JSON object")
        if r.get("schema") != REAL_OBSERVATION_SCHEMA:
            raise ValueError(f"observation #{idx} has invalid schema: {r.get('schema')!r}")
        if r.get("synthetic") is not False:
            raise ValueError(f"observation #{idx} has non-false synthetic flag: contamination detected")
        if r.get("method") == "synthetic":
            raise ValueError(f"observation #{idx} has synthetic method")
        if str(r.get("source_id", "")).startswith("synthetic:"):
            raise ValueError(f"observation #{idx} has synthetic source_id")

        obs_id = r.get("observation_id")
        if not isinstance(obs_id, str) or not obs_id.startswith("obs_"):
            raise ValueError(f"observation #{idx} has invalid observation_id: {obs_id!r}")
        if obs_id in obs_ids:
            raise ValueError(f"duplicate observation_id '{obs_id}' detected")
        obs_ids.add(obs_id)

        ev_id = r.get("evidence_id")
        if not isinstance(ev_id, str) or not ev_id.startswith("event_"):
            raise ValueError(f"observation '{obs_id}' has invalid evidence_id: {ev_id!r}")
        referenced_evidence_ids.add(ev_id)

    # 3. Verify Events and Raw Evidence Hashes
    ev_list = decompressed_data["real_events.jsonl.gz"]
    if manifest.get("total_events") != len(ev_list):
        raise ValueError(
            f"manifest total_events ({manifest.get('total_events')}) "
            f"does not match actual record count ({len(ev_list)})"
        )
    event_ids: set[str] = set()

    for idx, r in enumerate(ev_list):
        if not isinstance(r, dict):
            raise ValueError(f"event #{idx} must be a JSON object")
        if r.get("schema") != REAL_EVENT_SCHEMA:
            raise ValueError(f"event #{idx} has invalid schema: {r.get('schema')!r}")
        if str(r.get("source_id", "")).startswith("synthetic:"):
            raise ValueError(f"event #{idx} has synthetic source_id")

        ev_id = r.get("event_id")
        if not isinstance(ev_id, str) or not ev_id.startswith("event_"):
            raise ValueError(f"event #{idx} has invalid event_id: {ev_id!r}")
        if ev_id in event_ids:
            raise ValueError(f"duplicate event_id '{ev_id}' detected")
        event_ids.add(ev_id)

        # Cryptographic raw evidence hash verification
        raw_status = r.get("raw_evidence_status")
        raw_sha = r.get("raw_sha256")
        if raw_status == "captured":
            raw_b64 = r.get("raw_payload_b64")
            if not raw_b64 or not isinstance(raw_b64, str):
                raise ValueError(f"captured event '{ev_id}' missing raw_payload_b64")
            try:
                raw_bytes = base64.b64decode(raw_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"event '{ev_id}' has malformed raw_payload_b64: {exc}") from exc
            computed_sha = sha256(raw_bytes).hexdigest()
            if computed_sha != raw_sha:
                raise ValueError(
                    f"raw DNS evidence hash mismatch for event '{ev_id}': "
                    f"manifest says {raw_sha}, computed {computed_sha}"
                )

    # 4. Observation-to-Event Referential Integrity
    missing_events = referenced_evidence_ids - event_ids
    if missing_events:
        raise ValueError(
            f"broken referential integrity: observations reference missing events "
            f"(sample: {sorted(missing_events)[:3]})"
        )

    # 5. Cryptographic Signature & Attestation Verification
    signature_verified = False
    key_id_verified = None
    key_fp_verified = None

    if trust is not None:
        InvalidSignature, _, Ed25519PublicKey, _ = _crypto()

        att_path = dir_path / ATTESTATION_NAME
        if not att_path.is_file() or att_path.is_symlink():
            raise ValueError(f"missing signed attestation '{ATTESTATION_NAME}' in release")
        if att_path.stat().st_size > MAX_ATTESTATION_BYTES:
            raise ValueError(f"attestation file exceeds size limit of {MAX_ATTESTATION_BYTES} bytes")

        try:
            att = json.loads(att_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise ValueError(f"invalid attestation JSON: {exc}") from exc

        if not isinstance(att, dict) or set(att) != {"schema", "key_id", "key_fingerprint", "payload", "signature_base64"}:
            raise ValueError("invalid attestation structure or fields")
        if att["schema"] != REAL_SIGNATURE_SCHEMA:
            raise ValueError(f"unsupported attestation schema: {att['schema']!r}")

        key_id = att["key_id"]
        if key_id in trust.revoked_key_ids:
            raise ValueError(f"signing key_id '{key_id}' has been revoked by operator trust policy")
        if key_id not in trust.trusted_keys:
            raise ValueError(f"unknown or untrusted key_id '{key_id}'")

        trusted_key = trust.trusted_keys[key_id]
        expected_fp = key_fingerprint(trusted_key.public_key_raw)
        if expected_fp in trust.revoked_fingerprints:
            raise ValueError(f"signing key fingerprint '{expected_fp}' has been revoked")
        if att["key_fingerprint"] != expected_fp:
            raise ValueError(
                f"key fingerprint mismatch for key_id '{key_id}': "
                f"attestation claims {att['key_fingerprint']}, trusted is {expected_fp}"
            )

        payload = att["payload"]
        if not isinstance(payload, dict) or payload.get("schema") != REAL_PAYLOAD_SCHEMA:
            raise ValueError("invalid attestation payload schema")
        if payload.get("dataset_type") != DATASET_TYPE_REAL:
            raise ValueError("attestation dataset_type mismatch")
        if payload.get("manifest_sha256") != manifest_sha:
            raise ValueError(
                f"signed manifest SHA-256 mismatch: attestation signed {payload.get('manifest_sha256')}, "
                f"actual manifest hash is {manifest_sha}"
            )
        if payload.get("publisher") != trust.expected_publisher:
            raise ValueError(
                f"publisher mismatch: attestation claims {payload.get('publisher')!r}, "
                f"expected {trust.expected_publisher!r}"
            )
        if trust.expected_source_commit and payload.get("source_commit") != trust.expected_source_commit:
            raise ValueError(
                f"source_commit mismatch: attestation claims {payload.get('source_commit')!r}, "
                f"expected {trust.expected_source_commit!r}"
            )

        # Cryptographic signature verification
        sig_text = att["signature_base64"]
        try:
            sig_raw = base64.b64decode(sig_text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"invalid base64 signature encoding: {exc}") from exc
        if len(sig_raw) != 64:
            raise ValueError(f"invalid Ed25519 signature length: {len(sig_raw)} bytes")

        message = DOMAIN_SEPARATOR_REAL + canonical_json(payload).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(trusted_key.public_key_raw).verify(sig_raw, message)
        except InvalidSignature as exc:
            raise ValueError("cryptographic Ed25519 signature verification failed: signature is forged or corrupted") from exc

        # Timestamp and Validity Window Checks
        current_dt = _dt(now) if now else datetime.now(timezone.utc)
        if not _dt(trusted_key.valid_from) <= current_dt <= _dt(trusted_key.valid_until):
            raise ValueError("operator trusted public key is expired or not yet valid")
        if not _dt(payload["issued_at"]) <= current_dt <= _dt(payload["expires_at"]):
            raise ValueError("signed release is expired or not yet valid")

        age_seconds = (current_dt - _dt(manifest["as_of"])).total_seconds()
        if age_seconds < 0:
            raise ValueError("dataset as_of timestamp is in the future")
        if age_seconds > trust.max_age_seconds:
            raise ValueError(f"dataset is stale: age ({age_seconds:.0f}s) exceeds max_age_seconds ({trust.max_age_seconds}s)")

        # Monotonic Sequence & Replay/Rollback Verification
        seq = payload["release_sequence"]
        if seq < trust.min_sequence:
            raise ValueError(f"release sequence {seq} is below trust min_sequence {trust.min_sequence}")

        if sequence_tracker is not None:
            last_accepted = sequence_tracker.get_last_accepted_sequence(payload["publisher"])
            if seq <= last_accepted and not allow_rollback:
                raise ValueError(
                    f"release sequence {seq} is replayed or downgraded "
                    f"(last accepted sequence was {last_accepted}); rejection enforced for rollback protection"
                )
            if not allow_rollback:
                sequence_tracker.update_accepted_sequence(payload["publisher"], seq)

        signature_verified = True
        key_id_verified = key_id
        key_fp_verified = expected_fp

    return {
        "verified": True,
        "dataset_type": DATASET_TYPE_REAL,
        "release_sequence": manifest.get("release_sequence"),
        "total_observations": len(obs_list),
        "total_events": len(ev_list),
        "manifest_sha256": manifest_sha,
        "publisher_signature_verified": signature_verified,
        "publisher_identity": manifest.get("publisher"),
        "key_id": key_id_verified,
        "key_fingerprint": key_fp_verified,
        "safe_to_autonomously_act": False,
        "publisher_real_world_identity_verified": False,
    }

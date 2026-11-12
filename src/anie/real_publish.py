"""Deterministic publication, detached Ed25519 signing, and integrity verification

for ANIE first-party real-world intelligence datasets.

Part of ANIE Phase 2 PR 4 (Authenticated First-Party Intelligence Publication).

Security & Invariant Boundaries:
1. Strict Pipeline Isolation: Unconditionally rejects synthetic observations,
   synthetic methods, or synthetic source IDs.
2. Bounded & Reproducible Serialization: Uses canonical JSON formatting, streaming
   record processing, and reproducible gzip archives (mtime=0, compresslevel=9) to
   guarantee byte-for-byte reproducibility across independent publication builds.
3. Air-Gapped Detached Signing: The primary Ed25519 private key never resides on the
   collector VM (anie-collector-01). The collector produces an unsigned candidate
   release; detached signing takes place in an isolated operator environment.
4. Cryptographic Provenance Authentication: The Ed25519 signature authenticates the
   publisher's release integrity and sequence; it does not claim absolute external truth
   for third-party DNS endpoints.
5. Anti-Replay & Rollback Protection: Stateless signature verification alone cannot
   prevent replay of previously signed historical releases. Genuine rollback protection
   is enforced via monotonic sequences and persistent verifier high-water mark tracking.
6. Local State Boundary: Deletion, truncation, or filesystem snapshot rollback of local
   verifier state cannot be detected without a trusted external anchor or protected initialization.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import time
from typing import Any, Iterable, Iterator
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
TRACKER_SCHEMA = "anie.verifier-sequence-tracker.v1"

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


class TrackerStateError(ValueError):
    """Raised when sequence tracker state file is corrupted, malformed, or invalid."""
    pass


class TrackerStateLostError(FileNotFoundError):
    """Raised when sequence tracker state file is unexpectedly missing or deleted."""
    pass


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


def load_private_key_file(path: str | Path) -> object:
    """Strictly load an Ed25519 private key from PEM or exactly 32 raw bytes.
    
    Rejects permissive parsing, truncated buffers, or unsupported key types.
    """
    key_path = Path(path)
    if not key_path.is_file() or key_path.is_symlink():
        raise ValueError(f"invalid private key file: '{key_path}'")
    key_bytes = key_path.read_bytes()

    _, Ed25519PrivateKey, _, serialization = _crypto()

    # 1. Try PEM encoding
    if b"-----BEGIN " in key_bytes:
        try:
            priv = serialization.load_pem_private_key(key_bytes, password=None)
        except Exception as exc:
            raise ValueError(f"failed to parse PEM private key: {exc}") from exc
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("PEM key is not an Ed25519 private key")
        return priv

    # 2. Raw 32-byte binary seed
    if len(key_bytes) == 32:
        return Ed25519PrivateKey.from_private_bytes(key_bytes)

    raise ValueError(
        f"unsupported private key format in '{key_path}': expected PEM or exactly 32 raw bytes, "
        f"got {len(key_bytes)} bytes (permissive truncation strictly rejected)"
    )


def load_public_key_file(path: str | Path) -> bytes:
    """Strictly load a 32-byte raw Ed25519 public key from PEM or exactly 32 raw bytes.
    
    Rejects permissive parsing, truncated buffers, or unsupported key types.
    """
    key_path = Path(path)
    if not key_path.is_file() or key_path.is_symlink():
        raise ValueError(f"invalid public key file: '{key_path}'")
    key_bytes = key_path.read_bytes()

    _, _, Ed25519PublicKey, serialization = _crypto()

    # 1. Try PEM encoding
    if b"-----BEGIN " in key_bytes:
        try:
            pub = serialization.load_pem_public_key(key_bytes)
        except Exception as exc:
            raise ValueError(f"failed to parse PEM public key: {exc}") from exc
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("PEM key is not an Ed25519 public key")
        return pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # 2. Raw 32-byte binary
    if len(key_bytes) == 32:
        return key_bytes

    raise ValueError(
        f"unsupported public key format in '{key_path}': expected PEM or exactly 32 raw bytes, "
        f"got {len(key_bytes)} bytes (permissive truncation strictly rejected)"
    )


def _write_deterministic_gzip(path: Path, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Write records to gzip archive with fixed metadata for byte-for-byte reproducibility.
    
    Streams line-by-line to avoid loading full partitions into memory.
    """
    uncompressed_bytes = 0
    record_count = 0
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
            for r in records:
                line = (canonical_json(r) + "\n").encode("utf-8")
                if len(line) > MAX_SINGLE_RECORD_BYTES:
                    raise ValueError(f"single record exceeds maximum allowed byte limit of {MAX_SINGLE_RECORD_BYTES}")
                uncompressed_bytes += len(line)
                if uncompressed_bytes > MAX_PARTITION_DECOMPRESSED_BYTES:
                    raise ValueError(
                        f"partition payload ({uncompressed_bytes} bytes) exceeds maximum bound "
                        f"of {MAX_PARTITION_DECOMPRESSED_BYTES} bytes"
                    )
                record_count += 1
                if record_count > MAX_RECORDS_PER_PARTITION:
                    raise ValueError(f"partition exceeded maximum record limit of {MAX_RECORDS_PER_PARTITION}")
                stream.write(line)

    file_bytes = path.stat().st_size
    if file_bytes > MAX_PARTITION_COMPRESSED_BYTES:
        raise ValueError(
            f"compressed partition '{path.name}' ({file_bytes} bytes) exceeds limit "
            f"of {MAX_PARTITION_COMPRESSED_BYTES} bytes"
        )

    # Stream-hash the compressed file with 64 KiB buffer
    h = sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    file_sha = h.hexdigest()

    return {
        "file": path.name,
        "sha256": file_sha,
        "records": record_count,
        "bytes": file_bytes,
    }


def export_canonical_dataset(
    store: RealObservationStore,
    as_of: str,
    limit: int = MAX_RECORDS_PER_PARTITION,
) -> tuple[list[RealObservation], list[RealCollectionEvent]]:
    """Export a consistent SQLite snapshot of real observations and referenced events.
    
    Guarantees:
    - Single consistent SQLite read transaction (snapshot isolation).
    - Observations ordered by (observed_at ASC, observation_id ASC).
    - Events ordered by (observed_at ASC, event_id ASC).
    - Referential integrity: all observation evidence_id references exist in events.
    - Raw evidence hashes verified for all exported events.
    - Rejects any synthetic record unconditionally.
    - Fail-closed if dataset exceeds limit (no silent truncation).
    """
    as_of_iso = utc_iso(as_of)
    with store._connect() as conn:
        conn.isolation_level = "DEFERRED"
        conn.execute("BEGIN")
        try:
            # Query limit + 1 to detect over-limit datasets without silent truncation
            obs_rows = conn.execute(
                """
                SELECT payload FROM real_observations
                WHERE observed_at <= ?
                ORDER BY observed_at ASC, observation_id ASC
                LIMIT ?
                """,
                (as_of_iso, limit + 1),
            ).fetchall()

            if len(obs_rows) > limit:
                raise ValueError(
                    f"dataset exceeds maximum partition limit of {limit} observations "
                    f"(found >{limit} records at or before as_of '{as_of_iso}'); "
                    f"silent truncation rejected"
                )

            if not obs_rows:
                raise ValueError(f"no real observations found at or before as_of cutoff '{as_of_iso}'")

            observations: list[RealObservation] = []
            needed_evidence_ids: set[str] = set()

            for (obs_json,) in obs_rows:
                raw_obs = json.loads(obs_json)
                if raw_obs.get("synthetic") is not False:
                    raise PermissionError("synthetic observation found in real database: publication aborted")
                if raw_obs.get("method") == "synthetic":
                    raise PermissionError("synthetic collection method found in real database: publication aborted")
                if str(raw_obs.get("source_id", "")).startswith("synthetic:"):
                    raise PermissionError("synthetic source_id found in real database: publication aborted")

                obs = RealObservation.from_dict(raw_obs)
                observations.append(obs)
                needed_evidence_ids.add(obs.evidence_id)

            ev_rows = conn.execute(
                """
                SELECT event_id, payload, raw_payload, raw_sha256, raw_evidence_status
                FROM real_events
                WHERE observed_at <= ?
                ORDER BY observed_at ASC, event_id ASC
                LIMIT ?
                """,
                (as_of_iso, limit + 1),
            ).fetchall()

            if len(ev_rows) > limit:
                raise ValueError(
                    f"dataset exceeds maximum partition limit of {limit} events "
                    f"(found >{limit} records at or before as_of '{as_of_iso}'); "
                    f"silent truncation rejected"
                )

            events: list[RealCollectionEvent] = []
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

            conn.commit()
            return observations, events
        except Exception:
            conn.rollback()
            raise


def publish_real(
    store_or_data: RealObservationStore | tuple[list[RealObservation], list[RealCollectionEvent]],
    output_dir: str | Path,
    as_of: str,
    *,
    publisher_identity: str = "anie-first-party",
    release_sequence: int = 1,
    source_commit: str | None = None,
    published_at: str | None = None,
    limit: int = MAX_RECORDS_PER_PARTITION,
) -> dict[str, Any]:
    """Publish a deterministic, canonical real-world intelligence dataset.
    
    Creates unsigned candidate release artifacts with atomic staging.
    When published_at is explicitly specified, manifests are 100% byte-for-byte reproducible.
    """
    output_path = Path(output_dir)
    if output_path.exists() and any(output_path.iterdir()):
        raise FileExistsError(
            f"output directory '{output_path}' must be empty; overwriting previous releases is prohibited"
        )

    if not isinstance(release_sequence, int) or release_sequence < 1:
        raise ValueError(f"release_sequence must be a positive integer >= 1: got {release_sequence}")

    as_of_iso = utc_iso(as_of)
    now_iso = utc_iso(published_at) if published_at is not None else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

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
        obs_records = (o.to_dict() for o in observations)
        obs_meta = _write_deterministic_gzip(staging_path / "real_observations.jsonl.gz", obs_records)

        ev_records = (e.to_dict() for e in events)
        ev_meta = _write_deterministic_gzip(staging_path / "real_events.jsonl.gz", ev_records)

        commit_val = source_commit or ("0" * 40)
        if not _COMMIT_RE.fullmatch(commit_val):
            raise ValueError(f"invalid source_commit: {commit_val!r} (must be 40-character hex)")

        manifest = {
            "schema": REAL_MANIFEST_SCHEMA,
            "dataset_type": DATASET_TYPE_REAL,
            "publisher": publisher_identity,
            "release_sequence": release_sequence,
            "as_of": as_of_iso,
            "published_at": now_iso,
            "source_commit": commit_val,
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

        # Pre-publication candidate integrity self-verification
        verify_real_release(staging_path, integrity_only=True)

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
    
    Strictly binds all metadata:
    - Publisher identity must match manifest publisher.
    - Release sequence must match manifest sequence.
    - Source commit must match manifest source commit.
    - Outer envelope key ID and fingerprint must match inner payload.
    - Existing attestation files cannot be overwritten.
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

    # 1. Enforce publisher agreement
    if manifest.get("publisher") != publisher_identity:
        raise ValueError(
            f"publisher mismatch: manifest specifies {manifest.get('publisher')!r}, "
            f"signing requested {publisher_identity!r}"
        )

    # 2. Enforce sequence agreement
    if manifest.get("release_sequence") != release_sequence:
        raise ValueError(
            f"release sequence mismatch: manifest specifies {manifest.get('release_sequence')}, "
            f"signing requested {release_sequence}"
        )

    # 3. Enforce source commit agreement
    manifest_commit = manifest.get("source_commit", "0" * 40)
    if source_commit is not None:
        if not _COMMIT_RE.fullmatch(source_commit):
            raise ValueError(f"invalid source_commit: {source_commit!r}")
        if manifest_commit != source_commit:
            raise ValueError(
                f"source_commit mismatch: manifest specifies {manifest_commit!r}, "
                f"signing requested {source_commit!r}"
            )
    else:
        source_commit = manifest_commit

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
        "source_commit": source_commit,
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


@contextmanager
def _tracker_file_lock(lock_path: Path, timeout: float = 10.0) -> Iterator[None]:
    """Cross-platform advisory file lock for sequence tracker state synchronization."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "a+", encoding="utf-8")
    start = time.monotonic()
    acquired = False
    try:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (BlockingIOError, OSError):
                if time.monotonic() - start > timeout:
                    raise TimeoutError(f"timed out waiting for sequence tracker lock at '{lock_path}'")
                time.sleep(0.02)
        yield
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
        try:
            f.close()
        except Exception:
            pass


class ReleaseSequenceTracker:
    """Persistent verifier state tracking accepted release sequences for rollback protection.
    
    Security Guarantee & Invariants:
    1. Fail-Closed: Corrupted, unreadable, or invalid state files raise TrackerStateError.
       Never silently resets accepted sequences to zero on operational errors.
    2. Concurrency-Safe: Atomic multi-process file locking protects read-modify-write cycles.
       Concurrent verifiers can never cause a lower sequence to overwrite a higher sequence.
    3. State Lost Detection: Missing state files raise TrackerStateLostError when
       explicit initialization is required.
    4. Atomic Durability: State updates are written to temporary files and atomically replaced.
    5. Local State Boundary Notice:
       Deletion, truncation, or filesystem snapshot rollback of this local verifier state
       file CANNOT be detected locally without a trusted external anchor (such as a
       transparency log, TPM monotonic counter, or multi-party distributed consensus).
       Local rollback protection assumes the local filesystem storage path is protected
       against unauthorized tampering or arbitrary deletion.
    """

    def __init__(self, state_path: str | Path, *, auto_init: bool = False):
        self.state_path = Path(state_path)
        self.lock_path = self.state_path.with_suffix(".lock")
        if auto_init and not self.state_path.exists():
            self.initialize(force=False)

    def initialize(self, force: bool = False) -> None:
        """Explicitly initialize an empty sequence tracker state file."""
        with _tracker_file_lock(self.lock_path):
            if self.state_path.exists() and not force:
                raise FileExistsError(f"sequence tracker state file already exists: '{self.state_path}'")
            now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            data = {
                "schema": TRACKER_SCHEMA,
                "initialized_at": now_iso,
                "updated_at": now_iso,
                "sequences": {},
            }
            self._write_state_atomic(data)

    def is_initialized(self) -> bool:
        """Check if tracker state file exists and has valid schema."""
        if not self.state_path.is_file():
            return False
        try:
            with _tracker_file_lock(self.lock_path):
                self._read_state_locked()
            return True
        except Exception:
            return False

    def _read_state_locked(self) -> dict[str, Any]:
        """Read and strictly validate state file under lock."""
        if not self.state_path.exists():
            raise TrackerStateLostError(
                f"sequence tracker state file '{self.state_path}' does not exist (uninitialized or state lost)"
            )
        try:
            raw_text = self.state_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise TrackerStateError(f"failed to read sequence tracker state file: {exc}") from exc

        try:
            data = json.loads(raw_text)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TrackerStateError(f"corrupted sequence tracker state JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise TrackerStateError("tracker state file must contain a JSON object")
        if data.get("schema") != TRACKER_SCHEMA:
            raise TrackerStateError(f"unsupported tracker state schema: {data.get('schema')!r}")

        sequences = data.get("sequences")
        if not isinstance(sequences, dict):
            raise TrackerStateError("tracker state 'sequences' field must be a dictionary")

        for pub, seq in sequences.items():
            if not isinstance(pub, str) or not pub:
                raise TrackerStateError(f"invalid publisher key in tracker sequences: {pub!r}")
            if type(seq) is not int or seq < 0:
                raise TrackerStateError(f"invalid sequence value for publisher '{pub}': {seq!r} (must be int >= 0)")

        return data

    def _write_state_atomic(self, data: dict[str, Any]) -> None:
        """Write state atomically via temporary file and replace."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.parent / f".tmp.{self.state_path.name}.{uuid.uuid4().hex}"
        try:
            tmp.write_text(canonical_json(data) + "\n", encoding="utf-8")
            tmp.replace(self.state_path)
        except Exception:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
            raise

    def get_last_accepted_sequence(self, publisher: str, *, allow_uninitialized: bool = False) -> int:
        """Get last accepted sequence for publisher. Fails closed on corruption or missing state."""
        with _tracker_file_lock(self.lock_path):
            if not self.state_path.exists():
                if allow_uninitialized:
                    return 0
                raise TrackerStateLostError(
                    f"sequence tracker state file '{self.state_path}' does not exist (uninitialized or state lost)"
                )
            data = self._read_state_locked()
            return int(data["sequences"].get(publisher, 0))

    def update_accepted_sequence(
        self,
        publisher: str,
        sequence: int,
        *,
        allow_uninitialized: bool = False,
    ) -> None:
        """Atomically advance accepted sequence. Fails closed on rollback or concurrency conflict."""
        if type(sequence) is not int or sequence < 1:
            raise ValueError(f"sequence must be an integer >= 1: got {sequence!r}")
        with _tracker_file_lock(self.lock_path):
            if not self.state_path.exists():
                if allow_uninitialized:
                    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                    data = {
                        "schema": TRACKER_SCHEMA,
                        "initialized_at": now_iso,
                        "updated_at": now_iso,
                        "sequences": {},
                    }
                else:
                    raise TrackerStateLostError(
                        f"sequence tracker state file '{self.state_path}' does not exist (uninitialized or state lost)"
                    )
            else:
                data = self._read_state_locked()

            current = int(data["sequences"].get(publisher, 0))
            if sequence <= current:
                raise ValueError(
                    f"cannot advance sequence to {sequence}: current accepted sequence for '{publisher}' "
                    f"is {current} (rollback/downgrade prevented)"
                )

            data["sequences"][publisher] = sequence
            data["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            self._write_state_atomic(data)


def _iter_bounded_gzip_records(
    stream: Any,
    *,
    max_record_bytes: int = MAX_SINGLE_RECORD_BYTES,
    max_total_bytes: int = MAX_PARTITION_DECOMPRESSED_BYTES,
    max_records: int = MAX_RECORDS_PER_PARTITION,
    partition_name: str = "partition",
) -> Iterator[tuple[int, bytes]]:
    """Yield (line_number, record_bytes) from a gzip stream using bounded line reading.
    
    Enforces per-record byte limits during reading so an arbitrarily large record
    cannot be accumulated into memory before rejection.
    Enforces total decompression byte budgets and record-count ceilings.
    Rejects records lacking required newline boundaries.
    """
    total_decompressed = 0
    record_num = 0

    while True:
        # Read at most max_record_bytes + 1 bytes for the current record line.
        # This bounds memory allocation to at most max_record_bytes + 1 bytes during reading.
        chunk = stream.readline(max_record_bytes + 1)
        if not chunk:
            break

        record_num += 1
        if record_num > max_records:
            raise ValueError(
                f"partition '{partition_name}' exceeded maximum record limit of {max_records}"
            )

        if len(chunk) > max_record_bytes:
            raise ValueError(
                f"record #{record_num} in '{partition_name}' exceeds byte limit of {max_record_bytes} "
                f"during streaming read"
            )

        if not chunk.endswith(b"\n"):
            raise ValueError(
                f"record #{record_num} in '{partition_name}' lacks required newline boundary"
            )

        total_decompressed += len(chunk)
        if total_decompressed > max_total_bytes:
            raise ValueError(
                f"partition '{partition_name}' exceeded decompression limit of {max_total_bytes} bytes"
            )

        yield record_num, chunk[:-1]


def verify_real_release(
    directory: str | Path,
    trust: RealReleaseTrust | None = None,
    *,
    integrity_only: bool = False,
    now: str | None = None,
    allow_rollback: bool = False,
    sequence_tracker: ReleaseSequenceTracker | None = None,
    allow_uninitialized_state: bool = False,
) -> dict[str, Any]:
    """Verify integrity, referential consistency, raw evidence hashes, and signatures.
    
    Distinguishes four distinct validation tiers:
    - structural_valid: Manifest and partition file structures conform to schema limits.
    - evidence_integrity_valid: Record schemas, raw wire hashes, deterministic ordering,
      and referential integrity are fully verified via model reconstruction.
    - publisher_authenticated: Cryptographic Ed25519 signature verified against operator trust policy.
    - anti_rollback_verified: Release sequence verified monotonically against persistent state.
      Explicitly False whenever allow_rollback=True bypasses enforcement or sequence_tracker is None.
    
    When integrity_only=True, candidate integrity is verified without requiring a trust policy;
    candidate verification is explicitly marked unauthenticated.
    """
    if not integrity_only and trust is None:
        raise ValueError(
            "authenticated release verification requires a RealReleaseTrust configuration. "
            "For unsigned candidate inspection, specify integrity_only=True explicitly."
        )

    dir_path = Path(directory)
    if not dir_path.is_dir() or dir_path.is_symlink():
        raise ValueError(f"release path '{dir_path}' must be a genuine directory")

    raw_manifest, manifest_sha, manifest = _read_and_validate_manifest(dir_path)

    # 1. Structural Partition File Verification
    files_map = {f["file"]: f for f in manifest["files"]}

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

        # Stream-hash compressed partition with 64 KiB buffer
        h = sha256()
        with fpath.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        if h.hexdigest() != expected_meta.get("sha256"):
            raise ValueError(f"SHA-256 integrity mismatch for partition '{fname}'")

    # 2. Bounded Streaming Decompression & Strict Model Reconstruction for Events
    events_path = dir_path / "real_events.jsonl.gz"
    event_meta = files_map["real_events.jsonl.gz"]
    event_ids: set[str] = set()
    prev_event_order: tuple[str, str] | None = None
    event_count = 0

    with gzip.open(events_path, "rb") as gz:
        for line_num, line_bytes in _iter_bounded_gzip_records(
            gz,
            max_record_bytes=MAX_SINGLE_RECORD_BYTES,
            max_total_bytes=MAX_PARTITION_DECOMPRESSED_BYTES,
            max_records=MAX_RECORDS_PER_PARTITION,
            partition_name="real_events.jsonl.gz",
        ):
            try:
                raw_dict = json.loads(line_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"malformed JSON in real_events line #{line_num}: {exc}") from exc

            # Strict reconstruction through model validator
            event = RealCollectionEvent.from_dict(raw_dict)

            # Re-verify raw wire evidence hash and status
            if not event.verify_raw_evidence():
                raise ValueError(f"raw evidence verification failed for event '{event.event_id}' at line #{line_num}")

            # Check strict deterministic ordering: (observed_at, event_id) strictly increasing
            current_order = (event.observed_at, event.event_id)
            if prev_event_order is not None and current_order <= prev_event_order:
                if current_order == prev_event_order:
                    raise ValueError(f"duplicate event_id '{event.event_id}' detected at line #{line_num}")
                raise ValueError(f"events partition out of deterministic order at line #{line_num}: {current_order} <= {prev_event_order}")
            prev_event_order = current_order

            event_ids.add(event.event_id)
            event_count += 1

    if event_count != event_meta.get("records"):
        raise ValueError(f"record count mismatch for real_events: expected {event_meta.get('records')}, got {event_count}")
    if manifest.get("total_events") != event_count:
        raise ValueError(f"manifest total_events ({manifest.get('total_events')}) does not match actual count ({event_count})")

    # 3. Bounded Streaming Decompression & Strict Model Reconstruction for Observations
    obs_path = dir_path / "real_observations.jsonl.gz"
    obs_meta = files_map["real_observations.jsonl.gz"]
    prev_obs_order: tuple[str, str] | None = None
    obs_count = 0

    with gzip.open(obs_path, "rb") as gz:
        for line_num, line_bytes in _iter_bounded_gzip_records(
            gz,
            max_record_bytes=MAX_SINGLE_RECORD_BYTES,
            max_total_bytes=MAX_PARTITION_DECOMPRESSED_BYTES,
            max_records=MAX_RECORDS_PER_PARTITION,
            partition_name="real_observations.jsonl.gz",
        ):
            try:
                raw_dict = json.loads(line_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"malformed JSON in real_observations line #{line_num}: {exc}") from exc

            # Strict reconstruction through model validator
            obs = RealObservation.from_dict(raw_dict)

            # Check strict deterministic ordering: (observed_at, observation_id) strictly increasing
            current_order = (obs.observed_at, obs.observation_id)
            if prev_obs_order is not None and current_order <= prev_obs_order:
                if current_order == prev_obs_order:
                    raise ValueError(f"duplicate observation_id '{obs.observation_id}' detected at line #{line_num}")
                raise ValueError(f"observations partition out of deterministic order at line #{line_num}: {current_order} <= {prev_obs_order}")
            prev_obs_order = current_order

            # Referential integrity: check evidence_id exists in events partition
            if obs.evidence_id not in event_ids:
                raise ValueError(f"broken referential integrity: observation '{obs.observation_id}' references unknown evidence_id '{obs.evidence_id}'")

            obs_count += 1

    if obs_count != obs_meta.get("records"):
        raise ValueError(f"record count mismatch for real_observations: expected {obs_meta.get('records')}, got {obs_count}")
    if manifest.get("total_observations") != obs_count:
        raise ValueError(f"manifest total_observations ({manifest.get('total_observations')}) does not match actual count ({obs_count})")

    # 4. Integrity-Only Early Exit
    if integrity_only:
        return {
            "status": "CANDIDATE_INTEGRITY_VERIFIED",
            "authenticated": False,
            "integrity_only": True,
            "structural_valid": True,
            "evidence_integrity_valid": True,
            "publisher_authenticated": False,
            "anti_rollback_verified": False,
            "dataset_type": DATASET_TYPE_REAL,
            "release_sequence": manifest.get("release_sequence"),
            "total_observations": obs_count,
            "total_events": event_count,
            "manifest_sha256": manifest_sha,
            "publisher_identity": manifest.get("publisher"),
            "key_id": None,
            "key_fingerprint": None,
            "safe_to_autonomously_act": False,
            "publisher_real_world_identity_verified": False,
        }

    # 5. Cryptographic Signature & Attestation Authentication
    assert trust is not None
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

    payload = att["payload"]
    if not isinstance(payload, dict) or payload.get("schema") != REAL_PAYLOAD_SCHEMA:
        raise ValueError("invalid attestation payload schema")
    if payload.get("dataset_type") != DATASET_TYPE_REAL:
        raise ValueError("attestation dataset_type mismatch")

    # P0: Enforce strict metadata agreement between attestation, payload, manifest, and trust
    key_id = att["key_id"]
    if payload.get("key_id") != key_id:
        raise ValueError(f"outer attestation key_id '{key_id}' does not match signed payload key_id '{payload.get('key_id')}'")

    key_fp = att["key_fingerprint"]
    if payload.get("key_fingerprint") != key_fp:
        raise ValueError("outer attestation key_fingerprint does not match signed payload key_fingerprint")

    if payload.get("publisher") != manifest.get("publisher"):
        raise ValueError("signed payload publisher mismatch with manifest publisher")
    if payload.get("publisher") != trust.expected_publisher:
        raise ValueError(
            f"publisher mismatch: attestation claims {payload.get('publisher')!r}, "
            f"expected {trust.expected_publisher!r}"
        )
    if manifest.get("publisher") != trust.expected_publisher:
        raise ValueError(
            f"manifest publisher mismatch: manifest claims {manifest.get('publisher')!r}, "
            f"expected {trust.expected_publisher!r}"
        )

    if payload.get("release_sequence") != manifest.get("release_sequence"):
        raise ValueError(
            f"signed sequence mismatch: payload specifies {payload.get('release_sequence')}, "
            f"manifest specifies {manifest.get('release_sequence')}"
        )

    if payload.get("source_commit") != manifest.get("source_commit"):
        raise ValueError(
            f"signed commit mismatch: payload specifies {payload.get('source_commit')!r}, "
            f"manifest specifies {manifest.get('source_commit')!r}"
        )
    if trust.expected_source_commit and payload.get("source_commit") != trust.expected_source_commit:
        raise ValueError(
            f"source_commit mismatch: attestation claims {payload.get('source_commit')!r}, "
            f"expected {trust.expected_source_commit!r}"
        )

    if payload.get("manifest_sha256") != manifest_sha:
        raise ValueError(
            f"signed manifest SHA-256 mismatch: attestation signed {payload.get('manifest_sha256')}, "
            f"actual manifest hash is {manifest_sha}"
        )

    # Trust policy & revocation checks
    if key_id in trust.revoked_key_ids:
        raise ValueError(f"signing key_id '{key_id}' has been revoked by operator trust policy")
    if key_id not in trust.trusted_keys:
        raise ValueError(f"unknown or untrusted key_id '{key_id}'")

    trusted_key = trust.trusted_keys[key_id]
    expected_fp = key_fingerprint(trusted_key.public_key_raw)
    if expected_fp in trust.revoked_fingerprints:
        raise ValueError(f"signing key fingerprint '{expected_fp}' has been revoked")
    if key_fp != expected_fp:
        raise ValueError(
            f"key fingerprint mismatch for key_id '{key_id}': "
            f"attestation claims {key_fp}, trusted is {expected_fp}"
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

    # 6. Monotonic Sequence & Anti-Rollback Verification
    seq = payload["release_sequence"]
    if seq < trust.min_sequence:
        raise ValueError(f"release sequence {seq} is below trust min_sequence {trust.min_sequence}")

    anti_rollback_verified = False
    if sequence_tracker is not None:
        last_accepted = sequence_tracker.get_last_accepted_sequence(
            payload["publisher"],
            allow_uninitialized=allow_uninitialized_state,
        )
        if seq <= last_accepted and not allow_rollback:
            raise ValueError(
                f"release sequence {seq} is replayed or downgraded "
                f"(last accepted sequence was {last_accepted}); rejection enforced for rollback protection"
            )
        if not allow_rollback:
            sequence_tracker.update_accepted_sequence(
                payload["publisher"],
                seq,
                allow_uninitialized=allow_uninitialized_state,
            )
            anti_rollback_verified = True
        else:
            anti_rollback_verified = False

    return {
        "status": "AUTHENTICATED",
        "authenticated": True,
        "integrity_only": False,
        "structural_valid": True,
        "evidence_integrity_valid": True,
        "publisher_authenticated": True,
        "anti_rollback_verified": anti_rollback_verified,
        "dataset_type": DATASET_TYPE_REAL,
        "release_sequence": seq,
        "total_observations": obs_count,
        "total_events": event_count,
        "manifest_sha256": manifest_sha,
        "publisher_identity": payload["publisher"],
        "key_id": key_id,
        "key_fingerprint": expected_fp,
        "safe_to_autonomously_act": False,
        "publisher_real_world_identity_verified": False,
    }

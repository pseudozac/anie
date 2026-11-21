"""Multi-Collector Federation Trust Architecture (Milestone M3.11).

Provides:
- Versioned collector receipt data models (schema anie.collector-receipt.v1).
- Ed25519 detached attestation signing for independent collectors.
- Trust-root enrollment, rotation, and revocation for collector identities.
- Monotonic sequence tracking, replay protection, and equivocation conflict detection.
- Purely offline verification with zero external network or infrastructure dependencies.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

COLLECTOR_RECEIPT_SCHEMA_V1 = "anie.collector-receipt.v1"
DOMAIN_SEPARATOR_RECEIPT_V1 = b"ANIE-COLLECTOR-RECEIPT-V1:"

_KEY_ID_RE = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,64}$")
_COLLECTOR_ID_RE = re.compile(r"^[a-zA-Z0-9_\-\.:/]{1,64}$")


def _crypto():
    """Import cryptography primitives lazily."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 federation signing and verification requires cryptography: "
            "pip install 'anie-intelligence[signing]'"
        ) from exc
    return InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization


def _dt(iso_str: str) -> datetime:
    """Parse ISO-8601 UTC timestamp."""
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))


@dataclass(frozen=True)
class CollectorReceipt:
    """Versioned cryptographic receipt issued by an empirical collector."""
    schema: str
    collector_identity: str
    key_id: str
    key_fingerprint: str
    dataset_digest: str
    collection_interval: dict[str, str]
    sequence_number: int
    source_context: dict[str, Any]
    signature_base64: str

    def __post_init__(self):
        if self.schema != COLLECTOR_RECEIPT_SCHEMA_V1:
            raise ValueError(f"unsupported receipt schema: {self.schema!r}")
        if not _COLLECTOR_ID_RE.fullmatch(self.collector_identity):
            raise ValueError(f"invalid collector_identity: {self.collector_identity!r}")
        if not _KEY_ID_RE.fullmatch(self.key_id):
            raise ValueError(f"invalid key_id: {self.key_id!r}")
        if len(self.key_fingerprint) != 64 or not all(c in "0123456789abcdef" for c in self.key_fingerprint.lower()):
            raise ValueError(f"invalid key_fingerprint SHA-256: {self.key_fingerprint!r}")
        if len(self.dataset_digest) != 64 or not all(c in "0123456789abcdef" for c in self.dataset_digest.lower()):
            raise ValueError(f"invalid dataset_digest SHA-256: {self.dataset_digest!r}")
        if self.sequence_number < 1:
            raise ValueError(f"sequence_number must be >= 1, got {self.sequence_number}")

        started_at = self.collection_interval.get("started_at")
        completed_at = self.collection_interval.get("completed_at")
        if not started_at or not completed_at:
            raise ValueError("collection_interval must specify started_at and completed_at")
        if _dt(started_at) > _dt(completed_at):
            raise ValueError("collection_interval started_at must be <= completed_at")

    def canonical_payload_dict(self) -> dict[str, Any]:
        """Produce the canonical, deterministic receipt payload excluding signature."""
        return {
            "schema": self.schema,
            "collector_identity": self.collector_identity,
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "dataset_digest": self.dataset_digest,
            "collection_interval": {
                "started_at": self.collection_interval["started_at"],
                "completed_at": self.collection_interval["completed_at"],
            },
            "sequence_number": self.sequence_number,
            "source_context": dict(sorted(self.source_context.items())),
        }

    def canonical_payload_bytes(self) -> bytes:
        """Serialize canonical payload to deterministic UTF-8 JSON bytes."""
        return json.dumps(
            self.canonical_payload_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def payload_sha256(self) -> str:
        """SHA-256 digest of the canonical receipt payload."""
        return sha256(self.canonical_payload_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert full receipt including signature to dictionary."""
        d = self.canonical_payload_dict()
        d["signature_base64"] = self.signature_base64
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CollectorReceipt":
        """Reconstruct CollectorReceipt from dictionary."""
        return cls(
            schema=data["schema"],
            collector_identity=data["collector_identity"],
            key_id=data["key_id"],
            key_fingerprint=data["key_fingerprint"],
            dataset_digest=data["dataset_digest"],
            collection_interval=dict(data["collection_interval"]),
            sequence_number=int(data["sequence_number"]),
            source_context=dict(data.get("source_context", {})),
            signature_base64=data["signature_base64"],
        )


def sign_collector_receipt(
    private_key: Any,
    *,
    collector_identity: str,
    key_id: str,
    dataset_digest: str,
    started_at: str,
    completed_at: str,
    sequence_number: int,
    source_context: dict[str, Any] | None = None,
) -> CollectorReceipt:
    """Sign and issue a deterministic CollectorReceipt using an Ed25519 private key."""
    InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization = _crypto()
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an instance of cryptography Ed25519PrivateKey")

    pub_key = private_key.public_key()
    pub_raw = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_fingerprint = sha256(pub_raw).hexdigest()

    unsigned = CollectorReceipt(
        schema=COLLECTOR_RECEIPT_SCHEMA_V1,
        collector_identity=collector_identity,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
        dataset_digest=dataset_digest,
        collection_interval={"started_at": started_at, "completed_at": completed_at},
        sequence_number=sequence_number,
        source_context=source_context or {},
        signature_base64="",
    )

    msg = DOMAIN_SEPARATOR_RECEIPT_V1 + unsigned.canonical_payload_bytes()
    sig_bytes = private_key.sign(msg)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    return CollectorReceipt(
        schema=unsigned.schema,
        collector_identity=unsigned.collector_identity,
        key_id=unsigned.key_id,
        key_fingerprint=unsigned.key_fingerprint,
        dataset_digest=unsigned.dataset_digest,
        collection_interval=unsigned.collection_interval,
        sequence_number=unsigned.sequence_number,
        source_context=unsigned.source_context,
        signature_base64=sig_b64,
    )


@dataclass
class CollectorKeyEnrollment:
    """Record of an enrolled collector public key in the trust store."""
    collector_identity: str
    key_id: str
    key_fingerprint: str
    public_key_raw_bytes: bytes
    valid_from: str
    valid_until: str
    revoked: bool = False
    revocation_reason: str | None = None


class CollectorTrustStore:
    """In-memory or SQLite-backed trust root for federated collector verification."""

    def __init__(self):
        self._keys: dict[tuple[str, str], CollectorKeyEnrollment] = {}
        self._revoked_keys: set[str] = set()

    def enroll_key(
        self,
        *,
        collector_identity: str,
        key_id: str,
        public_key: Any,
        valid_from: str,
        valid_until: str,
    ) -> CollectorKeyEnrollment:
        """Enroll an authorized collector public key with bounded validity interval."""
        InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization = _crypto()
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("public_key must be an instance of cryptography Ed25519PublicKey")

        pub_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = sha256(pub_raw).hexdigest()

        if _dt(valid_from) >= _dt(valid_until):
            raise ValueError("valid_from must be strictly before valid_until")

        enrollment = CollectorKeyEnrollment(
            collector_identity=collector_identity,
            key_id=key_id,
            key_fingerprint=fingerprint,
            public_key_raw_bytes=pub_raw,
            valid_from=valid_from,
            valid_until=valid_until,
            revoked=False,
            revocation_reason=None,
        )
        self._keys[(collector_identity, key_id)] = enrollment
        return enrollment

    def revoke_key(self, key_id: str, reason: str = "administrative_revocation") -> None:
        """Revoke a collector key across all collectors."""
        self._revoked_keys.add(key_id)
        for (col_id, k_id), enrollment in self._keys.items():
            if k_id == key_id:
                enrollment.revoked = True
                enrollment.revocation_reason = reason

    def get_enrolled_key(
        self,
        collector_identity: str,
        key_id: str,
        *,
        as_of: str | None = None,
    ) -> tuple[Any | None, str]:
        """Retrieve and validate an enrolled public key.
        
        Returns (public_key, status):
        status can be "OK", "UNENROLLED_COLLECTOR", "UNKNOWN_KEY", "REVOKED_KEY", "EXPIRED_KEY", "NOT_YET_VALID".
        """
        InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization = _crypto()
        enrollment = self._keys.get((collector_identity, key_id))
        if enrollment is None:
            # Check if collector identity is completely unknown
            has_col = any(c == collector_identity for (c, _) in self._keys.keys())
            if not has_col:
                return None, "UNENROLLED_COLLECTOR"
            return None, "UNKNOWN_KEY"

        if enrollment.revoked or key_id in self._revoked_keys:
            return None, "REVOKED_KEY"

        now_dt = _dt(as_of) if as_of else datetime.now(timezone.utc)
        if now_dt < _dt(enrollment.valid_from):
            return None, "NOT_YET_VALID"
        if now_dt > _dt(enrollment.valid_until):
            return None, "EXPIRED_KEY"

        pub_key = Ed25519PublicKey.from_public_bytes(enrollment.public_key_raw_bytes)
        return pub_key, "OK"


class CollectorSequenceTracker:
    """Monotonic sequence and anti-replay tracker for federated collector streams."""

    def __init__(self):
        # Maps collector_identity -> {"max_sequence": int, "batches_by_seq": {seq: (digest, interval)}}
        self._state: dict[str, dict[str, Any]] = {}

    def check_and_advance(
        self,
        *,
        collector_identity: str,
        sequence_number: int,
        dataset_digest: str,
        collection_interval: dict[str, str],
    ) -> tuple[bool, str]:
        """Check sequence number against replay and equivocation conflicts.
        
        Returns (is_valid, reason).
        """
        if collector_identity not in self._state:
            self._state[collector_identity] = {
                "max_sequence": sequence_number,
                "batches_by_seq": {sequence_number: (dataset_digest, collection_interval)},
            }
            return True, "ACCEPTED"

        col_state = self._state[collector_identity]
        cur_max = col_state["max_sequence"]
        batches = col_state["batches_by_seq"]

        if sequence_number in batches:
            prev_digest, prev_int = batches[sequence_number]
            if prev_digest != dataset_digest:
                return False, f"COLLECTOR_EQUIVOCATION_CONFLICT: sequence {sequence_number} already recorded with different digest {prev_digest[:12]}..."
            return False, f"REPLAY_DETECTED: sequence {sequence_number} duplicate"

        if sequence_number <= cur_max:
            return False, f"REPLAY_DETECTED: sequence {sequence_number} <= current max {cur_max}"

        col_state["max_sequence"] = sequence_number
        batches[sequence_number] = (dataset_digest, collection_interval)
        return True, "ACCEPTED"


def verify_collector_receipt(
    receipt: CollectorReceipt | dict[str, Any],
    trust_store: CollectorTrustStore,
    *,
    sequence_tracker: CollectorSequenceTracker | None = None,
    now: str | None = None,
    allow_untracked_sequence: bool = False,
) -> dict[str, Any]:
    """Verify cryptographic receipt signature, trust enrollment, validity window, and anti-replay sequence."""
    InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization = _crypto()

    if isinstance(receipt, dict):
        try:
            rcpt = CollectorReceipt.from_dict(receipt)
        except Exception as exc:
            return {
                "verified": False,
                "status": "MALFORMED_RECEIPT",
                "reason": str(exc),
            }
    else:
        rcpt = receipt

    # 1. Trust Store Lookup
    as_of = now or rcpt.collection_interval.get("completed_at")
    pub_key, key_status = trust_store.get_enrolled_key(
        rcpt.collector_identity,
        rcpt.key_id,
        as_of=as_of,
    )
    if pub_key is None:
        return {
            "verified": False,
            "status": key_status,
            "reason": f"Collector key enrollment check failed: {key_status}",
            "collector_identity": rcpt.collector_identity,
            "key_id": rcpt.key_id,
        }

    # Verify key fingerprint matches enrolled public key
    pub_raw = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expected_fingerprint = sha256(pub_raw).hexdigest()
    if rcpt.key_fingerprint != expected_fingerprint:
        return {
            "verified": False,
            "status": "FINGERPRINT_MISMATCH",
            "reason": f"Receipt fingerprint '{rcpt.key_fingerprint}' does not match enrolled key '{expected_fingerprint}'",
            "collector_identity": rcpt.collector_identity,
            "key_id": rcpt.key_id,
        }

    # 2. Cryptographic Ed25519 Signature Verification
    try:
        sig_bytes = base64.b64decode(rcpt.signature_base64)
    except Exception as exc:
        return {
            "verified": False,
            "status": "MALFORMED_SIGNATURE_ENCODING",
            "reason": f"base64 signature decode error: {exc}",
        }

    msg = DOMAIN_SEPARATOR_RECEIPT_V1 + rcpt.canonical_payload_bytes()
    try:
        pub_key.verify(sig_bytes, msg)
    except InvalidSignature:
        return {
            "verified": False,
            "status": "INVALID_SIGNATURE",
            "reason": "Cryptographic signature verification failed over canonical receipt payload",
            "collector_identity": rcpt.collector_identity,
            "key_id": rcpt.key_id,
        }

    # 3. Monotonic Sequence and Anti-Replay Tracking
    if sequence_tracker is not None:
        valid_seq, seq_reason = sequence_tracker.check_and_advance(
            collector_identity=rcpt.collector_identity,
            sequence_number=rcpt.sequence_number,
            dataset_digest=rcpt.dataset_digest,
            collection_interval=rcpt.collection_interval,
        )
        if not valid_seq:
            return {
                "verified": False,
                "status": "REPLAY_OR_EQUIVOCATION",
                "reason": seq_reason,
                "collector_identity": rcpt.collector_identity,
                "sequence_number": rcpt.sequence_number,
            }

    return {
        "verified": True,
        "status": "VERIFIED",
        "collector_identity": rcpt.collector_identity,
        "key_id": rcpt.key_id,
        "sequence_number": rcpt.sequence_number,
        "dataset_digest": rcpt.dataset_digest,
        "payload_sha256": rcpt.payload_sha256(),
    }

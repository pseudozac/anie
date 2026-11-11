"""Offline Ed25519 authentication of ANIE synthetic releases.

A signature proves possession of a private key corresponding to an
INDEPENDENTLY PINNED public key. It does not prove a real-world publisher
identity or authorize public distribution. Never embed production private
keys or accept public keys bundled with downloaded artifacts.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re

from .observations import canonical_json, utc_iso
from .publish import verify_release

# Import only when this optional feature is used; core ANIE is dependency-free.
def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise RuntimeError("offline release signing requires: pip install 'anie-intelligence[signing]'") from exc
    return InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, serialization


SIGNATURE_SCHEMA = "anie.ed25519-attestation.v1"
PAYLOAD_SCHEMA = "anie.synthetic-release.v1"
ATTESTATION_NAME = "attestation.ed25519.json"
DOMAIN_SEPARATOR = b"ANIE-SYNTHETIC-ED25519-RELEASE-V1\x00"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = "pseudozac/anie"
_BUILDER = "local-offline"
_MAX_ATTESTATION_BYTES = 8192


def _dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(utc_iso(value).replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("invalid UTC timestamp") from exc


def _read_manifest(directory: Path) -> tuple[bytes, str, dict]:
    path = directory / "manifest.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError("missing or unsafe manifest")
    payload = path.read_bytes()
    try:
        obj = json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid manifest JSON") from exc
    if not isinstance(obj, dict) or obj.get("dataset_type") != "synthetic_demo_only":
        raise ValueError("only synthetic release manifests are authorized")
    return payload, sha256(payload).hexdigest(), obj


def key_fingerprint(public_key_raw: bytes) -> str:
    if not isinstance(public_key_raw, bytes) or len(public_key_raw) != 32:
        raise ValueError("expected a 32-byte Ed25519 public key")
    return sha256(public_key_raw).hexdigest()


@dataclass(frozen=True)
class SignedReleaseTrust:
    """Operator-supplied trust roots and exact expected build provenance.

    The caller must persist the previously accepted sequence and maintain
    revocations outside the downloaded package. This object cannot secure
    those independent trust inputs by itself.
    """
    public_key_raw: bytes
    expected_source_commit: str
    last_accepted_sequence: int = 0
    max_age_seconds: int = 30 * 86400
    key_valid_from: str = "2020-01-01T00:00:00Z"
    key_valid_until: str = "2100-01-01T00:00:00Z"
    revoked_fingerprints: frozenset[str] = field(default_factory=frozenset)
    expected_repository: str = _REPOSITORY
    expected_builder: str = _BUILDER

    def __post_init__(self) -> None:
        key_fingerprint(self.public_key_raw)
        if not isinstance(self.expected_source_commit, str) or not _COMMIT.fullmatch(self.expected_source_commit):
            raise ValueError("source commit must be a complete lowercase SHA")
        if type(self.last_accepted_sequence) is not int or not 0 <= self.last_accepted_sequence <= 2**63 - 2:
            raise ValueError("invalid accepted release sequence")
        if type(self.max_age_seconds) is not int or not 0 <= self.max_age_seconds <= 30 * 86400:
            raise ValueError("invalid maximum age")
        if self.expected_repository != _REPOSITORY or self.expected_builder != _BUILDER:
            raise ValueError("unapproved publisher identity or builder")
        if _dt(self.key_valid_from) >= _dt(self.key_valid_until):
            raise ValueError("invalid key validity window")
        if not isinstance(self.revoked_fingerprints, frozenset) or any(not isinstance(v, str) or not _SHA256.fullmatch(v) for v in self.revoked_fingerprints):
            raise ValueError("invalid revoked key set")


def _validate_payload(payload: dict) -> None:
    fields = {
        "schema", "repository", "source_commit", "builder", "dataset_type",
        "manifest_sha256", "release_sequence", "issued_at", "expires_at",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("invalid signed payload fields")
    if payload["schema"] != PAYLOAD_SCHEMA or payload["dataset_type"] != "synthetic_demo_only":
        raise ValueError("unsupported signed release schema or origin")
    if payload["repository"] != _REPOSITORY or payload["builder"] != _BUILDER:
        raise ValueError("unapproved signed repository or builder")
    if not isinstance(payload["source_commit"], str) or not _COMMIT.fullmatch(payload["source_commit"]):
        raise ValueError("invalid source commit")
    if not isinstance(payload["manifest_sha256"], str) or not _SHA256.fullmatch(payload["manifest_sha256"]):
        raise ValueError("invalid manifest digest")
    if type(payload["release_sequence"]) is not int or not 1 <= payload["release_sequence"] <= 2**63 - 1:
        raise ValueError("invalid release sequence")
    if _dt(payload["issued_at"]) >= _dt(payload["expires_at"]):
        raise ValueError("invalid release validity period")
    if (_dt(payload["expires_at"]) - _dt(payload["issued_at"])).total_seconds() > 30 * 86400:
        raise ValueError("release lifetime exceeds 30 days")


def _message(payload: dict) -> bytes:
    _validate_payload(payload)
    return DOMAIN_SEPARATOR + canonical_json(payload).encode("utf-8")


def _public_key_raw(private_key: object) -> bytes:
    _, Ed25519PrivateKey, _, serialization = _crypto()
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("expected an in-memory Ed25519 private key")
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_synthetic_release(
    directory: str | Path,
    private_key: object,
    *,
    source_commit: str,
    release_sequence: int,
    issued_at: str,
    expires_at: str,
) -> dict:
    """Sign a local synthetic dataset in place with a caller-held ephemeral key.

    No network or key generation; private key is never written by this module.
    Existing attestation files cannot be overwritten.
    """
    directory = Path(directory)
    _, digest, manifest = _read_manifest(directory)
    verify_release(directory)  # Recompute data and evidence graph before signing.
    # Signed validity must not precede assessed-at; prevent stale signing attempts.
    if _dt(issued_at) < _dt(manifest["assessed_at"]):
        raise ValueError("cannot sign before dataset assessment time")
    payload = {
        "schema": PAYLOAD_SCHEMA,
        "repository": _REPOSITORY,
        "source_commit": source_commit,
        "builder": _BUILDER,
        "dataset_type": "synthetic_demo_only",
        "manifest_sha256": digest,
        "release_sequence": release_sequence,
        "issued_at": utc_iso(issued_at),
        "expires_at": utc_iso(expires_at),
    }
    message = _message(payload)
    raw_key = _public_key_raw(private_key)
    attestation = {
        "schema": SIGNATURE_SCHEMA,
        "payload": payload,
        "key_fingerprint": key_fingerprint(raw_key),
        "signature_base64": base64.b64encode(private_key.sign(message)).decode("ascii"),
    }
    dest = directory / ATTESTATION_NAME
    # Reject overwrite and symlinks rather than replacing a previous attestation.
    with dest.open("x", encoding="utf-8") as file:
        file.write(canonical_json(attestation) + "\n")
    return attestation


def verify_signed_synthetic_release(
    directory: str | Path,
    trust: SignedReleaseTrust,
    *,
    now: str,
) -> dict:
    """Authenticate the signed release using an independently pinned key.

    No implicit trust-on-first-use. Caller updates trusted monotonic state
    only AFTER verification and an atomic consumer import transaction.
    """
    if not isinstance(trust, SignedReleaseTrust):
        raise ValueError("explicit SignedReleaseTrust is required")
    directory = Path(directory)
    path = directory / ATTESTATION_NAME
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_ATTESTATION_BYTES:
        raise ValueError("missing or unsafe signed attestation")
    try:
        attestation = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid signed attestation") from exc
    if not isinstance(attestation, dict) or set(attestation) != {"schema", "payload", "key_fingerprint", "signature_base64"}:
        raise ValueError("invalid attestation fields")
    if attestation["schema"] != SIGNATURE_SCHEMA:
        raise ValueError("unsupported attestation schema")
    payload = attestation["payload"]
    message = _message(payload)
    fingerprint = key_fingerprint(trust.public_key_raw)
    if fingerprint in trust.revoked_fingerprints:
        raise ValueError("signing key revoked")
    if attestation["key_fingerprint"] != fingerprint:
        raise ValueError("publisher key fingerprint mismatch")
    signature_text = attestation["signature_base64"]
    if not isinstance(signature_text, str) or len(signature_text) != 88:
        raise ValueError("invalid signature encoding")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
        raise ValueError("invalid signature bytes")
    InvalidSignature, _, Ed25519PublicKey, _ = _crypto()
    try:
        Ed25519PublicKey.from_public_bytes(trust.public_key_raw).verify(signature, message)
    except InvalidSignature as exc:
        raise ValueError("Ed25519 signature verification failed") from exc
    # Only after cryptographic verification, interpret claimed metadata.
    if payload["repository"] != trust.expected_repository or payload["builder"] != trust.expected_builder:
        raise ValueError("unexpected publisher identity")
    if payload["source_commit"] != trust.expected_source_commit:
        raise ValueError("wrong source commit")
    if payload["release_sequence"] <= trust.last_accepted_sequence:
        raise ValueError("replayed or downgraded release sequence")
    current = _dt(now)
    if not _dt(trust.key_valid_from) <= current <= _dt(trust.key_valid_until):
        raise ValueError("trust key expired or not yet valid")
    if not _dt(payload["issued_at"]) <= current <= _dt(payload["expires_at"]):
        raise ValueError("signed release not currently valid")
    _, digest, manifest = _read_manifest(directory)
    if digest != payload["manifest_sha256"]:
        raise ValueError("signed manifest digest mismatch")
    assessed = _dt(manifest["assessed_at"])
    age = (current - assessed).total_seconds()
    if age < 0 or age > trust.max_age_seconds:
        raise ValueError("synthetic dataset future-dated or stale")
    if _dt(payload["issued_at"]) < assessed:
        raise ValueError("signature predates dataset assessment")
    verified = verify_release(directory)
    return {
        **verified,
        "publisher_signature_verified": True,
        "trust_method": "operator_pinned_ed25519_public_key",
        "publisher_key_fingerprint": fingerprint,
        "source_commit": payload["source_commit"],
        "release_sequence": payload["release_sequence"],
        "manifest_sha256": digest,
        "safe_to_autonomously_act": False,
        "publisher_real_world_identity_verified": False,
    }

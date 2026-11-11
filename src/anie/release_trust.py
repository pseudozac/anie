"""Offline consumer trust gate for synthetic ANIE release directories.

Trust is established OUTSIDE the downloaded artifact by a separately pinned
manifest SHA-256. This is not a digital signature or publisher attestation.
No network calls, publication, or AEGIS integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re

from . import SCHEMA
from .observations import utc_iso
from .publish import verify_release, MANIFEST_SCHEMA

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ConsumerTrustPolicy:
    """Out-of-band pin supplied by operator, not from the release itself."""
    manifest_sha256: str
    max_age_seconds: int = 86400 * 30
    expected_schema: str = SCHEMA
    expected_dataset_type: str = "synthetic_demo_only"

    def __post_init__(self) -> None:
        if not isinstance(self.manifest_sha256, str) or not _SHA.fullmatch(self.manifest_sha256):
            raise ValueError("manifest SHA-256 pin must be exactly 64 lowercase hex characters")
        if type(self.max_age_seconds) is not int or not 0 <= self.max_age_seconds <= 86400 * 365:
            raise ValueError("invalid maximum age")
        if self.expected_schema != SCHEMA or self.expected_dataset_type != "synthetic_demo_only":
            raise ValueError("unsupported consumer schema or dataset type")


def verify_pinned_synthetic_release(
    directory: str | Path,
    policy: ConsumerTrustPolicy,
    *,
    now: str,
) -> dict:
    """Fail closed on hash mismatch, staleness, unsupported contracts or data corruption.

    Caller MUST obtain manifest_sha256 from an independently authenticated
    channel. Supplying the hash from the same untrusted download is unsafe.
    """
    directory = Path(directory)
    manifest_file = directory / "manifest.json"
    if not manifest_file.is_file() or manifest_file.is_symlink():
        raise ValueError("missing or unsafe manifest")
    if manifest_file.stat().st_size > 65536:
        raise ValueError("manifest exceeds size limit")
    actual = sha256(manifest_file.read_bytes()).hexdigest()
    if actual != policy.manifest_sha256:
        raise ValueError("out-of-band manifest pin mismatch")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("unsupported manifest schema")
    if manifest.get("intelligence_schema") != policy.expected_schema:
        raise ValueError("unsupported intelligence schema")
    if manifest.get("dataset_type") != policy.expected_dataset_type:
        raise ValueError("unsupported dataset type")
    from datetime import datetime
    assessed = datetime.fromisoformat(utc_iso(manifest.get("assessed_at")).replace("Z", "+00:00"))
    current = datetime.fromisoformat(utc_iso(now).replace("Z", "+00:00"))
    age = (current - assessed).total_seconds()
    if age < 0:
        raise ValueError("future-dated release")
    if age > policy.max_age_seconds:
        raise ValueError("stale release")
    result = verify_release(directory)
    return {
        **result,
        "trust_method": "operator_supplied_out_of_band_sha256_pin",
        "publisher_signature_verified": False,
        "manifest_sha256": actual,
        "age_seconds": int(age),
        "safe_to_autonomously_act": False,
    }


def validate_release_provenance(provenance: dict, *, expected_commit: str, manifest_sha256: str) -> dict:
    """Pure contract validator for FUTURE signed attestation envelope metadata.

    Never treat successful validation as a cryptographic signature check.
    """
    if not isinstance(provenance, dict) or set(provenance) != {
        "schema", "source_commit", "manifest_sha256", "builder", "dataset_type",
        "signature_state",
    }:
        raise ValueError("invalid provenance envelope")
    if not isinstance(expected_commit, str) or not _COMMIT.fullmatch(expected_commit):
        raise ValueError("invalid expected source commit")
    if not isinstance(manifest_sha256, str) or not _SHA.fullmatch(manifest_sha256):
        raise ValueError("invalid expected manifest hash")
    if provenance["schema"] != "anie.release-provenance.v1":
        raise ValueError("unsupported provenance schema")
    if provenance["source_commit"] != expected_commit or provenance["manifest_sha256"] != manifest_sha256:
        raise ValueError("source-to-artifact provenance mismatch")
    if provenance["dataset_type"] != "synthetic_demo_only":
        raise ValueError("non-synthetic provenance not authorized")
    if provenance["builder"] != "local-offline":
        raise ValueError("unapproved builder identity")
    if provenance["signature_state"] != "unsigned_design_only":
        raise ValueError("unverified signature claim")
    return {"metadata_consistent": True, "publisher_signature_verified": False}

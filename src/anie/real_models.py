"""Strictly validated real-world observation and collection provenance models.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 1).
Separated from synthetic models to prevent cross-contamination.

Invariants:
- Real observations MUST explicitly have synthetic=False.
- Method MUST NOT be "synthetic"; genuine measurements use "dns" or "rdap".
- Confidence is explicitly nullable; factual verification attributes are kept separate.
- Evidence references are cryptographically linked to RealCollectionEvent.
- Deterministic canonical serialization is enforced for all IDs.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any

from .observations import (
    canonical_json,
    normalized_domain,
    normalized_ip,
    utc_iso,
    _normalize_value,
    KINDS,
    STATUSES,
    ERROR_CODES,
)

REAL_OBSERVATION_SCHEMA = "anie.observation.real.v1"
REAL_EVENT_SCHEMA = "anie.collection-event.real.v1"
REAL_REQUEST_SCHEMA = "anie.collection-request.real.v1"

ALLOWED_REAL_METHODS = {"dns", "rdap"}
DNSSEC_STATUSES = {"secure", "insecure", "bogus", "indeterminate"}
RESPONSE_AUTHENTICITIES = {"authoritative", "recursive", "unverified"}
TRANSPORT_SECURITIES = {"tls_pinned", "tls_unpinned", "plain"}
RAW_EVIDENCE_STATUSES = {"captured", "unavailable", "redacted", "oversized"}

MAX_RAW_PAYLOAD_BYTES = 65535
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = re.compile(r"^[a-zA-Z0-9_.:-]{1,80}$")
_EVENT_ID = re.compile(r"^event_[0-9a-f]{64}$")


@dataclass(frozen=True)
class FactualVerification:
    """Factual, empirical verification attributes of a measurement transport."""
    dnssec_status: str
    response_authenticity: str
    transport_security: str
    resolver_identity: str
    wire_rcode: str
    raw_evidence_status: str

    def __post_init__(self):
        if self.dnssec_status not in DNSSEC_STATUSES:
            raise ValueError(f"invalid dnssec_status: {self.dnssec_status}")
        if self.response_authenticity not in RESPONSE_AUTHENTICITIES:
            raise ValueError(f"invalid response_authenticity: {self.response_authenticity}")
        if self.transport_security not in TRANSPORT_SECURITIES:
            raise ValueError(f"invalid transport_security: {self.transport_security}")
        if not isinstance(self.resolver_identity, str) or not self.resolver_identity:
            raise ValueError("resolver_identity must be a non-empty string")
        if not isinstance(self.wire_rcode, str) or not self.wire_rcode:
            raise ValueError("wire_rcode must be a non-empty string")
        if self.raw_evidence_status not in RAW_EVIDENCE_STATUSES:
            raise ValueError(f"invalid raw_evidence_status: {self.raw_evidence_status}")

    def to_dict(self) -> dict[str, str]:
        return {
            "dnssec_status": self.dnssec_status,
            "response_authenticity": self.response_authenticity,
            "transport_security": self.transport_security,
            "resolver_identity": self.resolver_identity,
            "wire_rcode": self.wire_rcode,
            "raw_evidence_status": self.raw_evidence_status,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "FactualVerification":
        if not isinstance(raw, dict):
            raise ValueError("factual_verification must be a dict")
        allowed = {
            "dnssec_status",
            "response_authenticity",
            "transport_security",
            "resolver_identity",
            "wire_rcode",
            "raw_evidence_status",
        }
        if set(raw) != allowed:
            raise ValueError(f"unexpected factual_verification fields: {set(raw) ^ allowed}")
        return cls(
            dnssec_status=raw["dnssec_status"],
            response_authenticity=raw["response_authenticity"],
            transport_security=raw["transport_security"],
            resolver_identity=raw["resolver_identity"],
            wire_rcode=raw["wire_rcode"],
            raw_evidence_status=raw["raw_evidence_status"],
        )


@dataclass(frozen=True)
class RealCollectionRequest:
    """Strictly typed and canonicalized target collection request."""
    kind: str
    subject: str
    observed_at: str
    target_endpoint: str
    pinned_ip: str

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"unsupported request kind: {self.kind}")
        if not isinstance(self.target_endpoint, str) or not self.target_endpoint.startswith("https://"):
            raise ValueError("target_endpoint must be a valid https URL")
        if not isinstance(self.pinned_ip, str) or not self.pinned_ip:
            raise ValueError("pinned_ip must be specified")

    @classmethod
    def create(
        cls,
        kind: str,
        subject: str,
        observed_at: str,
        target_endpoint: str,
        pinned_ip: str,
    ) -> "RealCollectionRequest":
        norm_subject = (
            normalized_domain(subject)
            if KINDS[kind] == "domain"
            else normalized_ip(subject)
        )
        norm_time = utc_iso(observed_at)
        norm_ip = normalized_ip(pinned_ip)
        return cls(kind, norm_subject, norm_time, target_endpoint, norm_ip)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REAL_REQUEST_SCHEMA,
            "kind": self.kind,
            "subject": self.subject,
            "observed_at": self.observed_at,
            "target_endpoint": self.target_endpoint,
            "pinned_ip": self.pinned_ip,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RealCollectionRequest":
        if not isinstance(raw, dict) or raw.get("schema") != REAL_REQUEST_SCHEMA:
            raise ValueError("invalid RealCollectionRequest schema")
        return cls.create(
            kind=raw["kind"],
            subject=raw["subject"],
            observed_at=raw["observed_at"],
            target_endpoint=raw["target_endpoint"],
            pinned_ip=raw["pinned_ip"],
        )


@dataclass(frozen=True)
class RealCollectionEvent:
    """Immutable provenance capture record preserving empirical wire evidence.
    
    Stores normalized capture metadata, factual transport verification,
    and optional bounded raw wire payload (capped at 65,535 bytes).
    """
    request: RealCollectionRequest
    response_code: str
    raw_sha256: str
    raw_evidence_status: str
    factual_verification: FactualVerification
    source_id: str
    observed_at: str
    raw_payload: bytes | None = None

    def __post_init__(self):
        if not isinstance(self.request, RealCollectionRequest):
            raise ValueError("request must be an instance of RealCollectionRequest")
        if not isinstance(self.response_code, str) or not self.response_code:
            raise ValueError("response_code must be non-empty")
        if not isinstance(self.raw_sha256, str) or not _HEX_64.fullmatch(self.raw_sha256):
            raise ValueError("raw_sha256 must be a 64-character lowercase hex digest")
        if self.raw_evidence_status not in RAW_EVIDENCE_STATUSES:
            raise ValueError(f"invalid raw_evidence_status: {self.raw_evidence_status}")
        if not isinstance(self.factual_verification, FactualVerification):
            raise ValueError("factual_verification must be an instance of FactualVerification")
        if not isinstance(self.source_id, str) or not _SOURCE.fullmatch(self.source_id):
            raise ValueError("invalid source_id format")
        if self.source_id.startswith("synthetic:"):
            raise ValueError("real collection event cannot originate from synthetic source")
        if not isinstance(self.observed_at, str):
            raise ValueError("observed_at must be an ISO-8601 string")
        
        # Verify raw payload constraints and integrity
        if self.raw_evidence_status == "captured":
            if self.raw_payload is None:
                raise ValueError("raw_payload must be provided when raw_evidence_status is 'captured'")
            if not isinstance(self.raw_payload, (bytes, bytearray)):
                raise ValueError("raw_payload must be bytes")
            if len(self.raw_payload) > MAX_RAW_PAYLOAD_BYTES:
                raise ValueError(f"raw_payload exceeds maximum size of {MAX_RAW_PAYLOAD_BYTES} bytes")
            computed_sha = sha256(self.raw_payload).hexdigest()
            if computed_sha != self.raw_sha256:
                raise ValueError(f"raw_sha256 mismatch: expected {self.raw_sha256}, got {computed_sha}")
        elif self.raw_evidence_status in {"unavailable", "redacted", "oversized"}:
            if self.raw_payload is not None:
                if len(self.raw_payload) > MAX_RAW_PAYLOAD_BYTES and self.raw_evidence_status != "oversized":
                    raise ValueError("payload exceeding bounds must have status 'oversized'")
                computed_sha = sha256(self.raw_payload).hexdigest()
                if computed_sha != self.raw_sha256:
                    raise ValueError(f"raw_sha256 mismatch: expected {self.raw_sha256}, got {computed_sha}")

    def verify_raw_evidence(self) -> bool:
        """Explicitly re-verify raw evidence payload against raw_sha256 and status constraints."""
        if self.raw_evidence_status == "captured":
            if self.raw_payload is None or not isinstance(self.raw_payload, (bytes, bytearray)):
                return False
            if len(self.raw_payload) > MAX_RAW_PAYLOAD_BYTES:
                return False
            return sha256(self.raw_payload).hexdigest() == self.raw_sha256
        elif self.raw_evidence_status in RAW_EVIDENCE_STATUSES:
            if self.raw_payload is not None:
                return sha256(self.raw_payload).hexdigest() == self.raw_sha256
            return bool(_HEX_64.fullmatch(self.raw_sha256))
        return False

    @property
    def event_id(self) -> str:
        """Deterministic canonical event ID."""
        canonical = canonical_json(self.to_canonical_dict())
        return "event_" + sha256(canonical.encode("utf-8")).hexdigest()

    def to_canonical_dict(self) -> dict[str, Any]:
        """Deterministic canonical serialization for identity hashing."""
        data: dict[str, Any] = {
            "factual_verification": self.factual_verification.to_dict(),
            "observed_at": self.observed_at,
            "raw_evidence_status": self.raw_evidence_status,
            "raw_sha256": self.raw_sha256,
            "request": self.request.to_dict(),
            "response_code": self.response_code,
            "schema": REAL_EVENT_SCHEMA,
            "source_id": self.source_id,
        }
        if self.raw_payload is not None:
            data["raw_payload_b64"] = base64.b64encode(self.raw_payload).decode("ascii")
        return data

    def to_dict(self) -> dict[str, Any]:
        """Full representation including event_id."""
        d = self.to_canonical_dict()
        d["event_id"] = self.event_id
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RealCollectionEvent":
        if not isinstance(raw, dict) or raw.get("schema") != REAL_EVENT_SCHEMA:
            raise ValueError("invalid RealCollectionEvent schema")
        request = RealCollectionRequest.from_dict(raw["request"])
        factual = FactualVerification.from_dict(raw["factual_verification"])
        raw_payload = None
        if "raw_payload_b64" in raw and raw["raw_payload_b64"] is not None:
            raw_payload = base64.b64decode(raw["raw_payload_b64"])
        event = cls(
            request=request,
            response_code=raw["response_code"],
            raw_sha256=raw["raw_sha256"],
            raw_evidence_status=raw["raw_evidence_status"],
            factual_verification=factual,
            source_id=raw["source_id"],
            observed_at=utc_iso(raw["observed_at"]),
            raw_payload=raw_payload,
        )
        if not event.verify_raw_evidence():
            raise ValueError(f"raw evidence verification failed for event {event.event_id}")
        if "event_id" in raw and raw["event_id"] != event.event_id:
            raise ValueError("event_id integrity mismatch")
        return event


@dataclass(frozen=True)
class RealObservation:
    """Strictly validated real-world observation point-in-time snapshot.
    
    Mandatory Invariants:
    - synthetic MUST be False.
    - method MUST be in {"dns", "rdap"}, NEVER "synthetic".
    - confidence is explicitly nullable (None if unassessed).
    - evidence_id MUST link to an authenticated RealCollectionEvent.
    """
    subject: str
    kind: str
    observed_at: str
    values: tuple[str, ...]
    status: str
    source_id: str
    method: str
    synthetic: bool
    evidence_id: str
    factual_verification: FactualVerification
    ttl_seconds: int | None = None
    error_code: str | None = None
    confidence: float | None = None

    def __post_init__(self):
        if self.synthetic is not False:
            raise ValueError("real observation must explicitly have synthetic=False")
        if self.method not in ALLOWED_REAL_METHODS:
            raise ValueError(f"real observation method must be in {ALLOWED_REAL_METHODS}; got {self.method}")
        if self.kind not in KINDS:
            raise ValueError(f"unsupported kind: {self.kind}")
        if self.status not in STATUSES:
            raise ValueError(f"unsupported status: {self.status}")
        if not isinstance(self.source_id, str) or not _SOURCE.fullmatch(self.source_id):
            raise ValueError("invalid source_id format")
        if self.source_id.startswith("synthetic:"):
            raise ValueError("real observation cannot have synthetic source_id")
        if not isinstance(self.evidence_id, str) or not _EVENT_ID.fullmatch(self.evidence_id):
            raise ValueError(f"evidence_id must match event_[0-9a-f]{{64}}; got {self.evidence_id}")
        if not isinstance(self.factual_verification, FactualVerification):
            raise ValueError("factual_verification must be an instance of FactualVerification")
        
        # Validate confidence: explicitly nullable; if present, must be bounded [0.0, 1.0]
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
                raise ValueError("confidence must be a float or None")
            if not (0.0 <= float(self.confidence) <= 1.0):
                raise ValueError("confidence must be between 0.0 and 1.0 inclusive")

        # Status & values validation
        if (self.status == "ok") != bool(self.values):
            raise ValueError("status 'ok' requires nonempty values; empty/error requires empty values")
        if self.status == "error":
            if self.error_code not in ERROR_CODES:
                raise ValueError("errors require a valid error_code")
        elif self.error_code is not None:
            raise ValueError("successful or empty observations cannot have error_code")

        if self.ttl_seconds is not None:
            if type(self.ttl_seconds) is not int or not (0 <= self.ttl_seconds <= 604800):
                raise ValueError("ttl_seconds must be an integer between 0 and 604800")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RealObservation":
        if not isinstance(raw, dict):
            raise ValueError("real observation must be a dictionary")
        if raw.get("schema") != REAL_OBSERVATION_SCHEMA:
            raise ValueError(f"expected schema {REAL_OBSERVATION_SCHEMA}, got {raw.get('schema')}")
        
        allowed_keys = {
            "schema",
            "subject",
            "kind",
            "observed_at",
            "values",
            "status",
            "source_id",
            "method",
            "synthetic",
            "evidence_id",
            "factual_verification",
            "ttl_seconds",
            "error_code",
            "confidence",
            "observation_id",
        }
        if set(raw) - allowed_keys:
            raise ValueError(f"unrecognized real observation fields: {set(raw) - allowed_keys}")

        synthetic = raw.get("synthetic")
        if synthetic is not False:
            raise ValueError("real observation must have synthetic=False")

        kind = raw.get("kind")
        if kind not in KINDS:
            raise ValueError("unsupported kind")
        subject = (
            normalized_domain(raw.get("subject"))
            if KINDS[kind] == "domain"
            else normalized_ip(raw.get("subject"))
        )

        vals = raw.get("values", [])
        if not isinstance(vals, list) or len(vals) > 64 or any(not isinstance(v, str) or len(v) > 256 for v in vals):
            raise ValueError("values must be a bounded list of strings")
        normalized_vals = tuple(sorted({_normalize_value(kind, v, subject) for v in vals}))

        factual = FactualVerification.from_dict(raw.get("factual_verification", {}))
        confidence = raw.get("confidence")
        if confidence is not None:
            confidence = float(confidence)

        ob = cls(
            subject=subject,
            kind=kind,
            observed_at=utc_iso(raw.get("observed_at")),
            values=normalized_vals,
            status=raw.get("status"),
            source_id=raw.get("source_id"),
            method=raw.get("method"),
            synthetic=False,
            evidence_id=raw.get("evidence_id"),
            factual_verification=factual,
            ttl_seconds=raw.get("ttl_seconds"),
            error_code=raw.get("error_code"),
            confidence=confidence,
        )
        if "observation_id" in raw and raw["observation_id"] != ob.observation_id:
            raise ValueError("observation_id integrity mismatch")
        return ob

    @property
    def observation_id(self) -> str:
        """Deterministic canonical observation ID."""
        canonical = canonical_json(self.to_canonical_dict())
        return "obs_" + sha256(canonical.encode("utf-8")).hexdigest()

    def to_canonical_dict(self) -> dict[str, Any]:
        """Deterministic canonical representation for identity hashing."""
        return {
            "confidence": self.confidence,
            "error_code": self.error_code,
            "evidence_id": self.evidence_id,
            "factual_verification": self.factual_verification.to_dict(),
            "kind": self.kind,
            "method": self.method,
            "observed_at": self.observed_at,
            "schema": REAL_OBSERVATION_SCHEMA,
            "source_id": self.source_id,
            "status": self.status,
            "subject": self.subject,
            "synthetic": False,
            "ttl_seconds": self.ttl_seconds,
            "values": list(self.values),
        }

    def to_dict(self) -> dict[str, Any]:
        """Full representation including observation_id."""
        d = self.to_canonical_dict()
        d["observation_id"] = self.observation_id
        return d

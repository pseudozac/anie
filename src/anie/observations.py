"""Strictly validated, complete point-in-time observation snapshots.

Each DNS snapshot represents an entire answer set returned for one query type.
Errors are never interpreted as a negative result or evidence of a DNS change.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import re
from typing import Any

KINDS = {"dns_a": "domain", "dns_aaaa": "domain", "dns_ptr": "ip", "rdap_asn": "ip", "rdap_network": "ip"}
STATUSES = {"ok", "empty", "error"}
ERROR_CODES = {"timeout", "unavailable", "invalid_response", "rate_limited", "unknown"}
_SOURCE = re.compile(r"^[a-zA-Z0-9_.:-]{1,80}$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def utc_iso(value: str) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp must be a compact ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalized_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("domain must be a string")
    value = value.rstrip(".").lower()
    if not value or len(value) > 253 or any(ord(ch) < 33 for ch in value):
        raise ValueError("invalid domain")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    labels = value.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid domain labels")
    return value


def normalized_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid IP address") from exc


def _normalize_value(kind: str, value: str, subject: str) -> str:
    if kind in {"dns_a", "dns_aaaa"}:
        addr = ipaddress.ip_address(value)
        if (kind == "dns_a" and addr.version != 4) or (kind == "dns_aaaa" and addr.version != 6):
            raise ValueError("DNS record address-family mismatch")
        return str(addr)
    if kind == "dns_ptr":
        return normalized_domain(value)
    if kind == "rdap_asn":
        match = re.fullmatch(r"(?:AS)?([0-9]{1,10})", value, re.IGNORECASE)
        if not match or not 0 <= int(match.group(1)) <= 4294967295:
            raise ValueError("invalid ASN")
        return f"AS{int(match.group(1))}"
    if kind == "rdap_network":
        network = ipaddress.ip_network(value, strict=False)
        if ipaddress.ip_address(subject) not in network:
            raise ValueError("RDAP network must contain subject IP")
        return str(network)
    raise ValueError("unsupported kind")


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class Observation:
    subject: str
    kind: str
    observed_at: str
    values: tuple[str, ...]
    status: str
    source_id: str
    method: str
    synthetic: bool
    ttl_seconds: int | None = None
    error_code: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Observation":
        if not isinstance(raw, dict):
            raise ValueError("observation must be an object")
        allowed = {"subject", "kind", "observed_at", "values", "status", "source_id", "method", "synthetic", "ttl_seconds", "error_code"}
        if set(raw) - allowed:
            raise ValueError("unrecognized observation field")
        kind = raw.get("kind")
        if kind not in KINDS:
            raise ValueError("unsupported observation kind")
        subject = normalized_domain(raw.get("subject")) if KINDS[kind] == "domain" else normalized_ip(raw.get("subject"))
        status = raw.get("status")
        if status not in STATUSES:
            raise ValueError("unsupported observation status")
        vals = raw.get("values")
        if not isinstance(vals, list) or len(vals) > 64 or any(not isinstance(v, str) or len(v) > 256 for v in vals):
            raise ValueError("values must be a bounded array of strings")
        normalized = tuple(sorted({_normalize_value(kind, v, subject) for v in vals}))
        if (status == "ok") != bool(normalized):
            raise ValueError("ok requires nonempty values; empty/error requires no values")
        source = raw.get("source_id")
        if not isinstance(source, str) or not _SOURCE.fullmatch(source):
            raise ValueError("invalid source ID")
        method = raw.get("method")
        if method not in {"synthetic", "dns", "rdap"}:
            raise ValueError("invalid collection method")
        synthetic = raw.get("synthetic")
        if not isinstance(synthetic, bool):
            raise ValueError("synthetic must be boolean")
        if synthetic != (method == "synthetic"):
            raise ValueError("synthetic origin must match synthetic method")
        ttl = raw.get("ttl_seconds")
        if ttl is not None and (type(ttl) is not int or not 0 <= ttl <= 604800):
            raise ValueError("TTL out of bounds")
        error_code = raw.get("error_code")
        if status == "error":
            if error_code not in ERROR_CODES:
                raise ValueError("errors require a bounded error_code")
        elif error_code is not None:
            raise ValueError("successful observations cannot have error_code")
        if status == "empty" and normalized:
            raise ValueError("empty observation must have no values")
        return cls(subject, kind, utc_iso(raw.get("observed_at")), normalized, status, source, method, synthetic, ttl, error_code)

    @property
    def observation_id(self) -> str:
        return "obs_" + sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject, "kind": self.kind, "observed_at": self.observed_at,
            "values": list(self.values), "status": self.status, "source_id": self.source_id,
            "method": self.method, "synthetic": self.synthetic,
            "ttl_seconds": self.ttl_seconds, "error_code": self.error_code,
        }

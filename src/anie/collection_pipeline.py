"""Synthetic fixture-only DNS/RDAP pipeline; no live network transport exists.

CollectionEvent preserves response semantics separately from the v0.1
Observation schema, so old observation IDs and consumer contracts stay stable.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
from typing import Any, Mapping, Protocol

from .collection_policy import CollectionBudget, CollectionPolicy, ScopeDenied, normalize_subject
from .observations import Observation, canonical_json, normalized_domain, utc_iso

QUERY_KINDS = {"dns_a": "A", "dns_aaaa": "AAAA", "dns_ptr": "PTR"}
RDAP_KINDS = {"rdap_network"}
TRANSPORT_ERRORS = {"timeout": "timeout", "rate_limited": "rate_limited", "unavailable": "unavailable"}
RCODE_ERRORS = {"SERVFAIL": "unavailable", "REFUSED": "unavailable", "NOTIMP": "unavailable", "FORMERR": "invalid_response"}


@dataclass(frozen=True)
class CollectionRequest:
    kind: str
    subject: str
    observed_at: str

    @classmethod
    def create(cls, kind: str, subject: str, observed_at: str) -> "CollectionRequest":
        return cls(kind, normalize_subject(kind, subject), utc_iso(observed_at))


@dataclass(frozen=True)
class CollectionEvent:
    request: CollectionRequest
    response_code: str
    observation: Observation
    raw_sha256: str
    source_id: str

    @property
    def event_id(self) -> str:
        return "event_" + sha256(canonical_json(self.to_dict()).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "anie.collection-event.v1",
            "request": {"kind": self.request.kind, "subject": self.request.subject, "observed_at": self.request.observed_at},
            "response_code": self.response_code,
            "observation": {"observation_id": self.observation.observation_id, **self.observation.to_dict()},
            "raw_sha256": self.raw_sha256,
            "source_id": self.source_id,
        }


class OfflineTransport(Protocol):
    """Offline-only fixture interface; not an authorization to add a live client."""
    def exchange(self, request: CollectionRequest) -> Mapping[str, Any]: ...


class FixtureTransport:
    """Frozen, in-memory synthetic fixtures. No network or file I/O."""
    def __init__(self, fixtures: Mapping[tuple[str, str], Mapping[str, Any]]):
        if not isinstance(fixtures, Mapping) or len(fixtures) > 256:
            raise ValueError("fixtures must be a bounded mapping")
        self._data: dict[tuple[str, str], dict[str, Any]] = {}
        for (kind, subject), response in fixtures.items():
            if not isinstance(response, Mapping):
                raise ValueError("fixture must be an object")
            key = (kind, normalize_subject(kind, subject))
            if key in self._data:
                raise ValueError("duplicate normalized fixture key")
            # Deep copy and reject non-serializable data before any collection.
            import json
            self._data[key] = json.loads(canonical_json(dict(response)))

    def exchange(self, request: CollectionRequest) -> Mapping[str, Any]:
        key = (request.kind, request.subject)
        if key not in self._data:
            raise ScopeDenied("no explicit offline fixture available")
        return self._data[key].copy()


def _parse_dns(raw: Mapping[str, Any], request: CollectionRequest) -> tuple[str, list[str], int | None, str | None, str]:
    if raw.get("protocol") != "dns" or raw.get("truncated") is not False or raw.get("complete") is not True:
        raise ValueError("only complete, non-truncated DNS fixture snapshots are accepted")
    if raw.get("qtype") != QUERY_KINDS[request.kind]:
        raise ValueError("mismatched DNS question type")
    question = raw.get("question")
    normalized = normalized_domain(question) if request.kind != "dns_ptr" else normalize_subject("dns_ptr", question)
    if normalized != request.subject:
        raise ValueError("DNS response question does not match the requested target")
    rcode = raw.get("rcode")
    answers = raw.get("answers")
    if rcode not in {"NOERROR", "NXDOMAIN", *RCODE_ERRORS} or not isinstance(answers, list) or len(answers) > 64:
        raise ValueError("invalid DNS response code or answer list")
    if rcode in RCODE_ERRORS:
        if answers:
            raise ValueError("error response must not include a complete successful answer set")
        return "error", [], None, RCODE_ERRORS[rcode], rcode
    if rcode == "NXDOMAIN":
        if answers:
            raise ValueError("simplified NXDOMAIN fixture must not contain answer records")
        return "empty", [], _negative_ttl(raw), None, "NXDOMAIN"
    values = []
    ttls = []
    for item in answers:
        if not isinstance(item, dict) or item.get("type") != QUERY_KINDS[request.kind]:
            raise ValueError("unexpected DNS record type or malformed record")
        ttl = item.get("ttl")
        if type(ttl) is not int or not 0 <= ttl <= 604800:
            raise ValueError("invalid DNS TTL")
        value = item.get("value")
        if not isinstance(value, str):
            raise ValueError("invalid DNS answer value")
        values.append(value)
        ttls.append(ttl)
    if not values:
        if raw.get("negative_proof") != "NODATA":
            raise ValueError("cannot distinguish NODATA from referral/incomplete response")
        return "empty", [], _negative_ttl(raw), None, "NODATA"
    if raw.get("negative_proof") is not None:
        raise ValueError("positive DNS answer cannot be negative")
    return "ok", values, min(ttls), None, "ANSWER"


def _negative_ttl(raw: Mapping[str, Any]) -> int | None:
    ttl = raw.get("negative_ttl")
    if ttl is not None and (type(ttl) is not int or not 0 <= ttl <= 604800):
        raise ValueError("invalid negative TTL")
    return ttl


def _rdap_network(raw: Mapping[str, Any], subject: str) -> list[str]:
    if not isinstance(raw, dict) or raw.get("objectClassName") != "ip network":
        raise ValueError("RDAP /ip objectClassName mismatch")
    address = ipaddress.ip_address(subject)
    ip_version = raw.get("ipVersion")
    if ip_version is not None and ip_version != ("v4" if address.version == 4 else "v6"):
        raise ValueError("RDAP IP version mismatch")
    start = raw.get("startAddress")
    end = raw.get("endAddress")
    low = high = None
    if start is not None or end is not None:
        if not isinstance(start, str) or not isinstance(end, str):
            raise ValueError("incomplete RDAP address range")
        low, high = ipaddress.ip_address(start), ipaddress.ip_address(end)
        if low.version != address.version or high.version != address.version or low > high or not low <= address <= high:
            raise ValueError("RDAP range does not contain subject IP")
    cidrs = raw.get("cidr0_cidrs")
    candidates = []
    if cidrs is not None:
        if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 64:
            raise ValueError("invalid RDAP CIDR extension")
        for item in cidrs:
            if not isinstance(item, dict) or type(item.get("length")) is not int:
                raise ValueError("invalid CIDR extension entry")
            prefix = item.get("v4prefix" if address.version == 4 else "v6prefix")
            if not isinstance(prefix, str):
                raise ValueError("wrong CIDR address family")
            network = ipaddress.ip_network(f"{prefix}/{item['length']}", strict=True)
            if network.version != address.version:
                raise ValueError("RDAP CIDR address family mismatch")
            if low is not None and (network.network_address < low or network.broadcast_address > high):
                raise ValueError("CIDR extension inconsistent with RDAP address range")
            if address in network:
                candidates.append(str(network))
    elif low is not None:
        candidates = [str(net) for net in ipaddress.summarize_address_range(low, high) if address in net]
    else:
        raise ValueError("RDAP lacks address range and CIDR extension")
    if not candidates or len(candidates) > 64:
        raise ValueError("RDAP network does not contain subject IP")
    return candidates


def _parse_rdap(raw: Mapping[str, Any], request: CollectionRequest) -> tuple[str, list[str], int | None, str | None, str]:
    if raw.get("protocol") != "rdap":
        raise ValueError("expected RDAP fixture")
    status = raw.get("http_status")
    if type(status) is not int:
        raise ValueError("invalid HTTP status")
    if status == 429:
        return "error", [], None, "rate_limited", "HTTP_429"
    if status == 404:
        # RDAP absence does NOT prove an IP address or its registration is benign.
        return "error", [], None, "unavailable", "HTTP_404"
    if status >= 500 and status <= 599:
        return "error", [], None, "unavailable", "HTTP_5XX"
    if status != 200:
        return "error", [], None, "unavailable", "HTTP_ERROR"
    return "ok", _rdap_network(raw.get("body"), request.subject), None, None, "HTTP_200"


def parse_autnum_fixture(asn: str, response: Mapping[str, Any]) -> dict[str, Any]:
    """Parse independent RDAP autnum metadata, never invent an IP-to-ASN link."""
    if not isinstance(asn, str) or not asn.upper().startswith("AS") or not asn[2:].isdigit():
        raise ValueError("expected AS-prefixed decimal number")
    number = int(asn[2:])
    if not 0 <= number <= 4294967295 or not isinstance(response, Mapping):
        raise ValueError("invalid ASN or response")
    body = response.get("body")
    if response.get("protocol") != "rdap" or response.get("http_status") != 200 or not isinstance(body, dict) or body.get("objectClassName") != "autnum":
        raise ValueError("not a successful RDAP autnum response")
    first, last = body.get("startAutnum"), body.get("endAutnum")
    if type(first) is not int or type(last) is not int or not 0 <= first <= number <= last <= 4294967295:
        raise ValueError("autnum range inconsistent with ASN")
    return {"schema": "anie.autnum-context.v1", "asn": f"AS{number}", "start_asn": f"AS{first}", "end_asn": f"AS{last}", "synthetic": True, "ip_association": "not_established"}


class OfflineCollector:
    """Only accepts FixtureTransport, preventing accidental activation of live transport."""
    def __init__(self, policy: CollectionPolicy, transport: FixtureTransport, *, source_id: str = "synthetic:collector"):
        if not isinstance(transport, FixtureTransport):
            raise TypeError("ANIE v0.2 accepts FixtureTransport only; live transport disabled")
        if not isinstance(source_id, str) or not source_id.startswith("synthetic:"):
            raise ValueError("collector source must be synthetic in v0.2")
        self.transport = transport
        self.budget = CollectionBudget(policy)
        self.source_id = source_id

    def collect(self, kind: str, subject: str, observed_at: str) -> CollectionEvent:
        if kind not in QUERY_KINDS and kind not in RDAP_KINDS:
            raise ScopeDenied("unsupported v0.2 collection type; ASN does not establish IP association")
        request = CollectionRequest.create(kind, subject, observed_at)
        self.budget.reserve(request.kind, request.subject)
        raw = self.transport.exchange(request)
        payload = canonical_json(raw).encode("utf-8")
        self.budget.account_bytes(len(payload))
        digest = sha256(payload).hexdigest()
        if "transport_error" in raw:
            error = raw["transport_error"]
            if error not in TRANSPORT_ERRORS:
                result = ("error", [], None, "invalid_response", "INVALID_RESPONSE")
            else:
                result = ("error", [], None, TRANSPORT_ERRORS[error], error.upper())
        else:
            try:
                result = _parse_dns(raw, request) if kind in QUERY_KINDS else _parse_rdap(raw, request)
            except (ValueError, TypeError, KeyError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                result = ("error", [], None, "invalid_response", "INVALID_RESPONSE")
        status, values, ttl, error_code, outcome = result
        try:
            observation = Observation.from_dict({
                "subject": request.subject, "kind": request.kind, "observed_at": request.observed_at,
                "values": values, "status": status, "source_id": self.source_id,
                "method": "synthetic", "synthetic": True, "ttl_seconds": ttl,
                "error_code": error_code,
            })
        except ValueError:
            observation = Observation.from_dict({
                "subject": request.subject, "kind": request.kind, "observed_at": request.observed_at,
                "values": [], "status": "error", "source_id": self.source_id,
                "method": "synthetic", "synthetic": True, "ttl_seconds": None,
                "error_code": "invalid_response",
            })
            outcome = "INVALID_RESPONSE"
        return CollectionEvent(request, outcome, observation, digest, self.source_id)

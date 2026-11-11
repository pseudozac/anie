"""Offline parser adapters for synthetic DNS/RDAP responses.

No network access. Real clients will require separate approval and security design.
"""
from __future__ import annotations

from typing import Any
from .observations import Observation


def synthetic_dns(domain: str, rrtype: str, answers: list[str], observed_at: str, *, status: str = "ok", error_code: str | None = None) -> Observation:
    kind = {"A": "dns_a", "AAAA": "dns_aaaa"}.get(rrtype.upper())
    if kind is None:
        raise ValueError("v0.1 DNS parser supports A and AAAA; PTR uses synthetic_ptr")
    return Observation.from_dict({
        "subject": domain, "kind": kind, "observed_at": observed_at,
        "values": answers, "status": status, "source_id": "synthetic:dns",
        "method": "synthetic", "synthetic": True,
        "ttl_seconds": None, "error_code": error_code,
    })


def synthetic_rdap_network(ip: str, response: dict[str, Any], observed_at: str) -> Observation:
    if not isinstance(response, dict) or response.get("objectClassName") != "ip network":
        raise ValueError("not an IP network RDAP response")
    raw = response.get("cidr0_cidrs")
    if not isinstance(raw, list) or not 0 < len(raw) <= 16:
        raise ValueError("RDAP CIDR extension missing or bounded incorrectly")
    networks = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("invalid RDAP CIDR value")
        if "v4prefix" in item and type(item.get("length")) is int:
            networks.append(f"{item['v4prefix']}/{item['length']}")
        elif "v6prefix" in item and type(item.get("length")) is int:
            networks.append(f"{item['v6prefix']}/{item['length']}")
        else:
            raise ValueError("invalid RDAP CIDR structure")
    return Observation.from_dict({
        "subject": ip, "kind": "rdap_network", "observed_at": observed_at,
        "values": networks, "status": "ok", "source_id": "synthetic:rdap",
        "method": "synthetic", "synthetic": True,
        "ttl_seconds": None, "error_code": None,
    })

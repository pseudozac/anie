"""Only synthetic RFC 2606-style domains and RFC 5737 documentation IPs."""
from __future__ import annotations
from .observations import Observation


def demo_observations() -> list[Observation]:
    base1, base2, base3, base4 = (
        "2026-11-09T08:00:00Z", "2026-11-10T08:00:00Z", "2026-11-10T14:00:00Z", "2026-11-11T08:00:00Z"
    )
    data: list[Observation] = []

    def add(subject: str, kind: str, at: str, values: list[str], status: str = "ok", error_code: str | None = None):
        data.append(Observation.from_dict({
            "subject": subject, "kind": kind, "observed_at": at,
            "values": values, "status": status, "source_id": "synthetic:demo",
            "method": "synthetic", "synthetic": True, "ttl_seconds": 300 if kind.startswith("dns_") else None,
            "error_code": error_code,
        }))

    for i in range(1, 33):
        domain = f"baseline-{i:02d}.example.test"
        ip = f"192.0.2.{i}"
        add(domain, "dns_a", base1, [ip])
        add(domain, "dns_a", base2, [ip])
        add(domain, "dns_a", base4, [ip])
    domain = "changing.example.test"
    add(domain, "dns_a", base1, ["198.51.100.21"])
    add(domain, "dns_a", base2, ["198.51.100.22"])
    add(domain, "dns_a", base3, [], status="error", error_code="timeout")
    add(domain, "dns_a", base4, ["198.51.100.23"])
    add("203.0.113.42", "rdap_asn", base4, ["AS64500"])
    add("203.0.113.42", "rdap_network", base4, ["203.0.113.0/24"])
    return data

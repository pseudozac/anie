"""Bounded pure RFC 1035 / RFC 8484 DNS message subset for ANIE.

Supports A/AAAA question/answer decoding and SOA-proven negative answers.
Unsupported CNAME/DNAME chains, referrals, DNSSEC validation and malformed
messages FAIL CLOSED. This module performs NO DNS queries or network I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct

from .observations import normalized_domain

MAX_MESSAGE = 65535
MAX_RECORDS = 96
TYPES = {"dns_a": 1, "dns_aaaa": 28}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass(frozen=True)
class ParsedDnsMessage:
    subject: str
    kind: str
    outcome: str
    status: str
    values: tuple[str, ...]
    ttl_seconds: int | None
    error_code: str | None

    def as_observation(self, *, observed_at: str, source_id: str):
        """Convert a separately authenticated live exchange to real provenance.

        Caller must establish actual DNS transport provenance separately.
        """
        from .observations import Observation
        return Observation.from_dict({
            "subject": self.subject, "kind": self.kind,
            "observed_at": observed_at, "values": list(self.values),
            "status": self.status, "source_id": source_id,
            "method": "dns", "synthetic": False,
            "ttl_seconds": self.ttl_seconds, "error_code": self.error_code,
        })


def make_dns_query(domain: str, kind: str) -> bytes:
    if kind not in TYPES:
        raise ValueError("only A/AAAA DoH preflight is supported")
    domain = normalized_domain(domain)
    labels = domain.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", TYPES[kind], 1)


def _read_name(message: bytes, position: int) -> tuple[str, int]:
    """Decode a compressed DNS name with strict bounds and cycle rejection."""
    end = None
    seen = set()
    labels = []
    expanded_len = 1
    for _ in range(129):  # DNS name can't have more than 127 labels.
        if position >= len(message):
            raise ValueError("truncated DNS label")
        size = message[position]
        if size & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((size & 0x3F) << 8) | message[position + 1]
            if pointer >= len(message) or pointer in seen:
                raise ValueError("DNS compression loop or invalid pointer")
            if end is None:
                end = position + 2
            seen.add(pointer)
            position = pointer
            continue
        if size & 0xC0:
            raise ValueError("invalid DNS label encoding")
        position += 1
        if size == 0:
            if not labels:
                return "", end if end is not None else position
            try:
                name = ".".join(label.decode("ascii") for label in labels)
                return normalized_domain(name), end if end is not None else position
            except (UnicodeError, ValueError) as exc:
                raise ValueError("invalid DNS name") from exc
        if size > 63 or position + size > len(message):
            raise ValueError("invalid DNS label length")
        label = message[position:position + size]
        position += size
        expanded_len += size + 1
        if expanded_len > 255:
            raise ValueError("expanded DNS name exceeds 255 bytes")
        labels.append(label)
    raise ValueError("excessive DNS label compression depth")


def _soa_negative_ttl(message: bytes, position: int, end: int, rr_ttl: int) -> int:
    """RFC 2308 negative TTL is min(SOA RR TTL, SOA MINIMUM)."""
    _, position = _read_name(message, position)
    _, position = _read_name(message, position)
    if position + 20 != end:
        raise ValueError("invalid SOA RDATA length")
    minimum = struct.unpack_from("!I", message, position + 16)[0]
    return min(rr_ttl, minimum, 604800)


def parse_dns_wire(message: bytes, *, domain: str, kind: str) -> ParsedDnsMessage:
    """Parse a single complete DNS response from a separately verified DoH exchange."""
    if kind not in TYPES:
        raise ValueError("unsupported query kind")
    subject = normalized_domain(domain)
    if not isinstance(message, bytes) or not 12 <= len(message) <= MAX_MESSAGE:
        raise ValueError("invalid or oversized DNS response")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", message)
    if ident != 0 or not flags & 0x8000 or flags & 0x0200 or (flags >> 11) & 0xF:
        raise ValueError("mismatched, truncated or non-response DNS packet")
    if qd != 1 or (an + ns + ar) > MAX_RECORDS:
        raise ValueError("invalid DNS question or resource record count")
    rcode = flags & 0xF
    if rcode not in RCODES:
        raise ValueError("unsupported DNS response code")
    question, pos = _read_name(message, 12)
    if pos + 4 > len(message):
        raise ValueError("truncated DNS question")
    rtype, rclass = struct.unpack_from("!HH", message, pos)
    pos += 4
    if question != subject or rtype != TYPES[kind] or rclass != 1:
        raise ValueError("DNS response question mismatch")
    vals = []
    ttls = []
    negative_ttl = None
    cname_seen = False
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            owner, pos = _read_name(message, pos)
            if pos + 10 > len(message):
                raise ValueError("truncated DNS resource record")
            typ, cls, ttl, rdlen = struct.unpack_from("!HHIH", message, pos)
            pos += 10
            end = pos + rdlen
            if end > len(message):
                raise ValueError("truncated DNS RDATA")
            if section == "answer":
                if typ in (5, 39):
                    cname_seen = True
                elif owner == subject and cls == 1 and typ == TYPES[kind]:
                    expected_size = 4 if kind == "dns_a" else 16
                    if rdlen != expected_size:
                        raise ValueError("DNS answer address-family mismatch")
                    vals.append(str(ipaddress.ip_address(message[pos:end])))
                    ttls.append(min(ttl, 604800))
            if section == "authority" and typ == 6 and cls == 1:
                if negative_ttl is not None:
                    raise ValueError("ambiguous multiple SOA records")
                negative_ttl = _soa_negative_ttl(message, pos, end, ttl)
            pos = end
    if pos != len(message):
        raise ValueError("trailing DNS packet bytes")
    if cname_seen:
        raise ValueError("CNAME/DNAME chain not yet supported; do not infer NODATA")
    rcode_name = RCODES[rcode]
    if rcode in (1, 2, 4, 5):
        if vals:
            raise ValueError("error response with positive answer")
        code = "invalid_response" if rcode == 1 else "unavailable"
        return ParsedDnsMessage(subject, kind, rcode_name, "error", (), None, code)
    if rcode == 3:
        if vals:
            raise ValueError("NXDOMAIN with positive answer")
        return ParsedDnsMessage(subject, kind, "NXDOMAIN", "empty", (), negative_ttl, None)
    if vals:
        if negative_ttl is not None:
            raise ValueError("positive DNS answer accompanied by negative SOA proof")
        return ParsedDnsMessage(subject, kind, "ANSWER", "ok", tuple(sorted(set(vals))), min(ttls), None)
    if negative_ttl is not None:
        return ParsedDnsMessage(subject, kind, "NODATA", "empty", (), negative_ttl, None)
    raise ValueError("NOERROR without answer or SOA: referral or incomplete DNS evidence")

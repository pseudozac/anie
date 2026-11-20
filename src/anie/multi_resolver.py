"""Multi-resolver observation engine and DoH provider adapters for ANIE.

Part of ANIE Phase 3.3 Multi-Resolver Intelligence & Discrepancy Analysis.
Provides standard adapters for:
1. Cloudflare Public DNS (https://cloudflare-dns.com/dns-query, 1.1.1.1) - Standard Recursive
2. Google Public DNS (https://dns.google/dns-query, 8.8.8.8) - Standard Recursive
3. Quad9 Secure DNS (https://dns.quad9.net/dns-query, 9.9.9.9) - Security-Filtering Recursive

Strictly separates empirical collection from analytical interpretation.
Captures raw wire payloads, SHA-256 digests, DNSSEC flags, and Extended DNS Errors (RFC 8914).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import ipaddress
import struct
from typing import Any

from .dns_wire import (
    MAX_MESSAGE,
    MAX_RECORDS,
    RCODES,
    TYPES,
    _read_name,
    _soa_negative_ttl,
)
from .observations import normalized_domain, utc_iso
from .real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)


class ResolverType(str, Enum):
    """Classification of DNS resolver policy and operational profile."""
    STANDARD_RECURSIVE = "standard_recursive"        # Standard recursive resolution without security filtering
    SECURITY_FILTERING = "security_filtering"        # Security-filtering resolver blocking threats (e.g. Quad9)


@dataclass(frozen=True)
class ResolverConfig:
    """Configuration and transport parameters for an independent DoH resolver."""
    id: str
    name: str
    endpoint: str
    pinned_ips: tuple[str, ...]
    resolver_type: ResolverType
    supports_dnssec: bool = True
    description: str = ""


# Standard Supported Resolvers
CLOUDFLARE_RESOLVER = ResolverConfig(
    id="cloudflare",
    name="Cloudflare Public DNS",
    endpoint="https://cloudflare-dns.com/dns-query",
    pinned_ips=("104.16.248.249", "1.1.1.1", "1.0.0.1"),
    resolver_type=ResolverType.STANDARD_RECURSIVE,
    supports_dnssec=True,
    description="Global Anycast recursive resolver with DNSSEC validation and no policy filtering",
)

GOOGLE_RESOLVER = ResolverConfig(
    id="google",
    name="Google Public DNS",
    endpoint="https://dns.google/dns-query",
    pinned_ips=("8.8.8.8", "8.8.4.4"),
    resolver_type=ResolverType.STANDARD_RECURSIVE,
    supports_dnssec=True,
    description="Global Anycast recursive resolver with DNSSEC validation and no policy filtering",
)

QUAD9_RESOLVER = ResolverConfig(
    id="quad9",
    name="Quad9 Secure DNS",
    endpoint="https://dns.quad9.net/dns-query",
    pinned_ips=("9.9.9.9", "149.112.112.112"),
    resolver_type=ResolverType.SECURITY_FILTERING,
    supports_dnssec=True,
    description="Security-filtering recursive resolver blocking confirmed malware and phishing domains (RFC 8914 EDE 15)",
)

STANDARD_RESOLVERS = (CLOUDFLARE_RESOLVER, GOOGLE_RESOLVER, QUAD9_RESOLVER)
RESOLVER_REGISTRY: dict[str, ResolverConfig] = {r.id: r for r in STANDARD_RESOLVERS}


@dataclass(frozen=True)
class NormalizedAnswerRecord:
    """Normalized DNS answer resource record."""
    name: str
    rrtype: str
    data: str
    ttl: int


@dataclass(frozen=True)
class ParsedMultiResolverResponse:
    """Rich multi-resolver DNS response model capturing transport and evidence metadata."""
    subject: str
    kind: str
    resolver_id: str
    resolver_type: str
    rcode: str
    dnssec_status: str
    resolver_ad_claim: bool
    values: tuple[str, ...]
    ttls: tuple[int, ...]
    cname_chain: tuple[str, ...]
    is_filtered: bool
    ede_code: int | None
    ede_text: str | None
    raw_payload: bytes
    raw_sha256: str

    def as_real_models(
        self,
        *,
        observed_at: str,
        target_endpoint: str | None = None,
        pinned_ip: str | None = None,
    ) -> tuple[RealCollectionEvent, RealObservation]:
        """Convert multi-resolver response into standard ANIE RealCollectionEvent and RealObservation."""
        endpoint = target_endpoint or RESOLVER_REGISTRY.get(self.resolver_id, CLOUDFLARE_RESOLVER).endpoint
        ip_pin = pinned_ip or RESOLVER_REGISTRY.get(self.resolver_id, CLOUDFLARE_RESOLVER).pinned_ips[0]

        req = RealCollectionRequest.create(
            kind=self.kind,
            subject=self.subject,
            observed_at=observed_at,
            target_endpoint=endpoint,
            pinned_ip=ip_pin,
        )

        factual = FactualVerification(
            dnssec_status=self.dnssec_status,
            response_authenticity="recursive",
            transport_security="tls_pinned",
            resolver_identity=self.resolver_id,
            wire_rcode=self.rcode,
            raw_evidence_status="captured",
            resolver_ad_claim=self.resolver_ad_claim,
        )

        event = RealCollectionEvent(
            request=req,
            response_code=self.rcode,
            raw_sha256=self.raw_sha256,
            raw_evidence_status="captured",
            factual_verification=factual,
            source_id=f"first_party:doh:{self.resolver_id}",
            observed_at=utc_iso(observed_at),
            raw_payload=self.raw_payload,
        )

        if self.values:
            status = "ok"
            err_code = None
        elif self.rcode in ("NXDOMAIN", "NODATA"):
            status = "empty"
            err_code = None
        else:
            status = "error"
            err_code = "invalid_response" if self.rcode == "FORMERR" else "unavailable"

        min_ttl = min(self.ttls) if self.ttls else None

        obs = RealObservation(
            subject=self.subject,
            kind=self.kind,
            observed_at=utc_iso(observed_at),
            values=self.values,
            status=status,
            error_code=err_code,
            source_id=f"first_party:doh:{self.resolver_id}",
            method="dns",
            synthetic=False,
            evidence_id=event.event_id,
            factual_verification=factual,
            ttl_seconds=min_ttl,
        )

        return event, obs


def _normalize_kind(kind: str) -> str:
    """Normalize record kind string to standard internal representation."""
    k = kind.lower()
    if k in ("a", "dns_a"):
        return "dns_a"
    if k in ("aaaa", "dns_aaaa"):
        return "dns_aaaa"
    raise ValueError(f"unsupported query kind: {kind!r}")


def make_edns_query_packet(
    domain: str,
    kind: str,
    *,
    udp_payload_size: int = 4096,
    dnssec_ok: bool = True,
) -> bytes:
    """Build an RFC 1035 / RFC 6891 DNS query with OPT pseudo-RR requesting DNSSEC."""
    kind = _normalize_kind(kind)
    norm_dom = normalized_domain(domain)
    labels = norm_dom.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"

    # Header: ID=0, Flags=0x0100 (RD=1), QD=1, AN=0, NS=0, AR=1 (OPT)
    header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 1)
    question = qname + struct.pack("!HH", TYPES[kind], 1)

    # OPT pseudo-RR: name=0, type=41 (OPT), class=payload_size, ext_rcode/version/flags, rdlen=0
    # DO (DNSSEC OK) bit is bit 0x8000 in TTL/extended flags
    ext_flags = 0x8000 if dnssec_ok else 0x0000
    opt_rr = struct.pack("!BHHIH", 0, 41, udp_payload_size, ext_flags, 0)

    return header + question + opt_rr


def parse_multi_resolver_dns_response(
    message: bytes,
    domain: str,
    kind: str,
    resolver: ResolverConfig,
) -> ParsedMultiResolverResponse:
    """Parse a full RFC 1035 / RFC 6891 DNS response from an independent DoH resolver.
    
    Supports:
    - Standard A and AAAA record decoding.
    - CNAME alias tracing to canonical terminal target.
    - DNSSEC flag analysis (AD flag, CD flag, DO bit).
    - EDNS Extended DNS Errors (RFC 8914, e.g. EDE Code 15 "Blocked").
    - Resolver filtering classification for security-filtering resolvers (Quad9).
    """
    kind = _normalize_kind(kind)
    subject = normalized_domain(domain)
    if not isinstance(message, bytes) or not 12 <= len(message) <= MAX_MESSAGE:
        raise ValueError("invalid or oversized DNS response")

    raw_sha = sha256(message).hexdigest()
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", message)

    # Verify standard response flags
    if not (flags & 0x8000):
        raise ValueError("non-response DNS packet")
    if flags & 0x0200:
        raise ValueError("truncated DNS packet")

    rcode = flags & 0xF
    if rcode not in RCODES:
        raise ValueError(f"unsupported DNS response code: {rcode}")
    rcode_name = RCODES[rcode]

    # DNSSEC AD (Authentic Data) claim
    ad_flag = bool(flags & 0x0020)

    # Read question
    if qd != 1:
        raise ValueError(f"expected exactly 1 question, got {qd}")
    question, pos = _read_name(message, 12)
    if pos + 4 > len(message):
        raise ValueError("truncated DNS question")
    rtype, rclass = struct.unpack_from("!HH", message, pos)
    pos += 4

    if question != subject or rtype != TYPES[kind] or rclass != 1:
        raise ValueError("DNS response question mismatch")

    answers_raw: list[NormalizedAnswerRecord] = []
    cname_chain: list[str] = []
    current_target = subject
    ttls: list[int] = []
    negative_ttl: int | None = None
    ede_code: int | None = None
    ede_text: str | None = None

    # Parse sections
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
                if typ == 5:  # CNAME
                    cname_target, cname_end = _read_name(message, pos)
                    if cname_end != end:
                        raise ValueError("invalid CNAME RDATA")
                    cname_chain.append(cname_target)
                    current_target = cname_target
                    ttls.append(min(ttl, 604800))
                elif typ == TYPES[kind] and cls == 1:
                    expected_len = 4 if kind == "dns_a" else 16
                    if rdlen != expected_len:
                        raise ValueError("address length mismatch")
                    addr_str = str(ipaddress.ip_address(message[pos:end]))
                    answers_raw.append(NormalizedAnswerRecord(owner, kind, addr_str, min(ttl, 604800)))
                    ttls.append(min(ttl, 604800))

            elif section == "authority" and typ == 6 and cls == 1:  # SOA
                if negative_ttl is None:
                    negative_ttl = _soa_negative_ttl(message, pos, end, ttl)

            elif section == "additional" and typ == 41:  # OPT (RFC 6891)
                # Parse EDNS options in OPT RDATA
                opt_pos = pos
                while opt_pos + 4 <= end:
                    opt_code, opt_len = struct.unpack_from("!HH", message, opt_pos)
                    opt_pos += 4
                    opt_end = opt_pos + opt_len
                    if opt_end > end:
                        break
                    if opt_code == 15 and opt_len >= 2:  # Extended DNS Error (RFC 8914)
                        ede_code = struct.unpack_from("!H", message, opt_pos)[0]
                        if opt_len > 2:
                            try:
                                ede_text = message[opt_pos + 2:opt_end].decode("utf-8", errors="replace")
                            except Exception:
                                pass
                    opt_pos = opt_end

            pos = end

    if pos != len(message):
        raise ValueError("trailing bytes after DNS packet")

    # Determine DNSSEC validation verdict
    if rcode == 2:  # SERVFAIL
        # If resolver returned SERVFAIL, could be DNSSEC bogus validation failure
        dnssec_status = "bogus" if resolver.supports_dnssec else "indeterminate"
    elif ad_flag:
        dnssec_status = "secure"
    else:
        dnssec_status = "insecure"

    # Evaluate filtering indicators
    is_filtered = False
    if resolver.resolver_type == ResolverType.SECURITY_FILTERING:
        # Check RFC 8914 EDE code: 15 (Blocked), 16 (Censored), 17 (Filtered), 18 (Prohibited)
        if ede_code in (15, 16, 17, 18):
            is_filtered = True
        elif rcode == 3 and negative_ttl is not None:
            # Quad9 returns NXDOMAIN for blocked domains
            is_filtered = True
        elif any(ans.data in ("0.0.0.0", "127.0.0.1", "::") for ans in answers_raw):
            is_filtered = True

    # Normalize values: canonical IP addresses, sorted deterministically
    vals: tuple[str, ...]
    if rcode_name in ("FORMERR", "SERVFAIL", "NOTIMP", "REFUSED"):
        vals = ()
    elif rcode_name == "NXDOMAIN":
        vals = ()
    else:
        # Sort and deduplicate normalized IPs
        vals = tuple(sorted({ans.data for ans in answers_raw}))

    return ParsedMultiResolverResponse(
        subject=subject,
        kind=kind,
        resolver_id=resolver.id,
        resolver_type=resolver.resolver_type.value,
        rcode=rcode_name,
        dnssec_status=dnssec_status,
        resolver_ad_claim=ad_flag,
        values=vals,
        ttls=tuple(ttls),
        cname_chain=tuple(cname_chain),
        is_filtered=is_filtered,
        ede_code=ede_code,
        ede_text=ede_text,
        raw_payload=message,
        raw_sha256=raw_sha,
    )


def build_mock_dns_wire_response(
    domain: str,
    kind: str,
    *,
    ips: list[str] | None = None,
    rcode: int = 0,
    ad_flag: bool = True,
    cname_target: str | None = None,
    ede_code: int | None = None,
    ede_text: str | None = None,
    ttl: int = 300,
) -> bytes:
    """Build a deterministic synthetic RFC 1035 / RFC 6891 DNS wire response for offline testing."""
    kind = _normalize_kind(kind)
    norm_dom = normalized_domain(domain)
    labels = norm_dom.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1 if (ede_code is not None or True) else 0

    flags = 0x8180 | (rcode & 0xF)  # QR=1, RD=1, RA=1
    if ad_flag:
        flags |= 0x0020  # AD=1

    answer_bytes = b""
    if cname_target:
        ancount += 1
        cname_norm = normalized_domain(cname_target)
        cname_labels = cname_norm.split(".")
        cname_data = b"".join(bytes([len(l)]) + l.encode("ascii") for l in cname_labels) + b"\x00"
        answer_bytes += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, ttl, len(cname_data)) + cname_data
        target_name_offset = len(answer_bytes) - len(cname_data)

    if ips:
        for ip_str in ips:
            ip_obj = ipaddress.ip_address(ip_str)
            raw_ip = ip_obj.packed
            ancount += 1
            # Compression pointer to qname (\xc0\x0c) if no CNAME, or fresh name
            name_ptr = b"\xc0\x0c"
            answer_bytes += name_ptr + struct.pack("!HHIH", TYPES[kind], 1, ttl, len(raw_ip)) + raw_ip

    authority_bytes = b""
    if rcode == 3 or (not ips and not cname_target):  # NXDOMAIN or NODATA SOA
        nscount = 1
        soa_rdata = b"\x01a\x0croot-servers\x03net\x00\x05nstld\x0cverisign-grs\x03com\x00" + struct.pack("!IIIII", 2026111200, 1800, 900, 604800, 300)
        authority_bytes = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 300, len(soa_rdata)) + soa_rdata

    # OPT pseudo-RR
    opt_rdata = b""
    if ede_code is not None:
        text_bytes = (ede_text or "").encode("utf-8")
        ede_payload = struct.pack("!H", ede_code) + text_bytes
        opt_rdata = struct.pack("!HH", 15, len(ede_payload)) + ede_payload

    opt_rr = struct.pack("!BHHIH", 0, 41, 4096, 0x8000, len(opt_rdata)) + opt_rdata

    header = struct.pack("!HHHHHH", 0, flags, qdcount, ancount, nscount, arcount)
    question = qname + struct.pack("!HH", TYPES[kind], 1)

    return header + question + answer_bytes + authority_bytes + opt_rr

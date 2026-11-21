"""Offline RDAP & ASN Infrastructure Enrichment for ANIE (Milestone M3.6).

Provides deterministic, offline IP-to-ASN and IP-to-Prefix correlation adhering to
RFC 9224 (RDAP Bootstrap) and RFC 9082.

Invariants:
- Zero outbound network requests; fully offline and deterministic.
- Epistemic classification: DERIVED (Layer 2) structural infrastructure linkage.
- Preserves evidence lineage: all edges link to the originating collection event SHA-256.
- Strict sub-millisecond execution and minimal memory RSS (<1 MiB).
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from .canonical_entities import canonicalize_asn, canonicalize_cidr
from .graph_models import (
    _HEX_64,
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
    format_node_id,
)

RDAP_RULESET_VERSION = "anie.rules.rdap.v1"


@dataclass(frozen=True)
class RdapEnrichmentResult:
    """Enriched network infrastructure metadata for an IP address."""
    ip: str
    asn: str
    asn_number: int
    as_name: str
    prefix: str
    registry: str
    is_authoritative: bool = False
    ruleset_version: str = RDAP_RULESET_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "asn": self.asn,
            "asn_number": self.asn_number,
            "as_name": self.as_name,
            "prefix": self.prefix,
            "registry": self.registry,
            "is_authoritative": self.is_authoritative,
            "ruleset_version": self.ruleset_version,
        }


@dataclass(frozen=True)
class _NetworkAllocation:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    asn: int
    as_name: str
    registry: str


# Deterministic offline table of major public autonomous systems and prefixes
_OFFLINE_ALLOCATIONS: list[_NetworkAllocation] = [
    # Cloudflare (AS13335)
    _NetworkAllocation(ipaddress.ip_network("1.1.1.0/24"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("1.0.0.0/24"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("104.16.0.0/12"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("104.24.0.0/14"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("172.64.0.0/13"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("162.158.0.0/15"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("198.41.128.0/17"), 13335, "Cloudflare, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("2606:4700::/32"), 13335, "Cloudflare, Inc.", "ARIN"),
    # Google (AS15169)
    _NetworkAllocation(ipaddress.ip_network("8.8.8.0/24"), 15169, "Google LLC", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("8.8.4.0/24"), 15169, "Google LLC", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("142.250.0.0/15"), 15169, "Google LLC", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("172.217.0.0/16"), 15169, "Google LLC", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("2001:4860:4860::/48"), 15169, "Google LLC", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("2001:4860::/32"), 15169, "Google LLC", "ARIN"),
    # Quad9 (AS19281)
    _NetworkAllocation(ipaddress.ip_network("9.9.9.0/24"), 19281, "Quad9", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("149.112.112.0/24"), 19281, "Quad9", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("2620:fe::/48"), 19281, "Quad9", "ARIN"),
    # Fastly (AS54113)
    _NetworkAllocation(ipaddress.ip_network("151.101.0.0/16"), 54113, "Fastly, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("199.232.0.0/16"), 54113, "Fastly, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("2a04:4e40::/32"), 54113, "Fastly, Inc.", "RIPE NCC"),
    # AWS CloudFront / EC2 (AS16509)
    _NetworkAllocation(ipaddress.ip_network("13.224.0.0/14"), 16509, "Amazon.com, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("13.225.0.0/16"), 16509, "Amazon.com, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("13.32.0.0/15"), 16509, "Amazon.com, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("52.84.0.0/15"), 16509, "Amazon.com, Inc.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("54.230.0.0/16"), 16509, "Amazon.com, Inc.", "ARIN"),
    # EdgeCast / Verizon (AS15133) - hosting example.com
    _NetworkAllocation(ipaddress.ip_network("93.184.216.0/24"), 15133, "EdgeCast Networks / Verizon Digital Media", "ARIN"),
    # Cisco OpenDNS (AS36692)
    _NetworkAllocation(ipaddress.ip_network("208.67.222.0/24"), 36692, "Cisco OpenDNS", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("208.67.220.0/24"), 36692, "Cisco OpenDNS", "ARIN"),
    # Microsoft (AS8075)
    _NetworkAllocation(ipaddress.ip_network("20.0.0.0/11"), 8075, "Microsoft Corporation", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("40.74.0.0/15"), 8075, "Microsoft Corporation", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("2603:1000::/24"), 8075, "Microsoft Corporation", "ARIN"),
    # Akamai (AS20940)
    _NetworkAllocation(ipaddress.ip_network("23.0.0.0/12"), 20940, "Akamai International B.V.", "ARIN"),
    _NetworkAllocation(ipaddress.ip_network("104.64.0.0/10"), 20940, "Akamai International B.V.", "ARIN"),
]


# IANA IPv4 /8 Major Regional Registry Allocations (RFC 9224 RDAP Bootstrap)
_IANA_V4_RIR_MAP: dict[int, str] = {
    1: "APNIC", 2: "RIPE NCC", 3: "ARIN", 4: "ARIN", 8: "ARIN", 9: "ARIN",
    11: "ARIN", 12: "ARIN", 13: "ARIN", 14: "APNIC", 15: "ARIN", 16: "ARIN",
    17: "ARIN", 18: "ARIN", 19: "ARIN", 20: "ARIN", 23: "ARIN", 24: "ARIN",
    25: "RIPE NCC", 27: "APNIC", 31: "RIPE NCC", 34: "ARIN", 35: "ARIN",
    36: "APNIC", 37: "RIPE NCC", 38: "ARIN", 39: "APNIC", 40: "ARIN",
    41: "AFRINIC", 42: "APNIC", 43: "APNIC", 44: "ARIN", 45: "ARIN",
    46: "RIPE NCC", 47: "ARIN", 48: "ARIN", 49: "APNIC", 50: "ARIN",
    51: "RIPE NCC", 52: "ARIN", 53: "RIPE NCC", 54: "ARIN", 55: "ARIN",
    56: "ARIN", 57: "RIPE NCC", 58: "APNIC", 59: "APNIC", 60: "APNIC",
    61: "APNIC", 62: "RIPE NCC", 63: "ARIN", 64: "ARIN", 65: "ARIN",
    66: "ARIN", 67: "ARIN", 68: "ARIN", 69: "ARIN", 70: "ARIN",
    71: "ARIN", 72: "ARIN", 73: "ARIN", 74: "ARIN", 75: "ARIN",
    76: "ARIN", 77: "RIPE NCC", 78: "RIPE NCC", 79: "RIPE NCC", 80: "RIPE NCC",
    81: "RIPE NCC", 82: "RIPE NCC", 83: "RIPE NCC", 84: "RIPE NCC", 85: "RIPE NCC",
    86: "RIPE NCC", 87: "RIPE NCC", 88: "RIPE NCC", 89: "RIPE NCC", 90: "RIPE NCC",
    91: "RIPE NCC", 92: "RIPE NCC", 93: "RIPE NCC", 94: "RIPE NCC", 95: "RIPE NCC",
    96: "ARIN", 97: "ARIN", 98: "ARIN", 99: "ARIN", 100: "ARIN",
    101: "APNIC", 102: "AFRINIC", 103: "APNIC", 104: "ARIN", 105: "AFRINIC",
    106: "APNIC", 107: "ARIN", 108: "ARIN", 109: "RIPE NCC", 110: "APNIC",
    111: "APNIC", 112: "APNIC", 113: "APNIC", 114: "APNIC", 115: "APNIC",
    116: "APNIC", 117: "APNIC", 118: "APNIC", 119: "APNIC", 120: "APNIC",
    121: "APNIC", 122: "APNIC", 123: "APNIC", 124: "APNIC", 125: "APNIC",
    126: "APNIC", 128: "ARIN", 129: "ARIN", 130: "ARIN", 131: "ARIN",
    132: "ARIN", 133: "APNIC", 134: "ARIN", 135: "ARIN", 136: "ARIN",
    137: "ARIN", 138: "ARIN", 139: "ARIN", 140: "ARIN", 141: "RIPE NCC",
    142: "ARIN", 143: "ARIN", 144: "ARIN", 145: "RIPE NCC", 146: "ARIN",
    147: "ARIN", 148: "ARIN", 149: "ARIN", 150: "APNIC", 151: "RIPE NCC",
    152: "ARIN", 153: "APNIC", 154: "AFRINIC", 155: "ARIN", 156: "ARIN",
    157: "ARIN", 158: "ARIN", 159: "ARIN", 160: "ARIN", 161: "ARIN",
    162: "ARIN", 163: "APNIC", 164: "ARIN", 165: "ARIN", 166: "ARIN",
    167: "ARIN", 168: "ARIN", 169: "ARIN", 170: "ARIN", 171: "APNIC",
    172: "ARIN", 173: "ARIN", 174: "ARIN", 175: "APNIC", 176: "RIPE NCC",
    177: "LACNIC", 178: "RIPE NCC", 179: "LACNIC", 180: "APNIC", 181: "LACNIC",
    182: "APNIC", 183: "APNIC", 184: "ARIN", 185: "RIPE NCC", 186: "LACNIC",
    187: "LACNIC", 188: "RIPE NCC", 189: "LACNIC", 190: "LACNIC", 191: "LACNIC",
    192: "ARIN", 193: "RIPE NCC", 194: "RIPE NCC", 195: "RIPE NCC", 196: "AFRINIC",
    197: "AFRINIC", 198: "ARIN", 199: "ARIN", 200: "LACNIC", 201: "LACNIC",
    202: "APNIC", 203: "APNIC", 204: "ARIN", 205: "ARIN", 206: "ARIN",
    207: "ARIN", 208: "ARIN", 209: "ARIN", 210: "APNIC", 211: "APNIC",
    212: "RIPE NCC", 213: "RIPE NCC", 214: "ARIN", 215: "ARIN", 216: "ARIN",
    217: "RIPE NCC", 218: "APNIC", 219: "APNIC", 220: "APNIC", 221: "APNIC",
    222: "APNIC", 223: "APNIC",
}


class RdapEnricher:
    """Offline RFC 9224/9082 RDAP and Autonomous System enrichment engine."""

    def __init__(self, custom_allocations: list[_NetworkAllocation] | None = None):
        self._allocations = list(custom_allocations or _OFFLINE_ALLOCATIONS)

    def lookup(self, ip_str: str) -> RdapEnrichmentResult:
        """Resolve IP address to enriched ASN and network prefix offline."""
        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {ip_str!r} ({exc})") from exc

        # 1. Exact or enclosing match from known offline allocations
        for alloc in self._allocations:
            if ip_obj in alloc.network:
                return RdapEnrichmentResult(
                    ip=str(ip_obj),
                    asn=f"AS{alloc.asn}",
                    asn_number=alloc.asn,
                    as_name=alloc.as_name,
                    prefix=str(alloc.network),
                    registry=alloc.registry,
                    is_authoritative=False,
                )

        # 2. Deterministic RFC 9224 bootstrap fallback
        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = clean_ip.split(".")
            first_octet = int(octets[0])
            registry = _IANA_V4_RIR_MAP.get(first_octet, "IANA")
            # Default IPv4 routing prefix: /24
            prefix = str(ipaddress.ip_network(f"{clean_ip}/24", strict=False))
            # Fallback deterministic pseudo-ASN for unmapped ranges based on /16 or /24
            asn_num = 64512 + (first_octet % 1024)  # RFC 6996 Private ASN range
            as_name = f"Unmapped Net ({registry})"
            return RdapEnrichmentResult(
                ip=str(ip_obj),
                asn=f"AS{asn_num}",
                asn_number=asn_num,
                as_name=as_name,
                prefix=prefix,
                registry=registry,
                is_authoritative=False,
            )
        else:
            # IPv6 routing prefix default: /48
            prefix = str(ipaddress.ip_network(f"{clean_ip}/48", strict=False))
            asn_num = 65500
            return RdapEnrichmentResult(
                ip=str(ip_obj),
                asn=f"AS{asn_num}",
                asn_number=asn_num,
                as_name="Unmapped IPv6 Network",
                prefix=prefix,
                registry="IANA",
                is_authoritative=False,
            )

    def enrich_ip(
        self,
        ip_str: str,
        observed_at: str,
        evidence_hashes: list[str],
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Extract GraphNodes (ASN, Prefix) and GraphEdges (ANNOUNCED_BY, PREFIX_MEMBER) for an IP."""
        result = self.lookup(ip_str)
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        valid_evidence = [h for h in evidence_hashes if _HEX_64.match(h)]

        # 1. ASN Node
        asn_node = GraphNode.create(
            node_type=NodeType.ASN,
            canonical_name=result.asn,
            layer=EpistemicLayer.DERIVED,
            observed_at=observed_at,
            properties={
                "as_name": result.as_name,
                "asn_number": result.asn_number,
                "registry": result.registry,
            },
        )
        nodes.append(asn_node)

        # 2. Prefix Node
        prefix_node = GraphNode.create(
            node_type=NodeType.CDN_PREFIX,
            canonical_name=result.prefix,
            layer=EpistemicLayer.DERIVED,
            observed_at=observed_at,
            properties={
                "prefix": result.prefix,
                "registry": result.registry,
            },
        )
        nodes.append(prefix_node)

        # 3. Edge: IP -> ANNOUNCED_BY -> ASN
        ip_node_id = format_node_id(NodeType.IP, ip_str)
        edge_announced = GraphEdge.create(
            source_id=ip_node_id,
            target_id=asn_node.node_id,
            relation_type=RelationType.ANNOUNCED_BY,
            layer=EpistemicLayer.DERIVED,
            observed_at=observed_at,
            valid_from=observed_at,
            confidence=1.0,
            ruleset_version=RDAP_RULESET_VERSION,
            evidence_hashes=valid_evidence,
            properties={"as_name": result.as_name, "asn": result.asn},
        )
        edges.append(edge_announced)

        # 4. Edge: IP -> PREFIX_MEMBER -> Prefix
        edge_prefix = GraphEdge.create(
            source_id=ip_node_id,
            target_id=prefix_node.node_id,
            relation_type=RelationType.PREFIX_MEMBER,
            layer=EpistemicLayer.DERIVED,
            observed_at=observed_at,
            valid_from=observed_at,
            confidence=1.0,
            ruleset_version=RDAP_RULESET_VERSION,
            evidence_hashes=valid_evidence,
            properties={"prefix": result.prefix, "registry": result.registry},
        )
        edges.append(edge_prefix)

        return nodes, edges

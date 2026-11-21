"""Canonical IOC and Infrastructure Entity Identifiers for ANIE and AEGIS consumers.

Standardizes entity identifiers according to canonical URI schemes:
- Domain: domain:<fqdn> (punycode, lowercased, stripped trailing dot)
- IPv4: ipv4:<ip> (canonical dotted-quad)
- IPv6: ipv6:<ip> (RFC 5952 canonical compressed)
- ASN: asn:AS<number> (uppercase AS prefix followed by decimal integer)
- CIDR: cidr:<network>/<prefix> (canonical network prefix)
- Resolver: resolver:<name> (lowercase alphanumeric resolver identifier)
- Claim: claim:<claim_id>
- Discrepancy: discrepancy:<analysis_id>
"""

from __future__ import annotations

import enum
import ipaddress
import re
from typing import Any, Tuple

# Supported entity types
ENTITY_TYPE_DOMAIN = "domain"
ENTITY_TYPE_IPV4 = "ipv4"
ENTITY_TYPE_IPV6 = "ipv6"
ENTITY_TYPE_ASN = "asn"
ENTITY_TYPE_CIDR = "cidr"
ENTITY_TYPE_RESOLVER = "resolver"
ENTITY_TYPE_CLAIM = "claim"
ENTITY_TYPE_DISCREPANCY = "discrepancy"
ENTITY_TYPE_CERT = "cert"

SUPPORTED_ENTITY_TYPES = frozenset({
    ENTITY_TYPE_DOMAIN,
    ENTITY_TYPE_IPV4,
    ENTITY_TYPE_IPV6,
    ENTITY_TYPE_ASN,
    ENTITY_TYPE_CIDR,
    ENTITY_TYPE_RESOLVER,
    ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_DISCREPANCY,
    ENTITY_TYPE_CERT,
})


class EntityType(str, enum.Enum):
    DOMAIN = ENTITY_TYPE_DOMAIN
    IPV4 = ENTITY_TYPE_IPV4
    IPV6 = ENTITY_TYPE_IPV6
    ASN = ENTITY_TYPE_ASN
    CIDR = ENTITY_TYPE_CIDR
    RESOLVER = ENTITY_TYPE_RESOLVER
    CLAIM = ENTITY_TYPE_CLAIM
    DISCREPANCY = ENTITY_TYPE_DISCREPANCY
    CERT = ENTITY_TYPE_CERT


_ASN_REGEX = re.compile(r"^(?:AS|as)?(\d{1,10})$")
_RESOLVER_REGEX = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")
_LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEX_64_REGEX = re.compile(r"^[0-9a-f]{64}$")


def canonicalize_domain(domain: str) -> str:
    """Canonicalize a domain name to lowercased, punycode-normalized FQDN without trailing dot."""
    if not domain or not isinstance(domain, str):
        raise ValueError("domain must be a non-empty string")
    
    dom = domain.strip().lower()
    if dom.endswith("."):
        dom = dom[:-1]
    
    if not dom:
        raise ValueError("empty domain after normalization")
    
    # Punycode round-trip normalization (RFC 5891)
    try:
        parts = dom.split(".")
        normalized_parts = []
        for part in parts:
            if not part:
                raise ValueError(f"empty label in domain: {domain!r}")
            # Encode IDN / unicode if present
            ascii_label = part.encode("idna").decode("ascii")
            if len(ascii_label) > 63:
                raise ValueError(f"label exceeds 63 characters: {part!r}")
            if not _LABEL_REGEX.match(ascii_label):
                raise ValueError(f"invalid characters or format in domain label: {part!r}")
            normalized_parts.append(ascii_label)
        
        canonical = ".".join(normalized_parts)
        if len(canonical) > 253:
            raise ValueError(f"domain exceeds 253 characters: {domain!r}")
        return canonical
    except Exception as exc:
        raise ValueError(f"invalid domain syntax: {domain!r} ({exc})") from exc


def canonicalize_ipv4(ip_str: str) -> str:
    """Canonicalize an IPv4 address string to standard dotted-decimal notation."""
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError("ipv4 address must be a non-empty string")
    try:
        addr = ipaddress.IPv4Address(ip_str.strip())
        return str(addr)
    except Exception as exc:
        raise ValueError(f"invalid IPv4 address: {ip_str!r} ({exc})") from exc


def canonicalize_ipv6(ip_str: str) -> str:
    """Canonicalize an IPv6 address string to standard RFC 5952 compressed notation."""
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError("ipv6 address must be a non-empty string")
    try:
        addr = ipaddress.IPv6Address(ip_str.strip())
        return addr.compressed
    except Exception as exc:
        raise ValueError(f"invalid IPv6 address: {ip_str!r} ({exc})") from exc


def canonicalize_asn(asn_val: str | int) -> str:
    """Canonicalize an Autonomous System Number to AS<number> format."""
    val_str = str(asn_val).strip()
    match = _ASN_REGEX.match(val_str)
    if not match:
        raise ValueError(f"invalid ASN format: {asn_val!r}")
    num = int(match.group(1))
    if not (0 <= num <= 4294967295):
        raise ValueError(f"ASN out of range [0, 4294967295]: {asn_val!r}")
    return f"AS{num}"


def canonicalize_cidr(cidr_str: str) -> str:
    """Canonicalize a network CIDR to standard canonical network representation."""
    if not cidr_str or not isinstance(cidr_str, str):
        raise ValueError("cidr must be a non-empty string")
    try:
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return str(net)
    except Exception as exc:
        raise ValueError(f"invalid CIDR prefix: {cidr_str!r} ({exc})") from exc


def canonicalize_resolver(resolver_str: str) -> str:
    """Canonicalize a resolver identifier to lowercase valid token."""
    if not resolver_str or not isinstance(resolver_str, str):
        raise ValueError("resolver must be a non-empty string")
    clean = resolver_str.strip().lower()
    if not _RESOLVER_REGEX.match(clean):
        raise ValueError(f"invalid resolver identifier syntax: {resolver_str!r}")
    return clean


def canonicalize_identifier(ident_str: str) -> str:
    """Canonicalize an opaque identifier (claim ID or discrepancy ID)."""
    if not ident_str or not isinstance(ident_str, str):
        raise ValueError("identifier must be a non-empty string")
    clean = ident_str.strip()
    if not _IDENTIFIER_REGEX.match(clean):
        raise ValueError(f"invalid identifier syntax: {ident_str!r}")
    return clean


def canonicalize_cert_fingerprint(fp_str: str) -> str:
    """Canonicalize an X.509 certificate SHA-256 fingerprint to lowercase 64-hex string."""
    if not fp_str or not isinstance(fp_str, str):
        raise ValueError("certificate fingerprint must be a non-empty string")
    clean = fp_str.strip().lower()
    if clean.startswith("sha256:"):
        clean = clean[7:]
    clean = clean.replace(":", "").replace(" ", "").replace("-", "")
    if not _HEX_64_REGEX.match(clean):
        raise ValueError(f"invalid certificate SHA-256 fingerprint syntax: {fp_str!r}")
    return clean


def infer_entity_type(raw_value: str) -> str:
    """Infer the entity type of an unadorned input string."""
    val = raw_value.strip()
    if val.startswith("anie:entity:"):
        val = val[len("anie:entity:"):]

    if val.startswith("prefix:") or val.startswith("cdn_prefix:"):
        return ENTITY_TYPE_CIDR

    if "/" in val:
        try:
            ipaddress.ip_network(val, strict=False)
            return ENTITY_TYPE_CIDR
        except ValueError:
            pass

    try:
        addr = ipaddress.ip_address(val)
        return ENTITY_TYPE_IPV4 if isinstance(addr, ipaddress.IPv4Address) else ENTITY_TYPE_IPV6
    except ValueError:
        pass

    if _ASN_REGEX.match(val):
        return ENTITY_TYPE_ASN

    if val.startswith("claim_") or val.startswith("claim:"):
        return ENTITY_TYPE_CLAIM

    if val.startswith("discrepancy_") or val.startswith("discrepancy:"):
        return ENTITY_TYPE_DISCREPANCY

    if val.startswith("cert:") or val.startswith("certificate:"):
        return ENTITY_TYPE_CERT

    clean_fp = val.lower().replace(":", "").replace(" ", "").replace("-", "")
    if len(clean_fp) == 64 and _HEX_64_REGEX.match(clean_fp):
        return ENTITY_TYPE_CERT

    # Default assumption for text strings with dots or alphabetic characters
    return ENTITY_TYPE_DOMAIN


def build_entity_uri(entity_type: str, value: Any) -> str:
    """Build a canonical URI given entity type and raw value."""
    etype = entity_type.strip().lower()
    if etype in ("prefix", "cdn_prefix"):
        etype = ENTITY_TYPE_CIDR
    elif etype in ("cert", "certificate"):
        etype = ENTITY_TYPE_CERT
    if etype not in SUPPORTED_ENTITY_TYPES:
        raise ValueError(f"unsupported entity type: {entity_type!r}; expected one of {sorted(SUPPORTED_ENTITY_TYPES)}")

    val_str = str(value).strip()
    # Strip type prefix if caller passed full URI
    if val_str.startswith(f"{etype}:"):
        val_str = val_str[len(etype) + 1:]

    if etype == ENTITY_TYPE_DOMAIN:
        cval = canonicalize_domain(val_str)
    elif etype == ENTITY_TYPE_IPV4:
        cval = canonicalize_ipv4(val_str)
    elif etype == ENTITY_TYPE_IPV6:
        cval = canonicalize_ipv6(val_str)
    elif etype == ENTITY_TYPE_ASN:
        cval = canonicalize_asn(val_str)
    elif etype == ENTITY_TYPE_CIDR:
        cval = canonicalize_cidr(val_str)
    elif etype == ENTITY_TYPE_RESOLVER:
        cval = canonicalize_resolver(val_str)
    elif etype == ENTITY_TYPE_CLAIM:
        # Strip claim_ prefix if present
        if val_str.startswith("claim_"):
            val_str = val_str[6:]
        cval = canonicalize_identifier(val_str)
    elif etype == ENTITY_TYPE_DISCREPANCY:
        # Strip discrepancy_ prefix if present
        if val_str.startswith("discrepancy_"):
            val_str = val_str[12:]
        cval = canonicalize_identifier(val_str)
    elif etype == ENTITY_TYPE_CERT:
        cval = canonicalize_cert_fingerprint(val_str)
    else:
        raise ValueError(f"unhandled entity type: {etype!r}")

    return f"{etype}:{cval}"


def canonical_domain_uri(domain: str) -> str:
    return build_entity_uri(ENTITY_TYPE_DOMAIN, domain)


def canonical_ipv4_uri(ip: str) -> str:
    return build_entity_uri(ENTITY_TYPE_IPV4, ip)


def canonical_ipv6_uri(ip: str) -> str:
    return build_entity_uri(ENTITY_TYPE_IPV6, ip)


def canonical_asn_uri(asn: str | int) -> str:
    return build_entity_uri(ENTITY_TYPE_ASN, asn)


def canonical_cidr_uri(cidr: str) -> str:
    return build_entity_uri(ENTITY_TYPE_CIDR, cidr)


def canonical_resolver_uri(name: str) -> str:
    return build_entity_uri(ENTITY_TYPE_RESOLVER, name)


def canonical_claim_uri(claim_id: str) -> str:
    return build_entity_uri(ENTITY_TYPE_CLAIM, claim_id)


def canonical_discrepancy_uri(disc_id: str) -> str:
    return build_entity_uri(ENTITY_TYPE_DISCREPANCY, disc_id)


def canonical_cert_uri(fingerprint: str) -> str:
    return build_entity_uri(ENTITY_TYPE_CERT, fingerprint)


def parse_entity_uri(uri: str) -> Tuple[str, str]:
    """Parse a canonical entity URI into (entity_type, canonical_value).
    
    If raw unadorned value is passed without a colon prefix, infers the entity type.
    """
    if not uri or not isinstance(uri, str):
        raise ValueError("URI must be a non-empty string")
    
    stripped = uri.strip()
    if stripped.startswith("anie:entity:"):
        stripped = stripped[len("anie:entity:"):]

    if ":" in stripped:
        prefix, rest = stripped.split(":", 1)
        prefix_clean = prefix.lower()
        if prefix_clean in ("prefix", "cdn_prefix"):
            prefix_clean = ENTITY_TYPE_CIDR
        if prefix_clean in SUPPORTED_ENTITY_TYPES:
            # Re-canonicalize to ensure syntax guarantees
            full_uri = build_entity_uri(prefix_clean, rest)
            return (prefix_clean, full_uri.split(":", 1)[1])

    # Infer type if not explicitly prefixed
    inferred = infer_entity_type(stripped)
    full_uri = build_entity_uri(inferred, stripped)
    return (inferred, full_uri.split(":", 1)[1])


def parse_canonical_uri(uri: str) -> Tuple[EntityType, str]:
    """Strictly parse a canonical entity URI requiring explicit scheme."""
    if not uri or not isinstance(uri, str):
        raise ValueError("URI must be a non-empty string")
    stripped = uri.strip()
    if stripped.startswith("anie:entity:"):
        stripped = stripped[len("anie:entity:"):]
    if ":" not in stripped:
        raise ValueError(f"Invalid canonical URI (missing colon prefix): {uri!r}")
    prefix, rest = stripped.split(":", 1)
    prefix_clean = prefix.lower()
    if prefix_clean not in SUPPORTED_ENTITY_TYPES:
        raise ValueError(f"Invalid canonical URI scheme: {prefix!r}")
    full_uri = build_entity_uri(prefix_clean, rest)
    canonical_val = full_uri.split(":", 1)[1]
    return EntityType(prefix_clean), canonical_val


def validate_canonical_uri(uri: str) -> bool:
    """Return True if uri is a strictly valid canonical URI."""
    try:
        parse_canonical_uri(uri)
        return True
    except Exception:
        return False


def entity_uri_to_node_id(uri: str) -> str:
    """Extract graph node_id from canonical URI."""
    _, canonical_val = parse_entity_uri(uri)
    return canonical_val


def node_id_to_canonical_uri(node_id: str, node_type: str) -> str:
    """Convert graph node_id and node_type to canonical entity URI."""
    ntype = node_type.strip().lower()
    if ntype == "domain":
        return canonical_domain_uri(node_id)
    elif ntype in ("ipv4", "ip"):
        if ":" in node_id:
            return canonical_ipv6_uri(node_id)
        return canonical_ipv4_uri(node_id)
    elif ntype == "ipv6":
        return canonical_ipv6_uri(node_id)
    elif ntype == "asn":
        return canonical_asn_uri(node_id)
    elif ntype in ("cidr", "cdn_prefix", "prefix"):
        return canonical_cidr_uri(node_id)
    elif ntype == "resolver":
        return canonical_resolver_uri(node_id)
    elif ntype == "claim":
        return canonical_claim_uri(node_id)
    elif ntype == "discrepancy":
        return canonical_discrepancy_uri(node_id)
    elif ntype in ("cert", "certificate"):
        return canonical_cert_uri(node_id)
    return build_entity_uri(infer_entity_type(node_id), node_id)

"""Deterministic Passive TLS and X.509 Certificate Enrichment for ANIE Intelligence Graph.

Extracts structured, cryptographically bound entities from observed TLS handshakes:
- Certificate Node (Layer 1 FACT, identified by lowercase SHA-256 fingerprint)
- SERVES_CERTIFICATE Edge from serving IP to Certificate (Layer 1 FACT)
- NAMES_DOMAIN Edges from Certificate to Subject Alternative Names (Layer 2 DERIVED)
- Multi-tenant CDN / PaaS guardrails preventing false guilt-by-association.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID

from .canonical_entities import (
    canonical_cert_uri,
    canonical_domain_uri,
    canonical_ipv4_uri,
    canonical_ipv6_uri,
    canonicalize_cert_fingerprint,
    canonicalize_domain,
)
from .graph_models import (
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
    format_node_id,
)
from .observations import utc_iso

TLS_RULESET_VERSION = "anie.tls-enrichment.v1"

_KNOWN_CDN_PAAS_DOMAINS = frozenset({
    "cloudflare.com",
    "azureedge.net",
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "akamaized.net",
    "edgekey.net",
    "edgesuite.net",
    "trafficmanager.net",
    "appspot.com",
    "github.io",
    "herokuapp.com",
    "wpengine.com",
})


@dataclass(frozen=True)
class ObservedTlsEndpointEvidence:
    """Genuinely observed live TLS endpoint connection evidence.
    
    Guarantees that a Layer 1 SERVES_CERTIFICATE FACT edge is grounded in
    authentic wire telemetry rather than speculative offline parsing.
    
    Mandatory Invariants:
    - ip: verified IPv4 or IPv6 string
    - port: port integer (1..65535, default 443)
    - sni: Server Name Indication hostname requested/negotiated
    - observed_at: UTC ISO 8601 observation timestamp
    - source_id: provenance identifier of the collector node
    - evidence_hash: cryptographic SHA-256 wire hash of raw handshake/certificate
    - tls_version: negotiated TLS protocol version (e.g. 'TLSv1.3', 'TLSv1.2')
    """
    ip: str
    port: int
    sni: str
    observed_at: str
    source_id: str
    evidence_hash: str
    tls_version: str = "TLSv1.3"

    def __post_init__(self):
        if not self.ip or not isinstance(self.ip, str):
            raise ValueError("ip must be a non-empty string")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"port out of valid range [1, 65535]: {self.port}")
        if not self.sni or not isinstance(self.sni, str):
            raise ValueError("sni must be a non-empty string")
        utc_iso(self.observed_at)
        if not self.source_id or not isinstance(self.source_id, str):
            raise ValueError("source_id must be a non-empty string")
        clean_hash = self.evidence_hash.strip().lower()
        if len(clean_hash) != 64 or not re.match(r"^[0-9a-f]{64}$", clean_hash):
            raise ValueError(f"evidence_hash must be a 64-char lowercase hex digest: {self.evidence_hash!r}")


@dataclass(frozen=True)
class TlsCertificateRecord:
    """Immutable parsed X.509 certificate observation."""
    sha256_fingerprint: str
    spki_sha256: str
    subject_cn: str | None
    subject_alt_names: tuple[str, ...]
    issuer_cn: str | None
    issuer_org: str | None
    serial_number: str
    not_before: str
    not_after: str
    is_self_signed: bool
    is_multi_tenant: bool
    multi_tenant_reason: str | None = None
    raw_der_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_der_certificate(der_bytes: bytes) -> TlsCertificateRecord:
    """Parse raw X.509 DER bytes into immutable TlsCertificateRecord."""
    if not der_bytes:
        raise ValueError("empty DER certificate bytes")

    cert = x509.load_der_x509_certificate(der_bytes)
    return _build_cert_record(cert, der_bytes)


def parse_pem_certificate(pem_text: str) -> TlsCertificateRecord:
    """Parse PEM formatted X.509 certificate string into TlsCertificateRecord."""
    clean_pem = pem_text.strip().encode("utf-8")
    if not clean_pem:
        raise ValueError("empty PEM certificate string")

    cert = x509.load_pem_x509_certificate(clean_pem)
    der_bytes = cert.public_bytes(Encoding.DER)
    return _build_cert_record(cert, der_bytes)


def _build_cert_record(cert: x509.Certificate, der_bytes: bytes) -> TlsCertificateRecord:
    """Extract and normalize X.509 attributes into TlsCertificateRecord."""
    sha256_fp = hashlib.sha256(der_bytes).hexdigest().lower()

    # Calculate SPKI SHA-256
    spki_bytes = cert.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    spki_sha256 = hashlib.sha256(spki_bytes).hexdigest().lower()

    # Subject Common Name
    subject_cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn = subject_cns[0].value.strip() if subject_cns else None

    # Issuer Common Name and Org
    issuer_cns = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = issuer_cns[0].value.strip() if issuer_cns else None

    issuer_orgs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    issuer_org = issuer_orgs[0].value.strip() if issuer_orgs else None

    # Subject Alternative Names
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value.strip().lower())
    except x509.ExtensionNotFound:
        pass

    if subject_cn and subject_cn.lower() not in sans:
        # Include subject CN in domain linkages if formatted as hostname
        if "." in subject_cn and not subject_cn.startswith(" "):
            sans.append(subject_cn.lower())

    normalized_sans = tuple(sorted(set(sans)))

    # Serial Number (decimal string representation)
    serial_str = str(cert.serial_number)

    # Validity Timestamps (UTC ISO 8601)
    # Use timezone-aware UTC datetime attributes
    try:
        nb_dt = cert.not_valid_before_utc
        na_dt = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older cryptography versions
        nb_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na_dt = cert.not_valid_after.replace(tzinfo=timezone.utc)

    not_before = nb_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = na_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Self-signed determination
    is_self_signed = (cert.subject == cert.issuer)

    # Multi-tenant classification guardrails
    is_multi_tenant = False
    multi_tenant_reason = None

    if len(normalized_sans) >= 15:
        is_multi_tenant = True
        multi_tenant_reason = f"High-density SAN certificate ({len(normalized_sans)} domains)"
    else:
        for san in normalized_sans:
            # Check wildcard or known CDN/PaaS root suffix
            base_sfx = ".".join(san.split(".")[-2:]) if "." in san else san
            if base_sfx in _KNOWN_CDN_PAAS_DOMAINS:
                is_multi_tenant = True
                multi_tenant_reason = f"Contains shared CDN/PaaS domain suffix: {base_sfx}"
                break

    return TlsCertificateRecord(
        sha256_fingerprint=sha256_fp,
        spki_sha256=spki_sha256,
        subject_cn=subject_cn,
        subject_alt_names=normalized_sans,
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        serial_number=serial_str,
        not_before=not_before,
        not_after=not_after,
        is_self_signed=is_self_signed,
        is_multi_tenant=is_multi_tenant,
        multi_tenant_reason=multi_tenant_reason,
        raw_der_sha256=sha256_fp,
    )


class TlsEnricher:
    """Generates graph entities and typed relationships from parsed TLS certificates."""

    def __init__(self, ruleset_version: str = TLS_RULESET_VERSION):
        self.ruleset_version = ruleset_version

    def enrich_certificate_metadata(
        self,
        cert_record: TlsCertificateRecord,
        observed_at: str,
        evidence_hashes: list[str] | tuple[str, ...] = (),
    ) -> tuple[GraphNode, list[GraphEdge]]:
        """Extract certificate node and derived domain nodes from offline certificate parsing.
        
        Strict Epistemic Invariant:
        Offline certificate parsing extracts certificate identity (FACT) and SAN domain linkages (DERIVED).
        It strictly does NOT assert live endpoint serving (SERVES_CERTIFICATE), as offline parsing alone
        does not imply live certificate serving.
        """
        obs_iso = utc_iso(observed_at)
        cert_fp = cert_record.sha256_fingerprint
        cert_node_id = f"anie:entity:cert:{cert_fp}"

        cert_props: dict[str, Any] = {
            "fingerprint_sha256": cert_fp,
            "spki_sha256": cert_record.spki_sha256,
            "subject_cn": cert_record.subject_cn,
            "issuer_cn": cert_record.issuer_cn,
            "issuer_org": cert_record.issuer_org,
            "serial_number": cert_record.serial_number,
            "not_before": cert_record.not_before,
            "not_after": cert_record.not_after,
            "is_self_signed": cert_record.is_self_signed,
            "is_multi_tenant": cert_record.is_multi_tenant,
            "san_count": len(cert_record.subject_alt_names),
        }
        if cert_record.multi_tenant_reason:
            cert_props["multi_tenant_reason"] = cert_record.multi_tenant_reason

        # Certificate Node (Layer 1 FACT)
        cert_node = GraphNode(
            node_id=cert_node_id,
            node_type=NodeType.CERTIFICATE.value,
            canonical_name=cert_fp,
            layer=EpistemicLayer.FACT.value,
            first_observed_at=obs_iso,
            last_observed_at=obs_iso,
            properties=cert_props,
            tx_time=obs_iso,
        )

        # NAMES_DOMAIN edges (Layer 2 DERIVED) for each SAN domain
        names_edges: list[GraphEdge] = []
        for san in cert_record.subject_alt_names:
            clean_san = san.lower().strip()
            if not clean_san:
                continue

            target_san = clean_san[2:] if clean_san.startswith("*.") else clean_san
            try:
                dom_uri = format_node_id(NodeType.DOMAIN, target_san)
            except Exception:
                continue

            names_props: dict[str, Any] = {
                "raw_san": clean_san,
                "is_wildcard": clean_san.startswith("*."),
            }
            if cert_record.is_multi_tenant:
                names_props["multi_tenant_context"] = "Shared multi-tenant or CDN certificate pool."

            names_edge = GraphEdge.create(
                source_id=cert_node_id,
                target_id=dom_uri,
                relation_type=RelationType.NAMES_DOMAIN,
                layer=EpistemicLayer.DERIVED,
                observed_at=obs_iso,
                confidence=1.0,
                ruleset_version=self.ruleset_version,
                evidence_hashes=list(evidence_hashes),
                properties=names_props,
            )
            names_edges.append(names_edge)

        return cert_node, names_edges

    def enrich_endpoint(
        self,
        ip: str,
        cert_record: TlsCertificateRecord,
        observed_at: str,
        evidence_hashes: list[str],
        port: int = 443,
        sni: str | None = None,
        source_id: str = "oracle-collector-01:tls",
        tls_version: str = "TLSv1.3",
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Extract graph nodes and edges for an IP genuinely observed serving a TLS certificate.
        
        Strict Epistemic Invariant:
        SERVES_CERTIFICATE FACT edges originate ONLY from genuine observed TLS endpoint evidence,
        including endpoint IP, SNI, port, collection time, and provenance source_id.
        Offline certificate parsing alone must not imply live certificate serving.
        """
        if not evidence_hashes or not any(h.strip() for h in evidence_hashes):
            raise ValueError(
                "SERVES_CERTIFICATE FACT edge requires verified live endpoint observation evidence hashes; "
                "offline certificate parsing alone must not imply live certificate serving."
            )
        if not ip or not isinstance(ip, str):
            raise ValueError("endpoint IP must be a non-empty string")
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of valid range [1, 65535]: {port}")

        effective_sni = (sni or cert_record.subject_cn or ip).strip().lower()

        # Build verified endpoint evidence anchor
        evidence = ObservedTlsEndpointEvidence(
            ip=ip,
            port=port,
            sni=effective_sni,
            observed_at=observed_at,
            source_id=source_id,
            evidence_hash=evidence_hashes[0],
            tls_version=tls_version,
        )

        obs_iso = utc_iso(observed_at)
        cert_node, names_edges = self.enrich_certificate_metadata(cert_record, obs_iso, evidence_hashes)
        nodes = [cert_node]
        edges = list(names_edges)

        # IP Node URI
        ip_uri = format_node_id(NodeType.IP, ip)

        # SERVES_CERTIFICATE edge (Layer 1 FACT)
        serves_props: dict[str, Any] = {
            "endpoint": f"{ip}:{port}",
            "ip": ip,
            "port": port,
            "sni": effective_sni,
            "collection_time": obs_iso,
            "source_id": source_id,
            "provenance": source_id,
            "tls_version": tls_version,
        }
        if cert_record.is_multi_tenant:
            serves_props["guardrail_notice"] = (
                "Serving endpoint associated with multi-tenant certificate. "
                "Does NOT infer exclusive domain ownership."
            )

        serves_edge = GraphEdge.create(
            source_id=ip_uri,
            target_id=cert_node.node_id,
            relation_type=RelationType.SERVES_CERTIFICATE,
            layer=EpistemicLayer.FACT,
            observed_at=obs_iso,
            confidence=1.0,
            ruleset_version=self.ruleset_version,
            evidence_hashes=evidence_hashes,
            properties=serves_props,
        )
        edges.insert(0, serves_edge)

        return nodes, edges

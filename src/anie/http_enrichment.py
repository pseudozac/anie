"""Deterministic Passive HTTP Response Metadata Enrichment for ANIE Intelligence Graph.

Milestone M3.8: Multi-Vector Intelligence, Passive HTTP Metadata & Competing Hypotheses.

Guarantees:
- Zero active crawling or outbound network generation (strictly offline parser & replay).
- Accepts only authorized, provenance-bearing observations (ObservedHttpEndpointEvidence).
- Extracts bounded, approved response fields: status_code, server, via, content-type, HSTS, CSP.
- Strictly strips response bodies, cookies, authentication tokens, query parameters, and sensitive headers.
- Hard resource bounds: max 64 headers, max 1024 bytes per value, max 16 KB aggregate header block.
- Classifies technology indicators strictly as spoofable, derived assertions (DERIVED), never wire facts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Any, Sequence

from .canonical_entities import (
    canonical_domain_uri,
    canonical_ipv4_uri,
    canonical_ipv6_uri,
    canonical_technology_uri,
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
from .observations import canonical_json, utc_iso

HTTP_RULESET_VERSION = "anie.http-enrichment.v1"

# Security & Privacy Guardrails: sensitive headers strictly excluded from storage & digests
_SENSITIVE_HEADER_NAMES = frozenset({
    "set-cookie",
    "cookie",
    "cookie2",
    "set-cookie2",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "csrf-token",
    "authentication",
    "proxy-authenticate",
    "www-authenticate",
    "bearer",
    "private-token",
    "x-amz-security-token",
    "x-session-token",
    "session-token",
    "x-forwarded-for",
    "client-ip",
    "x-real-ip",
})

# Approved passive telemetry headers for security posture & infrastructure analysis
_APPROVED_HEADER_NAMES = frozenset({
    "server",
    "via",
    "content-type",
    "strict-transport-security",
    "content-security-policy",
    "x-content-security-policy",
    "x-webkit-csp",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "access-control-allow-origin",
    "x-powered-by",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
    "cf-ray",
    "cf-cache-status",
    "x-amz-cf-id",
    "x-fastly-request-id",
    "x-github-request-id",
    "age",
    "date",
    "last-modified",
    "etag",
})

# Hard bounded memory and parsing complexity limits
MAX_HEADER_COUNT = 64
MAX_NAME_LEN = 64
MAX_VAL_LEN = 1024
MAX_AGGREGATE_BYTES = 16384  # 16 KiB
MAX_RAW_INPUT_BYTES = 65536  # 64 KiB

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_STATUS_LINE_RE = re.compile(r"^HTTP/(1\.[01]|2(?:\.0)?)\s+(\d{3})(?:\s+.*)?$", re.IGNORECASE)
_HEADER_SPLIT_RE = re.compile(r"^([^:]+):(.*)$")
_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class ObservedHttpEndpointEvidence:
    """Genuinely observed live HTTP wire transport evidence.
    
    Guarantees that HTTP assertions originate from verified collection telemetry
    rather than uncalibrated speculation.
    """
    ip: str
    port: int
    sni_or_host: str
    observed_at: str
    source_id: str
    evidence_hash: str
    http_version: str = "HTTP/1.1"

    def __post_init__(self):
        if not self.ip or not isinstance(self.ip, str):
            raise ValueError("ip must be a non-empty string")
        # Validate IP syntax
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {self.ip!r}") from exc

        if not (1 <= self.port <= 65535):
            raise ValueError(f"port out of valid range [1, 65535]: {self.port}")
        if not self.sni_or_host or not isinstance(self.sni_or_host, str):
            raise ValueError("sni_or_host must be a non-empty string")
        utc_iso(self.observed_at)
        if not self.source_id or not isinstance(self.source_id, str):
            raise ValueError("source_id must be a non-empty string")
        clean_hash = self.evidence_hash.strip().lower()
        if len(clean_hash) != 64 or not _HEX_64.fullmatch(clean_hash):
            raise ValueError(f"evidence_hash must be a 64-char lowercase hex digest: {self.evidence_hash!r}")
        if self.http_version not in ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"):
            raise ValueError(f"unsupported http_version: {self.http_version!r}")


@dataclass(frozen=True)
class HttpResponseRecord:
    """Sanitized, normalized point-in-time HTTP response metadata."""
    status_code: int
    http_version: str
    canonical_headers: tuple[tuple[str, str], ...]
    server: str | None
    via: str | None
    content_type: str | None
    hsts_header: str | None
    hsts_max_age: int | None
    hsts_include_subdomains: bool
    csp_present: bool
    technology_indicators: tuple[str, ...]
    canonical_header_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sanitize_header_value(raw_val: str) -> str:
    """Normalize header value: remove control characters and newlines, collapse whitespace, truncate."""
    # Strip any \r, \n, null bytes to prevent header injection or multi-line exploits
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", raw_val)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > MAX_VAL_LEN:
        cleaned = cleaned[:MAX_VAL_LEN]
    return cleaned


def _extract_technology_indicators(
    server: str | None,
    via: str | None,
    x_powered_by: str | None,
    extra_headers: dict[str, str],
) -> tuple[str, ...]:
    """Extract deterministic technology indicators from headers (strictly derived/spoofable)."""
    techs: set[str] = set()

    # Server signatures
    if server:
        s_lower = server.lower()
        if "cloudflare" in s_lower:
            techs.add("cloudflare")
        if "nginx" in s_lower:
            techs.add("nginx")
        if "apache" in s_lower:
            techs.add("apache")
        if "iis" in s_lower or "microsoft-iis" in s_lower:
            techs.add("microsoft-iis")
        if "caddy" in s_lower:
            techs.add("caddy")
        if "envoy" in s_lower:
            techs.add("envoy")
        if "fastly" in s_lower:
            techs.add("fastly")
        if "varnish" in s_lower:
            techs.add("varnish")
        if "akamaighost" in s_lower or "akamai" in s_lower:
            techs.add("akamai")
        if "litespeed" in s_lower:
            techs.add("litespeed")
        if "openresty" in s_lower:
            techs.add("openresty")
        if "traefik" in s_lower:
            techs.add("traefik")
        if "gunicorn" in s_lower:
            techs.add("gunicorn")
        if "uvicorn" in s_lower:
            techs.add("uvicorn")

    # Via signatures
    if via:
        v_lower = via.lower()
        if "varnish" in v_lower:
            techs.add("varnish")
        if "cloudfront" in v_lower:
            techs.add("cloudfront")
        if "squid" in v_lower:
            techs.add("squid")
        if "google" in v_lower:
            techs.add("google-frontend")
        if "akamai" in v_lower:
            techs.add("akamai")

    # X-Powered-By signatures (disclaimed as high-spoofability)
    if x_powered_by:
        x_lower = x_powered_by.lower()
        if "php" in x_lower:
            techs.add("php")
        if "express" in x_lower:
            techs.add("expressjs")
        if "asp.net" in x_lower:
            techs.add("aspnet")
        if "next.js" in x_lower:
            techs.add("nextjs")

    # Header-specific markers
    if "cf-ray" in extra_headers or "cf-cache-status" in extra_headers:
        techs.add("cloudflare")
    if "x-amz-cf-id" in extra_headers:
        techs.add("cloudfront")
    if "x-fastly-request-id" in extra_headers:
        techs.add("fastly")
    if "x-github-request-id" in extra_headers:
        techs.add("github-pages")

    return tuple(sorted(techs))


def parse_http1_response_headers(raw_input: bytes | str) -> HttpResponseRecord:
    """Parse raw HTTP/1.x wire response headers with strict bounds and sensitive scrubbing."""
    if isinstance(raw_input, bytes):
        if len(raw_input) > MAX_RAW_INPUT_BYTES:
            raw_input = raw_input[:MAX_RAW_INPUT_BYTES]
        text = raw_input.decode("latin-1", errors="replace")
    elif isinstance(raw_input, str):
        if len(raw_input) > MAX_RAW_INPUT_BYTES:
            raw_input = raw_input[:MAX_RAW_INPUT_BYTES]
        text = raw_input
    else:
        raise ValueError(f"expected bytes or str for raw_input, got {type(raw_input)}")

    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty HTTP response data")

    # 1. Parse Status Line
    status_line = lines[0].strip()
    status_match = _STATUS_LINE_RE.match(status_line)
    if not status_match:
        raise ValueError(f"malformed HTTP status line: {status_line!r}")

    http_version_raw = status_match.group(1)
    status_code = int(status_match.group(2))
    if not (100 <= status_code <= 599):
        raise ValueError(f"invalid HTTP status code: {status_code}")

    http_version = f"HTTP/{http_version_raw}"

    # 2. Parse Headers
    raw_headers: list[tuple[str, str]] = []
    current_aggregate_bytes = len(status_line.encode("utf-8"))

    for line in lines[1:]:
        s_line = line.strip()
        if not s_line:
            # Empty line signifies end of header section; ignore body completely
            break

        current_aggregate_bytes += len(line.encode("utf-8"))
        if current_aggregate_bytes > MAX_AGGREGATE_BYTES:
            # Aggregate header ceiling exceeded: stop parsing further headers safely
            break

        if len(raw_headers) >= MAX_HEADER_COUNT:
            # Header count ceiling reached
            break

        h_match = _HEADER_SPLIT_RE.match(line)
        if not h_match:
            # Malformed header line; discard safely
            continue

        h_name = h_match.group(1).strip().lower()
        h_val = h_match.group(2).strip()

        # Enforce name bounds
        if not h_name or len(h_name) > MAX_NAME_LEN:
            continue

        raw_headers.append((h_name, h_val))

    return _build_http_record(status_code, http_version, raw_headers)


def parse_http2_response_headers(
    headers: Sequence[tuple[str, str]] | dict[str, str] | Sequence[Sequence[str]],
) -> HttpResponseRecord:
    """Parse HTTP/2 pseudo-headers and response fields with strict bounds and sensitive scrubbing."""
    if isinstance(headers, dict):
        raw_list = list(headers.items())
    elif isinstance(headers, (list, tuple)):
        raw_list = [(str(h[0]), str(h[1])) for h in headers if len(h) >= 2]
    else:
        raise ValueError(f"unsupported headers structure: {type(headers)}")

    status_code: int | None = None
    processed_headers: list[tuple[str, str]] = []
    current_bytes = 0

    for name, val in raw_list:
        n_lower = name.strip().lower()
        v_str = str(val).strip()

        if n_lower == ":status":
            try:
                status_code = int(v_str)
                if not (100 <= status_code <= 599):
                    raise ValueError(f"invalid :status: {status_code}")
            except ValueError as exc:
                raise ValueError(f"malformed :status pseudo-header: {v_str!r}") from exc
            continue

        if n_lower.startswith(":"):
            # Ignore other pseudo-headers (e.g. :path, :method if passed in response)
            continue

        current_bytes += len(n_lower.encode("utf-8")) + len(v_str.encode("utf-8"))
        if current_bytes > MAX_AGGREGATE_BYTES:
            break
        if len(processed_headers) >= MAX_HEADER_COUNT:
            break

        if not n_lower or len(n_lower) > MAX_NAME_LEN:
            continue

        processed_headers.append((n_lower, v_str))

    if status_code is None:
        raise ValueError("HTTP/2 headers missing mandatory ':status' pseudo-header")

    return _build_http_record(status_code, "HTTP/2", processed_headers)


def _build_http_record(
    status_code: int,
    http_version: str,
    raw_headers: list[tuple[str, str]],
) -> HttpResponseRecord:
    """Normalize, scrub sensitive headers, extract approved fields, and calculate canonical digest."""
    sanitized_approved: list[tuple[str, str]] = []
    extra_headers: dict[str, str] = {}

    server: str | None = None
    via: str | None = None
    content_type: str | None = None
    hsts_header: str | None = None
    hsts_max_age: int | None = None
    hsts_include_subdomains: bool = False
    csp_present: bool = False
    x_powered_by: str | None = None

    for name, raw_val in raw_headers:
        n_clean = name.strip().lower()

        # Absolute Sensitive Header Blacklist: Drop immediately
        if n_clean in _SENSITIVE_HEADER_NAMES:
            continue

        # Reject names containing illegal control chars
        if re.search(r"[\x00-\x1f\x7f]", n_clean):
            continue

        val_clean = _sanitize_header_value(raw_val)

        # Retain only approved headers for metadata storage and technology inference
        if n_clean in _APPROVED_HEADER_NAMES:
            sanitized_approved.append((n_clean, val_clean))
            extra_headers[n_clean] = val_clean

            if n_clean == "server" and server is None:
                server = val_clean
            elif n_clean == "via" and via is None:
                via = val_clean
            elif n_clean == "content-type" and content_type is None:
                # Retain primary MIME media type only (e.g. 'text/html')
                content_type = val_clean.split(";")[0].strip().lower()
            elif n_clean == "strict-transport-security" and hsts_header is None:
                hsts_header = val_clean
                m_age = _HSTS_MAX_AGE_RE.search(val_clean)
                if m_age:
                    try:
                        hsts_max_age = int(m_age.group(1))
                    except ValueError:
                        hsts_max_age = None
                if "includesubdomains" in val_clean.lower():
                    hsts_include_subdomains = True
            elif n_clean in ("content-security-policy", "x-content-security-policy", "x-webkit-csp"):
                csp_present = True
            elif n_clean == "x-powered-by" and x_powered_by is None:
                x_powered_by = val_clean

    # Deterministic sorting of approved canonical headers
    sorted_headers = tuple(sorted(sanitized_approved, key=lambda x: (x[0], x[1])))

    # Technology extraction
    tech_indicators = _extract_technology_indicators(server, via, x_powered_by, extra_headers)

    # Compute deterministic canonical header digest in bounded memory
    hasher = hashlib.sha256()
    hasher.update(f"STATUS:{status_code}\n".encode("utf-8"))
    hasher.update(f"VERSION:{http_version}\n".encode("utf-8"))
    for h_name, h_val in sorted_headers:
        hasher.update(f"{h_name}:{h_val}\n".encode("utf-8"))
    header_digest = hasher.hexdigest().lower()

    return HttpResponseRecord(
        status_code=status_code,
        http_version=http_version,
        canonical_headers=sorted_headers,
        server=server,
        via=via,
        content_type=content_type,
        hsts_header=hsts_header,
        hsts_max_age=hsts_max_age,
        hsts_include_subdomains=hsts_include_subdomains,
        csp_present=csp_present,
        technology_indicators=tech_indicators,
        canonical_header_hash=header_digest,
    )


class HttpEnricher:
    """Enriches the ANIE intelligence graph with passive HTTP telemetry entities and relationships."""

    def __init__(self, ruleset_version: str = HTTP_RULESET_VERSION):
        self.ruleset_version = ruleset_version

    def enrich_http_metadata(
        self,
        record: HttpResponseRecord,
        evidence: ObservedHttpEndpointEvidence,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Generate graph nodes and typed relationships from verified passive HTTP metadata.
        
        Strict Epistemic Invariants:
        1. IP and Host nodes are grounded in Layer 1 FACT wire measurements.
        2. Technology entities and USES_TECHNOLOGY edges are classified strictly as Layer 2 DERIVED
           assertions with explicit heuristic confidence (<= 0.85) and spoofability disclaimers.
        3. PROTECTED_BY_POLICY edge links Domain to HSTS posture when valid HSTS is observed.
        """
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        obs_time = evidence.observed_at

        # 1. Subject Node (Host or IP)
        is_ip = False
        try:
            ipaddress.ip_address(evidence.sni_or_host)
            is_ip = True
            subj_type = NodeType.IP
            subj_name = evidence.sni_or_host
        except ValueError:
            subj_type = NodeType.DOMAIN
            subj_name = canonicalize_domain(evidence.sni_or_host)

        subject_node = GraphNode.create(
            node_type=subj_type,
            canonical_name=subj_name,
            layer=EpistemicLayer.FACT,
            observed_at=obs_time,
            properties={"http_observed": True, "http_version": evidence.http_version},
        )
        nodes.append(subject_node)

        # Also create IP node if different from subject
        ip_node = GraphNode.create(
            node_type=NodeType.IP,
            canonical_name=evidence.ip,
            layer=EpistemicLayer.FACT,
            observed_at=obs_time,
            properties={"endpoint_port": evidence.port},
        )
        nodes.append(ip_node)

        # 2. Technology Nodes and USES_TECHNOLOGY Edges (DERIVED / Heuristic)
        for tech in record.technology_indicators:
            tech_node = GraphNode.create(
                node_type=NodeType.TECHNOLOGY,
                canonical_name=tech,
                layer=EpistemicLayer.DERIVED,
                observed_at=obs_time,
                properties={
                    "technology_name": tech,
                    "is_spoofable": True,
                    "detection_source": "passive_http_header",
                    "notice": "Derived assertion from passive HTTP response header; subject to server header spoofing.",
                },
            )
            nodes.append(tech_node)

            # Edge from Subject (Domain) to Technology
            tech_edge = GraphEdge.create(
                source_id=subject_node.node_id,
                target_id=tech_node.node_id,
                relation_type=RelationType.USES_TECHNOLOGY,
                layer=EpistemicLayer.DERIVED,
                observed_at=obs_time,
                valid_from=obs_time,
                ruleset_version=self.ruleset_version,
                confidence=0.80,  # Explicitly bounded heuristic score (< 1.0)
                evidence_hashes=(evidence.evidence_hash,),
                properties={
                    "is_spoofable": True,
                    "header_hash": record.canonical_header_hash,
                    "status_code": record.status_code,
                    "server_header": record.server,
                    "via_header": record.via,
                    "notice": "Heuristic technology assertion; headers can be modified or spoofed by origins.",
                },
            )
            edges.append(tech_edge)

            # Edge from Serving IP to Technology
            ip_tech_edge = GraphEdge.create(
                source_id=ip_node.node_id,
                target_id=tech_node.node_id,
                relation_type=RelationType.USES_TECHNOLOGY,
                layer=EpistemicLayer.DERIVED,
                observed_at=obs_time,
                valid_from=obs_time,
                ruleset_version=self.ruleset_version,
                confidence=0.80,
                evidence_hashes=(evidence.evidence_hash,),
                properties={
                    "is_spoofable": True,
                    "endpoint_port": evidence.port,
                    "header_hash": record.canonical_header_hash,
                },
            )
            edges.append(ip_tech_edge)

        # 3. Security Policy Edge: HSTS
        if record.hsts_header and record.hsts_max_age is not None and record.hsts_max_age > 0:
            hsts_policy_node = GraphNode.create(
                node_type=NodeType.TECHNOLOGY,
                canonical_name="hsts-policy",
                layer=EpistemicLayer.DERIVED,
                observed_at=obs_time,
                properties={
                    "policy_type": "HSTS",
                    "max_age_seconds": record.hsts_max_age,
                    "include_subdomains": record.hsts_include_subdomains,
                },
            )
            nodes.append(hsts_policy_node)

            policy_edge = GraphEdge.create(
                source_id=subject_node.node_id,
                target_id=hsts_policy_node.node_id,
                relation_type=RelationType.PROTECTED_BY_POLICY,
                layer=EpistemicLayer.DERIVED,
                observed_at=obs_time,
                valid_from=obs_time,
                ruleset_version=self.ruleset_version,
                confidence=0.95,
                evidence_hashes=(evidence.evidence_hash,),
                properties={
                    "max_age_seconds": record.hsts_max_age,
                    "include_subdomains": record.hsts_include_subdomains,
                },
            )
            edges.append(policy_edge)

        return nodes, edges

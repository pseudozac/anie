"""Cross-Vector Intelligence Correlation Subsystem for ANIE.

Milestone M3.9: Cross-Vector Intelligence Correlation & AEGIS Consumer Integration.

Provides deterministic, explainable correlation across multi-vector telemetry:
1. DNS Vector: Multi-resolver answers, DNSSEC, TTL, wire RCODE.
2. TLS Vector: Certificate fingerprints, SANs, issuer, validity, live endpoint serving.
3. HTTP Vector: Status codes, Server, Via, HSTS, CSP, technology indicators.
4. BGP / RDAP Vector: Origin-AS, prefix delegation, registry attribution.

Strict Epistemic & Architectural Invariants:
- Explicitly separates temporal correlation from causation: co-occurrence in time does
  not imply causal dependency or maliciousness.
- Formulates competing hypotheses with explicit corroborating and contradicting evidence.
- Heuristic scores are rule-based corroboration metrics, NOT calibrated Bayesian probabilities.
- Every evidence reference is verified against authoritative first-party records; a user-supplied
  hash alone NEVER authenticates an observation.
- Bounded memory footprint (<200 MiB RAM) and strictly sub-quadratic execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import ipaddress
import json
import sqlite3
from typing import Any, Iterable, Sequence

from .canonical_entities import (
    canonical_domain_uri,
    canonical_ipv4_uri,
    canonical_ipv6_uri,
    canonicalize_domain,
    parse_entity_uri,
)
from .graph_models import (
    ClaimVerificationState,
    EpistemicLayer,
    NodeType,
    RelationType,
    format_node_id,
)
from .observations import canonical_json, utc_iso
from .real_models import RealCollectionEvent, RealObservation
from .temporal_intelligence import (
    CompetingHypothesis,
    HypothesisStatus,
    _PROVENANCE_TAGGED_NETWORKS,
)

CROSS_VECTOR_RULESET_VERSION = "anie.cross-vector-correlation.v1"
CROSS_VECTOR_FINDING_SCHEMA = "anie.cross-vector-finding.v2"


class FindingType(str, Enum):
    """Categorization of cross-vector findings."""
    CROSS_VECTOR_INFRASTRUCTURE_SHIFT = "CROSS_VECTOR_INFRASTRUCTURE_SHIFT"
    ROUTINE_CERTIFICATE_ROTATION = "ROUTINE_CERTIFICATE_ROTATION"
    CDN_PROVIDER_MIGRATION = "CDN_PROVIDER_MIGRATION"
    SHARED_HOSTING_REBALANCE = "SHARED_HOSTING_REBALANCE"
    MULTI_VECTOR_DIVERGENCE = "MULTI_VECTOR_DIVERGENCE"
    SINGLE_VECTOR_OBSERVATION = "SINGLE_VECTOR_OBSERVATION"


class FindingState(str, Enum):
    """Lifecycle state of a cross-vector finding."""
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class VectorObservationSummary:
    """Normalized summary of observations for a specific vector."""
    vector: str
    observed_at: str
    evidence_id: str
    evidence_hash: str
    values: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VectorObservationSummary":
        return cls(
            vector=data["vector"],
            observed_at=data["observed_at"],
            evidence_id=data["evidence_id"],
            evidence_hash=data["evidence_hash"],
            values=list(data.get("values", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class TemporalCorrelationNarrative:
    """Narrative separating temporal coincidence from causal relationship."""
    coincident_change_detected: bool
    causation_inferred: bool
    analysis: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TemporalCorrelationNarrative":
        return cls(
            coincident_change_detected=bool(data.get("coincident_change_detected", False)),
            causation_inferred=bool(data.get("causation_inferred", False)),
            analysis=str(data.get("analysis", "")),
        )


@dataclass(frozen=True)
class AbstentionState:
    """Explicit abstention tracking for multi-vector coverage."""
    abstained: bool
    reason: str | None
    participating_vectors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AbstentionState":
        return cls(
            abstained=bool(data.get("abstained", False)),
            reason=data.get("reason"),
            participating_vectors=list(data.get("participating_vectors", [])),
        )


@dataclass(frozen=True)
class CrossVectorFinding:
    """Normalized, uncertainty-aware cross-vector intelligence finding.
    
    Milestone M3.9: Conforms to AEGIS Consumer Contract V2 (anie.cross-vector-finding.v2).
    """
    subject_uri: str
    finding_type: str
    epistemic_layer: str
    asserted_at: str
    valid_from: str
    valid_until: str | None
    state: str
    temporal_correlation_vs_causation: TemporalCorrelationNarrative
    abstention_state: AbstentionState
    vectors: dict[str, VectorObservationSummary]
    competing_hypotheses: list[CompetingHypothesis]
    supersedes_finding_id: str | None = None
    superseded_by_finding_id: str | None = None
    ruleset_version: str = CROSS_VECTOR_RULESET_VERSION
    schema: str = CROSS_VECTOR_FINDING_SCHEMA
    disclaimer: str = (
        "Heuristic confidence scores are uncalibrated rule-based metrics, NOT calibrated "
        "Bayesian probabilities. Empirical novelty and infrastructure drift do not constitute "
        "proof of maliciousness or compromise."
    )
    unverified_evidence_references: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(init=False)

    def __post_init__(self):
        utc_iso(self.asserted_at)
        utc_iso(self.valid_from)
        if self.valid_until is not None:
            utc_iso(self.valid_until)

        # Deterministic content-addressed identifier
        id_material = {
            "subject_uri": self.subject_uri,
            "finding_type": self.finding_type,
            "asserted_at": self.asserted_at,
            "vectors": sorted(self.vectors.keys()),
            "evidence_hashes": sorted(v.evidence_hash for v in self.vectors.values()),
            "ruleset_version": self.ruleset_version,
        }
        digest = sha256(canonical_json(id_material).encode("utf-8")).hexdigest()
        object.__setattr__(self, "finding_id", f"fnd_{digest[:32]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "finding_id": self.finding_id,
            "subject_uri": self.subject_uri,
            "finding_type": self.finding_type,
            "epistemic_layer": self.epistemic_layer,
            "asserted_at": self.asserted_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "state": self.state,
            "supersedes_finding_id": self.supersedes_finding_id,
            "superseded_by_finding_id": self.superseded_by_finding_id,
            "temporal_correlation_vs_causation": self.temporal_correlation_vs_causation.to_dict(),
            "abstention_state": self.abstention_state.to_dict(),
            "vectors": {k: v.to_dict() for k, v in self.vectors.items()},
            "competing_hypotheses": [h.to_dict() for h in self.competing_hypotheses],
            "unverified_evidence_references": self.unverified_evidence_references,
            "ruleset_version": self.ruleset_version,
            "disclaimer": self.disclaimer,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CrossVectorFinding":
        vectors_dict = {}
        for k, v in data.get("vectors", {}).items():
            vectors_dict[k] = VectorObservationSummary.from_dict(v)

        hypotheses = []
        for h in data.get("competing_hypotheses", []):
            hypotheses.append(CompetingHypothesis.from_dict(h))

        return cls(
            subject_uri=data["subject_uri"],
            finding_type=data["finding_type"],
            epistemic_layer=data.get("epistemic_layer", EpistemicLayer.HYPOTHESIS.value),
            asserted_at=data["asserted_at"],
            valid_from=data["valid_from"],
            valid_until=data.get("valid_until"),
            state=data.get("state", FindingState.ACTIVE.value),
            temporal_correlation_vs_causation=TemporalCorrelationNarrative.from_dict(
                data.get("temporal_correlation_vs_causation", {})
            ),
            abstention_state=AbstentionState.from_dict(data.get("abstention_state", {})),
            vectors=vectors_dict,
            competing_hypotheses=hypotheses,
            supersedes_finding_id=data.get("supersedes_finding_id"),
            superseded_by_finding_id=data.get("superseded_by_finding_id"),
            ruleset_version=data.get("ruleset_version", CROSS_VECTOR_RULESET_VERSION),
            schema=data.get("schema", CROSS_VECTOR_FINDING_SCHEMA),
            disclaimer=data.get("disclaimer", ""),
            unverified_evidence_references=list(data.get("unverified_evidence_references", [])),
            properties=dict(data.get("properties", {})),
        )


def _is_cdn_ip(ip_str: str) -> tuple[bool, str]:
    """Check if an IP matches known published CDN / Anycast ranges with provenance."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        for pt_net in _PROVENANCE_TAGGED_NETWORKS:
            if addr in pt_net.network:
                return True, pt_net.provider
    except ValueError:
        pass
    return False, ""


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    """Check if a domain matches an exact name or wildcard pattern (*.example.com)."""
    d = domain.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    if d == p:
        return True
    if p.startswith("*."):
        suffix = p[2:]
        if d.endswith("." + suffix):
            return True
    return False


class CrossVectorCorrelator:
    """Engine for correlating multi-vector internet telemetry and synthesizing competing hypotheses."""

    def __init__(
        self,
        store: Any = None,
        ruleset_version: str = CROSS_VECTOR_RULESET_VERSION,
    ):
        self.store = store
        self.ruleset_version = ruleset_version

    def correlate_records(
        self,
        domain: str,
        observations: Sequence[Any] = (),
        events: Sequence[Any] | None = None,
        *,
        vectors: dict[str, VectorObservationSummary] | None = None,
        as_of: str | None = None,
    ) -> list[CrossVectorFinding]:
        """Correlate in-memory observation and event records or direct vector summaries for a domain."""
        canon_domain = canonicalize_domain(domain)
        subject_uri = format_node_id(NodeType.DOMAIN, canon_domain)
        now_iso = as_of or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Map events by event_id and raw_sha256 for fast lookup
        events_by_id: dict[str, Any] = {}
        events_by_hash: dict[str, Any] = {}
        if events:
            for ev in events:
                eid = getattr(ev, "event_id", None) or (ev.get("event_id") if isinstance(ev, dict) else None)
                ehash = getattr(ev, "raw_sha256", None) or (ev.get("raw_sha256") if isinstance(ev, dict) else None)
                if eid:
                    events_by_id[eid] = ev
                if ehash:
                    events_by_hash[ehash] = ev

        active_vectors: dict[str, VectorObservationSummary] = {}
        if vectors:
            active_vectors.update(vectors)

        all_evidence_hashes: set[str] = set()
        for v in active_vectors.values():
            if v.evidence_hash:
                all_evidence_hashes.add(v.evidence_hash)

        # If observations passed, parse them into vectors
        dns_obs: list[Any] = []
        tls_obs: list[Any] = []
        http_obs: list[Any] = []

        for obs in observations:
            subj = getattr(obs, "subject", "") or (obs.get("subject", "") if isinstance(obs, dict) else "")
            kind = getattr(obs, "kind", "") or (obs.get("kind", "") if isinstance(obs, dict) else "")
            if kind.startswith("dns_"):
                dns_obs.append(obs)
            elif "tls" in kind or kind in ("tls_cert", "tls_handshake"):
                tls_obs.append(obs)
            elif "http" in kind or kind in ("http_response", "http_metadata"):
                http_obs.append(obs)

        # 1. DNS Vector Summary if not already in vectors
        if dns_obs and "dns" not in active_vectors:
            latest_dns = max(dns_obs, key=lambda o: getattr(o, "observed_at", "") or o.get("observed_at", ""))
            ev_id = getattr(latest_dns, "evidence_id", "") or latest_dns.get("evidence_id", "")
            ev = events_by_id.get(ev_id)
            ev_hash = getattr(ev, "raw_sha256", None) if ev else (ev.get("raw_sha256") if isinstance(ev, dict) else None)
            if not ev_hash:
                ev_hash = sha256(ev_id.encode("utf-8")).hexdigest()
            all_evidence_hashes.add(ev_hash)

            dns_ips = []
            for o in dns_obs:
                vals = getattr(o, "values", None) or (o.get("values", []) if isinstance(o, dict) else [])
                for val in vals:
                    if isinstance(val, str) and ("." in val or ":" in val):
                        dns_ips.append(val.strip())

            active_vectors["dns"] = VectorObservationSummary(
                vector="dns",
                observed_at=getattr(latest_dns, "observed_at", now_iso) or latest_dns.get("observed_at", now_iso),
                evidence_id=ev_id,
                evidence_hash=ev_hash,
                values=sorted(set(dns_ips)),
                metadata={"total_dns_records": len(dns_obs)},
            )

        # 2. TLS Vector Summary if not already in vectors
        if tls_obs and "tls" not in active_vectors:
            latest_tls = max(tls_obs, key=lambda o: getattr(o, "observed_at", "") or o.get("observed_at", ""))
            ev_id = getattr(latest_tls, "evidence_id", "") or latest_tls.get("evidence_id", "")
            ev = events_by_id.get(ev_id)
            ev_hash = getattr(ev, "raw_sha256", None) if ev else (ev.get("raw_sha256") if isinstance(ev, dict) else None)
            if not ev_hash:
                ev_hash = sha256(ev_id.encode("utf-8")).hexdigest()
            all_evidence_hashes.add(ev_hash)

            tls_vals = getattr(latest_tls, "values", ()) or (latest_tls.get("values", []) if isinstance(latest_tls, dict) else [])
            tls_meta = {}
            if isinstance(latest_tls, dict):
                tls_meta = latest_tls.get("metadata", {})
            active_vectors["tls"] = VectorObservationSummary(
                vector="tls",
                observed_at=getattr(latest_tls, "observed_at", now_iso) or latest_tls.get("observed_at", now_iso),
                evidence_id=ev_id,
                evidence_hash=ev_hash,
                values=list(tls_vals),
                metadata=tls_meta,
            )

        # 3. HTTP Vector Summary if not already in vectors
        if http_obs and "http" not in active_vectors:
            latest_http = max(http_obs, key=lambda o: getattr(o, "observed_at", "") or o.get("observed_at", ""))
            ev_id = getattr(latest_http, "evidence_id", "") or latest_http.get("evidence_id", "")
            ev = events_by_id.get(ev_id)
            ev_hash = getattr(ev, "raw_sha256", None) if ev else (ev.get("raw_sha256") if isinstance(ev, dict) else None)
            if not ev_hash:
                ev_hash = sha256(ev_id.encode("utf-8")).hexdigest()
            all_evidence_hashes.add(ev_hash)

            http_vals = getattr(latest_http, "values", ()) or (latest_http.get("values", []) if isinstance(latest_http, dict) else [])
            http_meta = {}
            if isinstance(latest_http, dict):
                http_meta = latest_http.get("metadata", {})
            active_vectors["http"] = VectorObservationSummary(
                vector="http",
                observed_at=getattr(latest_http, "observed_at", now_iso) or latest_http.get("observed_at", now_iso),
                evidence_id=ev_id,
                evidence_hash=ev_hash,
                values=list(http_vals),
                metadata=http_meta,
            )

        # Multi-Vector Evidence Binding (Milestone M3.10 Security Audit):
        # Reject mismatched source-vector evidence (e.g. DNS event passed as HTTP evidence)
        for v_name, v_summary in active_vectors.items():
            ev_ref = v_summary.evidence_hash or v_summary.evidence_id
            if not ev_ref:
                continue

            ev_kind = None
            if self.store is not None and hasattr(self.store, "verify_evidence_authoritativeness"):
                ver_res = self.store.verify_evidence_authoritativeness(ev_ref)
                if ver_res.get("kind"):
                    ev_kind = ver_res.get("kind")
            elif events_by_id and v_summary.evidence_id in events_by_id:
                e = events_by_id[v_summary.evidence_id]
                ev_kind = getattr(e, "kind", None) or (e.get("kind") if isinstance(e, dict) else None)
            elif events_by_hash and v_summary.evidence_hash in events_by_hash:
                e = events_by_hash[v_summary.evidence_hash]
                ev_kind = getattr(e, "kind", None) or (e.get("kind") if isinstance(e, dict) else None)

            if ev_kind:
                if v_name == "dns" and not (ev_kind.startswith("dns_") or ev_kind == "dns"):
                    raise ValueError(f"Mismatched vector evidence: vector 'dns' cannot bind to evidence of kind {ev_kind!r}")
                elif v_name == "http" and not (ev_kind.startswith("http_") or ev_kind == "http"):
                    raise ValueError(f"Mismatched vector evidence: vector 'http' cannot bind to evidence of kind {ev_kind!r}")
                elif v_name == "tls" and not (ev_kind.startswith("tls_") or ev_kind == "tls"):
                    raise ValueError(f"Mismatched vector evidence: vector 'tls' cannot bind to evidence of kind {ev_kind!r}")
                elif v_name in ("bgp", "rdap") and not (ev_kind.startswith("rdap") or ev_kind.startswith("bgp")):
                    raise ValueError(f"Mismatched vector evidence: vector {v_name!r} cannot bind to evidence of kind {ev_kind!r}")

        # Authoritative Evidence Verification Invariant (Priority 5):
        # A user-supplied hash alone NEVER authenticates an observation.
        unverified_refs: list[str] = []
        verified_evidence_hashes: set[str] = set()

        for h in all_evidence_hashes:
            if self.store is not None and hasattr(self.store, "verify_evidence_authoritativeness"):
                res = self.store.verify_evidence_authoritativeness(h)
                if res.get("is_authoritative"):
                    verified_evidence_hashes.add(h)
                else:
                    unverified_refs.append(h)
            elif events_by_hash and h in events_by_hash:
                verified_evidence_hashes.add(h)
            else:
                unverified_refs.append(h)

        participating = sorted(active_vectors.keys())

        # Abstention Rule: If fewer than 2 vectors have observations, abstain from cross-vector inference
        if len(participating) < 2:
            return [
                CrossVectorFinding(
                    subject_uri=subject_uri,
                    finding_type=FindingType.SINGLE_VECTOR_OBSERVATION.value,
                    epistemic_layer=EpistemicLayer.FACT.value,
                    asserted_at=now_iso,
                    valid_from=now_iso,
                    valid_until=None,
                    state=FindingState.ACTIVE.value,
                    temporal_correlation_vs_causation=TemporalCorrelationNarrative(
                        coincident_change_detected=False,
                        causation_inferred=False,
                        analysis="Single-vector observation only. Cross-vector correlation abstained due to insufficient vector coverage.",
                    ),
                    abstention_state=AbstentionState(
                        abstained=True,
                        reason="INSUFFICIENT_MULTI_VECTOR_COVERAGE",
                        participating_vectors=participating,
                    ),
                    vectors=active_vectors,
                    competing_hypotheses=[],
                    unverified_evidence_references=unverified_refs,
                    ruleset_version=self.ruleset_version,
                )
            ]

        # Multi-Vector Transition and Alignment Analysis
        dns_summary = active_vectors.get("dns")
        tls_summary = active_vectors.get("tls")
        http_summary = active_vectors.get("http")

        # Check for CDN indicators
        has_cdn_ip = False
        cdn_provider = ""
        if dns_summary and dns_summary.values:
            for ip in dns_summary.values:
                is_cdn, prov = _is_cdn_ip(ip)
                if is_cdn:
                    has_cdn_ip = True
                    cdn_provider = prov
                    break

        tls_san_matches = False
        tls_is_cdn = False
        if tls_summary:
            san_names = [s.lower().rstrip(".") for s in tls_summary.metadata.get("san_names", [])]
            if not san_names and tls_summary.values:
                san_names = [s.lower().rstrip(".") for s in tls_summary.values if "." in s and len(s) != 64]
            if any(_domain_matches_pattern(canon_domain, s) for s in san_names):
                tls_san_matches = True
            issuer = str(tls_summary.metadata.get("issuer", "")).lower()
            if any(k in issuer for k in ("cloudflare", "fastly", "let's encrypt", "digicert", "amazon", "google")):
                tls_is_cdn = True

        http_server = ""
        http_matches_cdn = False
        if http_summary:
            http_server = str(http_summary.metadata.get("server", "")).lower()
            if not http_server and http_summary.values:
                http_server = str(http_summary.values[0]).lower()
            if any(k in http_server for k in ("cloudflare", "varnish", "cloudfront", "akamai", "nginx", "apache")):
                if cdn_provider and cdn_provider.lower() in http_server:
                    http_matches_cdn = True
                elif any(k in http_server for k in ("cloudflare", "varnish", "cloudfront")):
                    http_matches_cdn = True

        # Synthesize Competing Hypotheses
        hypotheses: list[CompetingHypothesis] = []

        # Hypothesis 1: Legitimate CDN / Cloud Migration
        label_cdn = "Legitimate CDN / Cloud Provider Migration"
        if has_cdn_ip or (http_matches_cdn and tls_is_cdn):
            status_cdn = HypothesisStatus.FAVORED.value
            score_cdn = 0.92
            expl_cdn = (
                f"Multi-vector observations for {canon_domain} show consistent edge proxy termination: "
                f"DNS resolved to {cdn_provider or 'Anycast/CDN'} IP space, TLS certificate terminates at edge, "
                f"and HTTP response headers ({http_server or 'proxy'}) indicate legitimate CDN infrastructure."
            )
        else:
            status_cdn = HypothesisStatus.CONTRADICTED.value
            score_cdn = 0.12
            expl_cdn = (
                f"CDN migration contradicted for {canon_domain}: resolved IPs ({dns_summary.values if dns_summary else 'none'}) "
                f"and HTTP headers do not match recognized CDN network ranges or signatures."
            )

        hypotheses.append(
            CompetingHypothesis(
                subject_uri=subject_uri,
                phenomenon="CROSS_VECTOR_INFRASTRUCTURE_SHIFT",
                hypothesis_label=label_cdn,
                status=status_cdn,
                heuristic_score=score_cdn,
                explanation=expl_cdn,
                supporting_evidence_hashes=tuple(sorted(verified_evidence_hashes if status_cdn == HypothesisStatus.FAVORED.value else ())),
                contradicting_evidence_hashes=tuple(sorted(verified_evidence_hashes if status_cdn == HypothesisStatus.CONTRADICTED.value else ())),
                falsifiability_condition=(
                    "Falsified if authoritative nameservers delegate to private origin or edge TLS termination fails."
                ),
                ruleset_version=self.ruleset_version,
                asserted_at=now_iso,
                valid_from=now_iso,
            )
        )

        # Hypothesis 2: Routine Certificate Renewal
        label_renewal = "Routine Certificate Renewal"
        if tls_summary and not has_cdn_ip and tls_san_matches:
            status_renewal = HypothesisStatus.FAVORED.value
            score_renewal = 0.88
            expl_renewal = (
                f"TLS certificate renewal observed for {canon_domain} with consistent SAN coverage while "
                f"underlying IP infrastructure remained stable."
            )
        else:
            status_renewal = HypothesisStatus.PLAUSIBLE.value if tls_summary else HypothesisStatus.CONTRADICTED.value
            score_renewal = 0.40 if tls_summary else 0.10
            expl_renewal = (
                f"Certificate renewal explanation for {canon_domain} is accompanied by concurrent routing or header shifts."
            )

        hypotheses.append(
            CompetingHypothesis(
                subject_uri=subject_uri,
                phenomenon="CROSS_VECTOR_INFRASTRUCTURE_SHIFT",
                hypothesis_label=label_renewal,
                status=status_renewal,
                heuristic_score=score_renewal,
                explanation=expl_renewal,
                supporting_evidence_hashes=tuple(sorted(verified_evidence_hashes if status_renewal == HypothesisStatus.FAVORED.value else ())),
                contradicting_evidence_hashes=tuple(sorted(verified_evidence_hashes if status_renewal == HypothesisStatus.CONTRADICTED.value else ())),
                falsifiability_condition=(
                    "Falsified if previous certificate was revoked prematurely or subject alternative names changed."
                ),
                ruleset_version=self.ruleset_version,
                asserted_at=now_iso,
                valid_from=now_iso,
            )
        )

        # Hypothesis 3: Multi-Vector Divergence / Inconsistency
        label_div = "Multi-Vector Divergence / Inconsistency"
        san_mismatch = bool(tls_summary and not tls_san_matches)
        http_error = bool(http_summary and http_summary.metadata.get("status_code", 200) in (404, 421, 502, 503))

        if san_mismatch or http_error:
            status_div = HypothesisStatus.FAVORED.value
            score_div = 0.85
            expl_div = (
                f"Divergence detected across vectors for {canon_domain}: "
                f"{'TLS SAN failed to include domain; ' if san_mismatch else ''}"
                f"{'HTTP response returned error code; ' if http_error else ''}"
                f"indicating potential routing misconfiguration or shared IP collision."
            )
        else:
            status_div = HypothesisStatus.CONTRADICTED.value
            score_div = 0.08
            expl_div = (
                f"Multi-vector divergence contradicted for {canon_domain}: DNS, TLS, and HTTP vectors "
                f"demonstrate consistent endpoint routing and valid host termination."
            )

        hypotheses.append(
            CompetingHypothesis(
                subject_uri=subject_uri,
                phenomenon="CROSS_VECTOR_INFRASTRUCTURE_SHIFT",
                hypothesis_label=label_div,
                status=status_div,
                heuristic_score=score_div,
                explanation=expl_div,
                supporting_evidence_hashes=tuple(sorted(verified_evidence_hashes if status_div == HypothesisStatus.FAVORED.value else ())),
                contradicting_evidence_hashes=tuple(sorted(verified_evidence_hashes if status_div == HypothesisStatus.CONTRADICTED.value else ())),
                falsifiability_condition=(
                    "Falsified if subsequent TLS handshakes and HTTP requests with matching SNI headers yield 200 OK."
                ),
                ruleset_version=self.ruleset_version,
                asserted_at=now_iso,
                valid_from=now_iso,
            )
        )

        # Finding Type selection
        if status_div == HypothesisStatus.FAVORED.value:
            finding_type = FindingType.MULTI_VECTOR_DIVERGENCE.value
        elif status_cdn == HypothesisStatus.FAVORED.value:
            finding_type = FindingType.CDN_PROVIDER_MIGRATION.value
        elif status_renewal == HypothesisStatus.FAVORED.value:
            finding_type = FindingType.ROUTINE_CERTIFICATE_ROTATION.value
        else:
            finding_type = FindingType.CROSS_VECTOR_INFRASTRUCTURE_SHIFT.value

        narrative = TemporalCorrelationNarrative(
            coincident_change_detected=True,
            causation_inferred=False,
            analysis=(
                f"Observations across vectors ({', '.join(participating)}) occurred within a shared observation window. "
                f"Temporal co-occurrence is treated as correlation and analyzed via competing hypotheses; "
                f"causal dependency is not assumed."
            ),
        )

        finding = CrossVectorFinding(
            subject_uri=subject_uri,
            finding_type=finding_type,
            epistemic_layer=EpistemicLayer.HYPOTHESIS.value,
            asserted_at=now_iso,
            valid_from=now_iso,
            valid_until=None,
            state=FindingState.ACTIVE.value,
            temporal_correlation_vs_causation=narrative,
            abstention_state=AbstentionState(
                abstained=False,
                reason=None,
                participating_vectors=participating,
            ),
            vectors=active_vectors,
            competing_hypotheses=hypotheses,
            unverified_evidence_references=unverified_refs,
            ruleset_version=self.ruleset_version,
        )

        return [finding]

    def correlate_from_store(
        self,
        domain: str,
        *,
        as_of: str | None = None,
        persist: bool = True,
    ) -> list[CrossVectorFinding]:
        """Query authoritative store, execute cross-vector correlation, and optionally persist findings."""
        if self.store is None:
            raise ValueError("store must be provided to correlate_from_store()")

        canon_domain = canonicalize_domain(domain)
        now_iso = as_of or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        vectors: dict[str, VectorObservationSummary] = {}
        all_events: list[Any] = []

        with self.store._connect() as conn:
            # 1. Query DNS from real_observations
            dns_rows = conn.execute(
                """
                SELECT o.observation_id, o.evidence_id, o.subject, o.kind, o.observed_at,
                       o.status, o.source_id, o.payload, e.raw_sha256
                FROM real_observations o
                LEFT JOIN real_events e ON o.evidence_id = e.event_id
                WHERE (o.subject = ? OR o.subject = ?) AND o.kind IN ('dns_a', 'dns_aaaa')
                ORDER BY o.observed_at DESC
                """,
                (canon_domain, f"{canon_domain}."),
            ).fetchall()

            resolved_ips: set[str] = set()
            if dns_rows:
                latest_dns = dns_rows[0]
                ev_id = latest_dns[1]
                ev_hash = latest_dns[8] or sha256(ev_id.encode("utf-8")).hexdigest()

                all_dns_ips = set()
                for r in dns_rows:
                    p_data = json.loads(r[7]) if r[7] else {}
                    for v in p_data.get("values", []):
                        if isinstance(v, str) and ("." in v or ":" in v):
                            all_dns_ips.add(v.strip())
                            resolved_ips.add(v.strip())

                vectors["dns"] = VectorObservationSummary(
                    vector="dns",
                    observed_at=latest_dns[4],
                    evidence_id=ev_id,
                    evidence_hash=ev_hash,
                    values=sorted(all_dns_ips),
                    metadata={"total_dns_records": len(dns_rows)},
                )

            # Build comprehensive candidate URIs for domain and resolved IPs
            candidate_uris = [
                format_node_id(NodeType.DOMAIN, canon_domain),
                canonical_domain_uri(canon_domain),
                canon_domain,
                f"{canon_domain}.",
            ]
            for ip in sorted(resolved_ips):
                candidate_uris.extend([
                    format_node_id(NodeType.IP, ip),
                    canonical_ipv4_uri(ip) if "." in ip else canonical_ipv6_uri(ip),
                    ip,
                ])

            ph = ",".join("?" for _ in candidate_uris)

            # 2. Query TLS from graph_nodes and graph_edges
            tls_sql = f"""
                SELECT n.node_id, n.canonical_name, n.properties_json, e.observed_at, e.evidence_hashes_json, e.edge_id
                FROM graph_edges e
                JOIN graph_nodes n ON (e.source_id = n.node_id OR e.target_id = n.node_id)
                WHERE (e.source_id IN ({ph}) OR e.target_id IN ({ph}))
                  AND LOWER(n.node_type) = 'certificate'
                ORDER BY e.observed_at DESC
                LIMIT 1
            """
            tls_params = candidate_uris + candidate_uris
            tls_rows = conn.execute(tls_sql, tls_params).fetchall()

            if tls_rows:
                tr = tls_rows[0]
                props = json.loads(tr[2]) if tr[2] else {}
                e_hashes = json.loads(tr[4]) if tr[4] else []
                ev_hash = e_hashes[0] if e_hashes else sha256(tr[5].encode("utf-8")).hexdigest()
                vectors["tls"] = VectorObservationSummary(
                    vector="tls",
                    observed_at=tr[3],
                    evidence_id=tr[5],
                    evidence_hash=ev_hash,
                    values=[tr[1]],
                    metadata=props,
                )

            # 3. Query HTTP from graph_nodes and graph_edges
            http_sql = f"""
                SELECT n.node_id, n.canonical_name, n.properties_json, e.observed_at, e.evidence_hashes_json, e.edge_id
                FROM graph_edges e
                JOIN graph_nodes n ON (e.source_id = n.node_id OR e.target_id = n.node_id)
                WHERE (e.source_id IN ({ph}) OR e.target_id IN ({ph}))
                  AND LOWER(n.node_type) = 'technology'
                ORDER BY e.observed_at DESC
                LIMIT 1
            """
            http_params = candidate_uris + candidate_uris
            http_rows = conn.execute(http_sql, http_params).fetchall()

            if http_rows:
                hr = http_rows[0]
                props = json.loads(hr[2]) if hr[2] else {}
                e_hashes = json.loads(hr[4]) if hr[4] else []
                ev_hash = e_hashes[0] if e_hashes else sha256(hr[5].encode("utf-8")).hexdigest()
                vectors["http"] = VectorObservationSummary(
                    vector="http",
                    observed_at=hr[3],
                    evidence_id=hr[5],
                    evidence_hash=ev_hash,
                    values=[hr[1]],
                    metadata={"server": hr[1], **props},
                )

        findings = self.correlate_records(
            domain=canon_domain,
            vectors=vectors,
            as_of=now_iso,
        )

        if persist and findings:
            for f in findings:
                if hasattr(self.store, "insert_cross_vector_finding"):
                    self.store.insert_cross_vector_finding(f)

        return findings

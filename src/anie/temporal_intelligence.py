"""Temporal Graph Intelligence Subsystem for ANIE (Milestone M3.4 & M3.4.1).

Provides deterministic, explainable analysis of historical DNS infrastructure:
1. Historical DNS infrastructure transitions (IP set changes across observation epochs and resolvers).
2. Domain-to-IP relationship evolution (duration, TTL stability, ephemeral/persistent categorization).
3. Shared infrastructure correlation (co-hosted domains on shared vs Anycast/CDN edge pools).
4. Resolver discrepancy timelines (persistent disagreement, security-filtering NXDOMAINs).
5. Fast-flux candidate indicators (rapid IP churn, low TTL, subnet diversity within 24h; non-malicious).
6. Unexpected resolution divergence (sudden Anycast-to-unicast shifts or provider divergence).

Strict Epistemic Guardrails:
- Every finding retains raw wire evidence hashes, timestamps, ruleset version, and uncertainty.
- Inferences are strictly classified as UNVERIFIED_HYPOTHESIS with explicit falsifiability conditions.
- Machine-generated claims are NEVER automatically promoted to ATTESTED_ASSERTION without genuine Ed25519 attestation.
- Confidence scores are explicit heuristic confidence ratings, not calibrated frequentist/Bayesian probabilities.
- Strictly prohibits inferring malicious intent from infrastructure churn, co-hosting, or discrepancies alone.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import ipaddress
import json
import sqlite3
from typing import Any, Iterable

from .discrepancy_models import RealDiscrepancyReport
from .graph_engine import GraphEngine
from .graph_models import (
    ClaimVerificationState,
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    IntelligenceClaim,
    NodeType,
    RelationType,
    format_node_id,
)
from .observations import canonical_json, utc_iso
from .real_models import RealCollectionEvent, RealObservation


class TemporalClaimType(str, Enum):
    """Categorization of temporal graph intelligence claims."""
    INFRASTRUCTURE_TRANSITION = "INFRASTRUCTURE_TRANSITION"
    IP_RELATIONSHIP_EVOLUTION = "IP_RELATIONSHIP_EVOLUTION"
    SHARED_INFRASTRUCTURE = "SHARED_INFRASTRUCTURE"
    RESOLVER_DISCREPANCY_TIMELINE = "RESOLVER_DISCREPANCY_TIMELINE"
    FAST_FLUX_INDICATOR = "FAST_FLUX_INDICATOR"
    RESOLUTION_DIVERGENCE_INDICATOR = "RESOLUTION_DIVERGENCE_INDICATOR"


@dataclass(frozen=True)
class ProvenanceTaggedNetwork:
    """Provenance-tracked IP network range for heuristic infrastructure classification."""
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    provider: str
    classification: str
    provenance: str


# Publicly published CDN / Anycast network ranges with explicit provenance attribution
_PROVENANCE_TAGGED_NETWORKS: list[ProvenanceTaggedNetwork] = [
    # Cloudflare published edge ranges
    ProvenanceTaggedNetwork(ipaddress.ip_network("1.1.1.0/24"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare public DNS range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("1.0.0.0/24"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare public DNS range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("104.16.0.0/12"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("104.24.0.0/14"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("172.64.0.0/13"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("162.158.0.0/15"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("198.41.128.0/17"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("2606:4700::/32"), "Cloudflare", "CDN_ANYCAST_HEURISTIC", "Cloudflare published IPv6 range"),
    # Fastly published edge ranges
    ProvenanceTaggedNetwork(ipaddress.ip_network("151.101.0.0/16"), "Fastly", "CDN_ANYCAST_HEURISTIC", "Fastly published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("199.232.0.0/16"), "Fastly", "CDN_ANYCAST_HEURISTIC", "Fastly published prefix range"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("2a04:4e40::/32"), "Fastly", "CDN_ANYCAST_HEURISTIC", "Fastly published IPv6 range"),
    # AWS CloudFront published ranges (ip-ranges.json)
    ProvenanceTaggedNetwork(ipaddress.ip_network("13.224.0.0/14"), "AWS CloudFront", "CDN_ANYCAST_HEURISTIC", "AWS ip-ranges.json CLOUDFRONT service"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("13.225.0.0/16"), "AWS CloudFront", "CDN_ANYCAST_HEURISTIC", "AWS ip-ranges.json CLOUDFRONT service"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("13.32.0.0/15"), "AWS CloudFront", "CDN_ANYCAST_HEURISTIC", "AWS ip-ranges.json CLOUDFRONT service"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("52.84.0.0/15"), "AWS CloudFront", "CDN_ANYCAST_HEURISTIC", "AWS ip-ranges.json CLOUDFRONT service"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("54.230.0.0/16"), "AWS CloudFront", "CDN_ANYCAST_HEURISTIC", "AWS ip-ranges.json CLOUDFRONT service"),
    # Akamai Edge Network
    ProvenanceTaggedNetwork(ipaddress.ip_network("23.0.0.0/12"), "Akamai", "CDN_ANYCAST_HEURISTIC", "Akamai published edge ranges"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("104.64.0.0/10"), "Akamai", "CDN_ANYCAST_HEURISTIC", "Akamai published edge ranges"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("184.24.0.0/13"), "Akamai", "CDN_ANYCAST_HEURISTIC", "Akamai published edge ranges"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("2.16.0.0/13"), "Akamai", "CDN_ANYCAST_HEURISTIC", "Akamai published edge ranges"),
    # Microsoft / Azure CDN
    ProvenanceTaggedNetwork(ipaddress.ip_network("20.150.0.0/15"), "Microsoft Azure", "CDN_ANYCAST_HEURISTIC", "Azure Front Door and CDN ranges"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("13.107.0.0/16"), "Microsoft Azure", "CDN_ANYCAST_HEURISTIC", "Azure Front Door and CDN ranges"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("20.0.0.0/11"), "Microsoft Azure", "CLOUD_EDGE_HEURISTIC", "Microsoft public cloud prefix"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("40.74.0.0/15"), "Microsoft Azure", "CLOUD_EDGE_HEURISTIC", "Microsoft public cloud prefix"),
    # Google Public DNS & Edge
    ProvenanceTaggedNetwork(ipaddress.ip_network("8.8.8.0/24"), "Google Public DNS", "ANYCAST_RESOLVER_HEURISTIC", "Google Public DNS Anycast documentation"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("8.8.4.0/24"), "Google Public DNS", "ANYCAST_RESOLVER_HEURISTIC", "Google Public DNS Anycast documentation"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("142.250.0.0/15"), "Google Edge", "CLOUD_EDGE_HEURISTIC", "Google Cloud / 1e100 net IP blocks"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("172.217.0.0/16"), "Google Edge", "CLOUD_EDGE_HEURISTIC", "Google Cloud / 1e100 net IP blocks"),
    # EdgeCast / Verizon Digital Media
    ProvenanceTaggedNetwork(ipaddress.ip_network("93.184.216.0/24"), "EdgeCast", "CDN_ANYCAST_HEURISTIC", "EdgeCast Anycast edge network"),
    # Quad9 Anycast Resolvers
    ProvenanceTaggedNetwork(ipaddress.ip_network("9.9.9.0/24"), "Quad9", "ANYCAST_RESOLVER_HEURISTIC", "Quad9 Anycast public resolver documentation"),
    ProvenanceTaggedNetwork(ipaddress.ip_network("149.112.112.0/24"), "Quad9", "ANYCAST_RESOLVER_HEURISTIC", "Quad9 Anycast public resolver documentation"),
]

# Recognized Public Dynamic DNS Provider Suffixes
_KNOWN_DYNAMIC_DNS_SUFFIXES: frozenset[str] = frozenset({
    "duckdns.org",
    "no-ip.com",
    "no-ip.org",
    "ddns.net",
    "dyndns.org",
    "zapto.org",
    "hopto.org",
    "freedns.afraid.org",
    "dynu.net",
    "dynu.com",
    "spdyn.de",
})


def classify_ip_infrastructure(ip_str: str) -> dict[str, Any]:
    """Classify an IP address using provenance-tagged prefix references.
    
    Returns heuristic classification disclaiming authoritative BGP routing proof.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for entry in _PROVENANCE_TAGGED_NETWORKS:
            if ip_obj in entry.network:
                return {
                    "ip": ip_str,
                    "is_known_anycast_heuristic": True,
                    "provider": entry.provider,
                    "classification": entry.classification,
                    "provenance": entry.provenance,
                    "authoritative": False,
                    "notice": "Heuristic prefix match only; does not provide authoritative BGP Anycast routing proof.",
                }
        return {
            "ip": ip_str,
            "is_known_anycast_heuristic": False,
            "provider": "Standard Unicast / Private",
            "classification": "UNICAST_OR_UNCLASSIFIED",
            "provenance": "unmatched_public_prefix",
            "authoritative": False,
            "notice": "No matching published CDN/Anycast prefix found.",
        }
    except ValueError:
        return {
            "ip": ip_str,
            "is_known_anycast_heuristic": False,
            "provider": "Invalid IP",
            "classification": "INVALID_IP",
            "provenance": "none",
            "authoritative": False,
            "notice": "Failed to parse IP address string.",
        }


def is_known_anycast_ip(ip_str: str) -> tuple[bool, str]:
    """Check if an IP belongs to known CDN/Anycast networks (backward-compatible wrapper).
    
    Returns (is_anycast_heuristic, provider_label).
    """
    res = classify_ip_infrastructure(ip_str)
    return res["is_known_anycast_heuristic"], res["provider"]


class TemporalIntelligenceEngine:
    """In-process temporal DNS intelligence analysis engine."""

    RULESET_VERSION = "anie.temporal-intelligence.v1"

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.graph_engine = GraphEngine(conn)

    def analyze_domain(
        self,
        domain: str,
        as_of: str | None = None,
    ) -> list[IntelligenceClaim]:
        """Execute all temporal intelligence detectors for a specific domain.
        
        Evaluates both IPv4 (dns_a) and IPv6 (dns_aaaa) observations, strictly bounded by as_of.
        Returns a list of evidence-backed IntelligenceClaim objects.
        """
        now_iso = utc_iso(as_of) if as_of else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        claims: list[IntelligenceClaim] = []

        # 1. Fetch all observations for domain (both IPv4 and IPv6, respecting as_of)
        if as_of:
            obs_rows = self.conn.execute(
                """
                SELECT payload, observed_at, status
                FROM real_observations
                WHERE subject = ? AND kind IN ('dns_a', 'dns_aaaa') AND observed_at <= ?
                ORDER BY observed_at ASC, observation_id ASC
                """,
                (domain, now_iso),
            ).fetchall()
        else:
            obs_rows = self.conn.execute(
                """
                SELECT payload, observed_at, status
                FROM real_observations
                WHERE subject = ? AND kind IN ('dns_a', 'dns_aaaa')
                ORDER BY observed_at ASC, observation_id ASC
                """,
                (domain,),
            ).fetchall()

        if not obs_rows:
            return claims

        observations = [RealObservation.from_dict(json.loads(r[0])) for r in obs_rows]

        # 2. Fetch all linking evidence events
        ev_ids = list({o.evidence_id for o in observations})
        events_by_id: dict[str, RealCollectionEvent] = {}
        if ev_ids:
            placeholders = ",".join("?" for _ in ev_ids)
            ev_rows = self.conn.execute(
                f"SELECT payload FROM real_events WHERE event_id IN ({placeholders})",
                ev_ids,
            ).fetchall()
            for r in ev_rows:
                ev = RealCollectionEvent.from_dict(json.loads(r[0]))
                events_by_id[ev.event_id] = ev

        # Run Detectors
        claims.extend(self._detect_infrastructure_transitions(domain, observations, events_by_id, now_iso))
        claims.extend(self._detect_ip_evolution(domain, observations, events_by_id, now_iso))
        claims.extend(self._detect_shared_infrastructure(domain, observations, events_by_id, now_iso))
        claims.extend(self._detect_discrepancy_timeline(domain, now_iso, as_of=as_of))
        claims.extend(self._detect_fast_flux_indicators(domain, observations, events_by_id, now_iso))
        claims.extend(self._detect_resolution_divergence(domain, observations, events_by_id, now_iso))

        return claims

    def analyze_all(
        self,
        as_of: str | None = None,
        limit_domains: int | None = None,
    ) -> list[IntelligenceClaim]:
        """Analyze all domain entities registered in the store and return claims."""
        now_iso = utc_iso(as_of) if as_of else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        sql = "SELECT DISTINCT subject FROM real_observations WHERE kind IN ('dns_a', 'dns_aaaa')"
        params: list[Any] = []
        if as_of:
            sql += " AND observed_at <= ?"
            params.append(now_iso)

        sql += " ORDER BY subject ASC"
        if limit_domains:
            sql += f" LIMIT {int(limit_domains)}"

        domains = [r[0] for r in self.conn.execute(sql, params).fetchall()]
        all_claims: list[IntelligenceClaim] = []

        for dom in domains:
            domain_claims = self.analyze_domain(dom, as_of=as_of)
            all_claims.extend(domain_claims)

        return all_claims

    # --- Detector Implementations ---

    def _detect_infrastructure_transitions(
        self,
        domain: str,
        observations: list[RealObservation],
        events_by_id: dict[str, RealCollectionEvent],
        now_iso: str,
    ) -> list[IntelligenceClaim]:
        """Detect transitions in resolved IP sets between distinct observation epochs and resolvers."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        # Group by observation time (epoch) and by resolver
        by_time: dict[str, set[str]] = defaultdict(set)
        by_resolver_time: dict[tuple[str, str], set[str]] = defaultdict(set)
        evidence_by_time: dict[str, set[str]] = defaultdict(set)

        for ob in observations:
            if ob.status == "ok" and ob.values:
                by_time[ob.observed_at].update(ob.values)
                by_resolver_time[(ob.source_id, ob.observed_at)].update(ob.values)
                ev = events_by_id.get(ob.evidence_id)
                if ev:
                    evidence_by_time[ob.observed_at].add(ev.raw_sha256)

        sorted_times = sorted(by_time.keys())
        if len(sorted_times) < 2:
            return claims

        for t_prev, t_curr in zip(sorted_times, sorted_times[1:]):
            prev_ips = sorted(by_time[t_prev])
            curr_ips = sorted(by_time[t_curr])

            if prev_ips != curr_ips:
                combined_hashes = sorted(evidence_by_time[t_prev] | evidence_by_time[t_curr])
                added_ips = sorted(set(curr_ips) - set(prev_ips))
                removed_ips = sorted(set(prev_ips) - set(curr_ips))

                explanation = (
                    f"Infrastructure transition observed for {domain}: IP set changed from "
                    f"{prev_ips} at {t_prev} to {curr_ips} at {t_curr} "
                    f"(added: {added_ips or 'none'}, removed: {removed_ips or 'none'})."
                )

                claim = IntelligenceClaim.create(
                    subject_uri=domain_uri,
                    claim_type=TemporalClaimType.INFRASTRUCTURE_TRANSITION.value,
                    layer=EpistemicLayer.HYPOTHESIS,
                    asserted_at=now_iso,
                    valid_from=t_curr,
                    confidence=0.85,
                    explanation=explanation,
                    supporting_evidence_hashes=combined_hashes,
                    supporting_node_ids=[domain_uri] + [format_node_id(NodeType.IP, ip) for ip in curr_ips],
                    verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
                    falsifiability_condition=(
                        "Falsified if intermediate unobserved queries demonstrate gradual rollover or "
                        "if multi-region DNS Anycast returns geographically differentiated responses."
                    ),
                    properties={
                        "previous_ips": prev_ips,
                        "new_ips": curr_ips,
                        "added_ips": added_ips,
                        "removed_ips": removed_ips,
                        "transition_time": t_curr,
                        "previous_time": t_prev,
                        "confidence_type": "heuristic_uncalibrated",
                    },
                )
                claims.append(claim)

        return claims

    def _detect_ip_evolution(
        self,
        domain: str,
        observations: list[RealObservation],
        events_by_id: dict[str, RealCollectionEvent],
        now_iso: str,
    ) -> list[IntelligenceClaim]:
        """Track stability, duration, and classification of domain-to-IP relationships."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        ip_stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "first_seen": None,
            "last_seen": None,
            "count": 0,
            "ttls": [],
            "evidence_hashes": set(),
        })

        for ob in observations:
            if ob.status == "ok" and ob.values:
                ev = events_by_id.get(ob.evidence_id)
                ev_hash = ev.raw_sha256 if ev else None
                for ip in ob.values:
                    entry = ip_stats[ip]
                    if entry["first_seen"] is None or ob.observed_at < entry["first_seen"]:
                        entry["first_seen"] = ob.observed_at
                    if entry["last_seen"] is None or ob.observed_at > entry["last_seen"]:
                        entry["last_seen"] = ob.observed_at
                    entry["count"] += 1
                    if ob.ttl_seconds is not None:
                        entry["ttls"].append(ob.ttl_seconds)
                    if ev_hash:
                        entry["evidence_hashes"].add(ev_hash)

        for ip, stats in ip_stats.items():
            dt_first = datetime.fromisoformat(stats["first_seen"].replace("Z", "+00:00"))
            dt_last = datetime.fromisoformat(stats["last_seen"].replace("Z", "+00:00"))
            duration_hours = max((dt_last - dt_first).total_seconds() / 3600.0, 0.0)

            if duration_hours < 24.0:
                classification = "ephemeral"
            elif duration_hours <= 168.0:
                classification = "transitional"
            else:
                classification = "persistent"

            is_anycast, provider = is_known_anycast_ip(ip)
            mean_ttl = round(sum(stats["ttls"]) / len(stats["ttls"]), 1) if stats["ttls"] else 300.0

            ip_uri = format_node_id(NodeType.IP, ip)
            explanation = (
                f"Domain {domain} associated with IP {ip} ({classification}, duration {duration_hours:.1f}h). "
                f"Infrastructure type: {provider}. Mean TTL: {mean_ttl}s across {stats['count']} observation(s)."
            )

            claim = IntelligenceClaim.create(
                subject_uri=domain_uri,
                claim_type=TemporalClaimType.IP_RELATIONSHIP_EVOLUTION.value,
                layer=EpistemicLayer.HYPOTHESIS,
                asserted_at=now_iso,
                valid_from=stats["first_seen"],
                valid_until=stats["last_seen"],
                confidence=0.80,
                explanation=explanation,
                supporting_evidence_hashes=sorted(stats["evidence_hashes"]),
                supporting_node_ids=[domain_uri, ip_uri],
                verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
                falsifiability_condition="Defeated if authoritative zone apex records record differing glue or delegations.",
                properties={
                    "ip": ip,
                    "classification": classification,
                    "duration_hours": round(duration_hours, 2),
                    "mean_ttl": mean_ttl,
                    "is_known_anycast": is_anycast,
                    "provider": provider,
                    "observation_count": stats["count"],
                    "confidence_type": "heuristic_uncalibrated",
                },
            )
            claims.append(claim)

        return claims

    def _detect_shared_infrastructure(
        self,
        domain: str,
        observations: list[RealObservation],
        events_by_id: dict[str, RealCollectionEvent],
        now_iso: str,
    ) -> list[IntelligenceClaim]:
        """Identify co-hosted domains on observed IP infrastructure with strict guardrails."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        latest_ips: set[str] = set()
        evidence_hashes: set[str] = set()
        latest_time = ""

        for ob in reversed(observations):
            if ob.status == "ok" and ob.values:
                latest_ips.update(ob.values)
                if not latest_time:
                    latest_time = ob.observed_at
                ev = events_by_id.get(ob.evidence_id)
                if ev:
                    evidence_hashes.add(ev.raw_sha256)

        for ip in latest_ips:
            co_hosted = self.graph_engine.find_co_hosted_domains(ip)
            # Remove self from co-hosted list
            other_domains = [d for d in co_hosted if d != domain]
            if other_domains:
                is_anycast, provider = is_known_anycast_ip(ip)
                ip_uri = format_node_id(NodeType.IP, ip)
                hosting_density = "HIGH_DENSITY_MULTI_TENANT" if len(other_domains) >= 20 else "LOW_DENSITY_POOL"

                guardrail_notice = (
                    "Co-hosting reflects shared multi-tenant hosting, CDN edge routing, or Anycast pools. "
                    "It strictly does NOT infer common administrative ownership, coordinated activity, or maliciousness."
                )

                explanation = (
                    f"Shared infrastructure correlation: {domain} is co-hosted with {len(other_domains)} other domain(s) "
                    f"on IP {ip} ({provider}, density: {hosting_density}). Correlated domains include: {other_domains[:5]}. {guardrail_notice}"
                )

                claim = IntelligenceClaim.create(
                    subject_uri=domain_uri,
                    claim_type=TemporalClaimType.SHARED_INFRASTRUCTURE.value,
                    layer=EpistemicLayer.HYPOTHESIS,
                    asserted_at=now_iso,
                    valid_from=latest_time or now_iso,
                    confidence=0.75,
                    explanation=explanation,
                    supporting_evidence_hashes=sorted(evidence_hashes),
                    supporting_node_ids=[domain_uri, ip_uri] + [format_node_id(NodeType.DOMAIN, d) for d in other_domains[:10]],
                    verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
                    falsifiability_condition="Invalidated if SNI inspection or reverse DNS demonstrates dedicated non-shared allocation.",
                    properties={
                        "ip": ip,
                        "co_hosted_count": len(other_domains),
                        "co_hosted_sample": other_domains[:10],
                        "hosting_density": hosting_density,
                        "is_known_anycast": is_anycast,
                        "provider": provider,
                        "guardrail_status": "PASS_NO_MALICIOUS_INFERENCE",
                        "confidence_type": "heuristic_uncalibrated",
                    },
                )
                claims.append(claim)

        return claims

    def _detect_discrepancy_timeline(
        self,
        domain: str,
        now_iso: str,
        as_of: str | None = None,
    ) -> list[IntelligenceClaim]:
        """Track multi-resolver consensus history and security-filtering divergence."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        if as_of:
            rows = self.conn.execute(
                """
                SELECT payload, analyzed_at, verdict, category
                FROM real_discrepancies
                WHERE subject = ? AND analyzed_at <= ?
                ORDER BY analyzed_at ASC
                """,
                (domain, now_iso),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT payload, analyzed_at, verdict, category
                FROM real_discrepancies
                WHERE subject = ?
                ORDER BY analyzed_at ASC
                """,
                (domain,),
            ).fetchall()

        if not rows:
            return claims

        total_analyses = len(rows)
        verdict_counts: dict[str, int] = defaultdict(int)
        category_counts: dict[str, int] = defaultdict(int)
        divergent_resolvers: set[str] = set()
        evidence_hashes: set[str] = set()
        filtering_events = 0
        first_analyzed = rows[0][1]
        last_analyzed = rows[-1][1]

        for r_json, _, verdict, category in rows:
            rep = RealDiscrepancyReport.from_dict(json.loads(r_json))
            verdict_counts[verdict] += 1
            category_counts[category] += 1
            if rep.filtering_metadata:
                filtering_events += 1
            if verdict != "AGREEMENT":
                divergent_resolvers.update(rep.participating_resolvers)
            evidence_hashes.update(rep.evidence_hashes.values())

        agreement_count = verdict_counts.get("AGREEMENT", 0)
        agreement_ratio = round(agreement_count / total_analyses, 3)

        explanation = (
            f"Resolver discrepancy timeline for {domain}: {total_analyses} analysis reports evaluated between "
            f"{first_analyzed} and {last_analyzed}. Consensus agreement rate: {agreement_ratio * 100:.1f}%. "
            f"Security filtering incidents: {filtering_events}. Divergent resolvers: {sorted(divergent_resolvers) or ['none']}."
        )

        claim = IntelligenceClaim.create(
            subject_uri=domain_uri,
            claim_type=TemporalClaimType.RESOLVER_DISCREPANCY_TIMELINE.value,
            layer=EpistemicLayer.HYPOTHESIS,
            asserted_at=now_iso,
            valid_from=first_analyzed,
            valid_until=last_analyzed,
            confidence=0.85,
            explanation=explanation,
            supporting_evidence_hashes=sorted(evidence_hashes),
            supporting_node_ids=[domain_uri],
            verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
            falsifiability_condition="Defeated if resolver authority proves upstream authoritative server failure during collection window.",
            properties={
                "total_analyses": total_analyses,
                "agreement_rate": agreement_ratio,
                "filtering_events": filtering_events,
                "verdict_breakdown": dict(verdict_counts),
                "category_breakdown": dict(category_counts),
                "confidence_type": "heuristic_uncalibrated",
            },
        )
        claims.append(claim)
        return claims

    def _detect_fast_flux_indicators(
        self,
        domain: str,
        observations: list[RealObservation],
        events_by_id: dict[str, RealCollectionEvent],
        now_iso: str,
    ) -> list[IntelligenceClaim]:
        """Detect deterministic indicators of high-frequency IP rotation with low TTL within 24 hours.
        
        Strict Epistemic Guardrail:
        - Strictly bounded to past 24-hour window from now_iso.
        - Must NOT infer maliciousness.
        - Must state falsifiability criteria (Anycast, CDN edge rotation, GSLB).
        """
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        t_now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        t_window_start = t_now - timedelta(hours=24)
        t_window_start_iso = t_window_start.isoformat(timespec="seconds").replace("+00:00", "Z")

        # Collect unique IPs, subnets, and TTLs strictly across past 24 hours
        observed_ips: set[str] = set()
        anycast_ips: set[str] = set()
        unicast_ips: set[str] = set()
        subnets_v4: set[str] = set()
        subnets_v6: set[str] = set()
        ttls: list[int] = []
        evidence_hashes: set[str] = set()

        window_obs = [
            ob for ob in observations
            if t_window_start_iso <= ob.observed_at <= now_iso
        ]

        for ob in window_obs:
            if ob.status == "ok" and ob.values:
                for ip in ob.values:
                    observed_ips.add(ip)
                    is_anycast, _ = is_known_anycast_ip(ip)
                    if is_anycast:
                        anycast_ips.add(ip)
                    else:
                        unicast_ips.add(ip)
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            subnets_v4.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
                        elif isinstance(ip_obj, ipaddress.IPv6Address):
                            subnets_v6.add(str(ipaddress.ip_network(f"{ip}/48", strict=False)))
                    except ValueError:
                        pass
                if ob.ttl_seconds is not None:
                    ttls.append(ob.ttl_seconds)
                ev = events_by_id.get(ob.evidence_id)
                if ev:
                    evidence_hashes.add(ev.raw_sha256)

        total_subnets = len(subnets_v4) + len(subnets_v6)
        median_ttl = sorted(ttls)[len(ttls) // 2] if ttls else 300
        is_dynamic_dns = any(domain == sfx or domain.endswith("." + sfx) for sfx in _KNOWN_DYNAMIC_DNS_SUFFIXES)
        is_pure_anycast = (len(anycast_ips) > 0 and len(unicast_ips) == 0)
        is_mixed_anycast = (len(anycast_ips) > 0 and len(unicast_ips) > 0)

        # Fast-Flux Heuristic Condition:
        # 1. >= 5 unique IPs observed within 24h
        # 2. Short median TTL <= 300s
        # 3. >= 2 distinct /24 (IPv4) or /48 (IPv6) subnets
        # 4. Exclude pure CDN Anycast pools (preserve contradictory evidence if mixed Anycast/Unicast)
        if len(observed_ips) >= 5 and median_ttl <= 300 and total_subnets >= 2 and not is_pure_anycast:
            contradictory_evidence = None

            if is_mixed_anycast:
                # Contradictory evidence: co-resolution across CDN edge pools and unicast infrastructure
                confidence = 0.85
                explanation = (
                    f"Anomalous mixed CDN Anycast/Unicast resolution detected for {domain}: Observed {len(unicast_ips)} "
                    f"standard unicast IP(s) co-resolved with {len(anycast_ips)} CDN Anycast edge IP(s) across {total_subnets} "
                    f"distinct subnets with low median TTL ({median_ttl}s). Contradictory evidence preserved against pure CDN classification."
                )
                contradictory_evidence = {
                    "pattern": "MIXED_ANYCAST_UNICAST",
                    "anycast_ips": sorted(anycast_ips),
                    "unicast_ips": sorted(unicast_ips),
                }
            elif is_dynamic_dns:
                if total_subnets <= 2:
                    # Normal residential churn within expected subscriber boundaries
                    confidence = 0.35
                    explanation = (
                        f"Dynamic IP rotation evaluated for {domain}: Observed {len(observed_ips)} unique IPs "
                        f"across {total_subnets} subnets with low median TTL ({median_ttl}s). Domain is hosted on "
                        f"a recognized public dynamic DNS provider; rapid residential IP churn is typical of consumer "
                        f"dynamic allocations rather than adversary fast-flux infrastructure."
                    )
                    contradictory_evidence = {
                        "is_dynamic_dns": True,
                        "dispersion_level": "NORMAL_RESIDENTIAL",
                        "subnet_count": total_subnets,
                    }
                else:
                    # Contradictory evidence: dynamic DNS with anomalous multi-subnet dispersion (>= 3 subnets)
                    confidence = 0.75
                    explanation = (
                        f"High-volatility multi-subnet dispersion detected for {domain} on dynamic DNS: "
                        f"Observed {len(observed_ips)} unique IPs across {total_subnets} distinct subnets ({len(subnets_v4)} IPv4 /24, {len(subnets_v6)} IPv6 /48) "
                        f"with low median TTL ({median_ttl}s). Broad subnet dispersion contradicts expected single-subscriber residential dynamic DNS churn."
                    )
                    contradictory_evidence = {
                        "is_dynamic_dns": True,
                        "dispersion_level": "ANOMALOUS_MULTI_SUBNET",
                        "subnet_count": total_subnets,
                    }
            else:
                confidence = 0.70
                explanation = (
                    f"Fast-flux candidate indicator detected for {domain}: Observed {len(observed_ips)} unique IPs "
                    f"across {total_subnets} distinct subnets ({len(subnets_v4)} IPv4 /24, {len(subnets_v6)} IPv6 /48) "
                    f"with low median TTL ({median_ttl}s) in past 24 hours. "
                    f"Notice: Fast-flux indicators measure dynamic volatility and do NOT infer maliciousness."
                )

            claim = IntelligenceClaim.create(
                subject_uri=domain_uri,
                claim_type=TemporalClaimType.FAST_FLUX_INDICATOR.value,
                layer=EpistemicLayer.HYPOTHESIS,
                asserted_at=now_iso,
                valid_from=t_window_start_iso,
                confidence=confidence,
                explanation=explanation,
                supporting_evidence_hashes=sorted(evidence_hashes),
                supporting_node_ids=[domain_uri] + [format_node_id(NodeType.IP, ip) for ip in list(observed_ips)[:10]],
                verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
                falsifiability_condition=(
                    "Falsified if infrastructure is verified as legitimate Anycast routing, cloud elastic load balancing, "
                    "content distribution network edge points, or dynamic GSLB multi-region failover."
                ),
                properties={
                    "unique_ip_count": len(observed_ips),
                    "total_subnet_count": total_subnets,
                    "subnet_count": total_subnets,
                    "ipv4_subnet_count": len(subnets_v4),
                    "ipv6_subnet_count": len(subnets_v6),
                    "median_ttl": median_ttl,
                    "is_dynamic_dns": is_dynamic_dns,
                    "is_mixed_anycast": is_mixed_anycast,
                    "contradictory_evidence": contradictory_evidence,
                    "window_start": t_window_start_iso,
                    "window_end": now_iso,
                    "guardrail_status": "PASS_NO_MALICIOUS_INFERENCE",
                    "confidence_type": "heuristic_uncalibrated",
                },
            )
            claims.append(claim)

        return claims

    def _detect_resolution_divergence(
        self,
        domain: str,
        observations: list[RealObservation],
        events_by_id: dict[str, RealCollectionEvent],
        now_iso: str,
    ) -> list[IntelligenceClaim]:
        """Detect abrupt transitions between known Anycast/CDN edge pools and unicast/private IP ranges."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        # Track transitions between anycast and non-anycast
        epochs: list[tuple[str, set[str], bool]] = []
        by_time: dict[str, set[str]] = defaultdict(set)
        evidence_by_time: dict[str, set[str]] = defaultdict(set)

        for ob in observations:
            if ob.status == "ok" and ob.values:
                by_time[ob.observed_at].update(ob.values)
                ev = events_by_id.get(ob.evidence_id)
                if ev:
                    evidence_by_time[ob.observed_at].add(ev.raw_sha256)

        for t in sorted(by_time.keys()):
            ips = by_time[t]
            has_anycast = any(is_known_anycast_ip(ip)[0] for ip in ips)
            epochs.append((t, ips, has_anycast))

        if len(epochs) < 2:
            return claims

        for (t1, ips1, anycast1), (t2, ips2, anycast2) in zip(epochs, epochs[1:]):
            if anycast1 != anycast2:
                combined_hashes = sorted(evidence_by_time[t1] | evidence_by_time[t2])
                from_desc = "Anycast/CDN Edge" if anycast1 else "Unicast/Dedicated"
                to_desc = "Anycast/CDN Edge" if anycast2 else "Unicast/Dedicated"

                explanation = (
                    f"Unexpected resolution divergence for {domain}: Route topology shifted from {from_desc} ({sorted(ips1)}) "
                    f"to {to_desc} ({sorted(ips2)}) between {t1} and {t2}."
                )

                claim = IntelligenceClaim.create(
                    subject_uri=domain_uri,
                    claim_type=TemporalClaimType.RESOLUTION_DIVERGENCE_INDICATOR.value,
                    layer=EpistemicLayer.HYPOTHESIS,
                    asserted_at=now_iso,
                    valid_from=t2,
                    confidence=0.80,
                    explanation=explanation,
                    supporting_evidence_hashes=combined_hashes,
                    supporting_node_ids=[domain_uri] + [format_node_id(NodeType.IP, ip) for ip in ips2],
                    verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
                    falsifiability_condition=(
                        "Falsified if zone administrator intentionally migrated infrastructure, altered CDN vendor, "
                        "or performed direct testing against origin servers."
                    ),
                    properties={
                        "from_topology": from_desc,
                        "to_topology": to_desc,
                        "from_ips": sorted(ips1),
                        "to_ips": sorted(ips2),
                        "transition_time": t2,
                        "confidence_type": "heuristic_uncalibrated",
                    },
                )
                claims.append(claim)

        return claims

    def ensure_competing_hypotheses_table(self) -> None:
        """Ensure the competing_hypotheses storage table exists."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS competing_hypotheses (
                hypothesis_id TEXT PRIMARY KEY,
                subject_uri TEXT NOT NULL,
                phenomenon TEXT NOT NULL,
                hypothesis_label TEXT NOT NULL,
                status TEXT NOT NULL,
                heuristic_score REAL NOT NULL,
                statistically_calibrated INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                supporting_evidence_hashes_json TEXT NOT NULL,
                contradicting_evidence_hashes_json TEXT NOT NULL,
                falsifiability_condition TEXT NOT NULL,
                ruleset_version TEXT NOT NULL,
                asserted_at TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                supersedes_hypothesis_id TEXT,
                payload TEXT NOT NULL
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_competing_hypotheses_subject ON competing_hypotheses(subject_uri)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_competing_hypotheses_phenomenon ON competing_hypotheses(phenomenon)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_competing_hypotheses_time ON competing_hypotheses(asserted_at)")

    def persist_competing_hypotheses(self, hypotheses: list[CompetingHypothesis]) -> None:
        """Persist generated hypotheses with historical preservation of superseded records."""
        self.ensure_competing_hypotheses_table()
        for hyp in hypotheses:
            if hyp.supersedes_hypothesis_id:
                old_row = self.conn.execute(
                    "SELECT payload FROM competing_hypotheses WHERE hypothesis_id = ?",
                    (hyp.supersedes_hypothesis_id,),
                ).fetchone()
                if old_row:
                    old_dict = json.loads(old_row[0])
                    old_dict["valid_until"] = hyp.asserted_at
                    old_dict["status"] = HypothesisStatus.SUPERSEDED.value
                    self.conn.execute(
                        """
                        UPDATE competing_hypotheses
                        SET status = ?, valid_until = ?, payload = ?
                        WHERE hypothesis_id = ?
                        """,
                        (HypothesisStatus.SUPERSEDED.value, hyp.asserted_at, canonical_json(old_dict), hyp.supersedes_hypothesis_id),
                    )

            payload_json = canonical_json(hyp.to_dict())
            self.conn.execute(
                """
                INSERT OR REPLACE INTO competing_hypotheses (
                    hypothesis_id, subject_uri, phenomenon, hypothesis_label,
                    status, heuristic_score, statistically_calibrated, explanation,
                    supporting_evidence_hashes_json, contradicting_evidence_hashes_json,
                    falsifiability_condition, ruleset_version, asserted_at,
                    valid_from, valid_until, supersedes_hypothesis_id, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hyp.hypothesis_id,
                    hyp.subject_uri,
                    hyp.phenomenon,
                    hyp.hypothesis_label,
                    hyp.status,
                    hyp.heuristic_score,
                    1 if hyp.statistically_calibrated else 0,
                    hyp.explanation,
                    canonical_json(list(hyp.supporting_evidence_hashes)),
                    canonical_json(list(hyp.contradicting_evidence_hashes)),
                    hyp.falsifiability_condition,
                    hyp.ruleset_version,
                    hyp.asserted_at,
                    hyp.valid_from,
                    hyp.valid_until,
                    hyp.supersedes_hypothesis_id,
                    payload_json,
                ),
            )
        self.conn.commit()

    def get_competing_hypotheses(
        self,
        subject_uri: str | None = None,
        include_superseded: bool = True,
    ) -> list[CompetingHypothesis]:
        """Query persisted competing hypotheses from SQLite."""
        self.ensure_competing_hypotheses_table()
        if subject_uri:
            if include_superseded:
                sql = "SELECT payload FROM competing_hypotheses WHERE subject_uri = ? ORDER BY asserted_at DESC"
                rows = self.conn.execute(sql, (subject_uri,)).fetchall()
            else:
                sql = "SELECT payload FROM competing_hypotheses WHERE subject_uri = ? AND status != ? ORDER BY asserted_at DESC"
                rows = self.conn.execute(sql, (subject_uri, HypothesisStatus.SUPERSEDED.value)).fetchall()
        else:
            if include_superseded:
                sql = "SELECT payload FROM competing_hypotheses ORDER BY asserted_at DESC"
                rows = self.conn.execute(sql).fetchall()
            else:
                sql = "SELECT payload FROM competing_hypotheses WHERE status != ? ORDER BY asserted_at DESC"
                rows = self.conn.execute(sql, (HypothesisStatus.SUPERSEDED.value,)).fetchall()

        return [CompetingHypothesis.from_dict(json.loads(r[0])) for r in rows]

    def project_hypotheses_to_graph(
        self,
        hypotheses: list[CompetingHypothesis],
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Project competing hypotheses into graph nodes and typed relationships."""
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        for hyp in hypotheses:
            hyp_node = GraphNode.create(
                node_type=NodeType.HYPOTHESIS,
                canonical_name=hyp.hypothesis_id,
                layer=EpistemicLayer.HYPOTHESIS,
                observed_at=hyp.asserted_at,
                properties={
                    "phenomenon": hyp.phenomenon,
                    "hypothesis_label": hyp.hypothesis_label,
                    "status": hyp.status,
                    "heuristic_score": hyp.heuristic_score,
                    "statistically_calibrated": hyp.statistically_calibrated,
                    "explanation": hyp.explanation,
                    "falsifiability_condition": hyp.falsifiability_condition,
                    "ruleset_version": hyp.ruleset_version,
                    "supersedes_hypothesis_id": hyp.supersedes_hypothesis_id,
                },
            )
            nodes.append(hyp_node)

            explains_edge = GraphEdge.create(
                source_id=hyp_node.node_id,
                target_id=hyp.subject_uri,
                relation_type=RelationType.EXPLAINS,
                layer=EpistemicLayer.HYPOTHESIS,
                observed_at=hyp.asserted_at,
                valid_from=hyp.valid_from,
                valid_until=hyp.valid_until,
                ruleset_version=hyp.ruleset_version,
                confidence=hyp.heuristic_score,
                evidence_hashes=hyp.supporting_evidence_hashes,
                properties={
                    "status": hyp.status,
                    "falsifiability_condition": hyp.falsifiability_condition,
                },
            )
            edges.append(explains_edge)

            if hyp.supersedes_hypothesis_id:
                old_node_id = format_node_id(NodeType.HYPOTHESIS, hyp.supersedes_hypothesis_id)
                supersedes_edge = GraphEdge.create(
                    source_id=hyp_node.node_id,
                    target_id=old_node_id,
                    relation_type=RelationType.SUPERSEDES,
                    layer=EpistemicLayer.HYPOTHESIS,
                    observed_at=hyp.asserted_at,
                    valid_from=hyp.asserted_at,
                    ruleset_version=hyp.ruleset_version,
                    confidence=1.0,
                    evidence_hashes=hyp.supporting_evidence_hashes,
                    properties={"historical_reasoning_preserved": True},
                )
                edges.append(supersedes_edge)

        return nodes, edges

    def evaluate_competing_hypotheses(
        self,
        domain: str,
        as_of: str | None = None,
    ) -> list[CompetingHypothesis]:
        """Evaluate alternative competing hypotheses for the observed infrastructure behavior of a domain.
        
        Evaluates:
        1. IP Volatility / Rotation: Legitimate CDN/Anycast Edge vs Suspicious Fast-Flux Candidate.
        2. Resolver Discrepancy: Upstream Security Filtering vs Regional GeoDNS Routing.
        
        Guarantees:
        - Supporting and contradicting evidence sets are partitioned separately.
        - Uncalibrated heuristic scores (0.0 to 1.0) strictly separate from calibrated probability.
        - Explicit abstention (INSUFFICIENT_EVIDENCE) when telemetry is sparse.
        - Historical revision / supersession linkage when earlier hypotheses exist.
        """
        now_iso = utc_iso(as_of) if as_of else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        domain_uri = format_node_id(NodeType.DOMAIN, domain)
        hypotheses: list[CompetingHypothesis] = []

        # 1. Fetch observations
        if as_of:
            obs_rows = self.conn.execute(
                """
                SELECT payload, observed_at, status
                FROM real_observations
                WHERE subject = ? AND kind IN ('dns_a', 'dns_aaaa') AND observed_at <= ?
                ORDER BY observed_at ASC, observation_id ASC
                """,
                (domain, now_iso),
            ).fetchall()
        else:
            obs_rows = self.conn.execute(
                """
                SELECT payload, observed_at, status
                FROM real_observations
                WHERE subject = ? AND kind IN ('dns_a', 'dns_aaaa')
                ORDER BY observed_at ASC, observation_id ASC
                """,
                (domain,),
            ).fetchall()

        observations = [RealObservation.from_dict(json.loads(r[0])) for r in obs_rows]
        ev_ids = list({o.evidence_id for o in observations})
        events_by_id: dict[str, RealCollectionEvent] = {}
        if ev_ids:
            placeholders = ",".join("?" for _ in ev_ids)
            ev_rows = self.conn.execute(
                f"SELECT payload FROM real_events WHERE event_id IN ({placeholders})",
                ev_ids,
            ).fetchall()
            for r in ev_rows:
                ev = RealCollectionEvent.from_dict(json.loads(r[0]))
                events_by_id[ev.event_id] = ev

        self.ensure_competing_hypotheses_table()
        existing_rows = self.conn.execute(
            "SELECT payload FROM competing_hypotheses WHERE subject_uri = ? AND status != ?",
            (domain_uri, HypothesisStatus.SUPERSEDED.value),
        ).fetchall()
        existing_by_label: dict[str, CompetingHypothesis] = {}
        for (p_raw,) in existing_rows:
            ex_hyp = CompetingHypothesis.from_dict(json.loads(p_raw))
            existing_by_label[ex_hyp.hypothesis_label] = ex_hyp

        # Phenomenon A: IP Volatility / Rotation
        if len(observations) < 2:
            all_hashes = tuple(events_by_id[o.evidence_id].raw_sha256 for o in observations if o.evidence_id in events_by_id)
            abstained = CompetingHypothesis(
                subject_uri=domain_uri,
                phenomenon="VOLATILE_IP_INFRASTRUCTURE",
                hypothesis_label="Indeterminate Infrastructure (Abstained)",
                status=HypothesisStatus.INSUFFICIENT_EVIDENCE.value,
                heuristic_score=0.0,
                explanation=f"Insufficient temporal observations ({len(observations)}) to form conclusive competing hypotheses.",
                supporting_evidence_hashes=all_hashes,
                contradicting_evidence_hashes=(),
                falsifiability_condition="Falsified when >= 2 distinct temporal measurement epochs are collected.",
                ruleset_version=self.RULESET_VERSION,
                asserted_at=now_iso,
                valid_from=now_iso,
                properties={"observation_count": len(observations)},
            )
            hypotheses.append(abstained)
        else:
            observed_ips: set[str] = set()
            ttls: list[int] = []
            cdn_evidence: set[str] = set()
            non_cdn_evidence: set[str] = set()
            subnets: set[str] = set()

            for ob in observations:
                if ob.status == "ok" and ob.values:
                    ev = events_by_id.get(ob.evidence_id)
                    ev_hash = ev.raw_sha256 if ev else ""
                    if ob.ttl_seconds is not None:
                        ttls.append(ob.ttl_seconds)

                    for ip in ob.values:
                        observed_ips.add(ip)
                        is_anycast, _ = is_known_anycast_ip(ip)
                        if is_anycast:
                            if ev_hash:
                                cdn_evidence.add(ev_hash)
                        else:
                            if ev_hash:
                                non_cdn_evidence.add(ev_hash)
                        try:
                            ip_o = ipaddress.ip_address(ip)
                            if ip_o.version == 4:
                                subnets.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
                            else:
                                subnets.add(str(ipaddress.ip_network(f"{ip}/48", strict=False)))
                        except ValueError:
                            pass

            median_ttl = sorted(ttls)[len(ttls) // 2] if ttls else 300
            is_all_cdn = len(non_cdn_evidence) == 0 and len(cdn_evidence) > 0
            is_mixed = len(non_cdn_evidence) > 0 and len(cdn_evidence) > 0

            # Hypothesis A1: Legitimate CDN / Anycast Edge Pool Rotation
            if is_all_cdn:
                status_a1 = HypothesisStatus.FAVORED.value
                score_a1 = 0.85
                expl_a1 = (
                    f"Observed IP churn ({len(observed_ips)} IPs, median TTL {median_ttl}s) for {domain} matches "
                    f"published CDN/Anycast edge networks across all observation epochs."
                )
            elif is_mixed:
                status_a1 = HypothesisStatus.PLAUSIBLE.value
                score_a1 = 0.50
                expl_a1 = (
                    f"Observed IP churn for {domain} exhibits mixed topology: CDN edge pools co-exist with "
                    f"unicast origin/provider IP addresses."
                )
            else:
                status_a1 = HypothesisStatus.CONTRADICTED.value
                score_a1 = 0.15
                expl_a1 = f"No observed IPs for {domain} belong to published CDN/Anycast edge networks."

            label_a1 = "Legitimate CDN / Anycast Edge Rotation"
            prev_a1 = existing_by_label.get(label_a1)
            supersedes_a1 = prev_a1.hypothesis_id if prev_a1 and prev_a1.status != status_a1 else None

            hyp_a1 = CompetingHypothesis(
                subject_uri=domain_uri,
                phenomenon="VOLATILE_IP_INFRASTRUCTURE",
                hypothesis_label=label_a1,
                status=status_a1,
                heuristic_score=score_a1,
                explanation=expl_a1,
                supporting_evidence_hashes=tuple(sorted(cdn_evidence)),
                contradicting_evidence_hashes=tuple(sorted(non_cdn_evidence)),
                falsifiability_condition=(
                    "Falsified if target IPs resolve to unannounced, non-CDN residential/enterprise ASNs "
                    "without Anycast BGP routing."
                ),
                ruleset_version=self.RULESET_VERSION,
                asserted_at=now_iso,
                valid_from=now_iso,
                supersedes_hypothesis_id=supersedes_a1,
                properties={
                    "unique_ips": len(observed_ips),
                    "median_ttl": median_ttl,
                    "cdn_evidence_count": len(cdn_evidence),
                    "non_cdn_evidence_count": len(non_cdn_evidence),
                },
            )
            hypotheses.append(hyp_a1)

            # Hypothesis A2: Suspicious Fast-Flux Infrastructure Candidate
            if is_all_cdn:
                status_a2 = HypothesisStatus.CONTRADICTED.value
                score_a2 = 0.10
                expl_a2 = (
                    f"Fast-flux candidate hypothesis contradicted for {domain}: All {len(observed_ips)} observed IPs "
                    f"belong to published, authenticated CDN/Anycast edge infrastructure."
                )
            elif len(observed_ips) >= 4 and len(subnets) >= 3 and median_ttl <= 300 and not is_all_cdn:
                status_a2 = HypothesisStatus.FAVORED.value
                score_a2 = 0.80
                expl_a2 = (
                    f"High-frequency IP churn detected for {domain} across {len(subnets)} distinct subnets "
                    f"with low TTL ({median_ttl}s) outside published CDN ranges."
                )
            else:
                status_a2 = HypothesisStatus.PLAUSIBLE.value
                score_a2 = 0.35
                expl_a2 = (
                    f"Infrastructure churn observed for {domain}, but insufficient subnet dispersion (< 3 subnets) "
                    f"to favor fast-flux candidate classification."
                )

            label_a2 = "Suspicious Fast-Flux Candidate"
            prev_a2 = existing_by_label.get(label_a2)
            supersedes_a2 = prev_a2.hypothesis_id if prev_a2 and prev_a2.status != status_a2 else None

            hyp_a2 = CompetingHypothesis(
                subject_uri=domain_uri,
                phenomenon="VOLATILE_IP_INFRASTRUCTURE",
                hypothesis_label=label_a2,
                status=status_a2,
                heuristic_score=score_a2,
                explanation=expl_a2,
                supporting_evidence_hashes=tuple(sorted(non_cdn_evidence)),
                contradicting_evidence_hashes=tuple(sorted(cdn_evidence)),
                falsifiability_condition=(
                    "Falsified if target IPs are verified to belong exclusively to published Anycast/CDN edge networks "
                    "rather than dynamic single-tenant hosts."
                ),
                ruleset_version=self.RULESET_VERSION,
                asserted_at=now_iso,
                valid_from=now_iso,
                supersedes_hypothesis_id=supersedes_a2,
                properties={
                    "unique_ips": len(observed_ips),
                    "subnet_count": len(subnets),
                    "median_ttl": median_ttl,
                },
            )
            hypotheses.append(hyp_a2)

        # Phenomenon B: Resolver Discrepancy (Filtering vs GeoDNS)
        disc_sql = "SELECT payload FROM real_discrepancies WHERE subject = ? AND verdict != 'AGREEMENT'"
        disc_params = [domain]
        if as_of:
            disc_sql += " AND analyzed_at <= ?"
            disc_params.append(now_iso)

        disc_rows = self.conn.execute(disc_sql, disc_params).fetchall()
        if disc_rows:
            filter_ev_hashes: set[str] = set()
            unfiltered_ev_hashes: set[str] = set()
            has_security_filter = False

            for (d_raw,) in disc_rows:
                disc = RealDiscrepancyReport.from_dict(json.loads(d_raw))
                if disc.category == "SECURITY_FILTERING" or any(k in disc.explanation.lower() for k in ("filter", "nxdomain", "refused")):
                    has_security_filter = True
                for res, ev_h in disc.evidence_hashes.items():
                    if res in ("quad9", "cleanbrowsing"):
                        filter_ev_hashes.add(ev_h)
                    else:
                        unfiltered_ev_hashes.add(ev_h)

            label_b1 = "Upstream Resolver Security Filtering"
            label_b2 = "GeoDNS / Multi-Region Routing Divergence"

            if has_security_filter:
                status_b1 = HypothesisStatus.FAVORED.value
                score_b1 = 0.90
                expl_b1 = (
                    f"Resolver discrepancy for {domain} matches upstream threat filtering / blocking: "
                    f"protective resolvers returned negative responses while public resolvers returned valid records."
                )

                status_b2 = HypothesisStatus.CONTRADICTED.value
                score_b2 = 0.15
                expl_b2 = (
                    f"GeoDNS routing divergence contradicted for {domain}: Divergence was caused by resolver security "
                    f"filtering (NXDOMAIN / blocked) rather than geographic IP answer variation."
                )
            else:
                status_b1 = HypothesisStatus.PLAUSIBLE.value
                score_b1 = 0.45
                expl_b1 = f"Resolver disagreement observed for {domain} without explicit security filtering indicators."

                status_b2 = HypothesisStatus.FAVORED.value
                score_b2 = 0.80
                expl_b2 = (
                    f"Resolver disagreement for {domain} is consistent with GeoDNS or recursive cache latency variation."
                )

            prev_b1 = existing_by_label.get(label_b1)
            supersedes_b1 = prev_b1.hypothesis_id if prev_b1 and prev_b1.status != status_b1 else None

            hyp_b1 = CompetingHypothesis(
                subject_uri=domain_uri,
                phenomenon="RESOLVER_DISCREPANCY",
                hypothesis_label=label_b1,
                status=status_b1,
                heuristic_score=score_b1,
                explanation=expl_b1,
                supporting_evidence_hashes=tuple(sorted(filter_ev_hashes)),
                contradicting_evidence_hashes=tuple(sorted(unfiltered_ev_hashes)),
                falsifiability_condition=(
                    "Falsified if discrepancy reproduces across unfiltered authoritative nameservers without security policies."
                ),
                ruleset_version=self.RULESET_VERSION,
                asserted_at=now_iso,
                valid_from=now_iso,
                supersedes_hypothesis_id=supersedes_b1,
            )
            hypotheses.append(hyp_b1)

            prev_b2 = existing_by_label.get(label_b2)
            supersedes_b2 = prev_b2.hypothesis_id if prev_b2 and prev_b2.status != status_b2 else None

            hyp_b2 = CompetingHypothesis(
                subject_uri=domain_uri,
                phenomenon="RESOLVER_DISCREPANCY",
                hypothesis_label=label_b2,
                status=status_b2,
                heuristic_score=score_b2,
                explanation=expl_b2,
                supporting_evidence_hashes=tuple(sorted(unfiltered_ev_hashes)),
                contradicting_evidence_hashes=tuple(sorted(filter_ev_hashes)),
                falsifiability_condition=(
                    "Falsified if queries from identical geolocations yield consistent positive answers."
                ),
                ruleset_version=self.RULESET_VERSION,
                asserted_at=now_iso,
                valid_from=now_iso,
                supersedes_hypothesis_id=supersedes_b2,
            )
            hypotheses.append(hyp_b2)

        return hypotheses


class HypothesisStatus(str, Enum):
    """Evaluation status of a competing hypothesis."""
    FAVORED = "FAVORED"
    PLAUSIBLE = "PLAUSIBLE"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True)
class CompetingHypothesis:
    """Attributable, alternative explanation for observed infrastructure telemetry.
    
    Milestone M3.8: Competing Hypothesis Engine.
    
    Guarantees:
    - Separates supporting evidence from contradicting evidence.
    - Explicit uncalibrated heuristic score (statistically_calibrated=False).
    - Falsifiability condition defined for scientific review.
    - Preserves historical supersession without silent destruction.
    """
    subject_uri: str
    phenomenon: str
    hypothesis_label: str
    status: str
    heuristic_score: float
    explanation: str
    supporting_evidence_hashes: tuple[str, ...]
    contradicting_evidence_hashes: tuple[str, ...]
    falsifiability_condition: str
    ruleset_version: str
    asserted_at: str
    valid_from: str
    valid_until: str | None = None
    supersedes_hypothesis_id: str | None = None
    statistically_calibrated: bool = False
    properties: dict[str, Any] = field(default_factory=dict)
    hypothesis_id: str = field(init=False)

    def __post_init__(self):
        if not self.subject_uri.startswith("anie:entity:"):
            raise ValueError(f"invalid subject_uri: {self.subject_uri!r}")
        if self.status not in [s.value for s in HypothesisStatus]:
            raise ValueError(f"unsupported hypothesis status: {self.status!r}")
        if not (0.0 <= self.heuristic_score <= 1.0):
            raise ValueError(f"heuristic_score must be in range [0.0, 1.0]: {self.heuristic_score}")
        if not self.explanation.strip():
            raise ValueError("explanation must be non-empty")
        if not self.falsifiability_condition.strip():
            raise ValueError("falsifiability_condition must be non-empty")
        utc_iso(self.asserted_at)
        utc_iso(self.valid_from)
        if self.valid_until is not None:
            utc_iso(self.valid_until)

        # Deterministic canonical hypothesis identifier
        id_material = {
            "subject_uri": self.subject_uri,
            "phenomenon": self.phenomenon,
            "hypothesis_label": self.hypothesis_label,
            "asserted_at": self.asserted_at,
            "ruleset_version": self.ruleset_version,
            "supporting_evidence_hashes": sorted(self.supporting_evidence_hashes),
            "contradicting_evidence_hashes": sorted(self.contradicting_evidence_hashes),
        }
        digest = sha256(canonical_json(id_material).encode("utf-8")).hexdigest()
        object.__setattr__(self, "hypothesis_id", f"hyp_{digest[:32]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "subject_uri": self.subject_uri,
            "phenomenon": self.phenomenon,
            "hypothesis_label": self.hypothesis_label,
            "status": self.status,
            "heuristic_score": self.heuristic_score,
            "statistically_calibrated": self.statistically_calibrated,
            "explanation": self.explanation,
            "supporting_evidence_hashes": list(self.supporting_evidence_hashes),
            "contradicting_evidence_hashes": list(self.contradicting_evidence_hashes),
            "falsifiability_condition": self.falsifiability_condition,
            "ruleset_version": self.ruleset_version,
            "asserted_at": self.asserted_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "supersedes_hypothesis_id": self.supersedes_hypothesis_id,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CompetingHypothesis":
        return cls(
            subject_uri=data["subject_uri"],
            phenomenon=data["phenomenon"],
            hypothesis_label=data["hypothesis_label"],
            status=data["status"],
            heuristic_score=float(data["heuristic_score"]),
            explanation=data["explanation"],
            supporting_evidence_hashes=tuple(data.get("supporting_evidence_hashes", ())),
            contradicting_evidence_hashes=tuple(data.get("contradicting_evidence_hashes", ())),
            falsifiability_condition=data["falsifiability_condition"],
            ruleset_version=data.get("ruleset_version", "anie.competing-hypotheses.v1"),
            asserted_at=data["asserted_at"],
            valid_from=data["valid_from"],
            valid_until=data.get("valid_until"),
            supersedes_hypothesis_id=data.get("supersedes_hypothesis_id"),
            statistically_calibrated=bool(data.get("statistically_calibrated", False)),
            properties=data.get("properties", {}),
        )


# Canonical alias conforming to M3.6 specification
EvidenceGraphDetector = TemporalIntelligenceEngine



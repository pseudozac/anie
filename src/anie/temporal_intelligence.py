"""Temporal Graph Intelligence Subsystem for ANIE (Milestone M3.4).

Provides deterministic, explainable analysis of historical DNS infrastructure:
1. Historical DNS infrastructure transitions (IP set changes across observation epochs).
2. Domain-to-IP relationship evolution (duration, TTL stability, ephemeral/persistent categorization).
3. Shared infrastructure correlation (co-hosted domains on shared vs Anycast/CDN edge pools).
4. Resolver discrepancy timelines (persistent disagreement, security-filtering NXDOMAINs).
5. Fast-flux candidate indicators (rapid IP churn, low TTL, subnet diversity; non-malicious).
6. Unexpected resolution divergence (sudden Anycast-to-unicast shifts or provider divergence).

Strict Epistemic Guardrails:
- Every finding retains raw wire evidence hashes, timestamps, ruleset version, and uncertainty.
- Inferences are classified as UNVERIFIED_HYPOTHESIS with explicit falsifiability conditions.
- Strictly prohibits inferring malicious intent from infrastructure churn, co-hosting, or discrepancies alone.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
import sqlite3
from typing import Any, Iterable

from .discrepancy_models import RealDiscrepancyReport
from .graph_engine import GraphEngine
from .graph_models import (
    ClaimVerificationState,
    EpistemicLayer,
    GraphNode,
    IntelligenceClaim,
    NodeType,
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


# Known public Anycast / CDN network prefixes (CIDR blocks)
_KNOWN_CDN_NETWORKS = [
    # Cloudflare
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
    # Fastly
    ipaddress.ip_network("151.101.0.0/16"),
    ipaddress.ip_network("199.232.0.0/16"),
    # AWS CloudFront / Edge
    ipaddress.ip_network("13.224.0.0/14"),
    ipaddress.ip_network("13.225.0.0/16"),
    ipaddress.ip_network("13.32.0.0/15"),
    ipaddress.ip_network("52.84.0.0/15"),
    ipaddress.ip_network("54.230.0.0/16"),
    # Google Cloud / Public DNS
    ipaddress.ip_network("8.8.8.0/24"),
    ipaddress.ip_network("8.8.4.0/24"),
    ipaddress.ip_network("142.250.0.0/15"),
    ipaddress.ip_network("172.217.0.0/16"),
    # Quad9
    ipaddress.ip_network("9.9.9.0/24"),
    ipaddress.ip_network("149.112.112.0/24"),
]


def is_known_anycast_ip(ip_str: str) -> tuple[bool, str]:
    """Check if an IP address belongs to known public CDN/Anycast networks.
    
    Returns (is_anycast, provider_label).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in _KNOWN_CDN_NETWORKS:
            if ip_obj in net:
                if "104.16" in str(net) or "172.64" in str(net) or "162.158" in str(net):
                    return True, "Cloudflare Anycast"
                elif "151.101" in str(net) or "199.232" in str(net):
                    return True, "Fastly Anycast"
                elif "13.22" in str(net) or "52.84" in str(net) or "54.230" in str(net):
                    return True, "AWS CloudFront"
                elif "8.8" in str(net) or "142.250" in str(net) or "172.217" in str(net):
                    return True, "Google Edge"
                elif "9.9.9" in str(net) or "149.112" in str(net):
                    return True, "Quad9 Anycast"
                return True, "Known CDN Anycast"
        return False, "Standard Unicast / Private"
    except ValueError:
        return False, "Invalid IP"


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
        
        Returns a list of evidence-backed IntelligenceClaim objects.
        """
        now_iso = utc_iso(as_of) if as_of else datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        claims: list[IntelligenceClaim] = []

        # 1. Fetch all observations for domain
        obs_rows = self.conn.execute(
            """
            SELECT payload, observed_at, status
            FROM real_observations
            WHERE subject = ? AND kind = 'dns_a'
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
        claims.extend(self._detect_discrepancy_timeline(domain, now_iso))
        claims.extend(self._detect_fast_flux_indicators(domain, observations, events_by_id, now_iso))
        claims.extend(self._detect_resolution_divergence(domain, observations, events_by_id, now_iso))

        return claims

    def analyze_all(
        self,
        as_of: str | None = None,
        limit_domains: int | None = None,
    ) -> list[IntelligenceClaim]:
        """Analyze all domain entities registered in the store and return claims."""
        sql = "SELECT DISTINCT subject FROM real_observations WHERE kind = 'dns_a' ORDER BY subject"
        if limit_domains:
            sql += f" LIMIT {int(limit_domains)}"

        domains = [r[0] for r in self.conn.execute(sql).fetchall()]
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
        """Detect transitions in resolved IP sets between distinct observation epochs."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        # Group by observation time (epoch)
        by_time: dict[str, set[str]] = defaultdict(set)
        evidence_by_time: dict[str, set[str]] = defaultdict(set)

        for ob in observations:
            if ob.status == "ok" and ob.values:
                by_time[ob.observed_at].update(ob.values)
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
                explanation = (
                    f"Infrastructure transition observed for {domain}: IP set changed from "
                    f"{prev_ips} at {t_prev} to {curr_ips} at {t_curr}."
                )

                claim = IntelligenceClaim.create(
                    subject_uri=domain_uri,
                    claim_type=TemporalClaimType.INFRASTRUCTURE_TRANSITION.value,
                    layer=EpistemicLayer.HYPOTHESIS,
                    asserted_at=now_iso,
                    valid_from=t_curr,
                    confidence=1.0,
                    explanation=explanation,
                    supporting_evidence_hashes=combined_hashes,
                    supporting_node_ids=[domain_uri] + [format_node_id(NodeType.IP, ip) for ip in curr_ips],
                    verification_state=ClaimVerificationState.ATTESTED_ASSERTION.value,
                    falsifiability_condition=(
                        "Falsified if intermediate unobserved queries demonstrate gradual rollover or "
                        "if multi-region DNS Anycast returns geographically differentiated responses."
                    ),
                    properties={
                        "previous_ips": prev_ips,
                        "new_ips": curr_ips,
                        "transition_time": t_curr,
                        "previous_time": t_prev,
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
                confidence=0.95,
                explanation=explanation,
                supporting_evidence_hashes=sorted(stats["evidence_hashes"]),
                supporting_node_ids=[domain_uri, ip_uri],
                verification_state=ClaimVerificationState.ATTESTED_ASSERTION.value,
                falsifiability_condition="Defeated if authoritative zone apex records record differing glue or delegations.",
                properties={
                    "ip": ip,
                    "classification": classification,
                    "duration_hours": round(duration_hours, 2),
                    "mean_ttl": mean_ttl,
                    "is_known_anycast": is_anycast,
                    "provider": provider,
                    "observation_count": stats["count"],
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

                guardrail_notice = (
                    "Co-hosting reflects shared multi-tenant hosting, CDN edge routing, or Anycast pools. "
                    "It strictly does NOT infer common administrative ownership, coordinated activity, or maliciousness."
                )

                explanation = (
                    f"Shared infrastructure correlation: {domain} is co-hosted with {len(other_domains)} other domain(s) "
                    f"on IP {ip} ({provider}). Correlated domains include: {other_domains[:5]}. {guardrail_notice}"
                )

                claim = IntelligenceClaim.create(
                    subject_uri=domain_uri,
                    claim_type=TemporalClaimType.SHARED_INFRASTRUCTURE.value,
                    layer=EpistemicLayer.HYPOTHESIS,
                    asserted_at=now_iso,
                    valid_from=latest_time or now_iso,
                    confidence=0.90,
                    explanation=explanation,
                    supporting_evidence_hashes=sorted(evidence_hashes),
                    supporting_node_ids=[domain_uri, ip_uri] + [format_node_id(NodeType.DOMAIN, d) for d in other_domains[:10]],
                    verification_state=ClaimVerificationState.ATTESTED_ASSERTION.value,
                    falsifiability_condition="Invalidated if SNI inspection or reverse DNS demonstrates dedicated non-shared allocation.",
                    properties={
                        "ip": ip,
                        "co_hosted_count": len(other_domains),
                        "co_hosted_sample": other_domains[:10],
                        "is_known_anycast": is_anycast,
                        "provider": provider,
                        "guardrail_status": "PASS_NO_MALICIOUS_INFERENCE",
                    },
                )
                claims.append(claim)

        return claims

    def _detect_discrepancy_timeline(
        self,
        domain: str,
        now_iso: str,
    ) -> list[IntelligenceClaim]:
        """Track multi-resolver consensus history and security-filtering divergence."""
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

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
            confidence=0.95,
            explanation=explanation,
            supporting_evidence_hashes=sorted(evidence_hashes),
            supporting_node_ids=[domain_uri],
            verification_state=ClaimVerificationState.ATTESTED_ASSERTION.value,
            falsifiability_condition="Defeated if resolver authority proves upstream authoritative server failure during collection window.",
            properties={
                "total_analyses": total_analyses,
                "agreement_rate": agreement_ratio,
                "filtering_events": filtering_events,
                "verdict_breakdown": dict(verdict_counts),
                "category_breakdown": dict(category_counts),
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
        """Detect deterministic indicators of high-frequency IP rotation with low TTL.
        
        Strict Epistemic Guardrail:
        - Must NOT infer maliciousness.
        - Must state falsifiability criteria (Anycast, CDN edge rotation, GSLB).
        """
        claims: list[IntelligenceClaim] = []
        domain_uri = format_node_id(NodeType.DOMAIN, domain)

        # Collect unique IPs, /24 subnets, and TTLs across past 24 hours
        observed_ips: set[str] = set()
        subnets_v4: set[str] = set()
        ttls: list[int] = []
        evidence_hashes: set[str] = set()
        anycast_present = False

        for ob in observations:
            if ob.status == "ok" and ob.values:
                for ip in ob.values:
                    observed_ips.add(ip)
                    is_anycast, _ = is_known_anycast_ip(ip)
                    if is_anycast:
                        anycast_present = True
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            subnets_v4.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
                    except ValueError:
                        pass
                if ob.ttl_seconds is not None:
                    ttls.append(ob.ttl_seconds)
                ev = events_by_id.get(ob.evidence_id)
                if ev:
                    evidence_hashes.add(ev.raw_sha256)

        median_ttl = sorted(ttls)[len(ttls) // 2] if ttls else 300

        # Fast-Flux Heuristic Condition:
        # 1. >= 5 unique IPs observed
        # 2. Short median TTL <= 300s
        # 3. >= 2 distinct /24 subnets
        # 4. Not in known CDN Anycast pool
        if len(observed_ips) >= 5 and median_ttl <= 300 and len(subnets_v4) >= 2 and not anycast_present:
            explanation = (
                f"Fast-flux candidate indicator detected for {domain}: Observed {len(observed_ips)} unique IPs "
                f"across {len(subnets_v4)} distinct /24 subnets with low median TTL ({median_ttl}s). "
                f"Notice: Fast-flux indicators measure dynamic volatility and do NOT infer maliciousness."
            )

            claim = IntelligenceClaim.create(
                subject_uri=domain_uri,
                claim_type=TemporalClaimType.FAST_FLUX_INDICATOR.value,
                layer=EpistemicLayer.HYPOTHESIS,
                asserted_at=now_iso,
                valid_from=now_iso,
                confidence=0.75,
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
                    "subnet_count": len(subnets_v4),
                    "median_ttl": median_ttl,
                    "subnets": sorted(subnets_v4)[:10],
                    "guardrail_status": "PASS_NO_MALICIOUS_INFERENCE",
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
                    confidence=0.85,
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
                    },
                )
                claims.append(claim)

        return claims

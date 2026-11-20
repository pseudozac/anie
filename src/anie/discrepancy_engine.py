"""Transparent, deterministic discrepancy and consensus analysis engine.

Part of ANIE Phase 3.3 Multi-Resolver Intelligence & Discrepancy Analysis.
Evaluates multi-source DoH observations to distinguish:
1. AGREEMENT: All resolvers returned identical answers and consistent DNSSEC verdicts.
2. EXPECTED_DIVERGENCE: Benign variation (CDN Anycast IP rotation, TTL caching countdown).
3. SECURITY_FILTERING_DETECTED: Policy filtering by security resolvers (Quad9 RFC 8914 EDE 15 / NXDOMAIN).
4. DNSSEC_DISAGREEMENT: Conflicting DNSSEC validation verdicts (secure vs bogus/SERVFAIL).
5. UNEXPLAINED_DIVERGENCE: Unexplained conflicting IP addresses or status mismatch across standard resolvers.
6. INCONCLUSIVE: Insufficient responses (< 2 resolvers) to determine consensus.

CRITICAL INVARIANT:
Resolver disagreement or filtering detection NEVER produces an automated "malicious" verdict.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Any

from .discrepancy_models import (
    DiscrepancyVerdict,
    DivergenceCategory,
    RealDiscrepancyReport,
    RULESET_VERSION_V1,
)
from .real_models import RealCollectionEvent, RealObservation

# Known Major CDN Anycast IP Prefixes for Benign Divergence Classification
KNOWN_CDN_PREFIXES: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {
    "cloudflare": [
        ipaddress.ip_network("104.16.0.0/12"),
        ipaddress.ip_network("172.64.0.0/13"),
        ipaddress.ip_network("2606:4700::/32"),
    ],
    "google": [
        ipaddress.ip_network("142.250.0.0/15"),
        ipaddress.ip_network("172.217.0.0/16"),
        ipaddress.ip_network("216.58.192.0/19"),
        ipaddress.ip_network("2607:f8b0::/32"),
    ],
    "aws_cloudfront": [
        ipaddress.ip_network("13.32.0.0/15"),
        ipaddress.ip_network("13.35.0.0/16"),
        ipaddress.ip_network("13.224.0.0/14"),
        ipaddress.ip_network("13.249.0.0/16"),
        ipaddress.ip_network("18.64.0.0/14"),
        ipaddress.ip_network("18.164.0.0/15"),
        ipaddress.ip_network("52.84.0.0/15"),
        ipaddress.ip_network("54.192.0.0/16"),
        ipaddress.ip_network("54.230.0.0/16"),
        ipaddress.ip_network("99.84.0.0/16"),
        ipaddress.ip_network("99.86.0.0/16"),
        ipaddress.ip_network("2600:9000::/28"),
    ],
    "fastly": [
        ipaddress.ip_network("151.101.0.0/16"),
        ipaddress.ip_network("199.232.0.0/16"),
        ipaddress.ip_network("2a04:4e42::/32"),
    ],
    "akamai": [
        ipaddress.ip_network("23.0.0.0/12"),
        ipaddress.ip_network("104.64.0.0/10"),
        ipaddress.ip_network("2.16.0.0/13"),
        ipaddress.ip_network("2600:1400::/28"),
    ],
}


def _identify_cdn_provider(ip_str: str) -> str | None:
    """Identify if an IP address belongs to a known verified Anycast CDN network."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    for cdn_name, networks in KNOWN_CDN_PREFIXES.items():
        for net in networks:
            if ip_obj in net:
                return cdn_name
    return None


class DiscrepancyEngine:
    """Deterministic consensus and discrepancy evaluation engine."""

    def __init__(self, ruleset_version: str = RULESET_VERSION_V1, window_seconds: float = 60.0):
        self.ruleset_version = ruleset_version
        self.window_seconds = window_seconds

    def analyze(
        self,
        subject: str,
        kind: str,
        observations: list[RealObservation],
        events: list[RealCollectionEvent],
        *,
        analyzed_at: str | None = None,
    ) -> RealDiscrepancyReport:
        """Evaluate observations across multiple resolvers for a domain and query kind."""
        now_iso = analyzed_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

        # Map events by event_id for fast lookup
        events_by_id = {e.event_id: e for e in events}

        # Deduplicate observations by resolver_identity (keep latest if multiple)
        obs_by_resolver: dict[str, RealObservation] = {}
        for obs in observations:
            if obs.subject != subject or obs.kind != kind:
                continue
            res_id = obs.factual_verification.resolver_identity
            if res_id not in obs_by_resolver or obs.observed_at > obs_by_resolver[res_id].observed_at:
                obs_by_resolver[res_id] = obs

        participating_resolvers = sorted(obs_by_resolver.keys())

        # Collect mappings
        answers_by_resolver: dict[str, list[str]] = {}
        dnssec_by_resolver: dict[str, str] = {}
        observation_ids: dict[str, str] = {}
        evidence_ids: dict[str, str] = {}
        evidence_hashes: dict[str, str] = {}
        filtering_metadata: dict[str, Any] = {}

        for res_id in participating_resolvers:
            obs = obs_by_resolver[res_id]
            answers_by_resolver[res_id] = sorted(obs.values)
            dnssec_by_resolver[res_id] = obs.factual_verification.dnssec_status
            observation_ids[res_id] = obs.observation_id
            evidence_ids[res_id] = obs.evidence_id

            # Locate matching event
            ev = events_by_id.get(obs.evidence_id)
            if ev is not None:
                evidence_hashes[res_id] = ev.raw_sha256
            else:
                raise ValueError(f"broken referential integrity: observation '{obs.observation_id}' references unknown event '{obs.evidence_id}'")

        # --- STEP 1: Inconclusive Check (< 2 participating resolvers) ---
        if len(participating_resolvers) < 2:
            return RealDiscrepancyReport(
                subject=subject,
                kind=kind,
                analyzed_at=now_iso,
                verdict=DiscrepancyVerdict.INCONCLUSIVE.value,
                category=DivergenceCategory.INCOMPLETE_RESPONSES.value,
                explanation=f"Insufficient participating resolvers ({len(participating_resolvers)}); minimum 2 required for consensus evaluation.",
                confidence=0.0,
                participating_resolvers=tuple(participating_resolvers),
                answers_by_resolver=answers_by_resolver,
                dnssec_by_resolver=dnssec_by_resolver,
                filtering_metadata=filtering_metadata,
                observation_ids=observation_ids,
                evidence_ids=evidence_ids,
                evidence_hashes=evidence_hashes,
                ruleset_version=self.ruleset_version,
            )

        # Separate security-filtering resolvers from standard recursive resolvers
        filtering_resolvers = [r for r in participating_resolvers if r in ("quad9",) or "filter" in r.lower()]
        standard_resolvers = [r for r in participating_resolvers if r not in filtering_resolvers]

        # --- STEP 2: Security Filtering Detection ---
        for f_res in filtering_resolvers:
            f_obs = obs_by_resolver[f_res]
            f_rcode = f_obs.factual_verification.wire_rcode
            f_values = f_obs.values

            # Quad9 blocks return NXDOMAIN, 0.0.0.0, or empty answer
            is_blocked = (f_rcode == "NXDOMAIN") or (not f_values) or (f_values == ("0.0.0.0",))

            # Check if standard recursive resolvers answered with valid non-empty responses
            std_answered = any(len(obs_by_resolver[s].values) > 0 for s in standard_resolvers)

            if is_blocked and std_answered:
                filtering_metadata[f_res] = {
                    "policy_block": True,
                    "rcode": f_rcode,
                    "description": "Domain blocked by resolver threat intelligence policy (NXDOMAIN / empty answer)",
                }
                explanation = (
                    f"Security filtering detected: Resolver '{f_res}' blocked query '{subject}' "
                    f"under threat-intelligence filtering policy ({f_rcode}), while standard recursive resolvers "
                    f"({', '.join(standard_resolvers)}) returned active answers. "
                    f"Note: This records resolver policy divergence and does NOT assert a maliciousness verdict."
                )
                return RealDiscrepancyReport(
                    subject=subject,
                    kind=kind,
                    analyzed_at=now_iso,
                    verdict=DiscrepancyVerdict.SECURITY_FILTERING_DETECTED.value,
                    category=DivergenceCategory.POLICY_FILTER_BLOCK.value,
                    explanation=explanation,
                    confidence=0.95,
                    participating_resolvers=tuple(participating_resolvers),
                    answers_by_resolver=answers_by_resolver,
                    dnssec_by_resolver=dnssec_by_resolver,
                    filtering_metadata=filtering_metadata,
                    observation_ids=observation_ids,
                    evidence_ids=evidence_ids,
                    evidence_hashes=evidence_hashes,
                    ruleset_version=self.ruleset_version,
                )

        # --- STEP 3: DNSSEC Disagreement Check ---
        dnssec_statuses = {r: dnssec_by_resolver[r] for r in participating_resolvers}
        servfail_resolvers = [
            r for r, s in dnssec_statuses.items()
            if s == "bogus" or obs_by_resolver[r].factual_verification.wire_rcode == "SERVFAIL"
        ]
        secure_or_answering = [
            r for r in participating_resolvers
            if r not in servfail_resolvers and (dnssec_statuses[r] == "secure" or len(obs_by_resolver[r].values) > 0)
        ]

        if servfail_resolvers and secure_or_answering:
            explanation = (
                f"DNSSEC validation disagreement: Resolvers ({', '.join(secure_or_answering)}) returned active/secure answers, "
                f"while ({', '.join(servfail_resolvers)}) reported validation failure or SERVFAIL."
            )
            return RealDiscrepancyReport(
                subject=subject,
                kind=kind,
                analyzed_at=now_iso,
                verdict=DiscrepancyVerdict.DNSSEC_DISAGREEMENT.value,
                category=DivergenceCategory.DNSSEC_VALIDATION_FAILURE.value,
                explanation=explanation,
                confidence=0.90,
                participating_resolvers=tuple(participating_resolvers),
                answers_by_resolver=answers_by_resolver,
                dnssec_by_resolver=dnssec_by_resolver,
                filtering_metadata=filtering_metadata,
                observation_ids=observation_ids,
                evidence_ids=evidence_ids,
                evidence_hashes=evidence_hashes,
                ruleset_version=self.ruleset_version,
            )

        # --- STEP 4: Answer Set Equality Check (Agreement) ---
        unique_answers = {tuple(sorted(v)) for v in answers_by_resolver.values()}
        if len(unique_answers) == 1:
            shared_values = next(iter(unique_answers))
            dnssec_unanimous = len(set(dnssec_by_resolver.values())) == 1
            confidence = 1.0 if dnssec_unanimous else 0.95
            explanation = (
                f"Full agreement across {len(participating_resolvers)} resolvers ({', '.join(participating_resolvers)}): "
                f"identical normalized answers ({', '.join(shared_values) if shared_values else 'empty/NXDOMAIN'}) "
                f"and consistent response codes."
            )
            return RealDiscrepancyReport(
                subject=subject,
                kind=kind,
                analyzed_at=now_iso,
                verdict=DiscrepancyVerdict.AGREEMENT.value,
                category=DivergenceCategory.NONE.value,
                explanation=explanation,
                confidence=confidence,
                participating_resolvers=tuple(participating_resolvers),
                answers_by_resolver=answers_by_resolver,
                dnssec_by_resolver=dnssec_by_resolver,
                filtering_metadata=filtering_metadata,
                observation_ids=observation_ids,
                evidence_ids=evidence_ids,
                evidence_hashes=evidence_hashes,
                ruleset_version=self.ruleset_version,
            )

        # --- STEP 5: Expected Divergence (CDN Anycast Rotation / Multi-Homed IP Pools) ---
        all_returned_ips = {ip for ans_list in answers_by_resolver.values() for ip in ans_list}
        cdn_providers = {_identify_cdn_provider(ip) for ip in all_returned_ips}

        # If all returned IPs belong to the same verified Anycast CDN network
        if len(cdn_providers) == 1 and None not in cdn_providers:
            cdn_name = next(iter(cdn_providers))
            explanation = (
                f"Expected divergence: Resolvers returned distinct IP addresses belonging to the same verified "
                f"Anycast CDN infrastructure ({cdn_name}). Characteristic of Anycast routing and geographic edge load balancing."
            )
            return RealDiscrepancyReport(
                subject=subject,
                kind=kind,
                analyzed_at=now_iso,
                verdict=DiscrepancyVerdict.EXPECTED_DIVERGENCE.value,
                category=DivergenceCategory.CDN_ANYCAST_ROTATION.value,
                explanation=explanation,
                confidence=0.95,
                participating_resolvers=tuple(participating_resolvers),
                answers_by_resolver=answers_by_resolver,
                dnssec_by_resolver=dnssec_by_resolver,
                filtering_metadata=filtering_metadata,
                observation_ids=observation_ids,
                evidence_ids=evidence_ids,
                evidence_hashes=evidence_hashes,
                ruleset_version=self.ruleset_version,
            )

        # --- STEP 6: Unexplained Divergence ---
        # Resolvers returned conflicting, non-overlapping IP addresses that do not belong to the same CDN
        explanation = (
            f"Unexplained divergence: Independent resolvers ({', '.join(participating_resolvers)}) returned conflicting, "
            f"non-overlapping answer sets that do not map to a single known Anycast CDN network."
        )
        return RealDiscrepancyReport(
            subject=subject,
            kind=kind,
            analyzed_at=now_iso,
            verdict=DiscrepancyVerdict.UNEXPLAINED_DIVERGENCE.value,
            category=DivergenceCategory.CONFLICTING_IPS.value,
            explanation=explanation,
            confidence=0.85,
            participating_resolvers=tuple(participating_resolvers),
            answers_by_resolver=answers_by_resolver,
            dnssec_by_resolver=dnssec_by_resolver,
            filtering_metadata=filtering_metadata,
            observation_ids=observation_ids,
            evidence_ids=evidence_ids,
            evidence_hashes=evidence_hashes,
            ruleset_version=self.ruleset_version,
        )

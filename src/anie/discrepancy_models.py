"""Strictly validated real-world multi-resolver discrepancy and consensus models.

Part of ANIE Phase 3.3 Multi-Resolver Intelligence Engine.
Captures empirical evidence and calibrated discrepancy analysis across independent DoH resolvers.

Mandatory Invariants:
- Confidence MUST be calibrated float in [0.0, 1.0].
- Discrepancy verdicts NEVER assert maliciousness or threat verdicts (preserves neutral provenance).
- Deterministic canonical serialization is enforced for analysis_id hashing.
- Every discrepancy report binds underlying observation_ids and evidence_ids.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import re
from typing import Any

from .observations import canonical_json, normalized_domain, utc_iso

DISCREPANCY_REPORT_SCHEMA = "anie.discrepancy-report.real.v1"
REAL_DISCREPANCY_SCHEMA = DISCREPANCY_REPORT_SCHEMA
RULESET_VERSION_V1 = "anie.discrepancy-engine.v1"

_ANALYSIS_ID_RE = re.compile(r"^discrepancy_[0-9a-f]{64}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


class DiscrepancyVerdict(str, Enum):
    """Classification of multi-resolver agreement and divergence."""
    AGREEMENT = "AGREEMENT"                              # All resolvers agree on answers and DNSSEC
    EXPECTED_DIVERGENCE = "EXPECTED_DIVERGENCE"          # Benign divergence (CDN Anycast, TTL drift, CNAME depth)
    SECURITY_FILTERING_DETECTED = "SECURITY_FILTERING_DETECTED"  # Quad9/filtering resolver blocked domain
    DNSSEC_DISAGREEMENT = "DNSSEC_DISAGREEMENT"          # Disagreement on DNSSEC authenticity (AD=1 vs SERVFAIL/AD=0)
    UNEXPLAINED_DIVERGENCE = "UNEXPLAINED_DIVERGENCE"    # Substantive conflict across standard recursive resolvers
    INCONCLUSIVE = "INCONCLUSIVE"                        # Insufficient responses (< 2 resolvers) to determine consensus


class DivergenceCategory(str, Enum):
    """Granular categorization of observed divergence."""
    NONE = "NONE"
    CDN_ANYCAST_ROTATION = "CDN_ANYCAST_ROTATION"
    TTL_DRIFT = "TTL_DRIFT"
    CNAME_ALIAS_CHAIN = "CNAME_ALIAS_CHAIN"
    POLICY_FILTER_BLOCK = "POLICY_FILTER_BLOCK"
    DNSSEC_VALIDATION_FAILURE = "DNSSEC_VALIDATION_FAILURE"
    CONFLICTING_IPS = "CONFLICTING_IPS"
    STATUS_MISMATCH = "STATUS_MISMATCH"
    INCOMPLETE_RESPONSES = "INCOMPLETE_RESPONSES"


DISCREPANCY_VERDICTS = frozenset(v.value for v in DiscrepancyVerdict)
DIVERGENCE_CATEGORIES = frozenset(c.value for c in DivergenceCategory)


@dataclass(frozen=True)
class RealDiscrepancyReport:
    """Deterministic, evidence-backed discrepancy analysis across multi-resolver observations."""
    subject: str
    kind: str
    analyzed_at: str
    verdict: str
    category: str
    explanation: str
    confidence: float
    participating_resolvers: tuple[str, ...]
    answers_by_resolver: dict[str, list[str]]
    dnssec_by_resolver: dict[str, str]
    filtering_metadata: dict[str, Any]
    observation_ids: dict[str, str]
    evidence_ids: dict[str, str]
    evidence_hashes: dict[str, str]
    ruleset_version: str = RULESET_VERSION_V1

    def __post_init__(self):
        # Validate domain & kind
        object.__setattr__(self, "subject", normalized_domain(self.subject))
        if self.kind not in ("dns_a", "dns_aaaa"):
            raise ValueError(f"unsupported query kind for discrepancy report: {self.kind!r}")

        # Validate timestamp
        object.__setattr__(self, "analyzed_at", utc_iso(self.analyzed_at))

        # Validate verdict and category
        if self.verdict not in DISCREPANCY_VERDICTS:
            raise ValueError(f"invalid discrepancy verdict: {self.verdict!r}")
        if self.category not in DIVERGENCE_CATEGORIES:
            raise ValueError(f"invalid divergence category: {self.category!r}")

        # Validate confidence
        if not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a float")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0: got {self.confidence}")

        # Validate resolvers
        if not self.participating_resolvers:
            raise ValueError("participating_resolvers must contain at least one resolver identity")
        for res_id in self.participating_resolvers:
            if not isinstance(res_id, str) or not res_id:
                raise ValueError("resolver identity must be a non-empty string")

        # Validate mappings
        for res_id in self.participating_resolvers:
            if res_id not in self.answers_by_resolver:
                raise ValueError(f"answers_by_resolver missing entry for participating resolver '{res_id}'")
            if res_id not in self.dnssec_by_resolver:
                raise ValueError(f"dnssec_by_resolver missing entry for participating resolver '{res_id}'")
            if res_id not in self.observation_ids:
                raise ValueError(f"observation_ids missing entry for participating resolver '{res_id}'")
            if res_id not in self.evidence_ids:
                raise ValueError(f"evidence_ids missing entry for participating resolver '{res_id}'")
            if res_id not in self.evidence_hashes:
                raise ValueError(f"evidence_hashes missing entry for participating resolver '{res_id}'")
            ehash = self.evidence_hashes[res_id]
            if not _HEX_64_RE.fullmatch(ehash):
                raise ValueError(f"invalid SHA-256 evidence hash for resolver '{res_id}': {ehash!r}")

    @property
    def analysis_id(self) -> str:
        """Deterministic canonical analysis ID derived from canonical JSON hash."""
        canonical = canonical_json(self.to_canonical_dict())
        return "discrepancy_" + sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def discrepancy_id(self) -> str:
        """Alias for analysis_id for backward and naming compatibility."""
        return self.analysis_id

    def to_canonical_dict(self) -> dict[str, Any]:
        """Deterministic canonical serialization for identity hashing."""
        return {
            "answers_by_resolver": {k: sorted(v) for k, v in sorted(self.answers_by_resolver.items())},
            "analyzed_at": self.analyzed_at,
            "category": self.category,
            "confidence": round(float(self.confidence), 4),
            "dnssec_by_resolver": dict(sorted(self.dnssec_by_resolver.items())),
            "evidence_hashes": dict(sorted(self.evidence_hashes.items())),
            "evidence_ids": dict(sorted(self.evidence_ids.items())),
            "explanation": self.explanation,
            "filtering_metadata": dict(sorted(self.filtering_metadata.items())),
            "kind": self.kind,
            "observation_ids": dict(sorted(self.observation_ids.items())),
            "participating_resolvers": sorted(self.participating_resolvers),
            "ruleset_version": self.ruleset_version,
            "schema": DISCREPANCY_REPORT_SCHEMA,
            "subject": self.subject,
            "verdict": self.verdict,
        }

    def to_dict(self) -> dict[str, Any]:
        """Full representation including analysis_id and discrepancy_id."""
        d = self.to_canonical_dict()
        d["analysis_id"] = self.analysis_id
        d["discrepancy_id"] = self.analysis_id
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RealDiscrepancyReport":
        if not isinstance(raw, dict) or raw.get("schema") != DISCREPANCY_REPORT_SCHEMA:
            raise ValueError(f"invalid RealDiscrepancyReport schema: {raw.get('schema')!r}")

        report = cls(
            subject=raw["subject"],
            kind=raw["kind"],
            analyzed_at=raw["analyzed_at"],
            verdict=raw["verdict"],
            category=raw["category"],
            explanation=raw["explanation"],
            confidence=float(raw["confidence"]),
            participating_resolvers=tuple(sorted(raw["participating_resolvers"])),
            answers_by_resolver={k: list(v) for k, v in raw["answers_by_resolver"].items()},
            dnssec_by_resolver=dict(raw["dnssec_by_resolver"]),
            filtering_metadata=dict(raw.get("filtering_metadata", {})),
            observation_ids=dict(raw["observation_ids"]),
            evidence_ids=dict(raw["evidence_ids"]),
            evidence_hashes=dict(raw["evidence_hashes"]),
            ruleset_version=raw.get("ruleset_version", RULESET_VERSION_V1),
        )

        if "analysis_id" in raw and raw["analysis_id"] != report.analysis_id:
            raise ValueError(f"analysis_id integrity mismatch: expected {report.analysis_id}, got {raw['analysis_id']}")

        return report

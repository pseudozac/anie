"""Foundational Graph-Native Intelligence Models for ANIE (Milestone M3.3.1).

Defines stable typed entity identities, temporal relationships, and the 4-layer
epistemic hierarchy:
- FACT: Directly observed empirical wire transport measurements (immutable).
- DERIVED: Deterministic structural relationships computed via versioned rulesets.
- HYPOTHESIS: Probabilistic inferences, anomaly indicators, and clustering models.
- VALIDATED: Analyst-verified assertions or cryptographically attested claims.

Invariants:
- All entities have stable, collision-free URI identifiers (e.g. 'anie:entity:domain:example.com').
- Relationships are bitemporal: 'observed_at' (measurement time) and 'valid_from'/'valid_until' (world validity).
- Derived assertions are deterministically reproducible from underlying Layer 1 facts.
- Resolver discrepancy or structural divergence NEVER implies maliciousness.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Any

from .observations import (
    canonical_json,
    normalized_domain,
    normalized_ip,
    utc_iso,
)

GRAPH_NODE_SCHEMA = "anie.graph-node.real.v1"
GRAPH_EDGE_SCHEMA = "anie.graph-edge.real.v1"
INTELLIGENCE_CLAIM_SCHEMA = "anie.intelligence-claim.real.v1"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class EpistemicLayer(str, Enum):
    """Epistemic classification preserving boundary between facts and inferences."""
    FACT = "FACT"
    DERIVED = "DERIVED"
    HYPOTHESIS = "HYPOTHESIS"
    VALIDATED = "VALIDATED"


class ClaimVerificationState(str, Enum):
    """Explicit verification state distinguishing hypothesis from attested assertions."""
    UNVERIFIED_HYPOTHESIS = "UNVERIFIED_HYPOTHESIS"
    ATTESTED_ASSERTION = "ATTESTED_ASSERTION"
    CONTESTED = "CONTESTED"
    REVOKED = "REVOKED"


class NodeType(str, Enum):
    """Entity node types in the ANIE intelligence graph."""
    DOMAIN = "domain"
    IP = "ip"
    RESOLVER = "resolver"
    ASN = "asn"
    CDN_PREFIX = "cdn_prefix"
    INTELLIGENCE_CLAIM = "claim"


class RelationType(str, Enum):
    """Typed temporal directed relationships."""
    RESOLVES_TO = "RESOLVES_TO"
    ALIASED_TO = "ALIASED_TO"
    ANNOUNCED_BY = "ANNOUNCED_BY"
    PREFIX_MEMBER = "PREFIX_MEMBER"
    QUERIED_VIA = "QUERIED_VIA"
    DISCREPANCY_FOR = "DISCREPANCY_FOR"
    DERIVED_FROM = "DERIVED_FROM"
    SUPPORTS_CLAIM = "SUPPORTS_CLAIM"


def format_node_id(node_type: NodeType | str, canonical_name: str) -> str:
    """Generate a stable, deterministic URI for an entity node."""
    t_val = node_type.value if isinstance(node_type, NodeType) else str(node_type).lower()
    norm_name = canonical_name.strip()
    if t_val == "domain":
        norm_name = normalized_domain(norm_name)
    elif t_val == "ip":
        norm_name = normalized_ip(norm_name)
    elif t_val == "asn":
        norm_name = str(int(norm_name.lower().removeprefix("as")))
    else:
        norm_name = norm_name.lower()
    return f"anie:entity:{t_val}:{norm_name}"


@dataclass(frozen=True)
class GraphNode:
    """Entity node in the ANIE intelligence graph."""
    node_id: str
    node_type: str
    canonical_name: str
    layer: str
    first_observed_at: str
    last_observed_at: str
    properties: dict[str, Any] = field(default_factory=dict)
    tx_time: str = ""
    schema: str = GRAPH_NODE_SCHEMA

    def __post_init__(self):
        if not self.node_id or not self.node_id.startswith("anie:entity:"):
            raise ValueError(f"invalid node_id URI: {self.node_id!r}")
        if self.node_type not in [t.value for t in NodeType]:
            raise ValueError(f"unsupported node_type: {self.node_type!r}")
        if self.layer not in [l.value for l in EpistemicLayer]:
            raise ValueError(f"unsupported layer: {self.layer!r}")
        utc_iso(self.first_observed_at)
        utc_iso(self.last_observed_at)
        if not self.tx_time:
            object.__setattr__(self, "tx_time", self.last_observed_at)
        else:
            utc_iso(self.tx_time)
        if self.schema != GRAPH_NODE_SCHEMA:
            raise ValueError(f"unsupported schema: {self.schema!r}")

    @classmethod
    def create(
        cls,
        node_type: NodeType | str,
        canonical_name: str,
        layer: EpistemicLayer | str,
        observed_at: str,
        properties: dict[str, Any] | None = None,
        tx_time: str | None = None,
    ) -> "GraphNode":
        t_val = node_type.value if isinstance(node_type, NodeType) else str(node_type).lower()
        l_val = layer.value if isinstance(layer, EpistemicLayer) else str(layer).upper()
        nid = format_node_id(t_val, canonical_name)
        obs_iso = utc_iso(observed_at)
        tt_iso = utc_iso(tx_time) if tx_time else obs_iso
        return cls(
            node_id=nid,
            node_type=t_val,
            canonical_name=canonical_name.strip(),
            layer=l_val,
            first_observed_at=obs_iso,
            last_observed_at=obs_iso,
            properties=dict(properties or {}),
            tx_time=tt_iso,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "node_id": self.node_id,
            "node_type": self.node_type,
            "canonical_name": self.canonical_name,
            "layer": self.layer,
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
            "tx_time": self.tx_time,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GraphNode":
        if not isinstance(data, dict):
            raise ValueError("node record must be a dict")
        return cls(
            node_id=data["node_id"],
            node_type=data["node_type"],
            canonical_name=data["canonical_name"],
            layer=data["layer"],
            first_observed_at=data["first_observed_at"],
            last_observed_at=data["last_observed_at"],
            properties=data.get("properties", {}),
            tx_time=data.get("tx_time", data.get("last_observed_at", "")),
            schema=data.get("schema", GRAPH_NODE_SCHEMA),
        )


@dataclass(frozen=True)
class GraphEdge:
    """Directed temporal relationship between entity nodes."""
    source_id: str
    target_id: str
    relation_type: str
    layer: str
    observed_at: str
    valid_from: str
    ruleset_version: str
    valid_until: str | None = None
    confidence: float = 1.0
    evidence_hashes: tuple[str, ...] = field(default_factory=tuple)
    properties: dict[str, Any] = field(default_factory=dict)
    tx_time: str = ""
    edge_id: str = field(init=False)
    schema: str = GRAPH_EDGE_SCHEMA

    def __post_init__(self):
        if not self.source_id.startswith("anie:entity:"):
            raise ValueError(f"invalid source_id: {self.source_id!r}")
        if not self.target_id.startswith("anie:entity:"):
            raise ValueError(f"invalid target_id: {self.target_id!r}")
        if self.relation_type not in [r.value for r in RelationType]:
            raise ValueError(f"unsupported relation_type: {self.relation_type!r}")
        if self.layer not in [l.value for l in EpistemicLayer]:
            raise ValueError(f"unsupported layer: {self.layer!r}")
        utc_iso(self.observed_at)
        utc_iso(self.valid_from)
        if self.valid_until is not None:
            utc_iso(self.valid_until)
        if not self.tx_time:
            object.__setattr__(self, "tx_time", self.observed_at)
        else:
            utc_iso(self.tx_time)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0: {self.confidence}")
        if not self.ruleset_version:
            raise ValueError("ruleset_version must be non-empty")
        for h in self.evidence_hashes:
            if not _HEX_64.fullmatch(h):
                raise ValueError(f"invalid evidence SHA-256 hash: {h!r}")

        # Deterministic canonical edge identifier
        id_material = {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type,
            "layer": self.layer,
            "observed_at": self.observed_at,
            "ruleset_version": self.ruleset_version,
        }
        digest = sha256(canonical_json(id_material).encode("utf-8")).hexdigest()
        object.__setattr__(self, "edge_id", f"edge_{digest}")

    @classmethod
    def create(
        cls,
        source_id: str,
        target_id: str,
        relation_type: RelationType | str,
        layer: EpistemicLayer | str,
        observed_at: str,
        *,
        valid_from: str | None = None,
        valid_until: str | None = None,
        confidence: float = 1.0,
        ruleset_version: str = "anie.graph-rules.v1",
        evidence_hashes: tuple[str, ...] | list[str] = (),
        properties: dict[str, Any] | None = None,
        tx_time: str | None = None,
    ) -> "GraphEdge":
        r_val = relation_type.value if isinstance(relation_type, RelationType) else str(relation_type)
        l_val = layer.value if isinstance(layer, EpistemicLayer) else str(layer).upper()
        obs_iso = utc_iso(observed_at)
        vf_iso = utc_iso(valid_from) if valid_from else obs_iso
        vu_iso = utc_iso(valid_until) if valid_until else None
        tt_iso = utc_iso(tx_time) if tx_time else obs_iso
        return cls(
            source_id=source_id,
            target_id=target_id,
            relation_type=r_val,
            layer=l_val,
            observed_at=obs_iso,
            valid_from=vf_iso,
            valid_until=vu_iso,
            confidence=float(confidence),
            ruleset_version=ruleset_version,
            evidence_hashes=tuple(sorted(evidence_hashes)),
            properties=dict(properties or {}),
            tx_time=tt_iso,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type,
            "layer": self.layer,
            "observed_at": self.observed_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "tx_time": self.tx_time,
            "confidence": self.confidence,
            "ruleset_version": self.ruleset_version,
            "evidence_hashes": list(self.evidence_hashes),
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GraphEdge":
        if not isinstance(data, dict):
            raise ValueError("edge record must be a dict")
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relation_type=data["relation_type"],
            layer=data["layer"],
            observed_at=data["observed_at"],
            valid_from=data["valid_from"],
            ruleset_version=data.get("ruleset_version", "anie.graph-rules.v1"),
            valid_until=data.get("valid_until"),
            confidence=float(data.get("confidence", 1.0)),
            evidence_hashes=tuple(data.get("evidence_hashes", ())),
            properties=data.get("properties", {}),
            tx_time=data.get("tx_time", data.get("observed_at", "")),
            schema=data.get("schema", GRAPH_EDGE_SCHEMA),
        )


@dataclass(frozen=True)
class IntelligenceClaim:
    """Attributable, explainable derived hypothesis or analyst-validated assertion.
    
    Guarantees:
    - Cryptographic binding to underlying Layer 1 evidence hashes.
    - Explicit epistemic layer (HYPOTHESIS vs VALIDATED).
    - Reproducible regeneration version and parameters.
    - Calibrated confidence and human-readable explanation.
    """
    subject_uri: str
    claim_type: str
    layer: str
    asserted_at: str
    valid_from: str
    ruleset_version: str
    explanation: str
    confidence: float
    supporting_evidence_hashes: tuple[str, ...]
    supporting_node_ids: tuple[str, ...]
    valid_until: str | None = None
    analyst_identity: str | None = None
    attestation_signature: str | None = None
    verification_state: str = ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value
    falsifiability_condition: str | None = None
    claim_id: str = field(init=False)
    schema: str = INTELLIGENCE_CLAIM_SCHEMA

    def __post_init__(self):
        if not self.subject_uri.startswith("anie:entity:"):
            raise ValueError(f"invalid subject_uri: {self.subject_uri!r}")
        if self.layer not in (EpistemicLayer.HYPOTHESIS.value, EpistemicLayer.VALIDATED.value):
            raise ValueError(f"claims must belong to HYPOTHESIS or VALIDATED layer, got {self.layer!r}")
        if self.verification_state not in [s.value for s in ClaimVerificationState]:
            raise ValueError(f"unsupported verification_state: {self.verification_state!r}")
        utc_iso(self.asserted_at)
        utc_iso(self.valid_from)
        if self.valid_until is not None:
            utc_iso(self.valid_until)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0: {self.confidence}")
        if not self.explanation.strip():
            raise ValueError("explanation must be non-empty")
        if not self.supporting_evidence_hashes:
            raise ValueError("claims require at least one supporting Layer 1 evidence hash")

        id_material = {
            "subject_uri": self.subject_uri,
            "claim_type": self.claim_type,
            "layer": self.layer,
            "asserted_at": self.asserted_at,
            "ruleset_version": self.ruleset_version,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "supporting_evidence_hashes": sorted(self.supporting_evidence_hashes),
        }
        digest = sha256(canonical_json(id_material).encode("utf-8")).hexdigest()
        object.__setattr__(self, "claim_id", f"claim_{digest}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "subject_uri": self.subject_uri,
            "claim_type": self.claim_type,
            "layer": self.layer,
            "asserted_at": self.asserted_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "ruleset_version": self.ruleset_version,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "supporting_evidence_hashes": list(self.supporting_evidence_hashes),
            "supporting_node_ids": list(self.supporting_node_ids),
            "analyst_identity": self.analyst_identity,
            "attestation_signature": self.attestation_signature,
            "verification_state": self.verification_state,
            "falsifiability_condition": self.falsifiability_condition,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntelligenceClaim":
        if not isinstance(data, dict):
            raise ValueError("claim record must be a dict")
        v_state = data.get(
            "verification_state",
            ClaimVerificationState.ATTESTED_ASSERTION.value
            if data.get("attestation_signature")
            else ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
        )
        return cls(
            subject_uri=data["subject_uri"],
            claim_type=data["claim_type"],
            layer=data["layer"],
            asserted_at=data["asserted_at"],
            valid_from=data["valid_from"],
            ruleset_version=data["ruleset_version"],
            explanation=data["explanation"],
            confidence=float(data["confidence"]),
            supporting_evidence_hashes=tuple(data["supporting_evidence_hashes"]),
            supporting_node_ids=tuple(data.get("supporting_node_ids", ())),
            valid_until=data.get("valid_until"),
            analyst_identity=data.get("analyst_identity"),
            attestation_signature=data.get("attestation_signature"),
            verification_state=v_state,
            falsifiability_condition=data.get("falsifiability_condition"),
            schema=data.get("schema", INTELLIGENCE_CLAIM_SCHEMA),
        )

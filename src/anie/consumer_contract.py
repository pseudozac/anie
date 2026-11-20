"""Production-Grade Intelligence Consumer Contract for AEGIS and Third-Party Systems.

Provides a stable, versioned, independently verifiable output interface:
- Canonical IOC and infrastructure entity identifiers
- Immutable source observations and provenance
- Derived relationships and historical changes
- Hypotheses with explicit uncertainty and confidence disclaimers
- Bounded queries and deterministic cursor-based pagination
- Standardized Canonical IOC Threat Intelligence Feed

Zero AEGIS Internal Dependency:
Operates directly against ANIE SQLite stores or deserialized release bundles.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .canonical_entities import (
    build_entity_uri,
    canonicalize_domain,
    infer_entity_type,
    parse_entity_uri,
)
from .graph_models import ClaimVerificationState, IntelligenceClaim
from .real_store import RealObservationStore

CONSUMER_CONTRACT_VERSION = "anie.consumer-contract.v1"
IOC_FEED_SCHEMA = "anie.canonical-ioc-feed.v1"
PROVENANCE_BUNDLE_SCHEMA = "anie.entity-provenance-bundle.v1"

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500


def encode_cursor(
    order_key: Any = None,
    id_val: Any = None,
    *,
    offset: Any = None,
    sort_key: Any = None,
) -> str:
    """Encode deterministic pagination cursor as Base64 JSON."""
    if offset is not None and order_key is None:
        order_key = offset
    if sort_key is not None and id_val is None:
        id_val = sort_key
    payload = json.dumps({"k": str(order_key), "id": str(id_val)}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def decode_cursor(cursor_str: str | None) -> Tuple[Any, Any]:
    """Decode cursor into (order_key, id_val)."""
    if cursor_str is None:
        return (0, None)
    try:
        raw = base64.urlsafe_b64decode(str(cursor_str).encode("ascii")).decode("utf-8")
        data = json.loads(raw)
        k = data.get("k")
        if isinstance(k, str) and k.isdigit():
            k = int(k)
        return k, data.get("id")
    except Exception:
        return (0, None)


@dataclass(frozen=True)
class PaginatedResult:
    items: list[dict[str, Any]]
    next_cursor: str | None
    has_more: bool
    limit: int
    contract_version: str = CONSUMER_CONTRACT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


@dataclass(frozen=True)
class EntityProvenanceBundle:
    schema: str
    entity_uri: str
    entity: dict[str, Any]
    claims: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    supporting_observations: list[dict[str, Any]]
    forensic_events: list[dict[str, Any]]
    generated_at: str

    @property
    def observations(self) -> list[dict[str, Any]]:
        return self.supporting_observations

    @property
    def raw_evidence_events(self) -> list[dict[str, Any]]:
        return self.forensic_events

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


@dataclass(frozen=True)
class CanonicalIocFeed:
    schema: str
    generated_at: str
    as_of: str
    total_indicators: int
    indicators: list[dict[str, Any]]
    feed_schema: str = IOC_FEED_SCHEMA
    publisher: str = "anie-first-party"
    license: str = "Apache-2.0"
    notice: str = (
        "First-party empirical threat intelligence observations and unverified hypotheses. "
        "Heuristic confidence scores are uncalibrated and require independent verification."
    )

    @property
    def disclaimer(self) -> str:
        return self.notice

    @property
    def accuracy_vs_confidence_note(self) -> str:
        return (
            "Empirical detector accuracy is tested against controlled ground-truth datasets. "
            "Heuristic confidence scores are rule-based indicators and not Bayesian probabilities."
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


class AnieIntelligenceClient:
    """Production-grade, read-only consumer client for ANIE intelligence."""

    def __init__(self, store: RealObservationStore):
        self.store = store

    @classmethod
    def from_database_path(cls, db_path: str | Path) -> AnieIntelligenceClient:
        """Instantiate client directly from SQLite database path."""
        store = RealObservationStore(db_path)
        return cls(store)

    def query_entities(
        self,
        *,
        entity_type: str | None = None,
        search_term: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> PaginatedResult:
        """Query knowledge graph entity nodes with deterministic cursor pagination."""
        bounded_limit = max(1, min(limit, MAX_PAGE_SIZE))
        
        cursor_name = None
        cursor_id = None
        if cursor is not None:
            cursor_name, cursor_id = decode_cursor(cursor)

        query_sql = ["SELECT node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json, payload FROM graph_nodes WHERE 1=1"]
        params: list[Any] = []

        if entity_type is not None:
            query_sql.append("AND node_type = ?")
            params.append(entity_type)

        if search_term is not None and search_term.strip():
            query_sql.append("AND canonical_name LIKE ?")
            params.append(f"%{search_term.strip().lower()}%")

        if cursor_name is not None and cursor_id is not None:
            query_sql.append("AND (canonical_name, node_id) > (?, ?)")
            params.extend([cursor_name, cursor_id])

        query_sql.append("ORDER BY canonical_name ASC, node_id ASC LIMIT ?")
        params.append(bounded_limit + 1)

        with self.store._connect() as conn:
            rows = conn.execute(" ".join(query_sql), params).fetchall()

        has_more = len(rows) > bounded_limit
        result_rows = rows[:bounded_limit]

        items = []
        for r in result_rows:
            props = json.loads(r[6]) if r[6] else {}
            try:
                etype, cval = parse_entity_uri(r[0])
                canon_uri = f"{etype}:{cval}"
            except Exception:
                canon_uri = r[0]
            items.append({
                "node_id": r[0],
                "entity_uri": canon_uri,
                "uri": canon_uri,
                "entity_type": r[1],
                "canonical_name": r[2],
                "layer": r[3],
                "first_observed_at": r[4],
                "last_observed_at": r[5],
                "properties": props,
            })

        next_cursor = None
        if has_more and result_rows:
            last = result_rows[-1]
            next_cursor = encode_cursor(last[2], last[0])

        return PaginatedResult(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
            limit=bounded_limit,
        )

    def query_claims(
        self,
        *,
        subject_uri: str | None = None,
        entity_uri: str | None = None,
        claim_type: str | None = None,
        layer: str | None = None,
        verification_state: str | None = None,
        min_confidence: float = 0.0,
        as_of: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> PaginatedResult:
        """Query intelligence claims with historical as_of and cursor pagination."""
        if entity_uri is not None and subject_uri is None:
            subject_uri = entity_uri

        bounded_limit = max(1, min(limit, MAX_PAGE_SIZE))

        cursor_time = None
        cursor_id = None
        if cursor is not None:
            cursor_time, cursor_id = decode_cursor(cursor)

        query_sql = ["""
            SELECT claim_id, subject_uri, claim_type, layer, asserted_at, valid_from, valid_until,
                   ruleset_version, confidence, explanation, supporting_evidence_hashes_json,
                   supporting_node_ids_json, analyst_identity, attestation_signature, payload
            FROM intelligence_claims
            WHERE confidence >= ?
        """]
        params: list[Any] = [float(min_confidence)]

        if subject_uri is not None:
            # Canonicalize search subject URI
            _, cval = parse_entity_uri(subject_uri)
            query_sql.append("AND (subject_uri = ? OR subject_uri LIKE ?)")
            params.extend([subject_uri, f"%{cval}%"])

        if claim_type is not None:
            query_sql.append("AND claim_type = ?")
            params.append(claim_type)

        if layer is not None:
            query_sql.append("AND layer = ?")
            params.append(layer)

        if as_of is not None:
            query_sql.append("AND asserted_at <= ?")
            params.append(as_of)

        if cursor_time is not None and cursor_id is not None:
            # Descending order pagination
            query_sql.append("AND (asserted_at, claim_id) < (?, ?)")
            params.extend([cursor_time, cursor_id])

        query_sql.append("ORDER BY asserted_at DESC, claim_id DESC LIMIT ?")
        params.append(bounded_limit + 1)

        with self.store._connect() as conn:
            rows = conn.execute(" ".join(query_sql), params).fetchall()

        has_more = len(rows) > bounded_limit
        result_rows = rows[:bounded_limit]

        items = []
        for r in result_rows:
            payload = json.loads(r[14]) if r[14] else {}
            vstate = payload.get("verification_state", ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value)
            
            if verification_state is not None and vstate != verification_state:
                continue

            try:
                setype, scval = parse_entity_uri(r[1])
                subj_canon = f"{setype}:{scval}"
            except Exception:
                subj_canon = r[1]

            items.append({
                "claim_id": r[0],
                "subject_uri": subj_canon,
                "claim_type": r[2],
                "layer": r[3],
                "asserted_at": r[4],
                "valid_from": r[5],
                "valid_until": r[6],
                "ruleset_version": r[7],
                "confidence": r[8],
                "confidence_type": payload.get("properties", {}).get("confidence_type", "heuristic_uncalibrated"),
                "confidence_disclaimer": payload.get("properties", {}).get(
                    "confidence_disclaimer",
                    "Heuristic confidence score is not a calibrated statistical probability."
                ),
                "verification_state": vstate,
                "explanation": r[9],
                "supporting_evidence_hashes": json.loads(r[10]) if r[10] else [],
                "supporting_node_ids": json.loads(r[11]) if r[11] else [],
                "analyst_identity": r[12],
                "attestation_signature": r[13],
            })

        next_cursor = None
        if has_more and result_rows:
            last = result_rows[-1]
            next_cursor = encode_cursor(last[4], last[0])

        return PaginatedResult(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
            limit=bounded_limit,
        )

    def query_relationships(
        self,
        entity_uri: str | None = None,
        *,
        source_uri: str | None = None,
        target_uri: str | None = None,
        direction: str = "BOTH",
        relation_type: str | None = None,
        as_of: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> PaginatedResult:
        """Query knowledge graph relationship edges."""
        bounded_limit = max(1, min(limit, MAX_PAGE_SIZE))

        cursor_time = None
        cursor_id = None
        if cursor is not None:
            cursor_time, cursor_id = decode_cursor(cursor)

        query_sql = ["""
            SELECT edge_id, source_id, target_id, relation_type, layer, observed_at,
                   valid_from, valid_until, confidence, ruleset_version, evidence_hashes_json,
                   properties_json
            FROM graph_edges
            WHERE 1=1
        """]
        params: list[Any] = []

        if entity_uri is not None:
            etype, cval = parse_entity_uri(entity_uri)
            canon_uri = f"{etype}:{cval}"
            legacy_node = f"anie:entity:{etype}:{cval}"
            dir_norm = direction.strip().upper()
            if dir_norm == "OUTGOING":
                query_sql.append("AND (source_id = ? OR source_id = ? OR source_id = ?)")
                params.extend([canon_uri, legacy_node, cval])
            elif dir_norm == "INCOMING":
                query_sql.append("AND (target_id = ? OR target_id = ? OR target_id = ?)")
                params.extend([canon_uri, legacy_node, cval])
            else:
                query_sql.append("AND (source_id = ? OR source_id = ? OR source_id = ? OR target_id = ? OR target_id = ? OR target_id = ?)")
                params.extend([canon_uri, legacy_node, cval, canon_uri, legacy_node, cval])

        if source_uri is not None:
            query_sql.append("AND source_id = ?")
            params.append(source_uri)

        if target_uri is not None:
            query_sql.append("AND target_id = ?")
            params.append(target_uri)

        if relation_type is not None:
            query_sql.append("AND relation_type = ?")
            params.append(relation_type)

        if as_of is not None:
            query_sql.append("AND observed_at <= ?")
            params.append(as_of)

        if cursor_time is not None and cursor_id is not None:
            query_sql.append("AND (observed_at, edge_id) > (?, ?)")
            params.extend([cursor_time, cursor_id])

        query_sql.append("ORDER BY observed_at ASC, edge_id ASC LIMIT ?")
        params.append(bounded_limit + 1)

        with self.store._connect() as conn:
            rows = conn.execute(" ".join(query_sql), params).fetchall()

        has_more = len(rows) > bounded_limit
        result_rows = rows[:bounded_limit]

        items = []
        for r in result_rows:
            try:
                stype, sval = parse_entity_uri(r[1])
                src_canon = f"{stype}:{sval}"
            except Exception:
                src_canon = r[1]

            try:
                ttype, tval = parse_entity_uri(r[2])
                tgt_canon = f"{ttype}:{tval}"
            except Exception:
                tgt_canon = r[2]

            items.append({
                "edge_id": r[0],
                "source_uri": src_canon,
                "target_uri": tgt_canon,
                "relation_type": r[3],
                "layer": r[4],
                "observed_at": r[5],
                "valid_from": r[6],
                "valid_until": r[7],
                "confidence": r[8],
                "ruleset_version": r[9],
                "evidence_hashes": json.loads(r[10]) if r[10] else [],
                "properties": json.loads(r[11]) if r[11] else {},
            })

        next_cursor = None
        if has_more and result_rows:
            last = result_rows[-1]
            next_cursor = encode_cursor(last[5], last[0])

        return PaginatedResult(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
            limit=bounded_limit,
        )

    def get_entity_provenance(self, entity_uri: str) -> EntityProvenanceBundle:
        """Retrieve full forensic evidence bundle for a canonical entity."""
        etype, cval = parse_entity_uri(entity_uri)
        canon_uri = f"{etype}:{cval}"
        legacy_node = f"anie:entity:{etype}:{cval}"

        with self.store._connect() as conn:
            # 1. Node metadata
            node_row = conn.execute(
                "SELECT node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json FROM graph_nodes WHERE node_id IN (?, ?, ?)",
                (canon_uri, legacy_node, cval),
            ).fetchone()

            node_dict = {}
            if node_row:
                node_dict = {
                    "node_id": node_row[0],
                    "node_type": node_row[1],
                    "canonical_name": node_row[2],
                    "layer": node_row[3],
                    "first_observed_at": node_row[4],
                    "last_observed_at": node_row[5],
                    "properties": json.loads(node_row[6]) if node_row[6] else {},
                }

            # 2. Associated Claims
            claim_rows = conn.execute(
                "SELECT claim_id, subject_uri, claim_type, asserted_at, confidence, explanation, supporting_evidence_hashes_json, payload FROM intelligence_claims WHERE subject_uri IN (?, ?, ?) OR subject_uri LIKE ?",
                (canon_uri, legacy_node, cval, f"%{cval}%"),
            ).fetchall()

            claims = []
            evidence_hashes = set()
            for cr in claim_rows:
                c_hashes = json.loads(cr[6]) if cr[6] else []
                evidence_hashes.update(c_hashes)
                payload = json.loads(cr[7]) if cr[7] else {}
                claims.append({
                    "claim_id": cr[0],
                    "subject_uri": cr[1],
                    "claim_type": cr[2],
                    "asserted_at": cr[3],
                    "confidence": cr[4],
                    "verification_state": payload.get("verification_state", ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value),
                    "explanation": cr[5],
                    "supporting_evidence_hashes": c_hashes,
                })

            # 3. Direct Relationships (Incoming & Outgoing)
            edge_rows = conn.execute(
                "SELECT edge_id, source_id, target_id, relation_type, observed_at, confidence, evidence_hashes_json FROM graph_edges WHERE source_id IN (?, ?, ?) OR target_id IN (?, ?, ?)",
                (canon_uri, legacy_node, cval, canon_uri, legacy_node, cval),
            ).fetchall()

            relationships = []
            for er in edge_rows:
                e_hashes = json.loads(er[6]) if er[6] else []
                evidence_hashes.update(e_hashes)
                relationships.append({
                    "edge_id": er[0],
                    "source_uri": er[1],
                    "target_uri": er[2],
                    "relation_type": er[3],
                    "observed_at": er[4],
                    "confidence": er[5],
                    "evidence_hashes": e_hashes,
                })

            # 4. Underlying Observations
            obs_rows = conn.execute(
                "SELECT observation_id, evidence_id, subject, kind, observed_at, status, source_id, payload FROM real_observations WHERE subject = ? OR subject LIKE ?",
                (cval, f"%{cval}%"),
            ).fetchall()

            obs_list = []
            event_ids = set()
            for orow in obs_rows:
                event_ids.add(orow[1])
                obs_list.append({
                    "observation_id": orow[0],
                    "evidence_id": orow[1],
                    "subject": orow[2],
                    "kind": orow[3],
                    "observed_at": orow[4],
                    "status": orow[5],
                    "source_id": orow[6],
                    "payload": json.loads(orow[7]) if orow[7] else {},
                })

            # 5. Raw Forensic Events
            events_list = []
            if event_ids:
                placeholders = ",".join("?" for _ in event_ids)
                event_rows = conn.execute(
                    f"SELECT event_id, subject, kind, observed_at, response_code, raw_sha256, payload FROM real_events WHERE event_id IN ({placeholders})",
                    list(event_ids),
                ).fetchall()

                for er in event_rows:
                    events_list.append({
                        "event_id": er[0],
                        "subject": er[1],
                        "kind": er[2],
                        "observed_at": er[3],
                        "response_code": er[4],
                        "raw_sha256": er[5],
                        "payload": json.loads(er[6]) if er[6] else {},
                    })

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return EntityProvenanceBundle(
            schema=PROVENANCE_BUNDLE_SCHEMA,
            entity_uri=entity_uri,
            entity=node_dict,
            claims=claims,
            relationships=relationships,
            supporting_observations=obs_list,
            forensic_events=events_list,
            generated_at=now_iso,
        )

    def export_canonical_ioc_feed(
        self,
        *,
        as_of: str | None = None,
        min_confidence: float = 0.0,
        layer: str | None = None,
    ) -> CanonicalIocFeed:
        """Export standardized Canonical Threat Intelligence IOC Feed."""
        res = self.query_claims(
            min_confidence=min_confidence,
            layer=layer,
            as_of=as_of,
            limit=MAX_PAGE_SIZE,
        )

        indicators = []
        for claim in res.items:
            etype = parse_entity_uri(claim["subject_uri"])[0]
            indicators.append({
                "indicator_id": f"ioc:{claim['claim_id']}",
                "indicator_uri": claim["subject_uri"],
                "entity_uri": claim["subject_uri"],
                "ioc_type": etype,
                "entity_type": etype,
                "claim_type": claim["claim_type"],
                "epistemic_status": claim["verification_state"],
                "confidence": claim["confidence"],
                "confidence_type": claim["confidence_type"],
                "confidence_disclaimer": claim["confidence_disclaimer"],
                "ruleset_version": claim["ruleset_version"],
                "explanation": claim["explanation"],
                "asserted_at": claim["asserted_at"],
                "supporting_evidence_hashes": claim["supporting_evidence_hashes"],
            })

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        feed_as_of = as_of or now_iso

        return CanonicalIocFeed(
            schema=IOC_FEED_SCHEMA,
            generated_at=now_iso,
            as_of=feed_as_of,
            total_indicators=len(indicators),
            indicators=indicators,
        )

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

CONSUMER_CONTRACT_VERSION_V1 = "anie.consumer-contract.v1"
CONSUMER_CONTRACT_VERSION_V2 = "anie.consumer-contract.v2"
CONSUMER_CONTRACT_VERSION = CONSUMER_CONTRACT_VERSION_V1

IOC_FEED_SCHEMA = "anie.canonical-ioc-feed.v1"
IOC_FEED_SCHEMA_V2 = "anie.canonical-ioc-feed.v2"
PROVENANCE_BUNDLE_SCHEMA = "anie.entity-provenance-bundle.v1"
CROSS_VECTOR_FINDING_SCHEMA = "anie.cross-vector-finding.v2"
FINDINGS_FEED_SCHEMA_V2 = "anie.cross-vector-finding-feed.v2"

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
    contract_version: str = CONSUMER_CONTRACT_VERSION_V1
    publisher: str = "anie-first-party"
    license: str = "Apache-2.0"
    next_cursor: str | None = None
    has_more: bool = False
    limit: int | None = None
    notice: str = (
        "First-party empirical threat intelligence observations and unverified hypotheses. "
        "Heuristic confidence scores are uncalibrated and require independent verification. "
        "Indicators represent infrastructure observations and anomaly hypotheses, not confirmed maliciousness."
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


@dataclass(frozen=True)
class NormalizedFindingsFeed:
    """Standardized AEGIS Consumer Contract V2 feed for cross-vector intelligence findings."""
    schema: str
    generated_at: str
    as_of: str
    total_findings: int
    findings: list[dict[str, Any]]
    contract_version: str = CONSUMER_CONTRACT_VERSION_V2
    publisher: str = "anie-first-party"
    license: str = "Apache-2.0"
    next_cursor: str | None = None
    has_more: bool = False
    limit: int | None = None
    notice: str = (
        "First-party empirical cross-vector intelligence findings and competing hypotheses. "
        "Heuristic confidence scores are uncalibrated rule-based metrics, NOT calibrated "
        "Bayesian probabilities. Empirical novelty and infrastructure drift do not constitute "
        "proof of maliciousness or compromise."
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
            # Canonicalize search subject URI and match exact candidates
            etype, cval = parse_entity_uri(subject_uri)
            candidates = [subject_uri, f"{etype}:{cval}", f"anie:entity:{etype}:{cval}", cval]
            if etype in ("ipv4", "ipv6"):
                candidates.extend([f"ip:{cval}", f"anie:entity:ip:{cval}"])
            elif etype == "domain":
                candidates.extend([f"domain:{cval}", f"anie:entity:domain:{cval}"])
            # Deduplicate preserving order
            seen_c = set()
            cand_list = [c for c in candidates if not (c in seen_c or seen_c.add(c))]
            placeholders = ",".join("?" for _ in cand_list)
            query_sql.append(f"AND subject_uri IN ({placeholders})")
            params.extend(cand_list)

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
        """Retrieve full forensic evidence bundle for a canonical entity using strict provenance isolation."""
        etype, cval = parse_entity_uri(entity_uri)
        canon_uri = f"{etype}:{cval}"
        legacy_node = f"anie:entity:{etype}:{cval}"

        # Construct strict candidate set for exact node / claim matching (NO substring LIKE matches)
        exact_node_candidates = [canon_uri, legacy_node, cval]
        if etype in ("ipv4", "ipv6"):
            exact_node_candidates.extend([f"ip:{cval}", f"anie:entity:ip:{cval}"])
        elif etype == "domain":
            exact_node_candidates.extend([f"domain:{cval}", f"anie:entity:domain:{cval}"])

        # Deduplicate preserving order
        seen_cand = set()
        cand_list = [c for c in exact_node_candidates if not (c in seen_cand or seen_cand.add(c))]

        with self.store._connect() as conn:
            # 1. Node metadata (Exact matching)
            placeholders_nodes = ",".join("?" for _ in cand_list)
            node_row = conn.execute(
                f"""
                SELECT node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json
                FROM graph_nodes
                WHERE node_id IN ({placeholders_nodes}) OR canonical_name = ?
                """,
                cand_list + [cval],
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

            # 2. Associated Claims (Exact canonical subject match only)
            claim_rows = conn.execute(
                f"""
                SELECT claim_id, subject_uri, claim_type, asserted_at, confidence, explanation,
                       supporting_evidence_hashes_json, payload
                FROM intelligence_claims
                WHERE subject_uri IN ({placeholders_nodes})
                """,
                cand_list,
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

            # 3. Direct Relationships (Incoming & Outgoing - Exact endpoint match)
            edge_rows = conn.execute(
                f"""
                SELECT edge_id, source_id, target_id, relation_type, observed_at, confidence, evidence_hashes_json
                FROM graph_edges
                WHERE source_id IN ({placeholders_nodes}) OR target_id IN ({placeholders_nodes})
                """,
                cand_list + cand_list,
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

            # 4. Underlying Observations (Strict Provenance Isolation: NO substring LIKE)
            obs_dict: dict[str, Any] = {}
            # Match observations where subject exactly equals cval or cval with trailing dot
            exact_subj_rows = conn.execute(
                """
                SELECT observation_id, evidence_id, subject, kind, observed_at, status, source_id, payload
                FROM real_observations
                WHERE subject = ? OR subject = ?
                """,
                (cval, f"{cval}."),
            ).fetchall()
            for orow in exact_subj_rows:
                obs_dict[orow[0]] = orow

            # If evidence hashes exist (from incoming edges or claims for this entity), pull linked observations
            if evidence_hashes:
                hash_list = list(evidence_hashes)
                for i in range(0, len(hash_list), 500):
                    chunk = hash_list[i : i + 500]
                    placeholders_chunk = ",".join("?" for _ in chunk)
                    linked_rows = conn.execute(
                        f"""
                        SELECT o.observation_id, o.evidence_id, o.subject, o.kind, o.observed_at, o.status, o.source_id, o.payload
                        FROM real_observations o
                        JOIN real_events e ON o.evidence_id = e.event_id
                        WHERE e.raw_sha256 IN ({placeholders_chunk})
                        """,
                        chunk,
                    ).fetchall()
                    for lrow in linked_rows:
                        # For IP entities, verify that the observation payload actually contains this IP in values
                        if etype in ("ipv4", "ipv6"):
                            payload_data = json.loads(lrow[7]) if lrow[7] else {}
                            vals = [str(v).strip().lower() for v in payload_data.get("values", [])]
                            if cval.lower() in vals:
                                obs_dict[lrow[0]] = lrow
                        else:
                            # For domain or other entities, verify exact subject match
                            if lrow[2].strip().lower().rstrip(".") == cval.strip().lower():
                                obs_dict[lrow[0]] = lrow

            obs_list = []
            event_ids = set()
            for orow in obs_dict.values():
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
                event_id_list = list(event_ids)
                for i in range(0, len(event_id_list), 500):
                    chunk = event_id_list[i : i + 500]
                    placeholders_ev = ",".join("?" for _ in chunk)
                    event_rows = conn.execute(
                        f"SELECT event_id, subject, kind, observed_at, response_code, raw_sha256, payload FROM real_events WHERE event_id IN ({placeholders_ev})",
                        chunk,
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
        cursor: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        fetch_all: bool = False,
        publisher_id: str | None = None,
    ) -> CanonicalIocFeed:
        """Export standardized Canonical Threat Intelligence IOC Feed with bounded pagination."""
        bounded_limit = max(1, min(limit, MAX_PAGE_SIZE))
        pub = publisher_id or "anie-first-party"
        all_indicators: list[dict[str, Any]] = []
        curr_cursor = cursor
        has_more_feed = False
        next_cursor_feed = None

        while True:
            fetch_limit = MAX_PAGE_SIZE if fetch_all else bounded_limit
            res = self.query_claims(
                min_confidence=min_confidence,
                layer=layer,
                as_of=as_of,
                cursor=curr_cursor,
                limit=fetch_limit,
            )

            for claim in res.items:
                etype = parse_entity_uri(claim["subject_uri"])[0]
                vstate = claim["verification_state"]
                if vstate == ClaimVerificationState.ATTESTED_ASSERTION.value:
                    indicator_category = "validated_threat_indicator"
                elif vstate in (ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value, "HYPOTHESIS"):
                    indicator_category = "infrastructure_observation"
                else:
                    indicator_category = "contested_or_revoked_observation"

                all_indicators.append({
                    "indicator_id": f"ioc:{claim['claim_id']}",
                    "indicator_uri": claim["subject_uri"],
                    "entity_uri": claim["subject_uri"],
                    "ioc_type": etype,
                    "entity_type": etype,
                    "indicator_category": indicator_category,
                    "maliciousness_inferred": False,
                    "claim_type": claim["claim_type"],
                    "epistemic_status": vstate,
                    "confidence": claim["confidence"],
                    "confidence_type": claim["confidence_type"],
                    "confidence_disclaimer": claim["confidence_disclaimer"],
                    "ruleset_version": claim["ruleset_version"],
                    "explanation": claim["explanation"],
                    "asserted_at": claim["asserted_at"],
                    "supporting_evidence_hashes": claim["supporting_evidence_hashes"],
                })

            if not fetch_all:
                has_more_feed = res.has_more
                next_cursor_feed = res.next_cursor
                break
            else:
                if not res.has_more or not res.next_cursor:
                    break
                curr_cursor = res.next_cursor

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        feed_as_of = as_of or now_iso

        return CanonicalIocFeed(
            schema=IOC_FEED_SCHEMA,
            generated_at=now_iso,
            as_of=feed_as_of,
            total_indicators=len(all_indicators),
            indicators=all_indicators,
            publisher=pub,
            next_cursor=next_cursor_feed,
            has_more=has_more_feed,
            limit=bounded_limit if not fetch_all else None,
        )

    def query_cross_vector_findings(
        self,
        *,
        subject_uri: str | None = None,
        finding_type: str | None = None,
        state: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> PaginatedResult:
        """Query normalized cross-vector findings with cursor pagination (Contract V2)."""
        bounded_limit = max(1, min(limit, MAX_PAGE_SIZE))
        cursor_time = None
        cursor_id = None
        if cursor is not None:
            cursor_time, cursor_id = decode_cursor(cursor)

        query_sql = [
            "SELECT finding_id, subject_uri, finding_type, epistemic_layer, asserted_at, valid_from, valid_until, state, supersedes_finding_id, payload FROM cross_vector_findings WHERE 1=1"
        ]
        params: list[Any] = []

        if subject_uri is not None:
            etype, cval = parse_entity_uri(subject_uri)
            cand_uris = [subject_uri, f"{etype}:{cval}", f"anie:entity:{etype}:{cval}", cval]
            # Deduplicate preserving order
            seen_cand = set()
            cand_list = [c for c in cand_uris if not (c in seen_cand or seen_cand.add(c))]
            placeholders = ",".join("?" for _ in cand_list)
            query_sql.append(f"AND subject_uri IN ({placeholders})")
            params.extend(cand_list)

        if finding_type is not None:
            query_sql.append("AND finding_type = ?")
            params.append(finding_type)

        if state is not None:
            query_sql.append("AND state = ?")
            params.append(state)

        if cursor_time is not None and cursor_id is not None:
            query_sql.append("AND (asserted_at, finding_id) < (?, ?)")
            params.extend([cursor_time, cursor_id])

        query_sql.append("ORDER BY asserted_at DESC, finding_id DESC LIMIT ?")
        params.append(bounded_limit + 1)

        with self.store._connect() as conn:
            rows = conn.execute(" ".join(query_sql), params).fetchall()

        has_more = len(rows) > bounded_limit
        result_rows = rows[:bounded_limit]

        items = []
        for r in result_rows:
            p_data = json.loads(r[9]) if r[9] else {}
            items.append(p_data)

        next_cursor = None
        if has_more and result_rows:
            last = result_rows[-1]
            next_cursor = encode_cursor(last[4], last[0])

        return PaginatedResult(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
            limit=bounded_limit,
            contract_version=CONSUMER_CONTRACT_VERSION_V2,
        )

    def get_cross_vector_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Fetch single cross-vector finding by ID."""
        if hasattr(self.store, "get_cross_vector_finding"):
            return self.store.get_cross_vector_finding(finding_id)
        return None

    def verify_evidence_authoritativeness(self, evidence_reference: str) -> dict[str, Any]:
        """Verify whether an evidence reference or hash resolves to an authoritative record."""
        if hasattr(self.store, "verify_evidence_authoritativeness"):
            return self.store.verify_evidence_authoritativeness(evidence_reference)
        return {
            "is_authoritative": False,
            "status": "UNVERIFIED_EVIDENCE_REFERENCE",
            "reason": "store does not support authoritative evidence verification",
        }

    def export_normalized_findings_feed(
        self,
        findings: list[dict[str, Any]] | None = None,
        *,
        as_of: str | None = None,
        subject_uri: str | None = None,
        finding_type: str | None = None,
        state: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
        fetch_all: bool = False,
        publisher_id: str | None = None,
    ) -> NormalizedFindingsFeed:
        """Export standardized Normalized Findings Feed conforming to Consumer Contract V2."""
        bounded_limit = max(1, min(limit, MAX_PAGE_SIZE))
        pub = publisher_id or "anie-first-party"

        if findings is not None:
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return NormalizedFindingsFeed(
                schema=FINDINGS_FEED_SCHEMA_V2,
                generated_at=now_iso,
                as_of=as_of or now_iso,
                total_findings=len(findings),
                findings=findings,
                publisher=pub,
                has_more=False,
                limit=len(findings),
            )

        all_findings: list[dict[str, Any]] = []
        curr_cursor = cursor
        has_more_feed = False
        next_cursor_feed = None

        while True:
            fetch_limit = MAX_PAGE_SIZE if fetch_all else bounded_limit
            res = self.query_cross_vector_findings(
                subject_uri=subject_uri,
                finding_type=finding_type,
                state=state,
                cursor=curr_cursor,
                limit=fetch_limit,
            )

            all_findings.extend(res.items)

            if not fetch_all:
                has_more_feed = res.has_more
                next_cursor_feed = res.next_cursor
                break
            else:
                if not res.has_more or not res.next_cursor:
                    break
                curr_cursor = res.next_cursor

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        feed_as_of = as_of or now_iso

        return NormalizedFindingsFeed(
            schema=FINDINGS_FEED_SCHEMA_V2,
            generated_at=now_iso,
            as_of=feed_as_of,
            total_findings=len(all_findings),
            findings=all_findings,
            publisher=pub,
            next_cursor=next_cursor_feed,
            has_more=has_more_feed,
            limit=bounded_limit if not fetch_all else None,
        )

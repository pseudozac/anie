"""Graph Engine and Temporal Knowledge Subsystem for ANIE (Milestone M3.3.1).

Transforms empirical Layer 1 observations and Layer 2 discrepancy reports into
a queryable, indexed property graph with epistemic classification:
- FACT (immutable wire captures)
- DERIVED (deterministic structural linkages)
- HYPOTHESIS (probabilistic inferences)
- VALIDATED (analyst-asserted claims)

Features:
- Pure SQLite / Python execution with zero external binary or daemon dependencies.
- Sub-millisecond k-hop recursive traversal.
- Evidence lineage tracing back to raw wire SHA-256 digests.
- Obsidian-compatible plaintext Markdown export with frontmatter and wikilinks.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .discrepancy_models import RealDiscrepancyReport
from .graph_models import (
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    IntelligenceClaim,
    NodeType,
    RelationType,
    format_node_id,
)
from .observations import canonical_json, normalized_domain, normalized_ip, utc_iso
from .rdap_enrichment import RdapEnricher
from .real_models import RealCollectionEvent, RealObservation


_WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


def sanitize_vault_filename(raw_name: str) -> str:
    """Sanitize entity identifier for safe cross-platform filesystem note storage.
    
    Protects against:
    - Path traversal: removes path separators and parent directory references
    - Null bytes and ASCII control characters (0x00-0x1F, 0x7F)
    - Windows reserved device names (CON, PRN, AUX, NUL, COM*, LPT*)
    - Characters illegal in Windows/Linux/macOS filenames (/ \\ : * ? \" < > |)
    - Leading/trailing whitespace and dots
    """
    clean = re.sub(r"[\x00-\x1f\x7f]", "", str(raw_name))
    clean = re.sub(r'[/\\:*?"<>|]', "_", clean)
    clean = clean.strip(". ")
    if not clean or clean in (".", ".."):
        clean = "unnamed_entity"
    stem = clean.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        clean = f"_{clean}"
    return clean[:200]


def _safe_write_vault_note(target_dir: Path, vault_root: Path, filename: str, content: str) -> bool:
    """Safely write a vault note preventing path traversal, symlink attacks, and oversized files."""
    safe_fn = sanitize_vault_filename(filename) + ".md"
    target_path = target_dir / safe_fn
    resolved_target = target_path.resolve()
    resolved_root = vault_root.resolve()

    try:
        resolved_target.relative_to(resolved_root)
    except ValueError:
        raise ValueError(f"path traversal attempt rejected: {filename!r}")

    if target_path.is_symlink():
        raise PermissionError(f"symlink attack rejected on vault target: {target_path}")

    # Bounded note size ceiling (500 KB)
    encoded = content.encode("utf-8")
    if len(encoded) > 500_000:
        content = encoded[:500_000].decode("utf-8", errors="ignore") + "\n\n<!-- TRUNCATED: note exceeded 500 KB vault ceiling -->\n"

    target_path.write_text(content, encoding="utf-8")
    return True


class GraphEngine:
    """In-process graph extraction, indexing, and query engine."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.rdap_enricher = RdapEnricher()

    # --- Extraction from Real Models ---

    def extract_from_observation(
        self,
        event: RealCollectionEvent,
        observation: RealObservation,
        enrich_rdap: bool = False,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Extract typed entity nodes and temporal directed edges from observation + event pair."""
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        obs_time = observation.observed_at
        ttl = observation.ttl_seconds
        valid_until = None
        if ttl is not None and ttl > 0:
            try:
                dt = datetime.fromisoformat(obs_time.replace("Z", "+00:00"))
                exp_ts = dt.timestamp() + ttl
                valid_until = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            except Exception:
                valid_until = None

        # 1. Subject Node (Domain or IP)
        if observation.kind in ("dns_ptr", "rdap_asn", "rdap_network"):
            subj_type = NodeType.IP
        elif observation.kind in ("dns_a", "dns_aaaa", "http_metadata", "tls_cert", "tls_handshake"):
            subj_type = NodeType.DOMAIN
        else:
            try:
                ipaddress.ip_address(observation.subject)
                subj_type = NodeType.IP
            except ValueError:
                subj_type = NodeType.DOMAIN
        domain_node = GraphNode.create(
            node_type=subj_type,
            canonical_name=observation.subject,
            layer=EpistemicLayer.FACT,
            observed_at=obs_time,
            properties={"kind": observation.kind},
        )
        nodes.append(domain_node)

        # 2. Resolver Node
        resolver_id = "unknown"
        if observation.factual_verification:
            resolver_id = observation.factual_verification.resolver_identity
        elif ":" in observation.source_id:
            resolver_id = observation.source_id.split(":")[-1]

        resolver_node = GraphNode.create(
            node_type=NodeType.RESOLVER,
            canonical_name=resolver_id,
            layer=EpistemicLayer.FACT,
            observed_at=obs_time,
            properties={"source_id": observation.source_id},
        )
        nodes.append(resolver_node)

        # Edge: Domain QUERIED_VIA Resolver
        edge_queried = GraphEdge.create(
            source_id=domain_node.node_id,
            target_id=resolver_node.node_id,
            relation_type=RelationType.QUERIED_VIA,
            layer=EpistemicLayer.FACT,
            observed_at=obs_time,
            confidence=1.0,
            evidence_hashes=[event.raw_sha256],
            properties={"status": observation.status, "rcode": event.response_code},
        )
        edges.append(edge_queried)

        # 3. Answer IPs and RESOLVES_TO edges
        for val in observation.values:
            try:
                ip_node = GraphNode.create(
                    node_type=NodeType.IP,
                    canonical_name=val,
                    layer=EpistemicLayer.FACT,
                    observed_at=obs_time,
                )
                nodes.append(ip_node)

                edge_resolves = GraphEdge.create(
                    source_id=domain_node.node_id,
                    target_id=ip_node.node_id,
                    relation_type=RelationType.RESOLVES_TO,
                    layer=EpistemicLayer.DERIVED,
                    observed_at=obs_time,
                    valid_from=obs_time,
                    valid_until=valid_until,
                    confidence=1.0,
                    evidence_hashes=[event.raw_sha256],
                    properties={
                        "kind": observation.kind,
                        "ttl_seconds": ttl,
                        "resolver": resolver_id,
                    },
                )
                edges.append(edge_resolves)

                if enrich_rdap:
                    rdap_nodes, rdap_edges = self.rdap_enricher.enrich_ip(
                        val, obs_time, [event.raw_sha256]
                    )
                    nodes.extend(rdap_nodes)
                    edges.extend(rdap_edges)
            except ValueError:
                # Value was not an IP (e.g. CNAME target)
                pass

        return nodes, edges

    def extract_from_discrepancy(
        self,
        report: RealDiscrepancyReport,
    ) -> tuple[GraphNode, list[GraphEdge]]:
        """Extract discrepancy intelligence claim node and linkages to domain and resolvers."""
        domain_uri = format_node_id(NodeType.DOMAIN, report.subject)
        analyzed_at = report.analyzed_at

        # Discrepancy analysis node
        disc_node = GraphNode(
            node_id=f"anie:entity:claim:{report.analysis_id}",
            node_type=NodeType.INTELLIGENCE_CLAIM.value,
            canonical_name=f"{report.subject} [{report.verdict}]",
            layer=EpistemicLayer.DERIVED.value,
            first_observed_at=analyzed_at,
            last_observed_at=analyzed_at,
            properties={
                "verdict": report.verdict,
                "category": report.category,
                "confidence": report.confidence,
                "explanation": report.explanation,
                "ruleset_version": report.ruleset_version,
            },
        )

        edges: list[GraphEdge] = []
        all_hashes = list(report.evidence_hashes.values())

        # Ensure domain node exists in graph
        dom_node = GraphNode.create(
            node_type=NodeType.DOMAIN,
            canonical_name=report.subject,
            layer=EpistemicLayer.FACT,
            observed_at=analyzed_at,
        )
        self.upsert_node(dom_node)

        # Edge: Claim SUPPORTS_CLAIM or DISCREPANCY_FOR Domain
        edges.append(GraphEdge.create(
            source_id=disc_node.node_id,
            target_id=domain_uri,
            relation_type=RelationType.DISCREPANCY_FOR,
            layer=EpistemicLayer.DERIVED,
            observed_at=analyzed_at,
            confidence=report.confidence,
            ruleset_version=report.ruleset_version,
            evidence_hashes=all_hashes,
            properties={"verdict": report.verdict, "category": report.category},
        ))

        # Edges to participating resolvers
        for res in report.participating_resolvers:
            res_node = GraphNode.create(
                node_type=NodeType.RESOLVER,
                canonical_name=res,
                layer=EpistemicLayer.FACT,
                observed_at=analyzed_at,
                properties={"resolver_identity": res},
            )
            self.upsert_node(res_node)
            res_uri = res_node.node_id
            res_hashes = [report.evidence_hashes[res]] if res in report.evidence_hashes else []
            edges.append(GraphEdge.create(
                source_id=disc_node.node_id,
                target_id=res_uri,
                relation_type=RelationType.DERIVED_FROM,
                layer=EpistemicLayer.DERIVED,
                observed_at=analyzed_at,
                confidence=report.confidence,
                ruleset_version=report.ruleset_version,
                evidence_hashes=res_hashes,
            ))

        return disc_node, edges

    # --- Ingestion into SQLite Graph Tables ---

    def upsert_node(self, node: GraphNode) -> bool:
        """Insert or update a graph node (merging observation timestamps). Returns True if newly inserted."""
        row = self.conn.execute(
            "SELECT first_observed_at, last_observed_at, properties_json FROM graph_nodes WHERE node_id = ?",
            (node.node_id,),
        ).fetchone()

        if row is None:
            self.conn.execute(
                """
                INSERT INTO graph_nodes (
                    node_id, node_type, canonical_name, layer,
                    first_observed_at, last_observed_at, properties_json, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    node.node_id,
                    node.node_type,
                    node.canonical_name,
                    node.layer,
                    node.first_observed_at,
                    node.last_observed_at,
                    canonical_json(node.properties),
                    canonical_json(node.to_dict()),
                ),
            )
            return True
        else:
            old_first, old_last, old_props_json = row
            new_first = min(old_first, node.first_observed_at)
            new_last = max(old_last, node.last_observed_at)
            props = json.loads(old_props_json)
            props.update(node.properties)
            updated_dict = node.to_dict()
            updated_dict["first_observed_at"] = new_first
            updated_dict["last_observed_at"] = new_last
            updated_dict["properties"] = props

            self.conn.execute(
                """
                UPDATE graph_nodes
                SET first_observed_at = ?, last_observed_at = ?, properties_json = ?, payload = ?
                WHERE node_id = ?
                """,
                (new_first, new_last, canonical_json(props), canonical_json(updated_dict), node.node_id),
            )
            return False

    def insert_edge(self, edge: GraphEdge) -> bool:
        """Insert a graph edge, or merge evidence hashes if edge_id already exists.
        
        Guarantees that no supporting evidence hashes are silently lost during deduplication.
        """
        row = self.conn.execute(
            "SELECT evidence_hashes_json, properties_json, payload FROM graph_edges WHERE edge_id = ?",
            (edge.edge_id,),
        ).fetchone()

        if row is None:
            self.conn.execute(
                """
                INSERT INTO graph_edges (
                    edge_id, source_id, target_id, relation_type, layer,
                    observed_at, valid_from, valid_until, confidence,
                    ruleset_version, evidence_hashes_json, properties_json, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    edge.edge_id,
                    edge.source_id,
                    edge.target_id,
                    edge.relation_type,
                    edge.layer,
                    edge.observed_at,
                    edge.valid_from,
                    edge.valid_until,
                    edge.confidence,
                    edge.ruleset_version,
                    json.dumps(list(edge.evidence_hashes)),
                    canonical_json(edge.properties),
                    canonical_json(edge.to_dict()),
                ),
            )
            return True
        else:
            # Edge exists: Merge evidence hashes to prevent silent evidence loss
            old_hashes = set(json.loads(row[0]))
            new_hashes = set(edge.evidence_hashes)
            merged_hashes = sorted(old_hashes | new_hashes)

            old_payload = json.loads(row[2])
            old_props = json.loads(row[1])
            old_props.update(edge.properties)
            old_payload["evidence_hashes"] = merged_hashes
            old_payload["properties"] = old_props

            self.conn.execute(
                """
                UPDATE graph_edges
                SET evidence_hashes_json = ?, properties_json = ?, payload = ?
                WHERE edge_id = ?
                """,
                (
                    json.dumps(merged_hashes),
                    canonical_json(old_props),
                    canonical_json(old_payload),
                    edge.edge_id,
                ),
            )
            return len(merged_hashes) > len(old_hashes)

    # --- Query Capabilities ---

    def get_node(self, node_id: str) -> GraphNode | None:
        row = self.conn.execute(
            "SELECT payload FROM graph_nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        return GraphNode.from_dict(json.loads(row[0])) if row else None

    def get_k_hop_neighborhood(
        self,
        start_node_id: str,
        max_depth: int = 1,
        layer_filter: list[str] | None = None,
        max_nodes: int = 1000,
        max_edges: int = 2500,
    ) -> dict[str, Any]:
        """Perform recursive traversal up to max_depth returning bounded nodes and edges.
        
        Hard Invariants:
        - max_depth: Bounded [0, 5]
        - max_nodes: Up to max_nodes expanded (default 1,000)
        - max_edges: Up to max_edges returned (default 2,500)
        - Cycle detection: Unambiguous comma-delimited exact token matching.
        """
        if max_depth < 0 or max_depth > 5:
            raise ValueError("max_depth must be between 0 and 5")
        if max_nodes <= 0:
            raise ValueError("max_nodes must be positive")
        if max_edges <= 0:
            raise ValueError("max_edges must be positive")

        if max_depth == 0:
            node = self.get_node(start_node_id)
            if not node:
                return {
                    "root_id": start_node_id,
                    "depth": 0,
                    "truncated": False,
                    "total_nodes_visited": 0,
                    "total_edges_visited": 0,
                    "max_depth_reached": 0,
                    "limit_nodes": max_nodes,
                    "limit_edges": max_edges,
                    "nodes": [],
                    "edges": [],
                }
            return {
                "root_id": start_node_id,
                "depth": 0,
                "truncated": False,
                "total_nodes_visited": 1,
                "total_edges_visited": 0,
                "max_depth_reached": 0,
                "limit_nodes": max_nodes,
                "limit_edges": max_edges,
                "nodes": [node.to_dict()],
                "edges": [],
            }

        if max_depth == 1:
            # High-performance direct index seek for 1-hop neighborhood with deterministic ordering
            edge_query = """
            SELECT payload, source_id, target_id FROM graph_edges
            WHERE source_id = ?
            UNION ALL
            SELECT payload, source_id, target_id FROM graph_edges
            WHERE target_id = ?
            ORDER BY source_id ASC, target_id ASC
            LIMIT ?
            """
            direct_edge_rows = self.conn.execute(edge_query, (start_node_id, start_node_id, max_edges + 1)).fetchall()
            is_truncated_edges = len(direct_edge_rows) > max_edges
            direct_edge_rows = direct_edge_rows[:max_edges]

            visited_set = {start_node_id}
            edge_list = []
            for r in direct_edge_rows:
                visited_set.add(r[1])
                visited_set.add(r[2])
                edge_list.append(GraphEdge.from_dict(json.loads(r[0])))
                if len(visited_set) > max_nodes:
                    break

            is_truncated_nodes = len(visited_set) > max_nodes
            visited_node_ids = sorted(list(visited_set)[:max_nodes])
            placeholders = ",".join("?" for _ in visited_node_ids)
            node_query = f"SELECT payload FROM graph_nodes WHERE node_id IN ({placeholders})"
            if layer_filter:
                l_placeholders = ",".join("?" for _ in layer_filter)
                node_query += f" AND layer IN ({l_placeholders}) ORDER BY node_id ASC"
                node_rows = self.conn.execute(node_query, (*visited_node_ids, *layer_filter)).fetchall()
            else:
                node_query += " ORDER BY node_id ASC"
                node_rows = self.conn.execute(node_query, visited_node_ids).fetchall()

            nodes = [GraphNode.from_dict(json.loads(r[0])) for r in node_rows]
            valid_node_ids = {n.node_id for n in nodes}
            edges = [
                e for e in edge_list
                if e.source_id in valid_node_ids and e.target_id in valid_node_ids
            ][:max_edges]

            return {
                "root_id": start_node_id,
                "depth": 1,
                "truncated": is_truncated_nodes or is_truncated_edges,
                "total_nodes_visited": len(visited_set),
                "total_edges_visited": len(edge_list),
                "max_depth_reached": 1 if edges else 0,
                "limit_nodes": max_nodes,
                "limit_edges": max_edges,
                "nodes": [n.to_dict() for n in nodes],
                "edges": [e.to_dict() for e in edges],
            }

        # Recursive CTE traversal with exact comma-delimited path token matching for depth > 1
        query = """
        WITH RECURSIVE traversal(curr_node_id, depth, path) AS (
            SELECT ?, 0, ',' || ? || ','
            UNION
            SELECT
                CASE WHEN e.source_id = t.curr_node_id THEN e.target_id ELSE e.source_id END,
                t.depth + 1,
                t.path || (CASE WHEN e.source_id = t.curr_node_id THEN e.target_id ELSE e.source_id END) || ','
            FROM traversal t
            JOIN graph_edges e ON (e.source_id = t.curr_node_id OR e.target_id = t.curr_node_id)
            WHERE t.depth < ?
              AND instr(t.path, ',' || (CASE WHEN e.source_id = t.curr_node_id THEN e.target_id ELSE e.source_id END) || ',') = 0
        )
        SELECT DISTINCT curr_node_id, depth FROM traversal ORDER BY depth ASC, curr_node_id ASC LIMIT ?;
        """
        rows = self.conn.execute(query, (start_node_id, start_node_id, max_depth, max_nodes + 1)).fetchall()
        is_truncated_nodes = len(rows) > max_nodes
        rows = rows[:max_nodes]
        visited_node_ids = sorted([r[0] for r in rows])
        max_d_reached = max((r[1] for r in rows), default=0)

        if not visited_node_ids:
            return {
                "root_id": start_node_id,
                "depth": max_depth,
                "truncated": False,
                "total_nodes_visited": 0,
                "total_edges_visited": 0,
                "max_depth_reached": 0,
                "limit_nodes": max_nodes,
                "limit_edges": max_edges,
                "nodes": [],
                "edges": [],
            }

        placeholders = ",".join("?" for _ in visited_node_ids)
        node_query = f"SELECT payload FROM graph_nodes WHERE node_id IN ({placeholders})"
        if layer_filter:
            l_placeholders = ",".join("?" for _ in layer_filter)
            node_query += f" AND layer IN ({l_placeholders}) ORDER BY node_id ASC"
            node_rows = self.conn.execute(node_query, (*visited_node_ids, *layer_filter)).fetchall()
        else:
            node_query += " ORDER BY node_id ASC"
            node_rows = self.conn.execute(node_query, visited_node_ids).fetchall()

        nodes = [GraphNode.from_dict(json.loads(r[0])) for r in node_rows]
        valid_node_ids = {n.node_id for n in nodes}

        # Fetch connecting edges using composite index seeks with deterministic ordering
        edge_query = f"""
        SELECT payload FROM graph_edges
        WHERE source_id IN ({placeholders}) AND target_id IN ({placeholders})
        ORDER BY source_id ASC, target_id ASC, edge_id ASC
        LIMIT ?
        """
        edge_rows = self.conn.execute(edge_query, (*visited_node_ids, *visited_node_ids, max_edges + 1)).fetchall()
        is_truncated_edges = len(edge_rows) > max_edges
        edge_rows = edge_rows[:max_edges]
        edges = []
        for r in edge_rows:
            e = GraphEdge.from_dict(json.loads(r[0]))
            if e.source_id in valid_node_ids and e.target_id in valid_node_ids:
                edges.append(e)

        return {
            "root_id": start_node_id,
            "depth": max_depth,
            "truncated": is_truncated_nodes or is_truncated_edges,
            "total_nodes_visited": len(visited_node_ids),
            "total_edges_visited": len(edges),
            "max_depth_reached": max_d_reached,
            "limit_nodes": max_nodes,
            "limit_edges": max_edges,
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
        }

    def find_co_hosted_domains(self, ip_address: str) -> list[str]:
        """Find all domains that resolve to the given IP address."""
        ip_uri = format_node_id(NodeType.IP, ip_address)
        rows = self.conn.execute(
            """
            SELECT DISTINCT n.canonical_name
            FROM graph_edges e
            JOIN graph_nodes n ON n.node_id = e.source_id
            WHERE e.target_id = ? AND e.relation_type = 'RESOLVES_TO'
            ORDER BY n.canonical_name ASC
            """,
            (ip_uri,),
        ).fetchall()
        return [r[0] for r in rows]

    def get_history(self, node_id: str) -> list[dict[str, Any]]:
        """Query all historical edges connected to a node ordered chronologically.
        
        Returns timeline of edge dictionaries with their incident entity details.
        """
        rows = self.conn.execute(
            """
            SELECT e.payload, n.canonical_name, n.node_type
            FROM graph_edges e
            JOIN graph_nodes n ON (n.node_id = CASE WHEN e.source_id = ? THEN e.target_id ELSE e.source_id END)
            WHERE e.source_id = ? OR e.target_id = ?
            ORDER BY e.valid_from ASC, e.observed_at ASC
            """,
            (node_id, node_id, node_id),
        ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def trace_evidence_lineage(self, node_or_edge_id: str) -> list[str]:
        """Return all raw wire SHA-256 evidence digests supporting a node or edge."""
        evidence_hashes = set()

        if node_or_edge_id.startswith("edge_"):
            row = self.conn.execute(
                "SELECT evidence_hashes_json FROM graph_edges WHERE edge_id = ?",
                (node_or_edge_id,),
            ).fetchone()
            if row:
                evidence_hashes.update(json.loads(row[0]))
        else:
            # Gather from incident edges
            rows = self.conn.execute(
                """
                SELECT evidence_hashes_json FROM graph_edges
                WHERE source_id = ? OR target_id = ?
                """,
                (node_or_edge_id, node_or_edge_id),
            ).fetchall()
            for r in rows:
                evidence_hashes.update(json.loads(r[0]))

        return sorted(evidence_hashes)

    def export_obsidian_markdown(self, domain_name: str) -> str:
        """Export an Obsidian-compatible Markdown note with frontmatter and wikilinks.
        
        Strict Escaping Guarantees:
        - YAML frontmatter values are quoted and sanitized against newline / delimiter injection.
        - Wikilink targets and names are sanitized to prevent nested bracket and delimiter breakage.
        """
        domain_uri = format_node_id(NodeType.DOMAIN, domain_name)
        node = self.get_node(domain_uri)
        if node is None:
            raise ValueError(f"domain node not found in graph: '{domain_name}'")

        # Query outgoing edges
        out_edges_rows = self.conn.execute(
            """
            SELECT e.target_id, e.relation_type, e.confidence, e.observed_at, n.canonical_name, n.node_type
            FROM graph_edges e
            JOIN graph_nodes n ON n.node_id = e.target_id
            WHERE e.source_id = ?
            ORDER BY e.relation_type, n.canonical_name
            """,
            (domain_uri,),
        ).fetchall()

        # Query incoming edges (claims, aliases)
        in_edges_rows = self.conn.execute(
            """
            SELECT e.source_id, e.relation_type, e.confidence, e.observed_at, n.canonical_name, n.node_type
            FROM graph_edges e
            JOIN graph_nodes n ON n.node_id = e.source_id
            WHERE e.target_id = ?
            ORDER BY e.relation_type, n.canonical_name
            """,
            (domain_uri,),
        ).fetchall()

        evidence_hashes = self.trace_evidence_lineage(domain_uri)

        def _escape_yaml_val(val: Any) -> str:
            if isinstance(val, (int, float)):
                return str(val)
            if isinstance(val, bool):
                return "true" if val else "false"
            clean = (
                str(val)
                .replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", " ")
                .replace("[[", "")
                .replace("]]", "")
                .strip()
            )
            return f'"{clean}"'

        def _escape_wikilink_token(val: Any) -> str:
            return (
                str(val)
                .replace("[[", "")
                .replace("]]", "")
                .replace("|", "-")
                .replace("\n", " ")
                .strip()
            )

        safe_canonical = _escape_wikilink_token(node.canonical_name)
        safe_type = _escape_wikilink_token(node.node_type)
        safe_layer = _escape_wikilink_token(node.layer)

        lines = [
            "---",
            f"id: {_escape_yaml_val(node.node_id)}",
            f"type: {_escape_yaml_val(node.node_type)}",
            f"canonical_name: {_escape_yaml_val(node.canonical_name)}",
            f"layer: {_escape_yaml_val(node.layer)}",
            f"first_observed_at: {_escape_yaml_val(node.first_observed_at)}",
            f"last_observed_at: {_escape_yaml_val(node.last_observed_at)}",
            "tags:",
            f"  - {_escape_yaml_val(f'anie/{node.node_type}')}",
            f"  - {_escape_yaml_val(f'anie/layer/{node.layer.lower()}')}",
            "---",
            f"# {safe_canonical}",
            "",
            "## Direct Relationships",
        ]

        if not out_edges_rows:
            lines.append("*No outgoing relationships recorded.*")
        else:
            for target_id, rel, conf, obs_time, target_name, target_type in out_edges_rows:
                s_tid = _escape_wikilink_token(target_id)
                s_tname = _escape_wikilink_token(target_name)
                s_rel = _escape_wikilink_token(rel)
                lines.append(f"- [[{s_tid}|{s_tname}]] ({s_rel}, confidence: {conf}, observed: {obs_time})")

        lines.append("")
        lines.append("## Inbound References & Intelligence Claims")
        if not in_edges_rows:
            lines.append("*No inbound references recorded.*")
        else:
            for source_id, rel, conf, obs_time, source_name, source_type in in_edges_rows:
                s_sid = _escape_wikilink_token(source_id)
                s_sname = _escape_wikilink_token(source_name)
                s_rel = _escape_wikilink_token(rel)
                lines.append(f"- [[{s_sid}|{s_sname}]] ({s_rel}, confidence: {conf})")

        lines.append("")
        lines.append("## Provenance & Evidence Anchors")
        if not evidence_hashes:
            lines.append("*No raw wire evidence anchors linked.*")
        else:
            for h in evidence_hashes:
                s_h = _escape_wikilink_token(h)
                lines.append(f"- SHA-256: `{s_h}`")

        # Query intelligence claims
        claims_rows = self.conn.execute(
            """
            SELECT payload
            FROM intelligence_claims
            WHERE subject_uri = ?
            ORDER BY asserted_at DESC
            """,
            (domain_uri,),
        ).fetchall()

        if claims_rows:
            lines.append("")
            lines.append("## Epistemic Intelligence Claims")
            for (c_json,) in claims_rows:
                claim = IntelligenceClaim.from_dict(json.loads(c_json))
                s_cid = _escape_wikilink_token(claim.claim_id)
                s_ctype = _escape_wikilink_token(claim.claim_type)
                s_vstate = _escape_wikilink_token(claim.verification_state)
                lines.append(f"### [[{s_cid}|{s_ctype}]] (State: `{s_vstate}`, Confidence: {claim.confidence})")
                lines.append(f"> {claim.explanation}")
                if claim.falsifiability_condition:
                    lines.append(f"> *Falsifiability:* {claim.falsifiability_condition}")
                lines.append("")

        return "\n".join(lines) + "\n"

    def export_obsidian_vault(self, output_dir: str | Path) -> dict[str, Any]:
        """Export the complete graph, entities, and claims into an Obsidian-compatible vault directory."""
        v_path = Path(output_dir)
        domains_dir = v_path / "domains"
        ips_dir = v_path / "ips"
        asns_dir = v_path / "asns"
        prefixes_dir = v_path / "prefixes"
        certs_dir = v_path / "certificates"
        claims_dir = v_path / "claims"
        techs_dir = v_path / "technologies"
        hypotheses_dir = v_path / "hypotheses"

        domains_dir.mkdir(parents=True, exist_ok=True)
        ips_dir.mkdir(parents=True, exist_ok=True)
        asns_dir.mkdir(parents=True, exist_ok=True)
        prefixes_dir.mkdir(parents=True, exist_ok=True)
        certs_dir.mkdir(parents=True, exist_ok=True)
        claims_dir.mkdir(parents=True, exist_ok=True)
        techs_dir.mkdir(parents=True, exist_ok=True)
        hypotheses_dir.mkdir(parents=True, exist_ok=True)

        exported_domains = 0
        exported_ips = 0
        exported_asns = 0
        exported_prefixes = 0
        exported_certs = 0
        exported_claims = 0
        exported_techs = 0
        exported_hypotheses = 0

        # 1. Export domains
        domain_rows = self.conn.execute(
            "SELECT canonical_name FROM graph_nodes WHERE node_type = 'domain' ORDER BY canonical_name"
        ).fetchall()
        for (dom,) in domain_rows:
            try:
                md_content = self.export_obsidian_markdown(dom)
                _safe_write_vault_note(domains_dir, v_path, dom, md_content)
                exported_domains += 1
            except Exception:
                pass

        # 2. Export IPs
        ip_rows = self.conn.execute(
            "SELECT canonical_name, node_id, first_observed_at, last_observed_at FROM graph_nodes WHERE node_type = 'ip' ORDER BY canonical_name"
        ).fetchall()
        for ip, node_id, first_seen, last_seen in ip_rows:
            co_hosted = self.find_co_hosted_domains(ip)

            # Query ASN and Prefix linkages
            asn_row = self.conn.execute(
                """
                SELECT n.canonical_name, n.properties_json
                FROM graph_edges e
                JOIN graph_nodes n ON n.node_id = e.target_id
                WHERE e.source_id = ? AND e.relation_type = 'ANNOUNCED_BY'
                LIMIT 1
                """,
                (node_id,),
            ).fetchone()

            prefix_row = self.conn.execute(
                """
                SELECT n.canonical_name, n.properties_json
                FROM graph_edges e
                JOIN graph_nodes n ON n.node_id = e.target_id
                WHERE e.source_id = ? AND e.relation_type = 'PREFIX_MEMBER'
                LIMIT 1
                """,
                (node_id,),
            ).fetchone()

            ip_lines = [
                "---",
                f'id: "{node_id}"',
                'type: "ip"',
                f'canonical_name: "{ip}"',
                f'first_observed_at: "{first_seen}"',
                f'last_observed_at: "{last_seen}"',
                "tags:",
                '  - "anie/ip"',
                "---",
                f"# IP: {ip}",
                "",
            ]

            if asn_row or prefix_row:
                ip_lines.append("## Infrastructure Topology")
                if asn_row:
                    asn_name = asn_row[0]
                    safe_asn = sanitize_vault_filename(asn_name)
                    asn_props = json.loads(asn_row[1] or "{}")
                    org_name = asn_props.get("as_name", "Unknown Org")
                    ip_lines.append(f"- **Autonomous System:** [[asns/{safe_asn}|{asn_name}]] ({org_name})")
                if prefix_row:
                    pref_name = prefix_row[0]
                    safe_pref = sanitize_vault_filename(pref_name)
                    pref_props = json.loads(prefix_row[1] or "{}")
                    reg = pref_props.get("registry", "IANA")
                    ip_lines.append(f"- **Network Prefix:** [[prefixes/{safe_pref}|{pref_name}]] ({reg})")
                ip_lines.append("")

            ip_lines.append("## Co-Hosted Domains")
            if co_hosted:
                for d in co_hosted:
                    ip_lines.append(f"- [[{d}]]")
            else:
                ip_lines.append("*No co-hosted domains identified.*")
            ip_lines.append("")
            _safe_write_vault_note(ips_dir, v_path, ip, "\n".join(ip_lines) + "\n")
            exported_ips += 1

        # 3. Export ASNs
        asn_rows = self.conn.execute(
            "SELECT canonical_name, node_id, first_observed_at, last_observed_at, properties_json FROM graph_nodes WHERE node_type = 'asn' ORDER BY canonical_name"
        ).fetchall()
        for asn_name, node_id, first_seen, last_seen, props_json in asn_rows:
            props = json.loads(props_json or "{}")
            as_org = props.get("as_name", "Unknown Autonomous System")
            registry = props.get("registry", "IANA")

            announced_ips = [
                r[0] for r in self.conn.execute(
                    """
                    SELECT n.canonical_name
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.node_id = e.source_id
                    WHERE e.target_id = ? AND e.relation_type = 'ANNOUNCED_BY'
                    ORDER BY n.canonical_name ASC
                    """,
                    (node_id,),
                ).fetchall()
            ]

            asn_lines = [
                "---",
                f'id: "{node_id}"',
                'type: "asn"',
                f'canonical_name: "{asn_name}"',
                f'as_name: "{as_org}"',
                f'registry: "{registry}"',
                f'first_observed_at: "{first_seen}"',
                f'last_observed_at: "{last_seen}"',
                "tags:",
                '  - "anie/asn"',
                "---",
                f"# Autonomous System: {asn_name}",
                f"**Organization / Network:** {as_org}  ",
                f"**Regional Internet Registry:** {registry}",
                "",
                "## Announced IP Infrastructure",
            ]
            if announced_ips:
                for ip in announced_ips:
                    s_ip = sanitize_vault_filename(ip)
                    asn_lines.append(f"- [[ips/{s_ip}|{ip}]]")
            else:
                asn_lines.append("*No member IPs directly linked.*")
            asn_lines.append("")
            _safe_write_vault_note(asns_dir, v_path, asn_name, "\n".join(asn_lines) + "\n")
            exported_asns += 1

        # 4. Export Prefixes
        prefix_rows = self.conn.execute(
            "SELECT canonical_name, node_id, first_observed_at, last_observed_at, properties_json FROM graph_nodes WHERE node_type = 'cdn_prefix' ORDER BY canonical_name"
        ).fetchall()
        for pref_name, node_id, first_seen, last_seen, props_json in prefix_rows:
            props = json.loads(props_json or "{}")
            registry = props.get("registry", "IANA")

            member_ips = [
                r[0] for r in self.conn.execute(
                    """
                    SELECT n.canonical_name
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.node_id = e.source_id
                    WHERE e.target_id = ? AND e.relation_type = 'PREFIX_MEMBER'
                    ORDER BY n.canonical_name ASC
                    """,
                    (node_id,),
                ).fetchall()
            ]

            pref_lines = [
                "---",
                f'id: "{node_id}"',
                'type: "cdn_prefix"',
                f'canonical_name: "{pref_name}"',
                f'registry: "{registry}"',
                f'first_observed_at: "{first_seen}"',
                f'last_observed_at: "{last_seen}"',
                "tags:",
                '  - "anie/prefix"',
                "---",
                f"# BGP Allocation Prefix: {pref_name}",
                f"**Regional Internet Registry:** {registry}",
                "",
                "## Member IP Infrastructure",
            ]
            if member_ips:
                for ip in member_ips:
                    s_ip = sanitize_vault_filename(ip)
                    pref_lines.append(f"- [[ips/{s_ip}|{ip}]]")
            else:
                pref_lines.append("*No member IPs directly linked.*")
            pref_lines.append("")
            _safe_write_vault_note(prefixes_dir, v_path, pref_name, "\n".join(pref_lines) + "\n")
            exported_prefixes += 1

        # 5. Export Certificates
        cert_rows = self.conn.execute(
            "SELECT canonical_name, node_id, first_observed_at, last_observed_at, properties_json FROM graph_nodes WHERE node_type = 'certificate' ORDER BY canonical_name"
        ).fetchall()
        for fp, node_id, first_seen, last_seen, props_json in cert_rows:
            props = json.loads(props_json or "{}")
            subject_cn = props.get("subject_cn", "Unknown Subject")
            issuer_cn = props.get("issuer_cn", "Unknown Issuer")
            not_before = props.get("not_before", "")
            not_after = props.get("not_after", "")
            is_self_signed = props.get("is_self_signed", False)
            is_multi_tenant = props.get("is_multi_tenant", False)

            serving_ips = [
                r[0] for r in self.conn.execute(
                    """
                    SELECT n.canonical_name
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.node_id = e.source_id
                    WHERE e.target_id = ? AND e.relation_type = 'SERVES_CERTIFICATE'
                    ORDER BY n.canonical_name ASC
                    """,
                    (node_id,),
                ).fetchall()
            ]

            named_domains = [
                r[0] for r in self.conn.execute(
                    """
                    SELECT n.canonical_name
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.node_id = e.target_id
                    WHERE e.source_id = ? AND e.relation_type = 'NAMES_DOMAIN'
                    ORDER BY n.canonical_name ASC
                    """,
                    (node_id,),
                ).fetchall()
            ]

            cert_lines = [
                "---",
                f'id: "{node_id}"',
                'type: "certificate"',
                f'fingerprint_sha256: "{fp}"',
                f'subject_cn: "{subject_cn}"',
                f'issuer_cn: "{issuer_cn}"',
                f'not_before: "{not_before}"',
                f'not_after: "{not_after}"',
                f'is_self_signed: {str(is_self_signed).lower()}',
                f'is_multi_tenant: {str(is_multi_tenant).lower()}',
                f'first_observed_at: "{first_seen}"',
                f'last_observed_at: "{last_seen}"',
                "tags:",
                '  - "anie/certificate"',
                "---",
                f"# X.509 Certificate: {fp[:16]}...",
                f"**Subject Common Name:** {subject_cn}  ",
                f"**Issuer:** {issuer_cn}  ",
                f"**Validity:** `{not_before}` to `{not_after}`",
                "",
                "## Serving IP Endpoints",
            ]
            if serving_ips:
                for ip in serving_ips:
                    s_ip = sanitize_vault_filename(ip)
                    cert_lines.append(f"- [[ips/{s_ip}|{ip}]]")
            else:
                cert_lines.append("*No serving IP endpoints recorded.*")
            cert_lines.append("")

            cert_lines.append("## Named Subject Alternative Domains")
            if named_domains:
                for dom in named_domains:
                    cert_lines.append(f"- [[{dom}]]")
            else:
                cert_lines.append("*No named domains recorded.*")
            cert_lines.append("")

            _safe_write_vault_note(certs_dir, v_path, fp, "\n".join(cert_lines) + "\n")
            exported_certs += 1

        # 6. Export Claims
        claim_rows = self.conn.execute(
            "SELECT payload FROM intelligence_claims ORDER BY asserted_at DESC"
        ).fetchall()
        for (c_json,) in claim_rows:
            claim = IntelligenceClaim.from_dict(json.loads(c_json))
            c_lines = [
                "---",
                f'id: "{claim.claim_id}"',
                'type: "claim"',
                f'claim_type: "{claim.claim_type}"',
                f'verification_state: "{claim.verification_state}"',
                f'confidence: {claim.confidence}',
                f'asserted_at: "{claim.asserted_at}"',
                "tags:",
                '  - "anie/claim"',
                f'  - "anie/claim/{claim.claim_type.lower()}"',
                "---",
                f"# Claim: {claim.claim_type}",
                f"**Subject:** [[{claim.subject_uri}]]",
                f"**Verification State:** `{claim.verification_state}`",
                f"**Confidence:** {claim.confidence}",
                "",
                "## Assessment Explanation",
                f"> {claim.explanation}",
                "",
                "## Falsifiability Condition",
                f"> {claim.falsifiability_condition or 'None specified'}",
                "",
            ]
            _safe_write_vault_note(claims_dir, v_path, claim.claim_id, "\n".join(c_lines) + "\n")
            exported_claims += 1

        # 7. Export Technologies (Milestone M3.8)
        tech_rows = self.conn.execute(
            "SELECT canonical_name, node_id, first_observed_at, last_observed_at, properties_json FROM graph_nodes WHERE node_type = 'technology' ORDER BY canonical_name"
        ).fetchall()
        for tech_name, node_id, first_seen, last_seen, props_json in tech_rows:
            props = json.loads(props_json or "{}")
            is_spoofable = props.get("is_spoofable", True)

            # Query associated domains
            linked_domains = [
                r[0] for r in self.conn.execute(
                    """
                    SELECT n.canonical_name
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.node_id = e.source_id
                    WHERE e.target_id = ? AND e.relation_type IN ('USES_TECHNOLOGY', 'PROTECTED_BY_POLICY') AND n.node_type = 'domain'
                    ORDER BY n.canonical_name ASC
                    """,
                    (node_id,),
                ).fetchall()
            ]

            # Query associated serving IPs
            linked_ips = [
                r[0] for r in self.conn.execute(
                    """
                    SELECT n.canonical_name
                    FROM graph_edges e
                    JOIN graph_nodes n ON n.node_id = e.source_id
                    WHERE e.target_id = ? AND e.relation_type = 'USES_TECHNOLOGY' AND n.node_type = 'ip'
                    ORDER BY n.canonical_name ASC
                    """,
                    (node_id,),
                ).fetchall()
            ]

            tech_lines = [
                "---",
                f'id: "{node_id}"',
                'type: "technology"',
                f'canonical_name: "{tech_name}"',
                f'is_spoofable: {str(is_spoofable).lower()}',
                f'first_observed_at: "{first_seen}"',
                f'last_observed_at: "{last_seen}"',
                "tags:",
                '  - "anie/technology"',
                f'  - "anie/technology/{sanitize_vault_filename(tech_name).lower()}"',
                "---",
                f"# Technology Indicator: {tech_name}",
                "> [!WARNING]",
                "> Derived assertion from passive HTTP telemetry; subject to origin header spoofing.",
                "",
                "## Associated Domain Infrastructure",
            ]
            if linked_domains:
                for dom in sorted(set(linked_domains)):
                    tech_lines.append(f"- [[domains/{sanitize_vault_filename(dom)}|{dom}]]")
            else:
                tech_lines.append("*No domains directly linked.*")
            tech_lines.append("")

            tech_lines.append("## Associated IP Endpoints")
            if linked_ips:
                for ip in sorted(set(linked_ips)):
                    tech_lines.append(f"- [[ips/{sanitize_vault_filename(ip)}|{ip}]]")
            else:
                tech_lines.append("*No IP endpoints directly linked.*")
            tech_lines.append("")

            _safe_write_vault_note(techs_dir, v_path, tech_name, "\n".join(tech_lines) + "\n")
            exported_techs += 1

        # 8. Export Competing Hypotheses (Milestone M3.8)
        has_hyp_table = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='competing_hypotheses'"
        ).fetchone()
        if has_hyp_table:
            hyp_rows = self.conn.execute(
                "SELECT payload FROM competing_hypotheses ORDER BY asserted_at DESC"
            ).fetchall()
            for (h_json,) in hyp_rows:
                h_data = json.loads(h_json)
                h_id = h_data.get("hypothesis_id", "hyp_unknown")
                h_label = h_data.get("hypothesis_label", "Unknown Hypothesis")
                h_subj = h_data.get("subject_uri", "")
                h_phenom = h_data.get("phenomenon", "")
                h_status = h_data.get("status", "PLAUSIBLE")
                h_score = h_data.get("heuristic_score", 0.0)
                h_expl = h_data.get("explanation", "")
                h_falsif = h_data.get("falsifiability_condition", "")
                h_asserted = h_data.get("asserted_at", "")
                h_supersedes = h_data.get("supersedes_hypothesis_id")
                supp_hashes = h_data.get("supporting_evidence_hashes", [])
                cont_hashes = h_data.get("contradicting_evidence_hashes", [])

                h_lines = [
                    "---",
                    f'id: "{h_id}"',
                    'type: "hypothesis"',
                    f'subject: "{h_subj}"',
                    f'phenomenon: "{h_phenom}"',
                    f'status: "{h_status}"',
                    f'heuristic_score: {h_score}',
                    'statistically_calibrated: false',
                    f'asserted_at: "{h_asserted}"',
                    "tags:",
                    '  - "anie/hypothesis"',
                    f'  - "anie/hypothesis/{h_status.lower()}"',
                    "---",
                    f"# Competing Hypothesis: {h_label}",
                    f"**Subject:** [[{h_subj}]]  ",
                    f"**Phenomenon:** `{h_phenom}`  ",
                    f"**Status:** `{h_status}`  ",
                    f"**Heuristic Score:** {h_score} *(Uncalibrated heuristic rating, not a calibrated probability)*",
                    "",
                    "## Assessment Explanation",
                    f"> {h_expl}",
                    "",
                    "## Falsifiability Condition",
                    f"> {h_falsif or 'None specified'}",
                    "",
                    "## Evidence Lineage",
                    "### Supporting Evidence Hashes",
                ]
                if supp_hashes:
                    for sh in supp_hashes:
                        h_lines.append(f"- SHA-256: `{sh}`")
                else:
                    h_lines.append("*None recorded.*")
                h_lines.append("")

                h_lines.append("### Contradicting Evidence Hashes")
                if cont_hashes:
                    for ch in cont_hashes:
                        h_lines.append(f"- SHA-256: `{ch}`")
                else:
                    h_lines.append("*None recorded.*")
                h_lines.append("")

                if h_supersedes:
                    h_lines.append(f"## Historical Supersession\n- Supersedes prior hypothesis: [[hypotheses/{h_supersedes}|{h_supersedes}]]\n")

                _safe_write_vault_note(hypotheses_dir, v_path, h_id, "\n".join(h_lines) + "\n")
                exported_hypotheses += 1

        # 9. Vault Readme Index
        readme = [
            "# ANIE Knowledge Graph Vault",
            "",
            f"- **Domains Indexed:** {exported_domains}",
            f"- **IPs Indexed:** {exported_ips}",
            f"- **Autonomous Systems (ASNs):** {exported_asns}",
            f"- **BGP Allocation Prefixes:** {exported_prefixes}",
            f"- **TLS Certificates:** {exported_certs}",
            f"- **Intelligence Claims:** {exported_claims}",
            f"- **Technology Indicators:** {exported_techs}",
            f"- **Competing Hypotheses:** {exported_hypotheses}",
            "",
            "## Exploration Roots",
            "- [[domains/|Domain Infrastructure Notes]]",
            "- [[ips/|IP Infrastructure Notes]]",
            "- [[asns/|Autonomous Systems (ASN)]]",
            "- [[prefixes/|BGP Allocation Prefixes]]",
            "- [[certificates/|TLS Certificates]]",
            "- [[claims/|Temporal Intelligence Claims]]",
            "- [[technologies/|Observed Technology Indicators]]",
            "- [[hypotheses/|Competing Hypotheses & Uncertainty Models]]",
        ]
        _safe_write_vault_note(v_path, v_path, "README", "\n".join(readme) + "\n")

        return {
            "vault_dir": str(v_path),
            "domains_exported": exported_domains,
            "ips_exported": exported_ips,
            "asns_exported": exported_asns,
            "prefixes_exported": exported_prefixes,
            "certs_exported": exported_certs,
            "claims_exported": exported_claims,
            "techs_exported": exported_techs,
            "hypotheses_exported": exported_hypotheses,
        }

    def search_intelligence(
        self,
        query: str,
        entity_type: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Search the FTS5 intelligence index using the current connection."""
        clean_q = query.strip()
        if not clean_q:
            return []

        try:
            if entity_type:
                sql = """
                SELECT entity_id, entity_type, title, snippet(intelligence_fts, 3, '[', ']', '...', 15) as excerpt, rank
                FROM intelligence_fts
                WHERE intelligence_fts MATCH ? AND entity_type = ?
                ORDER BY rank
                LIMIT ?
                """
                rows = self.conn.execute(sql, (clean_q, entity_type, limit)).fetchall()
            else:
                sql = """
                SELECT entity_id, entity_type, title, snippet(intelligence_fts, 3, '[', ']', '...', 15) as excerpt, rank
                FROM intelligence_fts
                WHERE intelligence_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """
                rows = self.conn.execute(sql, (clean_q, limit)).fetchall()
        except sqlite3.OperationalError:
            q_escaped = clean_q.replace('"', '""')
            escaped = f'"{q_escaped}"'
            if entity_type:
                sql = """
                SELECT entity_id, entity_type, title, snippet(intelligence_fts, 3, '[', ']', '...', 15) as excerpt, rank
                FROM intelligence_fts
                WHERE intelligence_fts MATCH ? AND entity_type = ?
                ORDER BY rank
                LIMIT ?
                """
                rows = self.conn.execute(sql, (escaped, entity_type, limit)).fetchall()
            else:
                sql = """
                SELECT entity_id, entity_type, title, snippet(intelligence_fts, 3, '[', ']', '...', 15) as excerpt, rank
                FROM intelligence_fts
                WHERE intelligence_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """
                rows = self.conn.execute(sql, (escaped, limit)).fetchall()

        return [
            {
                "entity_id": r[0],
                "entity_type": r[1],
                "title": r[2],
                "excerpt": r[3] or "",
                "rank": round(float(r[4]), 4),
            }
            for r in rows
        ]

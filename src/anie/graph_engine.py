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
from .real_models import RealCollectionEvent, RealObservation


class GraphEngine:
    """In-process graph extraction, indexing, and query engine."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # --- Extraction from Real Models ---

    def extract_from_observation(
        self,
        event: RealCollectionEvent,
        observation: RealObservation,
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
        subj_type = NodeType.DOMAIN if observation.kind in ("dns_a", "dns_aaaa") else NodeType.IP
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

    def upsert_node(self, node: GraphNode) -> None:
        """Insert or update a graph node (merging observation timestamps)."""
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
                return {"root_id": start_node_id, "depth": 0, "nodes": [], "edges": []}
            return {
                "root_id": start_node_id,
                "depth": 0,
                "nodes": [node.to_dict()],
                "edges": [],
            }

        if max_depth == 1:
            # High-performance direct index seek for 1-hop neighborhood (sub-millisecond)
            edge_query = """
            SELECT payload, source_id, target_id FROM graph_edges
            WHERE source_id = ?
            UNION ALL
            SELECT payload, source_id, target_id FROM graph_edges
            WHERE target_id = ?
            LIMIT ?
            """
            direct_edge_rows = self.conn.execute(edge_query, (start_node_id, start_node_id, max_edges)).fetchall()
            visited_set = {start_node_id}
            edge_list = []
            for r in direct_edge_rows:
                visited_set.add(r[1])
                visited_set.add(r[2])
                edge_list.append(GraphEdge.from_dict(json.loads(r[0])))
                if len(visited_set) >= max_nodes:
                    break

            visited_node_ids = list(visited_set)[:max_nodes]
            placeholders = ",".join("?" for _ in visited_node_ids)
            node_query = f"SELECT payload FROM graph_nodes WHERE node_id IN ({placeholders})"
            if layer_filter:
                l_placeholders = ",".join("?" for _ in layer_filter)
                node_query += f" AND layer IN ({l_placeholders})"
                node_rows = self.conn.execute(node_query, (*visited_node_ids, *layer_filter)).fetchall()
            else:
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
        SELECT DISTINCT curr_node_id, depth FROM traversal LIMIT ?;
        """
        rows = self.conn.execute(query, (start_node_id, start_node_id, max_depth, max_nodes)).fetchall()
        visited_node_ids = [r[0] for r in rows][:max_nodes]

        if not visited_node_ids:
            return {"nodes": [], "edges": []}

        placeholders = ",".join("?" for _ in visited_node_ids)
        node_query = f"SELECT payload FROM graph_nodes WHERE node_id IN ({placeholders})"
        if layer_filter:
            l_placeholders = ",".join("?" for _ in layer_filter)
            node_query += f" AND layer IN ({l_placeholders})"
            node_rows = self.conn.execute(node_query, (*visited_node_ids, *layer_filter)).fetchall()
        else:
            node_rows = self.conn.execute(node_query, visited_node_ids).fetchall()

        nodes = [GraphNode.from_dict(json.loads(r[0])) for r in node_rows]
        valid_node_ids = {n.node_id for n in nodes}

        # Fetch connecting edges using composite index seeks
        edge_query = f"""
        SELECT payload FROM graph_edges
        WHERE source_id IN ({placeholders}) AND target_id IN ({placeholders})
        LIMIT ?
        """
        edge_rows = self.conn.execute(edge_query, (*visited_node_ids, *visited_node_ids, max_edges)).fetchall()
        edges = []
        for r in edge_rows:
            e = GraphEdge.from_dict(json.loads(r[0]))
            if e.source_id in valid_node_ids and e.target_id in valid_node_ids:
                edges.append(e)
            if len(edges) >= max_edges:
                break

        return {
            "root_id": start_node_id,
            "depth": max_depth,
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
        claims_dir = v_path / "claims"

        domains_dir.mkdir(parents=True, exist_ok=True)
        ips_dir.mkdir(parents=True, exist_ok=True)
        claims_dir.mkdir(parents=True, exist_ok=True)

        exported_domains = 0
        exported_ips = 0
        exported_claims = 0

        # 1. Export domains
        domain_rows = self.conn.execute(
            "SELECT canonical_name FROM graph_nodes WHERE node_type = 'domain' ORDER BY canonical_name"
        ).fetchall()
        for (dom,) in domain_rows:
            try:
                md_content = self.export_obsidian_markdown(dom)
                safe_name = dom.replace("/", "_").replace("\\", "_")
                (domains_dir / f"{safe_name}.md").write_text(md_content, encoding="utf-8")
                exported_domains += 1
            except Exception:
                pass

        # 2. Export IPs
        ip_rows = self.conn.execute(
            "SELECT canonical_name, node_id, first_observed_at, last_observed_at FROM graph_nodes WHERE node_type = 'ip' ORDER BY canonical_name"
        ).fetchall()
        for ip, node_id, first_seen, last_seen in ip_rows:
            co_hosted = self.find_co_hosted_domains(ip)
            safe_ip = ip.replace(":", "_")
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
                "## Co-Hosted Domains",
            ]
            if co_hosted:
                for d in co_hosted:
                    ip_lines.append(f"- [[{d}]]")
            else:
                ip_lines.append("*No co-hosted domains identified.*")
            ip_lines.append("")
            (ips_dir / f"{safe_ip}.md").write_text("\n".join(ip_lines) + "\n", encoding="utf-8")
            exported_ips += 1

        # 3. Export Claims
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
            (claims_dir / f"{claim.claim_id}.md").write_text("\n".join(c_lines) + "\n", encoding="utf-8")
            exported_claims += 1

        # 4. Vault Readme Index
        readme = [
            "# ANIE Knowledge Graph Vault",
            "",
            f"- **Domains Indexed:** {exported_domains}",
            f"- **IPs Indexed:** {exported_ips}",
            f"- **Intelligence Claims:** {exported_claims}",
            "",
            "## Exploration Roots",
            "- [[domains/|Domain Infrastructure Notes]]",
            "- [[ips/|IP Infrastructure Notes]]",
            "- [[claims/|Temporal Intelligence Claims]]",
        ]
        (v_path / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8")

        return {
            "vault_dir": str(v_path),
            "domains_exported": exported_domains,
            "ips_exported": exported_ips,
            "claims_exported": exported_claims,
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

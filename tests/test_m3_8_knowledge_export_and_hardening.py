"""Verification and Hardening Suite for ANIE Milestone M3.8 Knowledge Export and Multi-Vector Integration."""
from hashlib import sha256
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from anie.graph_engine import GraphEngine
from anie.graph_models import EpistemicLayer, GraphNode, NodeType, RelationType, format_node_id
from anie.http_enrichment import (
    HttpEnricher,
    ObservedHttpEndpointEvidence,
    parse_http1_response_headers,
)
from anie.multi_resolver import build_mock_dns_wire_response
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore
from anie.temporal_intelligence import (
    CompetingHypothesis,
    HypothesisStatus,
    TemporalIntelligenceEngine,
)


def make_test_event_and_obs(
    domain: str,
    ips: list[str],
    observed_at: str,
    resolver: str = "cloudflare",
    ttl: int = 300,
    rcode: int = 0,
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_wire = build_mock_dns_wire_response(
        domain=domain,
        kind="A",
        ips=ips,
        rcode=rcode,
        ad_flag=(rcode == 0),
        ttl=ttl,
    )
    raw_sha = sha256(raw_wire).hexdigest()

    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=observed_at,
        target_endpoint=f"https://{resolver}.example.net/dns-query",
        pinned_ip="192.0.2.1",
    )
    factual = FactualVerification(
        dnssec_status="secure" if rcode == 0 else "indeterminate",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity=resolver,
        wire_rcode="NOERROR" if rcode == 0 else "NXDOMAIN",
        raw_evidence_status="captured",
        resolver_ad_claim=(rcode == 0),
    )
    event = RealCollectionEvent(
        request=req,
        response_code="NOERROR" if rcode == 0 else "NXDOMAIN",
        raw_sha256=raw_sha,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id=f"oracle-collector-01:{resolver}",
        observed_at=observed_at,
        raw_payload=raw_wire,
    )
    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=observed_at,
        values=tuple(ips),
        status="ok" if rcode == 0 else "empty",
        source_id=f"oracle-collector-01:{resolver}",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=ttl,
    )
    return event, obs


class TestM38KnowledgeExportAndHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="anie_m38_export_")
        self.db_path = Path(self.temp_dir) / "test_m38_export.sqlite"
        self.vault_path = Path(self.temp_dir) / "obsidian_vault"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_multi_vector_graph_and_vault_export(self):
        # 1. Ingest DNS observations
        ev1, ob1 = make_test_event_and_obs("secure.example.com", ["104.16.1.1"], "2026-11-21T08:00:00Z")
        ev2, ob2 = make_test_event_and_obs("secure.example.com", ["104.16.1.2"], "2026-11-21T08:10:00Z")
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            graph_engine = GraphEngine(conn)
            temp_engine = TemporalIntelligenceEngine(conn)

            # Ingest DNS into graph
            for ev, ob in [(ev1, ob1), (ev2, ob2)]:
                nodes, edges = graph_engine.extract_from_observation(ev, ob)
                for n in nodes:
                    graph_engine.upsert_node(n)
                for e in edges:
                    graph_engine.insert_edge(e)

            # 2. Ingest Passive HTTP Telemetry
            http_raw = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: cloudflare\r\n"
                b"Content-Type: text/html\r\n"
                b"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
            )
            http_rec = parse_http1_response_headers(http_raw)
            http_ev = ObservedHttpEndpointEvidence(
                ip="104.16.1.1",
                port=443,
                sni_or_host="secure.example.com",
                observed_at="2026-11-21T08:05:00Z",
                source_id="oracle-collector-01:http",
                evidence_hash="f" * 64,
                http_version="HTTP/1.1",
            )
            http_enricher = HttpEnricher()
            h_nodes, h_edges = http_enricher.enrich_http_metadata(http_rec, http_ev)
            for n in h_nodes:
                graph_engine.upsert_node(n)
            for e in h_edges:
                graph_engine.insert_edge(e)

            # 3. Evaluate and Persist Competing Hypotheses
            hyps = temp_engine.evaluate_competing_hypotheses("secure.example.com")
            temp_engine.persist_competing_hypotheses(hyps)
            hyp_nodes, hyp_edges = temp_engine.project_hypotheses_to_graph(hyps)
            for n in hyp_nodes:
                graph_engine.upsert_node(n)
            for e in hyp_edges:
                graph_engine.insert_edge(e)

            # 4. Export Obsidian Vault
            summary = graph_engine.export_obsidian_vault(self.vault_path)

            self.assertGreaterEqual(summary["domains_exported"], 1)
            self.assertGreaterEqual(summary["ips_exported"], 2)
            self.assertGreaterEqual(summary["techs_exported"], 2)  # cloudflare, hsts-policy
            self.assertGreaterEqual(summary["hypotheses_exported"], 2)  # cdn rotation, fast-flux

            # Verify files on disk
            tech_file = self.vault_path / "technologies" / "cloudflare.md"
            self.assertTrue(tech_file.exists())
            tech_text = tech_file.read_text(encoding="utf-8")
            self.assertIn("Technology Indicator: cloudflare", tech_text)
            self.assertIn("is_spoofable: true", tech_text)
            self.assertIn("[[domains/secure.example.com|secure.example.com]]", tech_text)

            hyp_files = list((self.vault_path / "hypotheses").glob("*.md"))
            self.assertGreaterEqual(len(hyp_files), 2)
            hyp_text = hyp_files[0].read_text(encoding="utf-8")
            self.assertIn("type: \"hypothesis\"", hyp_text)
            self.assertIn("statistically_calibrated: false", hyp_text)

            # Verify README index
            readme_file = self.vault_path / "README.md"
            self.assertTrue(readme_file.exists())
            readme_text = readme_file.read_text(encoding="utf-8")
            self.assertIn("Technology Indicators:", readme_text)
            self.assertIn("Competing Hypotheses:", readme_text)
            self.assertIn("- [[technologies/|Observed Technology Indicators]]", readme_text)
            self.assertIn("- [[hypotheses/|Competing Hypotheses & Uncertainty Models]]", readme_text)

    def test_vault_path_containment_and_sanitization(self):
        with self.store._connect() as conn:
            graph_engine = GraphEngine(conn)
            # Insert malicious technology name containing path traversal and Windows reserved name
            malicious_tech = GraphNode.create(
                node_type=NodeType.TECHNOLOGY,
                canonical_name="../../NUL",
                layer=EpistemicLayer.DERIVED,
                observed_at="2026-11-21T08:00:00Z",
            )
            graph_engine.upsert_node(malicious_tech)

            summary = graph_engine.export_obsidian_vault(self.vault_path)
            self.assertGreaterEqual(summary["techs_exported"], 1)

            # Ensure file is safely trapped inside vault_path/technologies
            exported_files = list((self.vault_path / "technologies").glob("*.md"))
            for f in exported_files:
                resolved = f.resolve()
                self.assertTrue(str(resolved).startswith(str(self.vault_path.resolve())))
                self.assertTrue(f.name.startswith("_"))

    def test_graph_query_performance(self):
        # 1-hop traversal performance budget: < 10 ms
        ev1, ob1 = make_test_event_and_obs("perf.example.com", ["104.16.1.1"], "2026-11-21T08:00:00Z")
        self.store.insert_record(ev1, ob1)

        with self.store._connect() as conn:
            graph_engine = GraphEngine(conn)
            nodes, edges = graph_engine.extract_from_observation(ev1, ob1)
            for n in nodes:
                graph_engine.upsert_node(n)
            for e in edges:
                graph_engine.insert_edge(e)

            t0 = time.perf_counter()
            res = graph_engine.get_k_hop_neighborhood(format_node_id(NodeType.DOMAIN, "perf.example.com"), max_depth=1)
            latency_ms = (time.perf_counter() - t0) * 1000.0

            self.assertLess(latency_ms, 10.0, f"1-hop latency exceeded 10 ms budget: {latency_ms:.2f} ms")
            self.assertGreaterEqual(len(res["nodes"]), 1)


if __name__ == "__main__":
    unittest.main()

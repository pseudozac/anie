"""Unit tests for M3.8 Competing Hypothesis Engine."""
from hashlib import sha256
from pathlib import Path
import shutil
import tempfile
import unittest

from anie.discrepancy_models import RealDiscrepancyReport
from anie.graph_models import EpistemicLayer, NodeType, RelationType, format_node_id
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


class TestCompetingHypothesisEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="anie_m38_test_")
        self.db_path = Path(self.temp_dir) / "test_m38.sqlite"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_insufficient_evidence_abstention(self):
        # 1 observation -> INSUFFICIENT_EVIDENCE
        ev1, ob1 = make_test_event_and_obs("example.com", ["93.184.216.34"], "2026-11-21T08:00:00Z")
        self.store.insert_record(ev1, ob1)

        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps = engine.evaluate_competing_hypotheses("example.com")
            self.assertEqual(len(hyps), 1)
            self.assertEqual(hyps[0].status, HypothesisStatus.INSUFFICIENT_EVIDENCE.value)
            self.assertEqual(hyps[0].heuristic_score, 0.0)
            self.assertFalse(hyps[0].statistically_calibrated)
            self.assertIn("Insufficient temporal observations", hyps[0].explanation)

    def test_cdn_rotation_competing_hypotheses(self):
        # Cloudflare published anycast IPs (104.16.132.229 and 104.16.133.229) across 2 epochs
        ev1, ob1 = make_test_event_and_obs("cdn.example.com", ["104.16.132.229"], "2026-11-21T08:00:00Z", ttl=300)
        ev2, ob2 = make_test_event_and_obs("cdn.example.com", ["104.16.133.229"], "2026-11-21T08:10:00Z", ttl=300)
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps = engine.evaluate_competing_hypotheses("cdn.example.com")
            self.assertEqual(len(hyps), 2)

            # Hypothesis 1: CDN Rotation should be FAVORED
            cdn_hyp = next(h for h in hyps if h.hypothesis_label == "Legitimate CDN / Anycast Edge Rotation")
            self.assertEqual(cdn_hyp.status, HypothesisStatus.FAVORED.value)
            self.assertGreaterEqual(cdn_hyp.heuristic_score, 0.8)
            self.assertIn(ev1.raw_sha256, cdn_hyp.supporting_evidence_hashes)
            self.assertIn(ev2.raw_sha256, cdn_hyp.supporting_evidence_hashes)
            self.assertEqual(len(cdn_hyp.contradicting_evidence_hashes), 0)

            # Hypothesis 2: Fast-Flux should be CONTRADICTED
            ff_hyp = next(h for h in hyps if h.hypothesis_label == "Suspicious Fast-Flux Candidate")
            self.assertEqual(ff_hyp.status, HypothesisStatus.CONTRADICTED.value)
            self.assertLessEqual(ff_hyp.heuristic_score, 0.2)
            self.assertIn(ev1.raw_sha256, ff_hyp.contradicting_evidence_hashes)
            self.assertIn(ev2.raw_sha256, ff_hyp.contradicting_evidence_hashes)

    def test_fast_flux_candidate_competing_hypotheses(self):
        # Non-CDN IPs across 4 distinct /24 subnets with low TTL (60s)
        ev1, ob1 = make_test_event_and_obs("flux.example.org", ["198.51.100.10", "203.0.113.20"], "2026-11-21T08:00:00Z", ttl=60)
        ev2, ob2 = make_test_event_and_obs("flux.example.org", ["192.0.2.30", "198.51.101.40"], "2026-11-21T08:05:00Z", ttl=60)
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps = engine.evaluate_competing_hypotheses("flux.example.org")
            self.assertEqual(len(hyps), 2)

            # Fast-Flux should be FAVORED
            ff_hyp = next(h for h in hyps if h.hypothesis_label == "Suspicious Fast-Flux Candidate")
            self.assertEqual(ff_hyp.status, HypothesisStatus.FAVORED.value)
            self.assertGreaterEqual(ff_hyp.heuristic_score, 0.8)

            # CDN should be CONTRADICTED
            cdn_hyp = next(h for h in hyps if h.hypothesis_label == "Legitimate CDN / Anycast Edge Rotation")
            self.assertEqual(cdn_hyp.status, HypothesisStatus.CONTRADICTED.value)
            self.assertLessEqual(cdn_hyp.heuristic_score, 0.2)

    def test_resolver_filtering_competing_hypotheses(self):
        # Insert observations and a security filtering discrepancy report
        ev1, ob1 = make_test_event_and_obs("blocked.example.com", ["93.184.216.34"], "2026-11-21T08:00:00Z", resolver="google")
        ev2, ob2 = make_test_event_and_obs("blocked.example.com", [], "2026-11-21T08:00:00Z", resolver="quad9", rcode=3)
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        disc = RealDiscrepancyReport(
            subject="blocked.example.com",
            kind="dns_a",
            analyzed_at="2026-11-21T08:06:00Z",
            verdict="SECURITY_FILTERING_DETECTED",
            category="POLICY_FILTER_BLOCK",
            explanation="Quad9 returned NXDOMAIN (threat blocking policy) while Google returned 93.184.216.34.",
            confidence=0.95,
            participating_resolvers=("google", "quad9"),
            answers_by_resolver={"google": ["93.184.216.34"], "quad9": []},
            dnssec_by_resolver={"google": "secure", "quad9": "indeterminate"},
            filtering_metadata={"blocked_by": ["quad9"]},
            evidence_ids={"google": ev1.event_id, "quad9": ev2.event_id},
            evidence_hashes={"google": ev1.raw_sha256, "quad9": ev2.raw_sha256},
            observation_ids={"google": ob1.observation_id, "quad9": ob2.observation_id},
        )
        self.store.insert_discrepancy(disc)

        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps = engine.evaluate_competing_hypotheses("blocked.example.com")
            filter_hyp = next((h for h in hyps if h.hypothesis_label == "Upstream Resolver Security Filtering"), None)
            geodns_hyp = next((h for h in hyps if h.hypothesis_label == "GeoDNS / Multi-Region Routing Divergence"), None)

            self.assertIsNotNone(filter_hyp)
            self.assertIsNotNone(geodns_hyp)
            self.assertEqual(filter_hyp.status, HypothesisStatus.FAVORED.value)
            self.assertEqual(geodns_hyp.status, HypothesisStatus.CONTRADICTED.value)
            self.assertIn(ev2.raw_sha256, filter_hyp.supporting_evidence_hashes)
            self.assertIn(ev1.raw_sha256, filter_hyp.contradicting_evidence_hashes)

    def test_hypothesis_persistence_and_supersession(self):
        ev1, ob1 = make_test_event_and_obs("evolving.example.com", ["104.16.1.1"], "2026-11-21T08:00:00Z")
        self.store.insert_record(ev1, ob1)

        # Initial run with 1 observation -> ABSTAINED
        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps_t1 = engine.evaluate_competing_hypotheses("evolving.example.com", as_of="2026-11-21T08:01:00Z")
            self.assertEqual(hyps_t1[0].status, HypothesisStatus.INSUFFICIENT_EVIDENCE.value)
            engine.persist_competing_hypotheses(hyps_t1)

        # Later run at t2 with second observation -> revised to FAVORED
        ev2, ob2 = make_test_event_and_obs("evolving.example.com", ["104.16.1.2"], "2026-11-21T08:10:00Z")
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps_t2 = engine.evaluate_competing_hypotheses("evolving.example.com", as_of="2026-11-21T08:11:00Z")
            cdn_hyp_t2 = next(h for h in hyps_t2 if h.hypothesis_label == "Legitimate CDN / Anycast Edge Rotation")
            self.assertEqual(cdn_hyp_t2.status, HypothesisStatus.FAVORED.value)
            engine.persist_competing_hypotheses(hyps_t2)

            # Verify historical preservation: both records remain in DB
            all_stored = engine.get_competing_hypotheses(format_node_id(NodeType.DOMAIN, "evolving.example.com"), include_superseded=True)
            self.assertGreaterEqual(len(all_stored), 2)

    def test_graph_projection(self):
        ev1, ob1 = make_test_event_and_obs("graph.example.com", ["104.16.1.1"], "2026-11-21T08:00:00Z")
        ev2, ob2 = make_test_event_and_obs("graph.example.com", ["104.16.1.2"], "2026-11-21T08:10:00Z")
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            engine = TemporalIntelligenceEngine(conn)
            hyps = engine.evaluate_competing_hypotheses("graph.example.com")
            nodes, edges = engine.project_hypotheses_to_graph(hyps)

            # Graph node validation
            self.assertEqual(len(nodes), len(hyps))
            for n in nodes:
                self.assertEqual(n.node_type, NodeType.HYPOTHESIS.value)
                self.assertEqual(n.layer, EpistemicLayer.HYPOTHESIS.value)

            # Graph edge validation
            explains_edges = [e for e in edges if e.relation_type == RelationType.EXPLAINS.value]
            self.assertEqual(len(explains_edges), len(hyps))
            for e in explains_edges:
                self.assertEqual(e.layer, EpistemicLayer.HYPOTHESIS.value)
                self.assertTrue(e.source_id.startswith("anie:entity:hypothesis:"))
                self.assertEqual(e.target_id, format_node_id(NodeType.DOMAIN, "graph.example.com"))


if __name__ == "__main__":
    unittest.main()

"""Unit and integration tests for Milestone M3.9: Cross-Vector Intelligence Correlation."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.cross_vector_correlation import (
    CrossVectorCorrelator,
    CrossVectorFinding,
    FindingState,
    FindingType,
    VectorObservationSummary,
)
from anie.graph_models import EpistemicLayer, GraphEdge, GraphNode, NodeType, RelationType
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore


def _make_dns_record(
    domain: str,
    ip: str,
    observed_at: str = "2026-11-20T10:00:00Z",
    resolver: str = "cloudflare",
) -> tuple[RealObservation, RealCollectionEvent]:
    raw_payload = f"raw_dns_{domain}_{ip}_{observed_at}_{resolver}".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=observed_at,
        target_endpoint=f"https://{resolver}-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity=resolver,
        wire_rcode="NOERROR",
        raw_evidence_status="captured",
    )
    event = RealCollectionEvent(
        request=req,
        response_code="ANSWER",
        raw_sha256=raw_hash,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id=f"first_party:doh:{resolver}",
        observed_at=observed_at,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=observed_at,
        values=(ip,),
        status="ok",
        source_id=f"first_party:doh:{resolver}",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    return obs, event


class TestM39CrossVectorCorrelation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_m39_cv.db"
        self.store = RealObservationStore(self.db_path)
        self.correlator = CrossVectorCorrelator(store=self.store)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_single_vector_abstention(self):
        """Verify that single-vector observations trigger explicit abstention."""
        obs_dns, ev_dns = _make_dns_record("example.com", "93.184.216.34")
        self.store.insert_record(ev_dns, obs_dns)

        findings = self.correlator.correlate_from_store("example.com")
        self.assertEqual(len(findings), 1)
        f = findings[0]

        self.assertTrue(f.abstention_state.abstained)
        self.assertEqual(f.abstention_state.reason, "INSUFFICIENT_MULTI_VECTOR_COVERAGE")
        self.assertEqual(f.abstention_state.participating_vectors, ["dns"])
        self.assertEqual(f.finding_type, FindingType.SINGLE_VECTOR_OBSERVATION.value)
        self.assertEqual(len(f.competing_hypotheses), 0)

    def test_cdn_provider_migration_correlation(self):
        """Verify DNS + TLS + HTTP correlation correctly favors CDN Migration hypothesis."""
        domain = "cloud-migrated.com"
        cdn_ip = "104.16.132.229"  # Cloudflare published prefix

        obs_dns, ev_dns = _make_dns_record(domain, cdn_ip)
        self.store.insert_record(ev_dns, obs_dns)

        # Add TLS cert and HTTP tech nodes to graph to test store-based multi-vector correlation
        with self.store._connect() as conn:
            # TLS Certificate Node and Edge
            cert_hash = hashlib.sha256(b"cert_cf_test").hexdigest()
            cert_node_id = f"anie:entity:cert:{cert_hash}"
            conn.execute(
                """
                INSERT INTO graph_nodes (node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json, payload)
                VALUES (?, 'certificate', ?, 'FACT', '2026-11-20T10:05:00Z', '2026-11-20T10:05:00Z', ?, '{}')
                """,
                (cert_node_id, cert_hash, json.dumps({"san_names": [domain, f"*.{domain}"], "issuer": "Cloudflare Inc ECC CA-3"})),
            )
            conn.execute(
                """
                INSERT INTO graph_edges (edge_id, source_id, target_id, relation_type, layer, observed_at, valid_from, valid_until, confidence, ruleset_version, evidence_hashes_json, properties_json, payload)
                VALUES (?, ?, ?, 'SAN_FOR', 'DERIVED', '2026-11-20T10:05:00Z', '2026-11-20T10:05:00Z', NULL, 1.0, 'v1', ?, '{}', '{}')
                """,
                ("edge_tls_1", cert_node_id, f"anie:entity:domain:{domain}", json.dumps([cert_hash])),
            )

            # HTTP Technology Node and Edge
            tech_node_id = "anie:entity:tech:cloudflare"
            http_hash = hashlib.sha256(b"http_cf_test").hexdigest()
            conn.execute(
                """
                INSERT INTO graph_nodes (node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json, payload)
                VALUES (?, 'technology', 'cloudflare', 'DERIVED', '2026-11-20T10:10:00Z', '2026-11-20T10:10:00Z', ?, '{}')
                """,
                (tech_node_id, json.dumps({"server": "cloudflare", "hsts_present": True})),
            )
            conn.execute(
                """
                INSERT INTO graph_edges (edge_id, source_id, target_id, relation_type, layer, observed_at, valid_from, valid_until, confidence, ruleset_version, evidence_hashes_json, properties_json, payload)
                VALUES (?, ?, ?, 'USES_TECHNOLOGY', 'DERIVED', '2026-11-20T10:10:00Z', '2026-11-20T10:10:00Z', NULL, 0.9, 'v1', ?, '{}', '{}')
                """,
                ("edge_http_1", f"anie:entity:domain:{domain}", tech_node_id, json.dumps([http_hash])),
            )

        findings = self.correlator.correlate_from_store(domain)
        self.assertEqual(len(findings), 1)
        f = findings[0]

        self.assertFalse(f.abstention_state.abstained)
        self.assertEqual(f.finding_type, FindingType.CDN_PROVIDER_MIGRATION.value)
        self.assertEqual(sorted(f.abstention_state.participating_vectors), ["dns", "http", "tls"])

        # Temporal correlation vs causation assertion
        self.assertTrue(f.temporal_correlation_vs_causation.coincident_change_detected)
        self.assertFalse(f.temporal_correlation_vs_causation.causation_inferred)
        self.assertIn("causal dependency is not assumed", f.temporal_correlation_vs_causation.analysis)

        # Competing Hypotheses evaluation
        self.assertGreaterEqual(len(f.competing_hypotheses), 2)
        hyp_cdn = next(h for h in f.competing_hypotheses if "CDN" in h.hypothesis_label)
        self.assertEqual(hyp_cdn.status, "FAVORED")
        self.assertGreaterEqual(hyp_cdn.heuristic_score, 0.85)

        hyp_div = next(h for h in f.competing_hypotheses if "Divergence" in h.hypothesis_label)
        self.assertEqual(hyp_div.status, "CONTRADICTED")
        self.assertLessEqual(hyp_div.heuristic_score, 0.20)

    def test_routine_certificate_renewal_correlation(self):
        """Verify that routine TLS renewal without DNS/HTTP shifts favors Renewal hypothesis."""
        domain = "stable-corp.org"
        static_ip = "198.51.100.50"  # Non-CDN stable IP

        obs_dns, ev_dns = _make_dns_record(domain, static_ip)
        self.store.insert_record(ev_dns, obs_dns)

        with self.store._connect() as conn:
            cert_hash = hashlib.sha256(b"cert_renewal_test").hexdigest()
            cert_node_id = f"anie:entity:cert:{cert_hash}"
            conn.execute(
                """
                INSERT INTO graph_nodes (node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json, payload)
                VALUES (?, 'certificate', ?, 'FACT', '2026-11-20T10:05:00Z', '2026-11-20T10:05:00Z', ?, '{}')
                """,
                (cert_node_id, cert_hash, json.dumps({"san_names": [domain], "issuer": "Let's Encrypt Authority X3"})),
            )
            conn.execute(
                """
                INSERT INTO graph_edges (edge_id, source_id, target_id, relation_type, layer, observed_at, valid_from, valid_until, confidence, ruleset_version, evidence_hashes_json, properties_json, payload)
                VALUES (?, ?, ?, 'SAN_FOR', 'DERIVED', '2026-11-20T10:05:00Z', '2026-11-20T10:05:00Z', NULL, 1.0, 'v1', ?, '{}', '{}')
                """,
                ("edge_tls_2", cert_node_id, f"anie:entity:domain:{domain}", json.dumps([cert_hash])),
            )

        findings = self.correlator.correlate_from_store(domain)
        self.assertEqual(len(findings), 1)
        f = findings[0]

        self.assertEqual(f.finding_type, FindingType.ROUTINE_CERTIFICATE_ROTATION.value)
        hyp_renewal = next(h for h in f.competing_hypotheses if "Renewal" in h.hypothesis_label)
        self.assertEqual(hyp_renewal.status, "FAVORED")
        self.assertGreaterEqual(hyp_renewal.heuristic_score, 0.80)

    def test_multi_vector_divergence_san_mismatch(self):
        """Verify that a SAN mismatch between DNS destination and served TLS cert favors Divergence."""
        domain = "target-site.com"
        target_ip = "192.0.2.88"

        obs_dns, ev_dns = _make_dns_record(domain, target_ip)
        self.store.insert_record(ev_dns, obs_dns)

        with self.store._connect() as conn:
            # Cert does NOT include target-site.com in SANs!
            cert_hash = hashlib.sha256(b"cert_divergence_test").hexdigest()
            cert_node_id = f"anie:entity:cert:{cert_hash}"
            conn.execute(
                """
                INSERT INTO graph_nodes (node_id, node_type, canonical_name, layer, first_observed_at, last_observed_at, properties_json, payload)
                VALUES (?, 'certificate', ?, 'FACT', '2026-11-20T10:05:00Z', '2026-11-20T10:05:00Z', ?, '{}')
                """,
                (cert_node_id, cert_hash, json.dumps({"san_names": ["unrelated-site.net"], "issuer": "DigiCert Global Root"})),
            )
            conn.execute(
                """
                INSERT INTO graph_edges (edge_id, source_id, target_id, relation_type, layer, observed_at, valid_from, valid_until, confidence, ruleset_version, evidence_hashes_json, properties_json, payload)
                VALUES (?, ?, ?, 'SAN_FOR', 'DERIVED', '2026-11-20T10:05:00Z', '2026-11-20T10:05:00Z', NULL, 1.0, 'v1', ?, '{}', '{}')
                """,
                ("edge_tls_3", cert_node_id, f"anie:entity:domain:{domain}", json.dumps([cert_hash])),
            )

        findings = self.correlator.correlate_from_store(domain)
        self.assertEqual(len(findings), 1)
        f = findings[0]

        self.assertEqual(f.finding_type, FindingType.MULTI_VECTOR_DIVERGENCE.value)
        hyp_div = next(h for h in f.competing_hypotheses if "Divergence" in h.hypothesis_label)
        self.assertEqual(hyp_div.status, "FAVORED")
        self.assertGreaterEqual(hyp_div.heuristic_score, 0.80)
        self.assertIn("TLS SAN failed to include domain", hyp_div.explanation)

    def test_deterministic_finding_serialization(self):
        """Verify that findings serialize and deserialize cleanly without loss."""
        domain = "serializable.com"
        vec_dns = VectorObservationSummary(
            vector="dns",
            observed_at="2026-11-20T10:00:00Z",
            evidence_id="ev_dns_1",
            evidence_hash=hashlib.sha256(b"ev_dns_1").hexdigest(),
            values=["104.16.1.1"],
        )
        vec_tls = VectorObservationSummary(
            vector="tls",
            observed_at="2026-11-20T10:05:00Z",
            evidence_id="ev_tls_1",
            evidence_hash=hashlib.sha256(b"ev_tls_1").hexdigest(),
            values=["cert_abc"],
            metadata={"san_names": [domain]},
        )

        findings = self.correlator.correlate_records(domain, vectors={"dns": vec_dns, "tls": vec_tls})
        self.assertEqual(len(findings), 1)
        original = findings[0]

        d = original.to_dict()
        reconstructed = CrossVectorFinding.from_dict(d)

        self.assertEqual(original.finding_id, reconstructed.finding_id)
        self.assertEqual(original.subject_uri, reconstructed.subject_uri)
        self.assertEqual(original.finding_type, reconstructed.finding_type)
        self.assertEqual(len(original.competing_hypotheses), len(reconstructed.competing_hypotheses))


if __name__ == "__main__":
    unittest.main()

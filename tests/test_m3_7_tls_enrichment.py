"""Tests for Milestone 3.7: Multi-Vector Observable Ingestion (Passive TLS & X.509 Certificate Correlation).

Verifies:
1. Cryptographic parsing of X.509 DER and PEM certificates (RFC 5280).
2. Extraction of immutable SHA-256 fingerprints, SPKI digests, and normalized SANs.
3. Multi-tenant CDN / PaaS guardrails preventing false guilt-by-association.
4. Deterministic graph entity and typed edge extraction (SERVES_CERTIFICATE, NAMES_DOMAIN).
5. Graph neighborhood traversal and 1-hop query performance (<10 ms).
6. Obsidian vault export rendering with bidirectional markdown wikilinks.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from anie.canonical_entities import (
    canonical_cert_uri,
    canonicalize_cert_fingerprint,
    parse_canonical_uri,
)
from anie.graph_engine import GraphEngine
from anie.graph_models import (
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
    format_node_id,
)
from anie.tls_enrichment import (
    TlsCertificateRecord,
    TlsEnricher,
    parse_der_certificate,
    parse_pem_certificate,
)


def _generate_test_certificate(
    subject_cn: str,
    san_list: list[str],
    issuer_org: str = "Test CA Ltd",
    is_self_signed: bool = False,
    days_valid: int = 90,
) -> tuple[bytes, str]:
    """Helper to generate a self-contained in-memory X.509 certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    issuer = subject if is_self_signed else x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer_org} Intermediate"),
    ])

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
    )

    if san_list:
        sans = [x509.DNSName(name) for name in san_list]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    der_bytes = cert.public_bytes(Encoding.DER)
    pem_text = cert.public_bytes(Encoding.PEM).decode("utf-8")
    return der_bytes, pem_text


class TestTlsCertificateParsing(unittest.TestCase):
    """Test cryptographic parsing and normalization of X.509 certificates."""

    def test_parse_der_and_pem_equality(self):
        der_bytes, pem_text = _generate_test_certificate(
            subject_cn="example.org",
            san_list=["example.org", "www.example.org", "api.example.org"],
            issuer_org="Let's Encrypt",
        )

        rec_der = parse_der_certificate(der_bytes)
        rec_pem = parse_pem_certificate(pem_text)

        self.assertEqual(rec_der.sha256_fingerprint, rec_pem.sha256_fingerprint)
        self.assertEqual(rec_der.spki_sha256, rec_pem.spki_sha256)
        self.assertEqual(rec_der.subject_cn, "example.org")
        self.assertIn("www.example.org", rec_der.subject_alt_names)
        self.assertIn("api.example.org", rec_der.subject_alt_names)
        self.assertEqual(rec_der.issuer_org, "Let's Encrypt")
        self.assertFalse(rec_der.is_self_signed)
        self.assertEqual(len(rec_der.sha256_fingerprint), 64)

    def test_self_signed_certificate_detection(self):
        der_bytes, _ = _generate_test_certificate(
            subject_cn="selfsigned.local",
            san_list=["selfsigned.local"],
            is_self_signed=True,
        )
        rec = parse_der_certificate(der_bytes)
        self.assertTrue(rec.is_self_signed)
        self.assertEqual(rec.subject_cn, "selfsigned.local")

    def test_multi_tenant_guardrail_classification(self):
        # 1. High-density SAN certificate (>= 15 domains)
        dense_sans = [f"client-{i:02d}.saas-tenant.com" for i in range(20)]
        der_dense, _ = _generate_test_certificate(
            subject_cn="edge.saas-tenant.com",
            san_list=dense_sans,
        )
        rec_dense = parse_der_certificate(der_dense)
        self.assertTrue(rec_dense.is_multi_tenant)
        self.assertIn("High-density SAN", rec_dense.multi_tenant_reason or "")

        # 2. Known CDN / PaaS domain suffix (e.g. cloudflare.com)
        der_cdn, _ = _generate_test_certificate(
            subject_cn="edge.customer.com",
            san_list=["edge.customer.com", "sni.cloudflare.com"],
        )
        rec_cdn = parse_der_certificate(der_cdn)
        self.assertTrue(rec_cdn.is_multi_tenant)
        self.assertIn("cloudflare.com", rec_cdn.multi_tenant_reason or "")

        # 3. Standard single-organization certificate
        der_std, _ = _generate_test_certificate(
            subject_cn="internal.corp.net",
            san_list=["internal.corp.net", "mail.corp.net"],
        )
        rec_std = parse_der_certificate(der_std)
        self.assertFalse(rec_std.is_multi_tenant)
        self.assertIsNone(rec_std.multi_tenant_reason)


class TestTlsEnrichmentAndGraphIntegration(unittest.TestCase):
    """Test graph extraction, typed relationships, and Obsidian markdown generation."""

    def setUp(self):
        self.enricher = TlsEnricher()

    def test_enrich_endpoint_generates_typed_nodes_and_edges(self):
        der_bytes, _ = _generate_test_certificate(
            subject_cn="portal.acme.org",
            san_list=["portal.acme.org", "auth.acme.org", "status.acme.org"],
            issuer_org="DigiCert Inc",
        )
        rec = parse_der_certificate(der_bytes)

        dummy_evidence_hash = "f" * 64
        nodes, edges = self.enricher.enrich_endpoint(
            ip="198.51.100.25",
            cert_record=rec,
            observed_at="2026-11-21T10:00:00Z",
            evidence_hashes=[dummy_evidence_hash],
            port=443,
        )

        # 1 Certificate node
        self.assertEqual(len(nodes), 1)
        cert_node = nodes[0]
        self.assertEqual(cert_node.node_type, NodeType.CERTIFICATE.value)
        self.assertEqual(cert_node.layer, EpistemicLayer.FACT.value)
        self.assertEqual(cert_node.node_id, f"anie:entity:cert:{rec.sha256_fingerprint}")
        self.assertEqual(cert_node.properties["subject_cn"], "portal.acme.org")

        # Edges: 1 SERVES_CERTIFICATE (IP -> Cert) + 3 NAMES_DOMAIN (Cert -> Domains)
        self.assertEqual(len(edges), 4)

        serves_edge = [e for e in edges if e.relation_type == RelationType.SERVES_CERTIFICATE.value][0]
        self.assertEqual(serves_edge.source_id, "anie:entity:ip:198.51.100.25")
        self.assertEqual(serves_edge.target_id, cert_node.node_id)
        self.assertEqual(serves_edge.layer, EpistemicLayer.FACT.value)
        self.assertIn(dummy_evidence_hash, serves_edge.evidence_hashes)
        self.assertEqual(serves_edge.properties["port"], 443)

        names_edges = [e for e in edges if e.relation_type == RelationType.NAMES_DOMAIN.value]
        self.assertEqual(len(names_edges), 3)
        for ne in names_edges:
            self.assertEqual(ne.source_id, cert_node.node_id)
            self.assertEqual(ne.layer, EpistemicLayer.DERIVED.value)
            self.assertIn(dummy_evidence_hash, ne.evidence_hashes)

    def test_graph_neighborhood_query_and_obsidian_export(self):
        der_bytes, _ = _generate_test_certificate(
            subject_cn="secure.example.com",
            san_list=["secure.example.com", "login.example.com"],
            issuer_org="Let's Encrypt",
        )
        rec = parse_der_certificate(der_bytes)

        from anie.real_store import RealObservationStore

        with TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_tls.sqlite"
            store = RealObservationStore(db_path)

            with store._connect() as conn:
                engine = GraphEngine(conn)
                nodes, edges = self.enricher.enrich_endpoint(
                    ip="198.51.100.77",
                    cert_record=rec,
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_hashes=["e" * 64],
                )
                # Add IP and Domain nodes for all SANs so neighborhood traversal and foreign keys succeed
                ip_node = GraphNode(
                    node_id="anie:entity:ip:198.51.100.77",
                    node_type="ip",
                    canonical_name="198.51.100.77",
                    layer="FACT",
                    first_observed_at="2026-11-21T10:00:00Z",
                    last_observed_at="2026-11-21T10:00:00Z",
                )
                engine.upsert_node(ip_node)

                for san in rec.subject_alt_names:
                    dom_node = GraphNode(
                        node_id=f"anie:entity:domain:{san}",
                        node_type="domain",
                        canonical_name=san,
                        layer="FACT",
                        first_observed_at="2026-11-21T10:00:00Z",
                        last_observed_at="2026-11-21T10:00:00Z",
                    )
                    engine.upsert_node(dom_node)

                for n in nodes:
                    engine.upsert_node(n)
                for e in edges:
                    engine.insert_edge(e)

                # Test 1-hop traversal from IP -> discovers Certificate
                t0 = time.perf_counter()
                hood_ip = engine.get_k_hop_neighborhood("anie:entity:ip:198.51.100.77", max_depth=1)
                t_ms = (time.perf_counter() - t0) * 1000.0

                self.assertLess(t_ms, 10.0, f"1-hop query latency {t_ms:.2f} ms exceeds 10 ms budget")
                cert_nodes_in_hood = [n for n in hood_ip["nodes"] if n["node_type"] == "certificate"]
                self.assertEqual(len(cert_nodes_in_hood), 1)
                self.assertEqual(cert_nodes_in_hood[0]["canonical_name"], rec.sha256_fingerprint)

                # Test Obsidian Vault Export
                with TemporaryDirectory() as tmp_vault:
                    vault_path = Path(tmp_vault)
                    res = engine.export_obsidian_vault(vault_path)

                    self.assertEqual(res["certs_exported"], 1)
                    self.assertEqual(res["ips_exported"], 1)

                    cert_note_path = vault_path / "certificates" / f"{rec.sha256_fingerprint}.md"
                    self.assertTrue(cert_note_path.exists(), "Certificate note should be exported into vault/certificates/")

                    cert_note_text = cert_note_path.read_text(encoding="utf-8")
                    self.assertIn('type: "certificate"', cert_note_text)
                    self.assertIn(f'fingerprint_sha256: "{rec.sha256_fingerprint}"', cert_note_text)
                    self.assertIn("[[ips/198.51.100.77|198.51.100.77]]", cert_note_text)
                    self.assertIn("[[secure.example.com]]", cert_note_text)

                    readme_text = (vault_path / "README.md").read_text(encoding="utf-8")
                    self.assertIn("- **TLS Certificates:** 1", readme_text)
                    self.assertIn("- [[certificates/|TLS Certificates]]", readme_text)


if __name__ == "__main__":
    unittest.main()

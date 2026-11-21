"""Unit tests for M3.8 Passive HTTP Response Metadata Enrichment."""
import hashlib
import unittest

from anie.graph_models import EpistemicLayer, NodeType, RelationType
from anie.http_enrichment import (
    HttpEnricher,
    HttpResponseRecord,
    ObservedHttpEndpointEvidence,
    parse_http1_response_headers,
    parse_http2_response_headers,
)


class TestHttpEnrichment(unittest.TestCase):
    def setUp(self):
        self.evidence_hash = "a" * 64
        self.evidence = ObservedHttpEndpointEvidence(
            ip="104.16.132.229",
            port=443,
            sni_or_host="example.com",
            observed_at="2026-11-21T08:00:00Z",
            source_id="oracle-collector-01:http",
            evidence_hash=self.evidence_hash,
            http_version="HTTP/1.1",
        )

    def test_parse_http1_clean(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: cloudflare\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
            b"CF-RAY: 8527a92c-DFW\r\n"
            b"\r\n"
            b"<!DOCTYPE html><html><body>Ignored Body</body></html>"
        )
        rec = parse_http1_response_headers(raw)
        self.assertEqual(rec.status_code, 200)
        self.assertEqual(rec.http_version, "HTTP/1.1")
        self.assertEqual(rec.server, "cloudflare")
        self.assertEqual(rec.content_type, "text/html")
        self.assertEqual(rec.hsts_max_age, 31536000)
        self.assertTrue(rec.hsts_include_subdomains)
        self.assertIn("cloudflare", rec.technology_indicators)
        self.assertTrue(len(rec.canonical_header_hash) == 64)

    def test_sensitive_header_stripping(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.24\r\n"
            "Set-Cookie: session_id=SECRET123; Secure; HttpOnly\r\n"
            "Authorization: Bearer supersecrettoken\r\n"
            "X-Api-Key: secretkey999\r\n"
            "X-Forwarded-For: 198.51.100.1\r\n"
            "Content-Type: application/json\r\n"
        )
        rec = parse_http1_response_headers(raw)
        header_names = [h[0] for h in rec.canonical_headers]
        self.assertNotIn("set-cookie", header_names)
        self.assertNotIn("authorization", header_names)
        self.assertNotIn("x-api-key", header_names)
        self.assertNotIn("x-forwarded-for", header_names)
        self.assertIn("server", header_names)
        self.assertIn("content-type", header_names)

    def test_parse_http2_headers(self):
        headers = [
            (":status", "200"),
            ("server", "nginx"),
            ("via", "1.1 varnish"),
            ("content-security-policy", "default-src 'self'"),
            ("set-cookie", "leak=should_be_stripped"),
        ]
        rec = parse_http2_response_headers(headers)
        self.assertEqual(rec.status_code, 200)
        self.assertEqual(rec.http_version, "HTTP/2")
        self.assertEqual(rec.server, "nginx")
        self.assertEqual(rec.via, "1.1 varnish")
        self.assertTrue(rec.csp_present)
        self.assertIn("nginx", rec.technology_indicators)
        self.assertIn("varnish", rec.technology_indicators)
        header_names = [h[0] for h in rec.canonical_headers]
        self.assertNotIn("set-cookie", header_names)

    def test_malformed_inputs_rejected(self):
        with self.assertRaises(ValueError):
            parse_http1_response_headers(b"")
        with self.assertRaises(ValueError):
            parse_http1_response_headers(b"NOT_HTTP 200 OK\r\n")
        with self.assertRaises(ValueError):
            parse_http1_response_headers(b"HTTP/1.1 999 InvalidCode\r\n")
        with self.assertRaises(ValueError):
            parse_http2_response_headers([("server", "caddy")])  # missing :status

    def test_bounded_header_limits(self):
        # Generate 100 headers, exceeding the max 64 ceiling
        lines = ["HTTP/1.1 200 OK"]
        for i in range(100):
            lines.append(f"X-Custom-{i}: value-{i}")
        lines.append("Server: apache")
        raw = "\r\n".join(lines)
        rec = parse_http1_response_headers(raw)
        self.assertLessEqual(len(rec.canonical_headers), 64)

    def test_graph_enrichment(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: cloudflare\r\n"
            b"Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
        )
        rec = parse_http1_response_headers(raw)
        enricher = HttpEnricher()
        nodes, edges = enricher.enrich_http_metadata(rec, self.evidence)

        # Nodes
        node_types = {n.node_type for n in nodes}
        self.assertIn(NodeType.DOMAIN.value, node_types)
        self.assertIn(NodeType.IP.value, node_types)
        self.assertIn(NodeType.TECHNOLOGY.value, node_types)

        # Epistemic layers
        tech_nodes = [n for n in nodes if n.node_type == NodeType.TECHNOLOGY.value]
        for tn in tech_nodes:
            self.assertEqual(tn.layer, EpistemicLayer.DERIVED.value)
            self.assertTrue(tn.properties.get("is_spoofable") or tn.canonical_name == "hsts-policy")

        # Edges
        rel_types = {e.relation_type for e in edges}
        self.assertIn(RelationType.USES_TECHNOLOGY.value, rel_types)
        self.assertIn(RelationType.PROTECTED_BY_POLICY.value, rel_types)

        for e in edges:
            self.assertEqual(e.layer, EpistemicLayer.DERIVED.value)
            self.assertLessEqual(e.confidence, 0.95)
            self.assertIn(self.evidence_hash, e.evidence_hashes)


if __name__ == "__main__":
    unittest.main()

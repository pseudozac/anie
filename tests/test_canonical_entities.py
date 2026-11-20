"""Tests for canonical entity identifiers and URI normalization (Phase 3.5)."""
from __future__ import annotations

import unittest

from anie.canonical_entities import (
    EntityType,
    canonical_asn_uri,
    canonical_cidr_uri,
    canonical_claim_uri,
    canonical_discrepancy_uri,
    canonical_domain_uri,
    canonical_ipv4_uri,
    canonical_ipv6_uri,
    canonical_resolver_uri,
    entity_uri_to_node_id,
    node_id_to_canonical_uri,
    parse_canonical_uri,
    validate_canonical_uri,
)


class TestCanonicalEntities(unittest.TestCase):
    def test_canonical_domain_uri(self):
        self.assertEqual(canonical_domain_uri("EXAMPLE.COM"), "domain:example.com")
        self.assertEqual(canonical_domain_uri("example.com."), "domain:example.com")
        self.assertEqual(canonical_domain_uri("sub.EXAMPLE.co.uk."), "domain:sub.example.co.uk")
        # Internationalized domain name (IDN) to punycode
        self.assertEqual(canonical_domain_uri("münchen.de"), "domain:xn--mnchen-3ya.de")

        # Invalid domains
        with self.assertRaises(ValueError):
            canonical_domain_uri("")
        with self.assertRaises(ValueError):
            canonical_domain_uri("   ")
        with self.assertRaises(ValueError):
            canonical_domain_uri("invalid space.com")

    def test_canonical_ipv4_uri(self):
        self.assertEqual(canonical_ipv4_uri("192.0.2.1"), "ipv4:192.0.2.1")
        self.assertEqual(canonical_ipv4_uri("10.0.0.1"), "ipv4:10.0.0.1")

        with self.assertRaises(ValueError):
            canonical_ipv4_uri("010.0.0.1")  # Leading zeros prohibited to prevent octal confusion
        with self.assertRaises(ValueError):
            canonical_ipv4_uri("999.999.999.999")
        with self.assertRaises(ValueError):
            canonical_ipv4_uri("2001:db8::1")
        with self.assertRaises(ValueError):
            canonical_ipv4_uri("not-an-ip")

    def test_canonical_ipv6_uri(self):
        # RFC 5952 compression
        self.assertEqual(canonical_ipv6_uri("2001:0db8:0000:0000:0000:0000:0000:0001"), "ipv6:2001:db8::1")
        self.assertEqual(canonical_ipv6_uri("2606:2800:220:1:248:1893:25c8:1946"), "ipv6:2606:2800:220:1:248:1893:25c8:1946")

        with self.assertRaises(ValueError):
            canonical_ipv6_uri("192.0.2.1")
        with self.assertRaises(ValueError):
            canonical_ipv6_uri("invalid::ipv6:::1")

    def test_canonical_asn_uri(self):
        self.assertEqual(canonical_asn_uri(15169), "asn:AS15169")
        self.assertEqual(canonical_asn_uri("15169"), "asn:AS15169")
        self.assertEqual(canonical_asn_uri("as15169"), "asn:AS15169")
        self.assertEqual(canonical_asn_uri("AS13335"), "asn:AS13335")

        with self.assertRaises(ValueError):
            canonical_asn_uri(-1)
        with self.assertRaises(ValueError):
            canonical_asn_uri("not_an_as")

    def test_canonical_cidr_uri(self):
        self.assertEqual(canonical_cidr_uri("192.0.2.0/24"), "cidr:192.0.2.0/24")
        self.assertEqual(canonical_cidr_uri("192.0.2.1/24"), "cidr:192.0.2.0/24")
        self.assertEqual(canonical_cidr_uri("2001:db8::/32"), "cidr:2001:db8::/32")

        with self.assertRaises(ValueError):
            canonical_cidr_uri("192.0.2.0/33")
        with self.assertRaises(ValueError):
            canonical_cidr_uri("invalid_cidr")

    def test_canonical_resolver_uri(self):
        self.assertEqual(canonical_resolver_uri("Cloudflare"), "resolver:cloudflare")
        self.assertEqual(canonical_resolver_uri("GOOGLE_DNS"), "resolver:google_dns")

        with self.assertRaises(ValueError):
            canonical_resolver_uri("")
        with self.assertRaises(ValueError):
            canonical_resolver_uri("   ")

    def test_canonical_claim_and_discrepancy_uri(self):
        self.assertEqual(canonical_claim_uri("claim_12345abcdef"), "claim:12345abcdef")
        self.assertEqual(canonical_claim_uri("12345abcdef"), "claim:12345abcdef")

        self.assertEqual(canonical_discrepancy_uri("discrepancy_abcdef123"), "discrepancy:abcdef123")
        self.assertEqual(canonical_discrepancy_uri("abcdef123"), "discrepancy:abcdef123")

        with self.assertRaises(ValueError):
            canonical_claim_uri("")
        with self.assertRaises(ValueError):
            canonical_discrepancy_uri("")

    def test_parse_and_validate_canonical_uri(self):
        valid_cases = [
            ("domain:example.com", EntityType.DOMAIN, "example.com"),
            ("ipv4:192.0.2.1", EntityType.IPV4, "192.0.2.1"),
            ("ipv6:2001:db8::1", EntityType.IPV6, "2001:db8::1"),
            ("asn:AS15169", EntityType.ASN, "AS15169"),
            ("cidr:192.0.2.0/24", EntityType.CIDR, "192.0.2.0/24"),
            ("resolver:cloudflare", EntityType.RESOLVER, "cloudflare"),
            ("claim:0123456789abcdef", EntityType.CLAIM, "0123456789abcdef"),
            ("discrepancy:0123456789abcdef", EntityType.DISCREPANCY, "0123456789abcdef"),
        ]

        for uri, expected_type, expected_id in valid_cases:
            self.assertTrue(validate_canonical_uri(uri), f"Expected {uri} to be valid")
            etype, eid = parse_canonical_uri(uri)
            self.assertEqual(etype, expected_type)
            self.assertEqual(eid, expected_id)

        invalid_cases = [
            "invalid_uri_without_prefix",
            "unknown:scheme",
            "domain:",
            "ipv4:999.999.999.999",
            "ipv6:::invalid::1",
            "asn:AS_NOT_INT",
            "cidr:invalid_cidr",
            "resolver:",
            ":empty_prefix",
        ]

        for inv in invalid_cases:
            self.assertFalse(validate_canonical_uri(inv), f"Expected {inv} to be invalid")
            with self.assertRaises(ValueError):
                parse_canonical_uri(inv)

    def test_node_id_interop(self):
        uri = "domain:example.com"
        node_id = entity_uri_to_node_id(uri)
        self.assertEqual(node_id, "example.com")
        self.assertEqual(node_id_to_canonical_uri(node_id, "DOMAIN"), uri)

        ip_uri = "ipv4:1.1.1.1"
        self.assertEqual(entity_uri_to_node_id(ip_uri), "1.1.1.1")
        self.assertEqual(node_id_to_canonical_uri("1.1.1.1", "IPV4"), ip_uri)


if __name__ == "__main__":
    unittest.main()

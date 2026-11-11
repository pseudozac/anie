import unittest
from anie.observations import Observation
from anie.collectors import synthetic_dns, synthetic_rdap_network

STAMP = "2026-11-11T08:00:00Z"


def obs(**overrides):
    d = dict(subject="EXAMPLE.TEST.", kind="dns_a", values=["192.0.2.1"], status="ok", observed_at=STAMP, source_id="synthetic:unit", method="synthetic", synthetic=True, ttl_seconds=300)
    d.update(overrides)
    return Observation.from_dict(d)


class TestObservations(unittest.TestCase):
    def test_canonical_id_and_dedup_normalization(self):
        a = obs(values=["192.0.2.2", "192.0.2.1", "192.0.2.1"])
        b = obs(subject="example.test", values=["192.0.2.1", "192.0.2.2"])
        self.assertEqual(a.observation_id, b.observation_id)
        self.assertEqual(a.subject, "example.test")

    def test_dns_family(self):
        with self.assertRaises(ValueError):
            obs(kind="dns_aaaa", values=["192.0.2.1"])
        self.assertEqual(obs(kind="dns_aaaa", values=["2001:db8::1"]).values, ("2001:db8::1",))

    def test_error_not_negative(self):
        with self.assertRaises(ValueError):
            obs(status="error", values=[], error_code=None)
        with self.assertRaises(ValueError):
            obs(status="error", values=["192.0.2.1"], error_code="timeout")
        self.assertEqual(obs(status="error", values=[], error_code="timeout").status, "error")
        self.assertEqual(obs(status="empty", values=[]).status, "empty")

    def test_timestamp_and_source_strict(self):
        for key, val in [("observed_at", "2026-11-11T08:00:00"), ("source_id", "x\nAuthorization: token"), ("ttl_seconds", -1), ("synthetic", False), ("subject", "-bad.test")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                obs(**{key: val})

    def test_rdap_cidr_containment(self):
        rdap = synthetic_rdap_network("203.0.113.10", {"objectClassName": "ip network", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]}, STAMP)
        self.assertEqual(rdap.values, ("203.0.113.0/24",))
        with self.assertRaises(ValueError):
            synthetic_rdap_network("192.0.2.10", {"objectClassName": "ip network", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]}, STAMP)

    def test_dns_fixture_collector(self):
        self.assertEqual(synthetic_dns("example.test", "A", ["192.0.2.8"], STAMP).values, ("192.0.2.8",))
        with self.assertRaises(ValueError):
            synthetic_dns("example.test", "TXT", ["anything"], STAMP)

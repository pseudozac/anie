"""Offline ANIE v0.2 collection demo: synthetic-only and no network calls."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile

from anie.collection_policy import CollectionPolicy
from anie.collection_pipeline import OfflineCollector, FixtureTransport
from anie.collection_ledger import CollectionLedger

DOMAIN = "sample.example.test"
IP = "203.0.113.17"

fixtures = {
    ("dns_a", DOMAIN): {
        "protocol": "dns", "qtype": "A", "question": DOMAIN,
        "rcode": "NOERROR", "answers": [{"type": "A", "value": "192.0.2.8", "ttl": 60}],
        "complete": True, "truncated": False,
    },
    ("rdap_network", IP): {
        "protocol": "rdap", "http_status": 200,
        "body": {"objectClassName": "ip network", "ipVersion": "v4",
                 "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
                 "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]},
    },
}

policy = CollectionPolicy(targets=frozenset({DOMAIN, IP}), kinds=frozenset({"dns_a", "rdap_network"}))
collector = OfflineCollector(policy, FixtureTransport(fixtures))

with tempfile.TemporaryDirectory(prefix="anie-offline-") as tmp:
    ledger = CollectionLedger(Path(tmp) / "collection.sqlite")
    events = [collector.collect("dns_a", DOMAIN, "2026-11-11T09:00:00Z"),
              collector.collect("rdap_network", IP, "2026-11-11T09:00:00Z")]
    for event in events:
        ledger.add(event)
    assert len(ledger.by_subject(DOMAIN)) == 1
    assert len(ledger.by_subject(IP)) == 1
    print(json.dumps({"offline": True, "network_requests": 0,
                      "events": [{"kind": e.request.kind, "outcome": e.response_code,
                                  "observation_id": e.observation.observation_id} for e in events]},
                     indent=2))

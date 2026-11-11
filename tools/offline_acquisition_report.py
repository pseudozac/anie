"""Bounded synthetic cache benchmark: deterministic workload, offline only.

Reports process-local counters and local resource usage; NO internet metrics,
no real DNS/RDAP service latency claims or production cost estimates.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import tracemalloc

from anie.collection_policy import CollectionPolicy
from anie.collection_pipeline import FixtureTransport, OfflineCollector
from anie.collection_ledger import CollectionLedger
from anie.offline_scheduler import OfflineCollectionScheduler

DOMAIN = "sample.example.test"
RESPONSE = {
    "protocol": "dns", "qtype": "A", "question": DOMAIN, "rcode": "NOERROR",
    "answers": [{"type": "A", "value": "192.0.2.8", "ttl": 60}],
    "complete": True, "truncated": False,
}


def main() -> None:
    policy = CollectionPolicy(
        targets=frozenset({DOMAIN}), kinds=frozenset({"dns_a"}),
        max_requests=100, max_requests_per_target=100,
    )
    with TemporaryDirectory(prefix="anie-v04-report-") as root:
        db = CollectionLedger(Path(root) / "events.sqlite")
        collector = OfflineCollector(policy, FixtureTransport({("dns_a", DOMAIN): RESPONSE}))
        scheduler = OfflineCollectionScheduler(collector, ledger=db)
        tracemalloc.start()
        start = time.perf_counter()
        when = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc)
        requests = 100
        for second in range(requests):
            now = (when + timedelta(seconds=second)).isoformat().replace("+00:00", "Z")
            result = scheduler.query("dns_a", DOMAIN, now=now)
            assert result.event.observation.synthetic
        elapsed = round(time.perf_counter() - start, 6)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        metrics = scheduler.metrics()
        stored = len(db.by_subject(DOMAIN))
        # TTL=60: fresh at t=0,60; 98 cache hits. No network occurs.
        assert metrics["fixture_exchanges"] == stored == 2
        assert metrics["cache_hits"] == requests - stored
        print(json.dumps({
            "dataset_type": "synthetic_demo_only",
            "network_requests": 0,
            "requested_lookups": requests,
            "fixture_exchanges": metrics["fixture_exchanges"],
            "cache_hits": metrics["cache_hits"],
            "sqlite_event_rows": stored,
            "fixture_exchanges_avoided": requests - stored,
            "local_elapsed_seconds": elapsed,
            "local_peak_allocated_bytes": peak,
            "not_real_world_benchmark": True,
        }, sort_keys=True))


if __name__ == "__main__":
    main()

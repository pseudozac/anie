"""Deterministic, offline-only acquisition scheduler and TTL-aware cache.

The scheduler accepts OfflineCollector ONLY. It never imports sockets,
HTTP clients or a DNS resolver, and never sleeps or starts background work.
A cache hit returns the ORIGINAL event/observed_at, not a new observation.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque

from .collection_pipeline import CollectionEvent, OfflineCollector
from .collection_policy import ScopeDenied, normalize_subject
from .collection_ledger import CollectionLedger
from .observations import utc_iso


def _time(timestamp: str) -> datetime:
    from datetime import datetime
    return datetime.fromisoformat(utc_iso(timestamp).replace("Z", "+00:00"))


def _positive_int(name: str, value: object, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class OfflineCacheConfig:
    """Local policy values; neither DNS TTL nor RDAP HTTP cache directives."""
    max_entries: int = 128
    max_positive_ttl_seconds: int = 3600
    max_negative_ttl_seconds: int = 3600
    rdap_refresh_seconds: int = 900
    error_cooldown_seconds: int = 5
    rate_limited_cooldown_seconds: int = 60
    max_requests_per_window: int = 16
    window_seconds: int = 60

    def __post_init__(self) -> None:
        for name, value, low, high in (
            ("max_entries", self.max_entries, 1, 512),
            ("max_positive_ttl_seconds", self.max_positive_ttl_seconds, 1, 86400),
            ("max_negative_ttl_seconds", self.max_negative_ttl_seconds, 1, 86400),
            ("rdap_refresh_seconds", self.rdap_refresh_seconds, 1, 86400),
            ("error_cooldown_seconds", self.error_cooldown_seconds, 1, 300),
            ("rate_limited_cooldown_seconds", self.rate_limited_cooldown_seconds, 1, 300),
            ("max_requests_per_window", self.max_requests_per_window, 1, 64),
            ("window_seconds", self.window_seconds, 1, 86400),
        ):
            _positive_int(name, value, low, high)


@dataclass(frozen=True)
class ScheduledResult:
    event: CollectionEvent
    from_cache: bool
    cache_lifetime_seconds: int
    # Original snapshot time is event.request.observed_at, even for a cache hit.


class OfflineCollectionScheduler:
    """Runs a bounded, explicit sequence of fixture queries.

    The existing CollectionLedger is append-only evidence storage; this
    in-memory optimization cache does NOT alter historical observations.
    Its state deliberately resets on restart and is never trusted across
    processes. A later persistent cache needs separate crash/replay tests.
    """

    def __init__(
        self,
        collector: OfflineCollector,
        *,
        config: OfflineCacheConfig | None = None,
        ledger: CollectionLedger | None = None,
    ):
        if not isinstance(collector, OfflineCollector):
            raise TypeError("only an offline fixture collector is supported")
        if ledger is not None and not isinstance(ledger, CollectionLedger):
            raise TypeError("ledger must be a local CollectionLedger")
        self.collector = collector
        self.config = config or OfflineCacheConfig()
        if not isinstance(self.config, OfflineCacheConfig):
            raise ValueError("invalid cache configuration")
        self.ledger = ledger
        self._cache: dict[tuple[str, str, str], tuple[datetime, CollectionEvent, int]] = {}
        self._requests: Deque[datetime] = deque()
        self._last_now: datetime | None = None
        self.fixture_exchanges = 0
        self.cache_hits = 0

    def _lifetime(self, event: CollectionEvent) -> int:
        observation = event.observation
        code = event.response_code
        if observation.status == "ok":
            if event.request.kind == "rdap_network":
                # Explicit LOCAL refresh policy, not an asserted RDAP source TTL.
                return self.config.rdap_refresh_seconds
            ttl = observation.ttl_seconds
            return min(ttl, self.config.max_positive_ttl_seconds) if ttl is not None else 0
        if observation.status == "empty":
            # No supplied, validated negative TTL -> do not reuse absence.
            ttl = observation.ttl_seconds
            return min(ttl, self.config.max_negative_ttl_seconds) if ttl is not None else 0
        if code in {"HTTP_429", "RATE_LIMITED"}:
            return self.config.rate_limited_cooldown_seconds
        # RFC 9520 requires caching DNS failures for >=1 and <=300 seconds.
        return self.config.error_cooldown_seconds

    def query(self, kind: str, subject: str, *, now: str) -> ScheduledResult:
        current = _time(now)
        if self._last_now is not None and current < self._last_now:
            raise ValueError("time went backwards; reset scheduler to avoid stale replays")
        self._last_now = current
        target = self.collector.budget.policy.authorize(kind, subject)
        if kind not in {"dns_a", "dns_aaaa", "dns_ptr", "rdap_network"}:
            raise ScopeDenied("unsupported offline acquisition kind")
        key = (kind, target, self.collector.source_id)
        cached = self._cache.get(key)
        if cached is not None:
            expires, event, lifetime = cached
            if current < expires:
                self.cache_hits += 1
                return ScheduledResult(event, True, lifetime)
            del self._cache[key]
        # Rolling-window quota; a cached request never consumes an upstream slot.
        earliest = current - timedelta(seconds=self.config.window_seconds)
        while self._requests and self._requests[0] <= earliest:
            self._requests.popleft()
        if len(self._requests) >= self.config.max_requests_per_window:
            raise ScopeDenied("synthetic upstream rate window exhausted")
        # Count requests before the fixture exchange; errors are not free retries.
        self._requests.append(current)
        self.fixture_exchanges += 1
        event = self.collector.collect(kind, target, utc_iso(now))
        if self.ledger is not None:
            self.ledger.add(event)
        ttl = self._lifetime(event)
        if ttl > 0:
            if len(self._cache) >= self.config.max_entries:
                oldest = min(self._cache, key=lambda cache_key: (self._cache[cache_key][0], cache_key))
                del self._cache[oldest]
            self._cache[key] = (current + timedelta(seconds=ttl), event, ttl)
        return ScheduledResult(event, False, ttl)

    @property
    def cache_entries(self) -> int:
        return len(self._cache)

    def metrics(self) -> dict[str, int]:
        return {
            "fixture_exchanges": self.fixture_exchanges,
            "cache_hits": self.cache_hits,
            "cache_entries": self.cache_entries,
            "request_window": len(self._requests),
        }

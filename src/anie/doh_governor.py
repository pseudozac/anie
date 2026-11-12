"""Strict target and resolver allowlists, rate governor, and anti-rebinding policies.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 2).
Enforces fail-closed security invariants before any network socket can be allocated:
1. Target allowlist: Strictly example.com and iana.org.
2. Kind allowlist: Strictly dns_a and dns_aaaa.
3. Resolver allowlist: Strictly https://cloudflare-dns.com/dns-query.
4. Anti-rebinding: Rejects all non-global IPs during resolver endpoint discovery.
5. Persistent rate governor: Enforces per-target, per-resolver, and daily query budgets.
6. Prohibits redirects, proxy bypasses, and unverified TLS certificates.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import socket
import sqlite3
from typing import Any, Callable
from urllib.parse import urlsplit

from .collection_policy import ScopeDenied, ensure_global_ip
from .observations import normalized_domain, utc_iso

ALLOWED_TARGET_DOMAINS = frozenset({"example.com", "iana.org"})
ALLOWED_QUERY_KINDS = frozenset({"dns_a", "dns_aaaa"})
ALLOWED_RESOLVER_HOSTS = frozenset({"cloudflare-dns.com"})
ALLOWED_RESOLVER_ENDPOINTS = frozenset({"https://cloudflare-dns.com/dns-query"})

DEFAULT_CONNECT_TIMEOUT_SECONDS = 3.0
DEFAULT_READ_TIMEOUT_SECONDS = 5.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 65535
MAX_RETRY_BUDGET = 1  # At most 1 retry permitted, and only for transient socket timeouts


def validate_target(domain: str, kind: str) -> tuple[str, str]:
    """Validate target domain and query kind against strict allowlists."""
    norm_domain = normalized_domain(domain)
    if norm_domain not in ALLOWED_TARGET_DOMAINS:
        raise ScopeDenied(
            f"target domain '{norm_domain}' is not authorized in allowlist; "
            f"allowed: {sorted(ALLOWED_TARGET_DOMAINS)}"
        )
    if kind not in ALLOWED_QUERY_KINDS:
        raise ScopeDenied(
            f"query kind '{kind}' is not authorized in allowlist; "
            f"allowed: {sorted(ALLOWED_QUERY_KINDS)}"
        )
    return norm_domain, kind


def validate_resolver_endpoint(url: str) -> tuple[str, str]:
    """Validate resolver endpoint URL and extract host and path."""
    if not isinstance(url, str) or len(url) > 2048:
        raise ScopeDenied("invalid resolver endpoint URL")
    if url not in ALLOWED_RESOLVER_ENDPOINTS:
        raise ScopeDenied(
            f"resolver endpoint '{url}' is not authorized; "
            f"allowed: {sorted(ALLOWED_RESOLVER_ENDPOINTS)}"
        )
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ScopeDenied("DoH resolver must use https scheme")
    if parsed.port not in (None, 443):
        raise ScopeDenied("DoH resolver port must be 443")
    if parsed.hostname not in ALLOWED_RESOLVER_HOSTS:
        raise ScopeDenied(f"DoH resolver host '{parsed.hostname}' is not authorized")
    if parsed.username or parsed.password or parsed.fragment:
        raise ScopeDenied("DoH resolver URL cannot include credentials or fragments")
    return parsed.hostname, parsed.path or "/dns-query"


def resolve_and_pin_endpoint(
    host: str,
    port: int = 443,
    getaddrinfo_fn: Callable[..., list[Any]] = socket.getaddrinfo,
) -> str:
    """Resolve fixed resolver host and strictly enforce global IP routing (Anti-Rebinding).
    
    If ANY resolved IP is private, reserved, loopback, or documentation, fails closed.
    Returns the first approved deterministic global IP.
    """
    if host not in ALLOWED_RESOLVER_HOSTS:
        raise ScopeDenied(f"resolver host '{host}' not authorized for address resolution")
    
    try:
        infos = getaddrinfo_fn(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeDenied(f"failed to resolve DoH resolver endpoint '{host}'") from exc

    if not infos or len(infos) > 32:
        raise ScopeDenied("DoH resolver address set empty or exceeds allowable limit")

    addresses = {info[4][0] for info in infos}
    # Fail closed if ANY address is not global (prevent mixed-answer rebinding attacks)
    approved_addresses = []
    for addr in addresses:
        try:
            global_addr = ensure_global_ip(addr)
            approved_addresses.append(global_addr)
        except (ValueError, ScopeDenied) as exc:
            raise ScopeDenied(
                f"DoH endpoint '{host}' resolved to non-global address '{addr}': {exc}"
            ) from exc

    if not approved_addresses:
        raise ScopeDenied("no approved public IP found for DoH endpoint")

    # Return deterministically sorted primary global address for pinning
    return sorted(approved_addresses)[0]


class DohRateGovernor:
    """Persistent SQLite-backed rate governor and query budget manager."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        max_target_per_hour: int = 10,
        target_cooldown_seconds: float = 2.0,
        max_resolver_per_hour: int = 60,
        max_daily_total: int = 200,
    ):
        if db_path is None or str(db_path) == ":memory:":
            self._is_memory = True
            self.db_path = Path(":memory:")
            self._mem_conn = sqlite3.connect(":memory:", timeout=10)
            self._mem_conn.execute("PRAGMA busy_timeout = 10000")
        else:
            self._is_memory = False
            self.db_path = Path(db_path)
            self._mem_conn = None
        self.max_target_per_hour = max_target_per_hour
        self.target_cooldown_seconds = target_cooldown_seconds
        self.max_resolver_per_hour = max_resolver_per_hour
        self.max_daily_total = max_daily_total
        self._init_db()

    def close(self) -> None:
        if self._is_memory and self._mem_conn is not None:
            self._mem_conn.close()
            self._mem_conn = None

    @contextmanager
    def _connect(self):
        if self._is_memory:
            if self._mem_conn is None:
                raise RuntimeError("in-memory rate governor is closed")
            yield self._mem_conn
            self._mem_conn.commit()
        else:
            conn = sqlite3.connect(self.db_path, timeout=10)
            try:
                conn.execute("PRAGMA busy_timeout = 10000")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _init_db(self) -> None:
        if not self._is_memory:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS doh_rate_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    resolver TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    timestamp_epoch REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_doh_rate_domain_time 
                ON doh_rate_log(domain, timestamp_epoch)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_doh_rate_resolver_time 
                ON doh_rate_log(resolver, timestamp_epoch)
            """)

    def check_and_reserve(
        self,
        domain: str,
        resolver: str,
        now_dt: datetime | None = None,
    ) -> str:
        """Check rate limits and reserve a query slot atomically.
        
        Raises ScopeDenied if any quota or cooldown is violated.
        Returns the ISO-8601 UTC timestamp of the reservation.
        """
        now = now_dt or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        epoch = now.timestamp()
        iso_str = now.isoformat(timespec="seconds").replace("+00:00", "Z")

        with self._connect() as conn:
            # 1. Cooldown check: Last query for this domain
            last_query = conn.execute("""
                SELECT timestamp_epoch FROM doh_rate_log 
                WHERE domain = ? 
                ORDER BY timestamp_epoch DESC LIMIT 1
            """, (domain,)).fetchone()
            if last_query is not None:
                elapsed = epoch - last_query[0]
                if elapsed < self.target_cooldown_seconds:
                    raise ScopeDenied(
                        f"target domain '{domain}' is in cooldown: {elapsed:.2f}s elapsed < "
                        f"{self.target_cooldown_seconds:.2f}s required"
                    )

            # 2. Hourly per-target quota: queries in last 3600 seconds
            target_hour_count = conn.execute("""
                SELECT COUNT(*) FROM doh_rate_log 
                WHERE domain = ? AND timestamp_epoch >= ?
            """, (domain, epoch - 3600)).fetchone()[0]
            if target_hour_count >= self.max_target_per_hour:
                raise ScopeDenied(
                    f"target domain '{domain}' exceeded hourly budget: "
                    f"{target_hour_count} >= {self.max_target_per_hour}"
                )

            # 3. Hourly per-resolver quota: queries in last 3600 seconds
            resolver_hour_count = conn.execute("""
                SELECT COUNT(*) FROM doh_rate_log 
                WHERE resolver = ? AND timestamp_epoch >= ?
            """, (resolver, epoch - 3600)).fetchone()[0]
            if resolver_hour_count >= self.max_resolver_per_hour:
                raise ScopeDenied(
                    f"resolver '{resolver}' exceeded hourly budget: "
                    f"{resolver_hour_count} >= {self.max_resolver_per_hour}"
                )

            # 4. Daily global quota: queries in last 86400 seconds
            daily_count = conn.execute("""
                SELECT COUNT(*) FROM doh_rate_log 
                WHERE timestamp_epoch >= ?
            """, (epoch - 86400,)).fetchone()[0]
            if daily_count >= self.max_daily_total:
                raise ScopeDenied(
                    f"global daily DoH quota exceeded: {daily_count} >= {self.max_daily_total}"
                )

            # Reserve slot
            conn.execute("""
                INSERT INTO doh_rate_log (domain, resolver, observed_at, timestamp_epoch)
                VALUES (?, ?, ?, ?)
            """, (domain, resolver, iso_str, epoch))

            return iso_str

    def get_remaining_budget(self, domain: str, resolver: str, now_dt: datetime | None = None) -> dict[str, int]:
        """Inspect current available query budget."""
        now = now_dt or datetime.now(timezone.utc)
        epoch = now.timestamp()
        with self._connect() as conn:
            target_hour = conn.execute("""
                SELECT COUNT(*) FROM doh_rate_log 
                WHERE domain = ? AND timestamp_epoch >= ?
            """, (domain, epoch - 3600)).fetchone()[0]
            resolver_hour = conn.execute("""
                SELECT COUNT(*) FROM doh_rate_log 
                WHERE resolver = ? AND timestamp_epoch >= ?
            """, (resolver, epoch - 3600)).fetchone()[0]
            daily = conn.execute("""
                SELECT COUNT(*) FROM doh_rate_log 
                WHERE timestamp_epoch >= ?
            """, (epoch - 86400,)).fetchone()[0]
            return {
                "target_hourly_remaining": max(0, self.max_target_per_hour - target_hour),
                "resolver_hourly_remaining": max(0, self.max_resolver_per_hour - resolver_hour),
                "daily_remaining": max(0, self.max_daily_total - daily),
            }

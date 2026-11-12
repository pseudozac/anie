"""Strict target and resolver allowlists, persistent rate governor, and anti-rebinding policies.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 2).

Enforces fail-closed security invariants before any network socket can be allocated:
1. Target allowlist: Strictly example.com and iana.org.
2. Kind allowlist: Strictly dns_a and dns_aaaa.
3. Resolver allowlist: Strictly https://cloudflare-dns.com/dns-query.
4. Batch restrictions: Maximum 2 target domains per batch.
5. Anti-rebinding: Rejects all non-global IPs during resolver endpoint discovery.
6. Persistent rate governor: Requires a durable, protected SQLite quota database.
   In-memory storage is strictly prohibited outside explicit test mode.
7. Atomic concurrent reservations: Enforces SQLite BEGIN IMMEDIATE transaction locking.
8. Conservative pilot budgets: Per-domain cooldown >= 30m, max 2 queries/domain/hour.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from .collection_policy import ScopeDenied, ensure_global_ip
from .observations import normalized_domain

ALLOWED_TARGET_DOMAINS = frozenset({"example.com", "iana.org"})
ALLOWED_QUERY_KINDS = frozenset({"dns_a", "dns_aaaa"})
ALLOWED_RESOLVER_HOSTS = frozenset({"cloudflare-dns.com"})
ALLOWED_RESOLVER_ENDPOINTS = frozenset({"https://cloudflare-dns.com/dns-query"})

MAX_DOMAINS_PER_BATCH = 2
DEFAULT_TARGET_COOLDOWN_SECONDS = 1800.0  # 30 minutes minimum cooldown
DEFAULT_MAX_TARGET_PER_HOUR = 2           # Consistent with 30m cooldown
DEFAULT_MAX_RESOLVER_PER_HOUR = 8
DEFAULT_MAX_DAILY_TOTAL = 16

DEFAULT_TOTAL_TIMEOUT_SECONDS = 5.0
DEFAULT_RESOLVER_DNS_TIMEOUT = 2.5
MAX_RESPONSE_BYTES = 65535
MAX_RETRY_BUDGET = 1  # At most 1 retry permitted, and strictly for transient socket timeouts


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


def validate_batch_domains(domains: list[str]) -> list[str]:
    """Ensure a batch contains at most MAX_DOMAINS_PER_BATCH unique authorized domains."""
    if len(set(domains)) > MAX_DOMAINS_PER_BATCH:
        raise ScopeDenied(
            f"batch exceeds maximum authorized domains: {len(set(domains))} > {MAX_DOMAINS_PER_BATCH}"
        )
    normalized = []
    for d in domains:
        norm = normalized_domain(d)
        if norm not in ALLOWED_TARGET_DOMAINS:
            raise ScopeDenied(f"batch domain '{norm}' is not authorized in allowlist")
        if norm not in normalized:
            normalized.append(norm)
    return normalized


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


_SUBPROCESS_RESOLVER_SCRIPT = """
import json
import socket
import sys

def main():
    if len(sys.argv) < 3:
        sys.exit(2)
    host = sys.argv[1]
    port = int(sys.argv[2])
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = list({info[4][0] for info in infos})
        json.dump({"status": "ok", "addresses": addresses}, sys.stdout)
    except socket.gaierror as exc:
        json.dump({"status": "gaierror", "error": str(exc)}, sys.stdout)
    except Exception as exc:
        json.dump({"status": "error", "error": str(exc)}, sys.stdout)

if __name__ == "__main__":
    main()
"""


def resolve_host_in_subprocess(
    host: str,
    port: int = 443,
    timeout: float = DEFAULT_RESOLVER_DNS_TIMEOUT,
    subproc_cmd: list[str] | None = None,
) -> list[str]:
    """Execute resolver hostname resolution in an isolated subprocess with explicit cancellation.
    
    If libc getaddrinfo or OS network resolution blocks indefinitely, the child process
    is forcefully killed via proc.kill() (SIGKILL on POSIX, TerminateProcess on Windows)
    and reaped via proc.wait(), guaranteeing zero leaked threads, zero orphan processes,
    and returning control immediately to the caller within the configured deadline.
    """
    cmd = subproc_cmd if subproc_cmd is not None else [
        sys.executable, "-c", _SUBPROCESS_RESOLVER_SCRIPT, host, str(port)
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        raise TimeoutError(
            f"resolver host '{host}' resolution exceeded deadline of {timeout:.2f}s"
        ) from exc
    except BaseException:
        proc.kill()
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        raise

    if proc.returncode != 0 and not stdout:
        raise ScopeDenied(
            f"resolver subprocess exited with code {proc.returncode}: {stderr.strip()}"
        )

    try:
        data = json.loads(stdout)
    except Exception as exc:
        raise ScopeDenied(f"invalid JSON response from resolver subprocess: {exc}") from exc

    status = data.get("status")
    if status == "ok":
        return data.get("addresses", [])
    elif status == "gaierror":
        raise ScopeDenied(f"failed to resolve DoH resolver endpoint '{host}': {data.get('error')}")
    else:
        raise ScopeDenied(f"resolver subprocess error: {data.get('error')}")


def resolve_and_pin_endpoint(
    host: str,
    port: int = 443,
    addrinfo_fn: Callable[..., list[Any]] | None = None,
    timeout: float = DEFAULT_RESOLVER_DNS_TIMEOUT,
    subproc_cmd: list[str] | None = None,
) -> str:
    """Resolve fixed resolver host within bounded deadline, enforcing global IP routing (Anti-Rebinding).
    
    Subprocess isolation is used by default to ensure blocking C-level getaddrinfo calls
    cannot keep the main execution path blocked or leak worker threads.
    If ANY resolved IP is private, reserved, loopback, or documentation, fails closed.
    Returns the first approved deterministic global IP.
    """
    if host not in ALLOWED_RESOLVER_HOSTS:
        raise ScopeDenied(f"resolver host '{host}' not authorized for address resolution")

    if timeout <= 0:
        raise TimeoutError(
            f"resolver host '{host}' resolution deadline exhausted (remaining: {timeout:.2f}s)"
        )

    # Use subprocess isolation when no in-memory mock addrinfo_fn is provided or subproc_cmd is set
    if subproc_cmd is not None or addrinfo_fn is None or addrinfo_fn is socket.getaddrinfo:
        raw_addresses = resolve_host_in_subprocess(
            host, port, timeout=timeout, subproc_cmd=subproc_cmd
        )
    else:
        # Fast direct execution for mocked unit test fixtures
        try:
            infos = addrinfo_fn(host, port, type=socket.SOCK_STREAM)
            raw_addresses = [info[4][0] for info in infos]
        except socket.gaierror as exc:
            raise ScopeDenied(f"failed to resolve DoH resolver endpoint '{host}'") from exc

    if not raw_addresses or len(raw_addresses) > 32:
        raise ScopeDenied("DoH resolver address set empty or exceeds allowable limit")

    approved_addresses = []
    for addr in set(raw_addresses):
        try:
            global_addr = ensure_global_ip(addr)
            approved_addresses.append(global_addr)
        except (ValueError, ScopeDenied) as exc:
            raise ScopeDenied(
                f"DoH endpoint '{host}' resolved to non-global address '{addr}': {exc}"
            ) from exc

    if not approved_addresses:
        raise ScopeDenied("no approved public IP found for DoH endpoint")

    return sorted(approved_addresses)[0]


class DohRateGovernor:
    """Persistent SQLite-backed rate governor with atomic multi-process transaction locking."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        max_target_per_hour: int = DEFAULT_MAX_TARGET_PER_HOUR,
        target_cooldown_seconds: float = DEFAULT_TARGET_COOLDOWN_SECONDS,
        max_resolver_per_hour: int = DEFAULT_MAX_RESOLVER_PER_HOUR,
        max_daily_total: int = DEFAULT_MAX_DAILY_TOTAL,
        allow_ephemeral_for_testing: bool = False,
        busy_timeout_ms: int = 5000,
    ):
        # 1. Reject invalid or nonpositive configuration values
        if type(max_target_per_hour) is not int or max_target_per_hour <= 0:
            raise ValueError(f"max_target_per_hour must be a positive integer; got {max_target_per_hour}")
        if not isinstance(target_cooldown_seconds, (int, float)) or isinstance(target_cooldown_seconds, bool) or target_cooldown_seconds <= 0:
            raise ValueError(f"target_cooldown_seconds must be a positive number; got {target_cooldown_seconds}")
        if type(max_resolver_per_hour) is not int or max_resolver_per_hour <= 0:
            raise ValueError(f"max_resolver_per_hour must be a positive integer; got {max_resolver_per_hour}")
        if type(max_daily_total) is not int or max_daily_total <= 0:
            raise ValueError(f"max_daily_total must be a positive integer; got {max_daily_total}")
        if type(busy_timeout_ms) is not int or busy_timeout_ms <= 0:
            raise ValueError(f"busy_timeout_ms must be a positive integer; got {busy_timeout_ms}")

        # 2. Enforce durable quota database for real collection
        if db_path is None or str(db_path) == ":memory:":
            if not allow_ephemeral_for_testing:
                raise ValueError(
                    "durable quota database required for real collection; "
                    "in-memory quota storage is disallowed outside explicit test mode"
                )
            self._is_memory = True
            self.db_path = Path(":memory:")
            self._mem_conn = sqlite3.connect(":memory:", timeout=busy_timeout_ms / 1000.0)
            self._mem_conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        else:
            self._is_memory = False
            self.db_path = Path(db_path)
            self._mem_conn = None
            try:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ScopeDenied(f"quota database path unwritable: {exc}") from exc

        self.max_target_per_hour = max_target_per_hour
        self.target_cooldown_seconds = float(target_cooldown_seconds)
        self.max_resolver_per_hour = max_resolver_per_hour
        self.max_daily_total = max_daily_total
        self.busy_timeout_ms = busy_timeout_ms
        self._init_db()

    @classmethod
    def create_test_governor(
        cls,
        *,
        max_target_per_hour: int = 10,
        target_cooldown_seconds: float = 2.0,
        max_resolver_per_hour: int = 60,
        max_daily_total: int = 200,
    ) -> "DohRateGovernor":
        """Explicit test-mode constructor enabling ephemeral in-memory quota tracking."""
        return cls(
            db_path=":memory:",
            max_target_per_hour=max_target_per_hour,
            target_cooldown_seconds=target_cooldown_seconds,
            max_resolver_per_hour=max_resolver_per_hour,
            max_daily_total=max_daily_total,
            allow_ephemeral_for_testing=True,
        )

    def close(self) -> None:
        """Close database connection."""
        if self._is_memory and self._mem_conn is not None:
            self._mem_conn.close()
            self._mem_conn = None

    @contextmanager
    def _connect(self, busy_timeout_ms: int | None = None):
        """Acquire database connection with fail-closed error handling."""
        ms = busy_timeout_ms if busy_timeout_ms is not None else self.busy_timeout_ms
        if self._is_memory:
            if self._mem_conn is None:
                raise ScopeDenied("quota database unavailable (connection closed)")
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
        else:
            try:
                conn = sqlite3.connect(self.db_path, timeout=ms / 1000.0, isolation_level=None)
            except (sqlite3.Error, OSError) as exc:
                raise ScopeDenied(f"quota database unavailable: {exc}") from exc
            try:
                conn.execute(f"PRAGMA busy_timeout = {ms}")
                conn.execute("PRAGMA journal_mode = WAL")
                yield conn
            except (sqlite3.Error, OSError) as exc:
                raise ScopeDenied(f"quota database operation failed: {exc}") from exc
            finally:
                conn.close()

    def _init_db(self) -> None:
        try:
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
        except (sqlite3.Error, OSError, ScopeDenied) as exc:
            if isinstance(exc, ScopeDenied):
                raise
            raise ScopeDenied(f"failed to initialize quota database: {exc}") from exc

    def check_and_reserve(
        self,
        domain: str,
        resolver: str,
        now_dt: datetime | None = None,
        timeout: float | None = None,
    ) -> str:
        """Atomically check quotas and reserve a slot using BEGIN IMMEDIATE locking.
        
        Ensures race-free reservations across concurrent processes. Fails closed.
        Bounded by remaining monotonic deadline timeout if specified.
        """
        t_start = time.monotonic()
        now = now_dt or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        epoch = now.timestamp()
        iso_str = now.isoformat(timespec="seconds").replace("+00:00", "Z")

        effective_busy_ms = self.busy_timeout_ms
        if timeout is not None:
            if timeout <= 0:
                raise TimeoutError("quota reservation deadline exhausted before lock acquisition")
            effective_busy_ms = max(1, int(min(timeout, self.busy_timeout_ms / 1000.0) * 1000))

        with self._connect(busy_timeout_ms=effective_busy_ms) as conn:
            # 1. Acquire IMMEDIATE write lock to block concurrent racers
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                if timeout is not None and (time.monotonic() - t_start) >= timeout:
                    raise TimeoutError(
                        f"quota database lock acquisition exceeded deadline of {timeout:.2f}s: {exc}"
                    ) from exc
                raise ScopeDenied(f"quota database lock contention: {exc}") from exc
                raise ScopeDenied(f"quota database lock contention: {exc}") from exc

            try:
                # 2. Cooldown check: Last query for this domain
                last_query = conn.execute("""
                    SELECT timestamp_epoch FROM doh_rate_log 
                    WHERE domain = ? 
                    ORDER BY timestamp_epoch DESC LIMIT 1
                """, (domain,)).fetchone()
                if last_query is not None:
                    elapsed = epoch - last_query[0]
                    if elapsed < self.target_cooldown_seconds:
                        conn.execute("ROLLBACK")
                        raise ScopeDenied(
                            f"target domain '{domain}' is in cooldown: {elapsed:.1f}s elapsed < "
                            f"{self.target_cooldown_seconds:.1f}s required"
                        )

                # 3. Hourly per-target quota: queries in last 3600 seconds
                target_count = conn.execute("""
                    SELECT COUNT(*) FROM doh_rate_log 
                    WHERE domain = ? AND timestamp_epoch >= ?
                """, (domain, epoch - 3600)).fetchone()[0]
                if target_count >= self.max_target_per_hour:
                    conn.execute("ROLLBACK")
                    raise ScopeDenied(
                        f"target domain '{domain}' hourly quota exhausted: "
                        f"{target_count} >= {self.max_target_per_hour}"
                    )

                # 4. Hourly per-resolver quota: queries in last 3600 seconds
                resolver_count = conn.execute("""
                    SELECT COUNT(*) FROM doh_rate_log 
                    WHERE resolver = ? AND timestamp_epoch >= ?
                """, (resolver, epoch - 3600)).fetchone()[0]
                if resolver_count >= self.max_resolver_per_hour:
                    conn.execute("ROLLBACK")
                    raise ScopeDenied(
                        f"resolver '{resolver}' hourly quota exhausted: "
                        f"{resolver_count} >= {self.max_resolver_per_hour}"
                    )

                # 5. Daily global quota: queries in last 86400 seconds
                daily_count = conn.execute("""
                    SELECT COUNT(*) FROM doh_rate_log 
                    WHERE timestamp_epoch >= ?
                """, (epoch - 86400,)).fetchone()[0]
                if daily_count >= self.max_daily_total:
                    conn.execute("ROLLBACK")
                    raise ScopeDenied(
                        f"daily global DoH quota exhausted: {daily_count} >= {self.max_daily_total}"
                    )

                # 6. Commit reservation atomically
                conn.execute("""
                    INSERT INTO doh_rate_log (domain, resolver, observed_at, timestamp_epoch)
                    VALUES (?, ?, ?, ?)
                """, (domain, resolver, iso_str, epoch))
                conn.execute("COMMIT")
                return iso_str
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

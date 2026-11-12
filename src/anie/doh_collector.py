"""First-party DNS-over-HTTPS (DoH) collection engine with end-to-end deadline enforcement.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 2).

Key Invariants:
1. Scope & Allowlists: Enforces strict target (example.com, iana.org) and resolver allowlists.
2. Rate Governor: Enforces persistent SQLite quota budgets (no in-memory defaults).
3. End-to-End Deadlines: Monotonic wall-clock deadline covers resolver address resolution,
   TCP connection, TLS handshake, HTTP body chunk reading, and retries.
   Deadlines are strictly preserved and NEVER reset across retries.
4. Bounded DNS Resolution: Employs bounded thread execution to ensure blocking C-level
   getaddrinfo calls cannot exceed the resolution deadline.
5. Evidence Integrity: Captures bounded raw DNS wire responses with SHA-256 verification.
6. DNSSEC Evidence Accuracy: Resolver AD flag is preserved strictly as a resolver claim
   (resolver_ad_claim=True) and does NOT set dnssec_status='secure'. DNSSEC status
   remains 'indeterminate' without independent local cryptographic validation.
   Does NOT infer DNSSEC-bogus from SERVFAIL alone.
7. PR 1 Integration: Produces valid RealCollectionEvent and RealObservation records.
8. Analytical Confidence: Explicitly nullable (None).
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from hashlib import sha256
import http.client
import io
from pathlib import Path
import socket
import ssl
import struct
import time
from typing import Any, Callable

from .collection_policy import ScopeDenied, ensure_global_ip
from .dns_wire import make_dns_query, parse_dns_wire, ParsedDnsMessage, RCODES
from .doh_governor import (
    DEFAULT_RESOLVER_DNS_TIMEOUT,
    DEFAULT_TOTAL_TIMEOUT_SECONDS,
    DohRateGovernor,
    MAX_RESPONSE_BYTES,
    MAX_RETRY_BUDGET,
    resolve_and_pin_endpoint,
    validate_batch_domains,
    validate_resolver_endpoint,
    validate_target,
)
from .real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)

SOURCE_ID = "first_party:doh:cloudflare"
RESOLVER_IDENTITY = "cloudflare_doh"


class DeadlineSocketWrapper:
    """Wraps an underlying socket or SSLSocket to cooperatively enforce monotonic deadline.
    
    Mitigates slow-trickle attacks where an upstream server transmits single bytes
    just before individual socket timeouts expire. On each recv, recv_into, or read call,
    recalculates remaining monotonic deadline and updates the socket timeout.
    If the monotonic deadline has expired, raises TimeoutError.
    
    Operational Boundary Note:
    This wrapper provides cooperative in-process timeout clamping at userspace I/O boundaries.
    It does not guarantee hard real-time preemption if an underlying C library or kernel driver
    enters an uninterruptible sleep state. Full outer cancellation guarantees require an
    independent supervisor watchdog (such as systemd RuntimeMaxSec in PR 3).
    """

    def __init__(self, raw_sock: Any, deadline: float):
        self._sock = raw_sock
        self._deadline = deadline

    def _check_deadline(self) -> float:
        rem = self._deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("monotonic deadline exceeded during socket receive")
        if hasattr(self._sock, "settimeout"):
            self._sock.settimeout(rem)
        return rem

    def recv_into(self, b: Any, *args: Any, **kwargs: Any) -> int:
        self._check_deadline()
        return self._sock.recv_into(b, *args, **kwargs)

    def recv(self, *args: Any, **kwargs: Any) -> bytes:
        self._check_deadline()
        return self._sock.recv(*args, **kwargs)

    def read(self, *args: Any, **kwargs: Any) -> bytes:
        self._check_deadline()
        if hasattr(self._sock, "read"):
            return self._sock.read(*args, **kwargs)
        return self._sock.recv(*args, **kwargs)

    def makefile(
        self,
        mode: str = "r",
        buffering: int | None = None,
        *,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> Any:
        if "b" in mode:
            raw = socket.SocketIO(self, mode)
            buf_size = buffering if (buffering is not None and buffering > 0) else io.DEFAULT_BUFFER_SIZE
            return io.BufferedReader(raw, buf_size)
        return self._sock.makefile(mode, buffering, encoding=encoding, errors=errors, newline=newline)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    """TLS hostname identity for fixed host, connect to validated IP only."""

    def __init__(
        self,
        ip: str,
        host: str,
        timeout: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
        deadline: float | None = None,
    ):
        self._pinned_ip_address = ensure_global_ip(ip)
        self._deadline = deadline
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(host, port=443, timeout=timeout, context=context)

    def _get_remaining(self) -> float:
        if self._deadline is not None:
            rem = self._deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("monotonic execution deadline exhausted before socket operation")
            return rem
        return self.timeout

    def connect(self):
        # 1. TCP connection using fresh remaining deadline
        rem_tcp = self._get_remaining()
        sock = socket.create_connection(
            (self._pinned_ip_address, 443), timeout=rem_tcp
        )
        try:
            # 2. TLS handshake using fresh remaining deadline
            rem_tls = self._get_remaining()
            sock.settimeout(rem_tls)
            ssl_sock = self._context.wrap_socket(sock, server_hostname=self.host)
            # 3. Wrap socket with deadline enforcement
            if self._deadline is not None:
                self.sock = DeadlineSocketWrapper(ssl_sock, self._deadline)
            else:
                self.sock = ssl_sock
        except BaseException:
            sock.close()
            raise


class DohCollector:
    """First-party DoH measurement collector operating under strict policy governance."""

    def __init__(
        self,
        rate_governor: DohRateGovernor | None = None,
        quota_db_path: str | Path | None = None,
        resolver_url: str = "https://cloudflare-dns.com/dns-query",
        timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
        connection_factory: Callable[..., Any] | None = None,
        addrinfo_fn: Callable[..., list[Any]] | None = None,
        subproc_cmd: list[str] | None = None,
    ):
        self.resolver_host, self.resolver_path = validate_resolver_endpoint(resolver_url)
        self.resolver_url = resolver_url

        # Require a durable rate governor or explicit quota db path
        if rate_governor is not None:
            self.rate_governor = rate_governor
        elif quota_db_path is not None:
            self.rate_governor = DohRateGovernor(quota_db_path)
        else:
            raise ValueError(
                "a durable rate_governor or quota_db_path is required for DohCollector; "
                "in-memory quota storage is disallowed for production collection"
            )

        self.timeout_seconds = float(timeout_seconds)
        self._connection_factory = connection_factory or _PinnedHttpsConnection
        self._addrinfo_fn = addrinfo_fn
        self._subproc_cmd = subproc_cmd

    def _execute_http_get(
        self,
        pinned_ip: str,
        query_wire: bytes,
        deadline: float,
    ) -> bytes:
        """Execute bounded HTTP GET with shared monotonic deadline across connection, reading, and retries."""
        query_param = base64.urlsafe_b64encode(query_wire).decode("ascii").rstrip("=")
        request_path = f"{self.resolver_path}?dns={query_param}"
        headers = {
            "Accept": "application/dns-message",
            "Accept-Encoding": "identity",
            "User-Agent": "ANIE-Research-Collector/0.5",
            "Connection": "close",
        }

        retries_remaining = MAX_RETRY_BUDGET
        while True:
            # Recompute remaining monotonic budget before each attempt
            rem_timeout = deadline - time.monotonic()
            if rem_timeout <= 0:
                raise TimeoutError(f"overall DoH deadline ({self.timeout_seconds:.2f}s) exceeded")

            try:
                conn = self._connection_factory(pinned_ip, self.resolver_host, rem_timeout, deadline=deadline)
            except TypeError:
                conn = self._connection_factory(pinned_ip, self.resolver_host, rem_timeout)

            try:
                # Ensure connection is established before request
                if not hasattr(conn, "sock") or conn.sock is None:
                    if hasattr(conn, "connect"):
                        conn.connect()

                # Wrap raw socket with DeadlineSocketWrapper if not already wrapped
                if hasattr(conn, "sock") and conn.sock is not None and not isinstance(conn.sock, DeadlineSocketWrapper):
                    conn.sock = DeadlineSocketWrapper(conn.sock, deadline)

                # HTTP request transmission under actual remaining deadline
                rem_req = deadline - time.monotonic()
                if rem_req <= 0:
                    raise TimeoutError(f"overall DoH deadline ({self.timeout_seconds:.2f}s) exceeded before request")
                if hasattr(conn, "sock") and conn.sock is not None:
                    conn.sock.settimeout(rem_req)

                conn.request("GET", request_path, headers=headers)

                # HTTP response headers under actual remaining deadline
                rem_resp = deadline - time.monotonic()
                if rem_resp <= 0:
                    raise TimeoutError(f"overall DoH deadline ({self.timeout_seconds:.2f}s) exceeded waiting for response headers")
                if hasattr(conn, "sock") and conn.sock is not None:
                    conn.sock.settimeout(rem_resp)

                response = conn.getresponse()

                # Treat redirects (HTTP 3xx) as a scope violation
                if 300 <= response.status < 400:
                    raise ScopeDenied(f"DoH HTTP redirect prohibited: status {response.status}")

                if response.status != 200:
                    raise ValueError(f"DoH HTTP status denied: {response.status}")

                content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/dns-message":
                    raise ValueError(f"unexpected DoH media type: '{content_type}'")

                content_length = response.getheader("Content-Length")
                if content_length is not None:
                    if not content_length.isdigit() or int(content_length) > MAX_RESPONSE_BYTES:
                        raise ValueError("oversized DoH content length header")

                # Read body in bounded chunks, checking deadline continuously (anti-slowloris)
                payload = bytearray()
                while len(payload) <= MAX_RESPONSE_BYTES:
                    rem_chunk = deadline - time.monotonic()
                    if rem_chunk <= 0:
                        raise TimeoutError(
                            f"overall DoH deadline ({self.timeout_seconds:.2f}s) exceeded while reading response body"
                        )
                    if hasattr(conn, "sock") and conn.sock is not None:
                        conn.sock.settimeout(rem_chunk)

                    chunk = response.read(min(4096, MAX_RESPONSE_BYTES + 1 - len(payload)))
                    if not chunk:
                        break
                    payload.extend(chunk)

                if len(payload) > MAX_RESPONSE_BYTES:
                    raise ValueError("oversized DoH response payload")

                return bytes(payload)
            except (socket.timeout, TimeoutError) as exc:
                rem_after = deadline - time.monotonic()
                if retries_remaining > 0 and rem_after > 0.5:
                    retries_remaining -= 1
                    continue
                raise TimeoutError(
                    f"DoH request timed out after {MAX_RETRY_BUDGET - retries_remaining} retry "
                    f"(remaining deadline: {rem_after:.2f}s): {exc}"
                ) from exc
            finally:
                conn.close()

    def collect(
        self,
        domain: str,
        kind: str,
        now_dt: datetime | None = None,
        timeout_seconds: float | None = None,
    ) -> tuple[RealCollectionEvent, RealObservation]:
        """Collect and parse genuine DoH measurement under monotonic wall-clock deadline."""
        start_time = time.monotonic()
        effective_timeout = float(timeout_seconds) if timeout_seconds is not None else self.timeout_seconds
        deadline = start_time + effective_timeout

        def remaining_timeout() -> float:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"overall DoH deadline ({effective_timeout:.2f}s) exceeded")
            return rem

        # 1. Scope & Allowlist enforcement
        norm_domain, norm_kind = validate_target(domain, kind)

        # 2. Rate governor budget check and reservation with monotonic deadline
        observed_at_iso = self.rate_governor.check_and_reserve(
            norm_domain, RESOLVER_IDENTITY, now_dt=now_dt, timeout=remaining_timeout()
        )

        # 3. Bounded endpoint resolution under monotonic deadline
        res_timeout = min(remaining_timeout(), DEFAULT_RESOLVER_DNS_TIMEOUT)
        pinned_ip = resolve_and_pin_endpoint(
            self.resolver_host,
            port=443,
            addrinfo_fn=self._addrinfo_fn,
            timeout=res_timeout,
            subproc_cmd=self._subproc_cmd,
        )

        # 4. Generate RFC 1035 wire query
        query_wire = make_dns_query(norm_domain, norm_kind)

        # 5. Execute bounded HTTPS GET exchange with monotonic deadline
        raw_payload = self._execute_http_get(pinned_ip, query_wire, deadline)
        raw_sha256 = sha256(raw_payload).hexdigest()

        # 6. Parse and classify DNS wire response
        parsed: ParsedDnsMessage = parse_dns_wire(
            raw_payload, domain=norm_domain, kind=norm_kind
        )

        # 7. Extract DNS header flags for empirical factual verification
        flags = struct.unpack_from("!H", raw_payload, 2)[0]
        aa = bool(flags & 0x0400)  # Authoritative Answer
        ad = bool(flags & 0x0020)  # Authentic Data (Resolver claim)
        ra = bool(flags & 0x0080)  # Recursion Available
        rcode = flags & 0x000F

        # Accurate DNSSEC Classification:
        # Resolver AD flag is strictly recorded as a resolver claim.
        # It does NOT assert independent DNSSEC validation; status remains 'indeterminate'.
        # SERVFAIL is an error and never inferred as DNSSEC-bogus without proof.
        dnssec_status = "indeterminate"
        resolver_ad_claim = bool(ad)

        if aa:
            response_authenticity = "authoritative"
        elif ra:
            response_authenticity = "recursive"
        else:
            response_authenticity = "unverified"

        wire_rcode_str = RCODES.get(rcode, f"RCODE_{rcode}")

        factual_verification = FactualVerification(
            dnssec_status=dnssec_status,
            response_authenticity=response_authenticity,
            transport_security="tls_pinned",
            resolver_identity=RESOLVER_IDENTITY,
            wire_rcode=wire_rcode_str,
            raw_evidence_status="captured",
            resolver_ad_claim=resolver_ad_claim,
        )

        # 8. Construct PR 1 RealCollectionRequest
        collection_request = RealCollectionRequest.create(
            kind=norm_kind,
            subject=norm_domain,
            observed_at=observed_at_iso,
            target_endpoint=self.resolver_url,
            pinned_ip=pinned_ip,
        )

        # 9. Construct PR 1 RealCollectionEvent (Forensic Ledger Record)
        event = RealCollectionEvent(
            request=collection_request,
            response_code=parsed.outcome,
            raw_sha256=raw_sha256,
            raw_evidence_status="captured",
            factual_verification=factual_verification,
            source_id=SOURCE_ID,
            observed_at=observed_at_iso,
            raw_payload=raw_payload,
        )

        # 10. Construct PR 1 RealObservation (Normalized Snapshot)
        observation = RealObservation(
            subject=norm_domain,
            kind=norm_kind,
            observed_at=observed_at_iso,
            values=parsed.values,
            status=parsed.status,
            source_id=SOURCE_ID,
            method="dns",
            synthetic=False,
            evidence_id=event.event_id,
            factual_verification=factual_verification,
            ttl_seconds=parsed.ttl_seconds,
            error_code=parsed.error_code,
            confidence=None,  # Strictly nullable analytical confidence
        )

        return event, observation

    def collect_batch(
        self,
        targets: list[tuple[str, str]],
        now_dt: datetime | None = None,
    ) -> list[tuple[RealCollectionEvent, RealObservation]]:
        """Collect bounded batch enforcing the 2-domain pilot constraint."""
        domains = [d for d, _ in targets]
        validate_batch_domains(domains)

        results = []
        for domain, kind in targets:
            pair = self.collect(domain, kind, now_dt=now_dt)
            results.append(pair)
        return results

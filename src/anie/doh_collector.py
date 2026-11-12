"""First-party DNS-over-HTTPS (DoH) collection engine.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 2).

Key Invariants:
1. Scope & Allowlists: Enforces strict target and resolver allowlists before connection.
2. Rate Governor: Enforces persistent per-target and per-resolver query budgets.
3. TLS Pinning: Binds connections to validated public IPs with strict SNI TLS verification.
4. Transport: Pure RFC 8484 wire-format GET with application/dns-message.
5. Evidence Integrity: Captures bounded raw DNS wire responses with SHA-256 verification.
6. PR 1 Integration: Produces valid RealCollectionEvent and RealObservation records.
7. Error Classification: Distinguishes ANSWER, NXDOMAIN, NODATA, SERVFAIL, and REFUSED.
8. Analytical Confidence: Explicitly nullable (None). Does NOT infer DNSSEC-bogus from SERVFAIL.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from hashlib import sha256
import http.client
from pathlib import Path
import socket
import ssl
import struct
from typing import Any, Callable

from .collection_policy import ScopeDenied, ensure_global_ip
from .dns_wire import make_dns_query, parse_dns_wire, ParsedDnsMessage, RCODES
from .doh_governor import (
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_READ_TIMEOUT_SECONDS,
    DEFAULT_TOTAL_TIMEOUT_SECONDS,
    DohRateGovernor,
    MAX_RESPONSE_BYTES,
    MAX_RETRY_BUDGET,
    resolve_and_pin_endpoint,
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


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    """TLS hostname identity for fixed host, connect to validated IP only."""

    def __init__(
        self,
        ip: str,
        host: str,
        timeout: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
    ):
        self._pinned_ip_address = ensure_global_ip(ip)
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(host, port=443, timeout=timeout, context=context)

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip_address, 443), timeout=self.timeout
        )
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class DohCollector:
    """First-party DoH measurement collector operating under strict policy governance."""

    def __init__(
        self,
        rate_governor: DohRateGovernor | None = None,
        resolver_url: str = "https://cloudflare-dns.com/dns-query",
        timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
        connection_factory: Callable[[str, str, float], Any] | None = None,
        addrinfo_fn: Callable[..., list[Any]] = socket.getaddrinfo,
    ):
        self.resolver_host, self.resolver_path = validate_resolver_endpoint(resolver_url)
        self.resolver_url = resolver_url
        self.rate_governor = rate_governor or DohRateGovernor()
        self.timeout_seconds = timeout_seconds
        self._connection_factory = connection_factory or _PinnedHttpsConnection
        self._addrinfo_fn = addrinfo_fn

    def _execute_http_get(
        self,
        pinned_ip: str,
        query_wire: bytes,
    ) -> bytes:
        """Execute bounded HTTP GET with strict RFC 8484 headers and single retry on timeout."""
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
            conn = self._connection_factory(pinned_ip, self.resolver_host, self.timeout_seconds)
            try:
                conn.request("GET", request_path, headers=headers)
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

                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise ValueError("oversized DoH response payload")

                return payload
            except (socket.timeout, TimeoutError) as exc:
                if retries_remaining > 0:
                    retries_remaining -= 1
                    continue
                raise TimeoutError(f"DoH request timed out after {MAX_RETRY_BUDGET} retry: {exc}") from exc
            finally:
                conn.close()

    def collect(
        self,
        domain: str,
        kind: str,
        now_dt: datetime | None = None,
    ) -> tuple[RealCollectionEvent, RealObservation]:
        """Collect and parse genuine DoH measurement, returning validated PR 1 models.
        
        Fail-closed:
        - Rejects unallowlisted domains or query kinds.
        - Enforces rate budgets and records reservation.
        - Captures raw wire bytes and computes SHA-256 evidence digest.
        - Classifies outcomes (ANSWER, NXDOMAIN, NODATA, SERVFAIL, REFUSED, FORMERR).
        - Sets confidence to None (strictly nullable).
        - Prevents DNSSEC-bogus inference from SERVFAIL alone.
        """
        # 1. Scope & Allowlist enforcement
        norm_domain, norm_kind = validate_target(domain, kind)

        # 2. Rate governor budget check and reservation
        observed_at_iso = self.rate_governor.check_and_reserve(
            norm_domain, RESOLVER_IDENTITY, now_dt=now_dt
        )

        # 3. Endpoint resolution & Anti-rebinding IP pinning
        pinned_ip = resolve_and_pin_endpoint(
            self.resolver_host, port=443, getaddrinfo_fn=self._addrinfo_fn
        )

        # 4. Generate RFC 1035 wire query
        query_wire = make_dns_query(norm_domain, norm_kind)

        # 5. Execute bounded HTTPS GET exchange
        raw_payload = self._execute_http_get(pinned_ip, query_wire)
        raw_sha256 = sha256(raw_payload).hexdigest()

        # 6. Parse and classify DNS wire response
        parsed: ParsedDnsMessage = parse_dns_wire(
            raw_payload, domain=norm_domain, kind=norm_kind
        )

        # 7. Extract DNS header flags for empirical factual verification
        flags = struct.unpack_from("!H", raw_payload, 2)[0]
        aa = bool(flags & 0x0400)  # Authoritative Answer
        ad = bool(flags & 0x0020)  # Authentic Data (DNSSEC)
        ra = bool(flags & 0x0080)  # Recursion Available
        rcode = flags & 0x000F

        # Classify DNSSEC and Authenticity without arbitrary inference
        if parsed.outcome == "ANSWER" and ad:
            dnssec_status = "secure"
        elif parsed.outcome == "SERVFAIL":
            # Mandatory Decision: Do NOT infer DNSSEC-bogus from SERVFAIL alone
            dnssec_status = "indeterminate"
        elif ad:
            dnssec_status = "secure"
        else:
            dnssec_status = "indeterminate"

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
            confidence=None,  # Nullable analytical confidence
        )

        return event, observation

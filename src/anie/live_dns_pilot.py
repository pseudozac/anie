"""One-shot, opt-in, tightly scoped REAL public DNS-over-HTTPS pilot.

Does not execute on import, in CI, or via ANIE's existing collectors.
Only example.com A/AAAA through Cloudflare's documented DoH endpoint.
Network is disabled unless the operator explicitly activates it via CLI.
No periodic jobs, scanning, bulk collection, cloud, or dataset publishing.

TLS is verified against cloudflare-dns.com; TCP is pinned to a previously
validated global IP, blocking DNS rebinding between validation and connect.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import http.client
import socket
import ssl

from .collection_policy import ScopeDenied, ensure_global_ip
from .dns_wire import ParsedDnsMessage, make_dns_query, parse_dns_wire

PILOT_DOMAIN = "example.com"
PILOT_KINDS = ("dns_a", "dns_aaaa")
PILOT_HOST = "cloudflare-dns.com"
PILOT_PATH = "/dns-query"
PILOT_URL = "https://cloudflare-dns.com/dns-query"
PILOT_ACK = "I approve two DNS queries for example.com"
MAX_PILOT_REQUESTS = 2
MAX_RESPONSE_BYTES = 65535
TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class PilotRequest:
    kind: str
    domain: str
    url: str
    accept: str = "application/dns-message"


def request_plan() -> tuple[PilotRequest, ...]:
    """Pure, inspectable GET plan. No network operation takes place."""
    requests = []
    for kind in PILOT_KINDS:
        packet = make_dns_query(PILOT_DOMAIN, kind)
        query = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")
        requests.append(PilotRequest(kind, PILOT_DOMAIN, f"{PILOT_URL}?dns={query}"))
    return tuple(requests)


def _pinned_ip() -> str:
    """Resolve the fixed resolver hostname and deny non-global answers."""
    infos = socket.getaddrinfo(PILOT_HOST, 443, type=socket.SOCK_STREAM)
    if not infos or len(infos) > 32:
        raise ScopeDenied("DoH endpoint resolution absent or too large")
    addresses = {info[4][0] for info in infos}
    # ALL results must be safe; do not choose a public answer if any are private.
    approved = tuple(sorted({ensure_global_ip(address) for address in addresses}))
    if not approved:
        raise ScopeDenied("no approved public resolver address")
    return approved[0]


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    """TLS hostname identity for fixed host, connect to validated IP only."""
    def __init__(self, ip: str):
        self._pinned_ip_address = ensure_global_ip(ip)
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(PILOT_HOST, port=443, timeout=TIMEOUT_SECONDS, context=context)

    def connect(self):
        sock = socket.create_connection((self._pinned_ip_address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=PILOT_HOST)
        except BaseException:
            sock.close()
            raise


def _fetch_doh(request: PilotRequest) -> bytes:
    """One HTTPS/443 GET without redirect, cookies, proxy or retries."""
    if (request.domain != PILOT_DOMAIN or request.kind not in PILOT_KINDS
            or request not in request_plan()):
        raise ScopeDenied("query outside fixed approved pilot plan")
    ip = _pinned_ip()
    conn = _PinnedHttpsConnection(ip)
    try:
        path = request.url.split(PILOT_HOST, 1)[1]
        conn.request("GET", path, headers={
            "Accept": "application/dns-message",
            "Accept-Encoding": "identity",
            "User-Agent": "ANIE-Research-ReadOnly-Pilot/0.4",
            "Connection": "close",
        })
        response = conn.getresponse()
        if response.status != 200:
            # HTTP 429, errors, redirects are never interpreted as DNS absence.
            raise ValueError(f"DoH HTTP status denied: {response.status}")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/dns-message":
            raise ValueError("unexpected DoH media type")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
            raise ValueError("oversized DoH content length")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise ValueError("oversized DoH payload")
        return payload
    finally:
        conn.close()


def run_live_dns_pilot(*, acknowledge_scope: str) -> list[dict]:
    """Require an exact operator acknowledgement BEFORE any network activity.

    Only the pinned HTTPS transport can create a real-provenance observation.
    Tests monkeypatch the private transport; no public transport injection.
    """
    if acknowledge_scope != PILOT_ACK:
        raise ScopeDenied("real-world DNS collection disabled without exact acknowledgement")
    result = []
    for request in request_plan():
        payload = _fetch_doh(request)
        parsed: ParsedDnsMessage = parse_dns_wire(
            payload, domain=request.domain, kind=request.kind
        )
        observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        record = parsed.as_observation(
            observed_at=observed_at, source_id="cloudflare_doh:pilot"
        )
        result.append({
            "subject": record.subject,
            "kind": record.kind,
            "observed_at": record.observed_at,
            "values": list(record.values),
            "status": record.status,
            "error_code": record.error_code,
            "ttl_seconds": record.ttl_seconds,
            "source": "cloudflare_doh:pilot",
            "response_code": parsed.outcome,
            "method": "dns",
            "synthetic": False,
            "stored": False,
            "published": False,
        })
    return result

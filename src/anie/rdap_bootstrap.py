"""Offline parser of *synthetic* IANA-style RDAP IP bootstrap registries.

Per RFC 9224, IP ranges use longest-prefix match. No network client,
bootstrap fetching, URLs opened, or DNS resolution in this module.
Registry URLs are DATA, not permission to contact an endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
from urllib.parse import urlsplit

from .observations import normalized_domain, utc_iso

MAX_BOOTSTRAP_BYTES = 512_000
MAX_SERVICES = 2048
MAX_PREFIXES_PER_SERVICE = 1024
MAX_URLS_PER_SERVICE = 8


@dataclass(frozen=True)
class RdapSelection:
    subject_ip: str
    matched_prefix: str
    base_urls: tuple[str, ...]
    registry_published_at: str
    origin: str = "synthetic:rdap-bootstrap"


def _safe_base_url(value: object) -> str:
    """Accept a syntactically safe HTTPS URL, never authorize an HTTP request."""
    if not isinstance(value, str) or not 12 <= len(value) <= 512:
        raise ValueError("invalid RDAP bootstrap URL")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        if (parts.scheme != "https" or not hostname or parts.username is not None
                or parts.password is not None or parts.fragment or parts.query
                or parts.port not in (None, 443) or "%" in parts.netloc
                or "\\" in parts.netloc or "@" in parts.netloc
                or not parts.netloc or not value.startswith("https://")):
            raise ValueError("unapproved RDAP bootstrap URL form")
        if any(ch.isspace() or ord(ch) < 33 for ch in value):
            raise ValueError("invalid RDAP bootstrap URL characters")
        if normalized_domain(hostname) != hostname:
            raise ValueError("noncanonical RDAP hostname")
        # Reject literal IPs and all-numeric dotted spellings (including
        # ambiguous legacy IPv4 forms). No network operation exists here.
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("IP literal RDAP endpoint is not approved")
        if all(label.isdigit() for label in hostname.split(".")):
            raise ValueError("ambiguous numeric IP endpoint")
        if hostname.endswith((".local", ".localhost", ".internal", ".home.arpa",
                              ".test", ".invalid", ".example")):
            raise ValueError("special-use RDAP endpoint")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid RDAP bootstrap URL") from exc
    return value


class OfflineRdapBootstrap:
    """Parse bounded IANA-like fixture data for one IP address family.

    Caller must independently authenticate any future real registry download.
    This module intentionally NEVER fetches the registry or contacts RDAP.
    """

    def __init__(self, registry: dict, *, family: int):
        if family not in (4, 6):
            raise ValueError("IP family must be 4 or 6")
        if not isinstance(registry, dict):
            raise ValueError("RDAP registry must be JSON object")
        if len(json.dumps(registry, ensure_ascii=True).encode("utf-8")) > MAX_BOOTSTRAP_BYTES:
            raise ValueError("RDAP bootstrap exceeds byte budget")
        if registry.get("version") != "1.0":
            raise ValueError("unsupported IANA bootstrap schema")
        timestamp = utc_iso(registry.get("publication"))
        if not isinstance(registry.get("services"), list) or not 0 < len(registry["services"]) <= MAX_SERVICES:
            raise ValueError("invalid RDAP service registry")
        routes: dict[ipaddress.IPv4Network | ipaddress.IPv6Network, tuple[str, ...]] = {}
        for service in registry["services"]:
            if not isinstance(service, list) or len(service) != 2:
                raise ValueError("invalid RDAP bootstrap service entry")
            prefixes, urls = service
            if (not isinstance(prefixes, list) or not 1 <= len(prefixes) <= MAX_PREFIXES_PER_SERVICE
                    or not isinstance(urls, list) or not 1 <= len(urls) <= MAX_URLS_PER_SERVICE):
                raise ValueError("invalid RDAP prefix or URL list")
            normalized_urls = tuple(_safe_base_url(url) for url in urls)
            if len(set(normalized_urls)) != len(normalized_urls):
                raise ValueError("duplicate RDAP service URL")
            for prefix in prefixes:
                if not isinstance(prefix, str) or len(prefix) > 64:
                    raise ValueError("invalid network prefix")
                try:
                    net = ipaddress.ip_network(prefix, strict=True)
                except ValueError as exc:
                    raise ValueError("invalid RDAP bootstrap CIDR") from exc
                if net.version != family:
                    raise ValueError("RDAP bootstrap IP family mismatch")
                if net in routes:
                    raise ValueError("duplicate/ambiguous RDAP bootstrap prefix")
                routes[net] = normalized_urls
        self._routes = tuple(sorted(routes.items(), key=lambda item: (-item[0].prefixlen, str(item[0]))))
        self.family = family
        self.published_at = timestamp

    def select(self, address: str) -> RdapSelection | None:
        """Return the most specific *offline* route, never a network request."""
        if not isinstance(address, str) or "%" in address:
            raise ValueError("invalid scoped/typed IP address")
        ip = ipaddress.ip_address(address)
        if ip.version != self.family:
            raise ValueError("RDAP registry IP family mismatch")
        for network, urls in self._routes:
            if ip in network:
                return RdapSelection(str(ip), str(network), urls, self.published_at)
        return None

    @property
    def route_count(self) -> int:
        return len(self._routes)

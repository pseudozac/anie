"""Offline-first scope and resource policy for planned collectors.

This module makes no network requests and authorizes NO live transport.
A future live implementation must enforce policy again at the socket/egress layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from urllib.parse import urlsplit

from .observations import KINDS, normalized_domain, normalized_ip


class ScopeDenied(ValueError):
    """A requested target, kind, destination, or budget is not authorized."""


def normalize_subject(kind: str, subject: str) -> str:
    if kind not in KINDS:
        raise ScopeDenied("unsupported collection kind")
    try:
        return normalized_domain(subject) if KINDS[kind] == "domain" else normalized_ip(subject)
    except ValueError as exc:
        raise ScopeDenied("invalid collection target") from exc


def _valid_number(value: object, *, lowest: int, highest: int) -> bool:
    return type(value) is int and lowest <= value <= highest


@dataclass(frozen=True)
class CollectionPolicy:
    """Exact target and kind allowlists, bounded synthetic fixture access only.

    Default constructor authorizes NO target. Real network collection is
    deliberately not expressible in this policy class.
    """
    targets: frozenset[str] = field(default_factory=frozenset)
    kinds: frozenset[str] = field(default_factory=frozenset)
    max_requests: int = 32
    max_requests_per_target: int = 8
    max_response_bytes: int = 65536
    max_total_response_bytes: int = 262144
    timeout_seconds: int = 5
    max_redirects: int = 0
    max_concurrency: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.targets, frozenset) or not self.targets or len(self.targets) > 64:
            # A truly empty policy is a valid fail-closed state.
            if not isinstance(self.targets, frozenset) or len(self.targets) > 64:
                raise ValueError("targets must be a bounded frozenset")
        if not isinstance(self.kinds, frozenset) or not self.kinds.issubset(KINDS) or len(self.kinds) > 5:
            raise ValueError("kinds must be a frozenset of supported collection kinds")
        if any(not isinstance(target, str) or not target or len(target) > 253 for target in self.targets):
            raise ValueError("invalid target allowlist")
        for target in self.targets:
            try:
                canonical = normalized_ip(target)
            except ValueError:
                canonical = normalized_domain(target)
            if canonical != target:
                raise ValueError("allowlisted targets must be canonical")
        bounds = {
            "max_requests": (self.max_requests, 1, 1000),
            "max_requests_per_target": (self.max_requests_per_target, 1, 100),
            "max_response_bytes": (self.max_response_bytes, 256, 1048576),
            "max_total_response_bytes": (self.max_total_response_bytes, 256, 16777216),
            "timeout_seconds": (self.timeout_seconds, 1, 30),
            "max_redirects": (self.max_redirects, 0, 3),
            "max_concurrency": (self.max_concurrency, 1, 4),
        }
        for key, (value, low, high) in bounds.items():
            if not _valid_number(value, lowest=low, highest=high):
                raise ValueError(f"invalid {key} policy limit")
        if self.max_response_bytes > self.max_total_response_bytes:
            raise ValueError("per-response maximum exceeds total budget")

    def authorize(self, kind: str, subject: str) -> str:
        target = normalize_subject(kind, subject)
        if kind not in self.kinds or target not in self.targets:
            raise ScopeDenied("target or kind is not explicitly authorized")
        return target

    def assert_public_target(self, subject: str) -> str:
        """Future-live design helper. Not sufficient to authorize network access.

        Also require an exact policy allowlist and a socket-level egress gate.
        """
        if subject not in self.targets:
            raise ScopeDenied("hostname/IP not explicitly allowlisted")
        try:
            ipaddress.ip_address(subject)
        except ValueError:
            pass
        else:
            return ensure_global_ip(subject)
        try:
            domain = normalized_domain(subject)
        except ValueError as exc:
            raise ScopeDenied("invalid domain") from exc
        if domain.endswith((".test", ".example", ".invalid", ".localhost", ".local", ".internal", ".home.arpa")):
            raise ScopeDenied("special-use or internal domain")
        return domain


def ensure_global_ip(address: str) -> str:
    """Deny private, reserved, special-use, unspecified and multicast addresses."""
    if not isinstance(address, str) or "%" in address:
        raise ValueError("invalid IP address or scoped IPv6")
    try:
        parsed = ipaddress.ip_address(address)
    except (TypeError, ValueError) as exc:
        raise ValueError("not an IP address") from exc
    if not parsed.is_global or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local or parsed.is_loopback:
        raise ScopeDenied("non-global IP destination")
    # Explicitly deny RFC5737 and RFC3849 documentation ranges across Python versions.
    if any(parsed in network for network in (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )):
        raise ScopeDenied("documentation IP is not a live destination")
    return str(parsed)


def validate_resolved_addresses(policy: CollectionPolicy, hostname: str, addresses: tuple[str, ...]) -> tuple[str, ...]:
    """Pure check only. Future transports MUST pin and recheck actual connect IP."""
    host = policy.assert_public_target(hostname)
    if not isinstance(addresses, tuple) or not addresses or len(addresses) > 16:
        raise ScopeDenied("missing or excessive address set")
    return tuple(sorted({ensure_global_ip(value) for value in addresses}))


def validate_https_redirect(policy: CollectionPolicy, url: str, addresses: tuple[str, ...], hop: int) -> str:
    """Pure simulated redirect validation; this module never opens a socket."""
    if type(hop) is not int or hop < 1 or hop > policy.max_redirects:
        raise ScopeDenied("redirect not allowed or hop budget exhausted")
    if not isinstance(url, str) or len(url) > 2048:
        raise ScopeDenied("invalid redirect URL")
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ScopeDenied("redirect must be absolute HTTPS without credentials or fragment")
        if parsed.port not in (None, 443):
            raise ScopeDenied("unapproved redirect port")
        hostname = parsed.hostname
        # Reject ambiguous authority and hostname encodings.
        if "%" in parsed.netloc or "\\" in parsed.netloc or not parsed.netloc:
            raise ScopeDenied("ambiguous redirect host")
        if not policy.assert_public_target(hostname):
            raise ScopeDenied("redirect destination denied")
        validate_resolved_addresses(policy, hostname, addresses)
    except (ValueError, UnicodeError) as exc:
        raise ScopeDenied("invalid redirect URL") from exc
    return url


class CollectionBudget:
    """Count requests before evaluating fixtures; enforce total/per-target bytes."""
    def __init__(self, policy: CollectionPolicy):
        self.policy = policy
        self.requests = 0
        self.total_bytes = 0
        self.by_target: dict[str, int] = {}

    def reserve(self, kind: str, subject: str) -> str:
        target = self.policy.authorize(kind, subject)
        if self.requests >= self.policy.max_requests or self.by_target.get(target, 0) >= self.policy.max_requests_per_target:
            raise ScopeDenied("request budget exhausted")
        self.requests += 1
        self.by_target[target] = self.by_target.get(target, 0) + 1
        return target

    def account_bytes(self, count: int) -> None:
        if not _valid_number(count, lowest=0, highest=self.policy.max_response_bytes):
            raise ScopeDenied("fixture exceeds per-response byte budget")
        if self.total_bytes + count > self.policy.max_total_response_bytes:
            raise ScopeDenied("fixture exceeds total byte budget")
        self.total_bytes += count

# ANIE v0.4 — offline acquisition planning and cache prototype

**Status:** Phase A (offline safety design + synthetic fixtures). **No live DNS/RDAP client, network egress, automatic retries, crawling, scanning or real-world collection enabled.** Issue #12 remains open until separately authorized pilot requirements are met.

## Design basis

- **RDAP:** RFC 9224 defines IANA IP bootstrap registries and longest-prefix matching to discover authoritative registration-data services. IANA operates separate IPv4 and IPv6 bootstrap registries; an observed service URL is *untrusted routing metadata*, never permission to contact it. The `OfflineRdapBootstrap` parser accepts synthetic IANA-style objects only and returns offline candidates, never an HTTP request.
- **DNS:** RFC 2308 distinguishes NXDOMAIN and NODATA from errors. RFC 9520 requires resolver-side resolution-failure caching in the 1–300 second range; this ANIE prototype caches synthetic error outcomes to simulate a respectful *application-level requery delay*, **not a compliant DNS recursive resolver implementation**. It does not implement DNS wire-format parsing, DNSSEC, CNAME chains, SOA validation, authoritative resolution or wire-level failure cache semantics.
- **RDAP HTTP:** lack of a response is not benign. `404`, `429`, `5xx` remain distinct collection-error evidence. Offline RDAP success is refreshed on an explicitly configured **local policy**, not a fabricated server TTL.

Research: [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224), [IANA IPv4 registry](https://www.iana.org/assignments/rdap-ipv4), [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308), [RFC 9520](https://www.rfc-editor.org/rfc/rfc9520).

## Prototype topology

```text
Explicit synthetic target+kind allowlist
           |
 OfflineRdapBootstrap (preloaded, synthetic registry only)
           |      NO LIVE URL INVOCATION
 OfflineCollectionScheduler (explicit now / deterministic request window)
           |
 Existing OfflineCollector + FixtureTransport ONLY
           |
 Existing validated CollectionEvent (original observed_at)
           |
 Existing append-only SQLite CollectionLedger
```

### Scheduler rules

| Outcome | Caching policy |
| --- | --- |
| DNS ANSWER | Respect record TTL, capped by local positive policy |
| NXDOMAIN or NODATA | Respect provided fixture negative TTL; without it, do not reuse a negative result |
| DNS timeout, SERVFAIL, REFUSED or malformed data | Small local cooldown (default 5 seconds, capped 300) while status remains **error**, never benign |
| HTTP 429 or synthetic rate-limited response | Local 60-second cooldown (bounded to 300) |
| RDAP HTTP 200 network | Configurable local recheck default 900 seconds (does **not** claim authoritative TTL) |

A cache hit returns the **same original event ID and observed_at timestamp**; it does not manufacture a new observation at query time. The scheduler records only fresh fixture exchanges in the append-only ledger. Local process memory is capped (128 entries by default, max 512); requests are capped by the existing CollectionPolicy plus a synthetic sliding-time window; no actual background workers, sleep/retries or network clients exist.

**Restart limitation:** the cache is in-memory and resets after process restart. The SQLite ledger persists provenance, but does not yet persist retry/cooldown state; a real production network collector must provide *durable cross-worker egress budgets, distributed rate limits, durable cooldown state, and atomic scheduling* before activation. This prototype must not be used as a live client or as a standalone authorization policy.

## Offline test and resource report

```bash
python -m unittest discover -s tests -v
python tools/offline_acquisition_report.py
python tools/check_repo.py
```

The 100-lookup synthetic report uses TTL=60 and deterministic virtual time. Expected **2 fixture exchanges, 98 cache hits, 2 SQLite events, 0 network requests**. Its local wall time and memory consumption describe only that test process, not expected performance against real DNS/RDAP endpoints. Database contents are synthetic RFC documentation values.

## Required production gates (not satisfied)

1. **Authorized target scope:** exact named public domains/IPs, purpose, rights/privacy and opt-out policy, source terms, allowed protocol and responsible-operator identity.
2. **Network confinement:** egress firewall; verified HTTPS/TLS; IANA bootstrap authentication/refresh; DNS rebinding and redirect rechecks bound to the actual socket address; IPv4/IPv6 special-use exclusions and route provenance.
3. **Abuse prevention:** durable per-provider and per-target quotas, retries compliant with RFC 9520, 429 Retry-After handling, backoff, global stop switch, concurrency/timeout/body budgets and alerting.
4. **Data controls:** schema versioning, uncertainty semantics, source evidence, retention/deletion, license restriction, audit log, signed publisher trust distribution and downstream version downgrade prevention.
5. **Acceptance:** adversarial sandbox tests, real service rate/terms verification, zero/limited monetary budget, explicit limited pilot activation scope and operator sign-off.

**Decision:** GO for offline fixtures and design tests. NO-GO for real-world collection and publication. No AEGIS or SNOOP access.

## v0.4.1 — bounded *manual* public DNS pilot

A new **manually acknowledged** exactly-two-query DoH pilot may be invoked separately from ANIE's offline engine; see [real-world pilot scope and security limits](REAL_WORLD_PILOT.md). This does not enable RDAP service querying, discovery, routine collection, cloud jobs or dataset publication. The default dry-run and GitHub CI remain network-free.

# Changelog

## Unreleased

## 0.4.1 — exact-scope manual DNS pilot preflight (2026-11-12)

- Fix compatibility with official IANA-style RDAP bootstrap records containing matched HTTPS/HTTP alternatives; never select HTTP.
- Add pure RFC 8484 DNS wire A/AAAA query and fail-closed response handling with negative SOA proof and distinct errors.
- Add manually opt-in, one-shot HTTPS DoH adapter for `example.com` A/AAAA only; two requests max per invocation, TLS verified, socket IP pinned and public, no redirects/retries/storage/publication. CI dry-run only.
- Add adversarial offline and mocked transport tests and documented real-world pilot terms/scope.


## 0.4.0 — offline acquisition and cache planning (Phase A, 2026-11-12)

- Parse bounded synthetic IANA-style RDAP IPv4/IPv6 bootstrap registries with longest-prefix matching and untrusted URL hygiene.
- Add deterministic TTL-aware offline DNS/RDAP scheduler with per-target/global quotas, negative/failure cooldown semantics, bounded memory and persistent append-only evidence snapshots.
- Preserve original timestamps and evidence IDs on cache hits; no live socket clients, real data, or network publication.
- Add adversarial fixtures, resource-count reporting and go/no-go acquisition design.


## 0.3.0 — offline synthetic release signature verification (2026-11-12)

- Add optional PyCA cryptography Ed25519 signature verification; core runtime remains standard-library only.
- Domain-separated authenticated payload binds manifest hash, source commit, repository, builder, release sequence and expiry.
- Operator-pinned key, local revocation and validity checks, monotonic sequence and tamper/replay regression tests.
- Offline ephemeral signing demonstration; no production key, authenticated GitHub identity, public release, AEGIS modification or live data.


- Offline synthetic-only consumer manifest pin verification and provenance metadata checks (not publisher authentication).
- Authenticated release, signing, licensing, cost, AEGIS rollback and revocation design; no real-data publication.


- Add deterministic chronological synthetic infrastructure-novelty benchmark, two non-ML baselines, abstention/uncertainty regression tests, model predictions fingerprint and memory/timing reporting. No live data or production verdict changes.


No live collectors, real-data publication, hosted services or external scanning approved.

## 0.2.0 — offline collection foundation (2026-11-11)

- Exact target/kind allowlists, bounded fixture and request budgets, pure global-address and redirect validation.
- Deterministic synthetic DNS A/AAAA/PTR response normalization; distinguish NXDOMAIN, NODATA, REFUSED, SERVFAIL, timeout and incomplete responses.
- RDAP IP network range/CIDR validation and standalone autnum parsing without invented IP-to-ASN attribution.
- Versioned collection-event schema and separate append-only SQLite ledger; v0.1 observation IDs and intelligence schema unchanged.
- Offline adversarial tests, collector demo and collection threat-model documentation.

## Previous foundation changes

- Repository-level coding-agent instructions and specialized agent profiles.
- Four reusable skills for observation contracts, ML evaluation, collector threat modeling and dataset release.
- Contributor templates, threat/privacy policies, branch/release procedures and dependency update configuration.
- CI pinning, read-only GitHub token, offline policy checks and synthetic replay.

No collector, network, publishing or runtime behavior changes.

## 0.1.0 source prototype — 2026-11-11

- Offline synthetic-only Python package, SQLite observations, temporal DNS features, unsupervised novelty model.
- Evidence-linked JSONL/gzip datasets, unsigned SHA-256 integrity manifests, local read-only consumer.
- No real-world collection, live distribution, or production AI threat detection.

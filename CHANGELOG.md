# Changelog

## Unreleased

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

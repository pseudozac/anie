# Changelog

## Unreleased

- PR 4: Authenticated first-party intelligence publication pipeline (`src/anie/real_publish.py`), detached Ed25519 signing, and multi-tier evidence verification.
- Deterministic canonical publication engine (`export_canonical_dataset()`, `publish_real()`) producing reproducible gzip archives (`mtime=0`, `compresslevel=9`) sorted by observation and event timestamps/IDs, single consistent SQLite read snapshot transactions (`BEGIN DEFERRED`), fail-closed over-limit dataset protection (no silent truncation), and atomic artifact generation.
- Manifest byte-for-byte reproducibility via explicit publication timestamps (`--published-at`).
- Complete metadata binding across manifest publisher, signed payload publisher, release sequence, git commit hashes, attestation key IDs, key fingerprints, and operator trust policies, preventing signature transposition even when mathematically valid.
- Air-gapped detached Ed25519 signing workflow (`sign_manifest_detached()` and CLI `anie sign-real`): primary signing keys never reside on the collector host (`anie-collector-01`), with strict key parsing (PEM and exactly 32 raw bytes, rejecting permissive truncation fallbacks).
- Independent four-tier consumer verification engine (`verify_real_release()` and CLI `anie verify-real`): distinguishes structural validation, evidence-integrity validation, publisher-signature authentication, and stateful anti-rollback verification, with an explicit `--integrity-only` mode for candidate inspection.
- Complete evidence model reconstruction: validates content-addressed IDs, raw DNS wire payload hashes (`raw_sha256`), record schema versions, strict deterministic ordering, duplicate ID rejection, and referential consistency.
- Memory-bounded streaming serialization, hashing, and decompression: guarantees execution within Oracle Cloud micro instance memory limits (1 GiB RAM) with decompression bomb protection ($\le 100\text{ MB}$ uncompressed ceiling, $\le 500\text{ KB}$ per-record limit).
- Hardened persistent verifier state tracking (`ReleaseSequenceTracker`): fail-closed error handling (`TrackerStateError`, `TrackerStateLostError`), concurrency-safe atomic multi-process file locking, prevention of lower-sequence overwrites, and documented local filesystem rollback boundaries.
- Key rotation and operator revocation support in `RealReleaseTrust` via multi-key maps (`trusted_keys`), `revoked_key_ids`, and `revoked_fingerprints`.
- Unconditional anti-contamination enforcement: rejects synthetic fixtures, synthetic methods, and synthetic source IDs within real publication artifacts.
- Comprehensive operational documentation and verified runbooks in `docs/REAL_PUBLICATION_AND_SIGNING.md`.
- PR 3: Bounded batch orchestrator (`BatchOrchestrator`, `src/anie/orchestrator.py`) and CLI subcommand `collect-batch` for resource-governed one-shot execution on Oracle Cloud micro instances (1 GiB RAM).
- Strict execution envelope: maximum 2 domains (`example.com`, `iana.org`), alternating query kinds (`dns_a` $\leftrightarrow$ `dns_aaaa`) across batches based on last persisted observation, canonicalized domain uniqueness, at most 1 query per domain per batch to strictly satisfy the 30-minute per-domain cooldown, and an absolute ceiling of $\le 4$ queries per batch.
- Fail-closed execution modes (`VALID_MODES = {"dry_run", "live"}`) preventing programmatic or CLI bypass; live collection strictly gated by `--live` and `ANIE_LIVE_COLLECTION_AUTHORIZED=1`.
- Preflight host health safeguards with fail-closed host metrics (no invented fallback RAM); distinguishes genuine resource shortages (`SKIPPED`) from operational errors (`FAILED`), and strictly validates memory/disk/timeout configuration thresholds.
- Single monotonic deadline for the entire batch passed to sequential operations; bounds total timeout at $\le 25.0$s to ensure systemd `TimeoutStartSec` (30s) cleanup headroom.
- Correct dry-run telemetry: records `queries_planned` separately while reporting zero execution counts (`queries_attempted=0`, `queries_succeeded=0`, `queries_failed=0`, `records_persisted=0`).
- Cross-platform advisory process locking (`acquire_collector_lock`) covering the complete execution critical section (query determination, preflight, collection, persistence, telemetry).
- Structured execution telemetry with single-line JSON records and bounded log file size rotation ($\le 5\text{ MiB}$).
- Hardened systemd templates (`systemd/anie-collector.service` and `systemd/anie-collector.timer`) configured with `Type=oneshot`, supervisor-enforced `TimeoutStartSec=30s`, `TimeoutStopSec=15s`, `KillMode=control-group`, `Restart=no`, and resource limits (`MemoryMax=128M`, `MemoryHigh=96M`, `CPUQuota=20%`, `Nice=19`).
- Comprehensive operational documentation in `systemd/README.md` explaining why `RuntimeMaxSec` does not apply to `Type=oneshot`, cgroup termination escalation, Linux kernel `TASK_UNINTERRUPTIBLE` (D-state) limitations, daily vs 4-hour schedule selection, and administrative verification/rollback runbooks.
- PR 2: First-party DNS-over-HTTPS (DoH) collection engine (`DohCollector`) and policy governor (`DohRateGovernor`).
- Strict target allowlist limited to `example.com` and `iana.org`, query kinds `dns_a` and `dns_aaaa`, and batch domain size limit ($\le 2$ domains per invocation).
- Anti-rebinding resolver endpoint resolution requiring all returned IPs to be verified global addresses before socket allocation, with isolated subprocess-based execution guaranteeing hard cancellation without blocking context managers or leaking threads/processes.
- Persistent SQLite-backed rate governor with atomic `BEGIN IMMEDIATE` multi-process locking, deadline-bounded lock acquisition, per-target 30-minute cooldown, conservative hourly quotas, and fail-closed error handling. Ephemeral in-memory storage restricted strictly to explicit test mode.
- Full RFC 8484 wire-format exchange with bounded response capture ($\le 65,535$ bytes) and SHA-256 evidence integrity.
- Comprehensive monotonic wall-clock deadline enforcement encompassing SQLite lock acquisition, endpoint resolution, TCP connect, TLS handshake, HTTP request transmission, response headers, chunked body streaming, and bounded retries without deadline reset.
- Cooperative deadline socket wrapper (`DeadlineSocketWrapper`) preventing slow-trickle servers from extending request durations via sub-timeout byte streaming during header or body reads; operational boundaries and external watchdog architecture documented for PR 3.
- Explicit DNS response classification for ANSWER, NXDOMAIN, NODATA, SERVFAIL, and REFUSED.
- Resolver AD flag recorded strictly as an untrusted third-party claim (`resolver_ad_claim=True`) while `dnssec_status` remains `'indeterminate'` without independent cryptographic proof.
- Mandatory invariants: SERVFAIL recorded as error without inferring DNSSEC-bogus; analytical confidence kept strictly nullable (`None`).
- PR 1: Introduce Phase 2 first-party intelligence data models (`RealObservation`, `RealCollectionEvent`, `FactualVerification`) and SQLite store (`RealObservationStore`).
- Replace arbitrary confidence multipliers with distinct empirical factual verification attributes and explicitly nullable analytical confidence.
- Enforce strict cross-pipeline isolation: real observations require `synthetic=False` and are rejected by synthetic publishers; synthetic fixtures are rejected by `RealObservationStore`.
- Implement referential integrity with `FOREIGN KEY ... ON DELETE RESTRICT` and two-phase retention invariants preventing evidence deletion while dependent observations remain.
- Replace unconstrained `INSERT OR IGNORE` with strict collision detection: accept identical duplicate records idempotently, reject conflicting identifiers with `IntegrityError`.
- Cryptographically verify raw evidence hashes when loading and exporting collection events.
- Document exact SQLite WAL durability and crash-recovery semantics under `NORMAL` and `FULL` synchronous modes without absolute durability claims.

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

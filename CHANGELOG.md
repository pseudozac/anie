# Changelog

## 0.6.0 (M3.10) — End-to-End Intelligence Verification & Consumer Integration Readiness (2026-11-21)

- **Security Review Remediation (PR #40 Audit & Hardening):**
  - *Priority 0: Retention Fail-Closed Defaults (`src/anie/retention.py`, `src/anie/cli.py`):*
    - Changed default `allow_destructive_pruning` from `True` to `False` in `RetentionPolicy`.
    - Enforced explicit authorized intent: destructive retention pruning strictly requires non-empty `operator_authorization`.
    - Added CLI flags `--allow-destructive-pruning` and `--operator-authorization` to `prune-retention`.
    - Fault-injection verification: proved transaction rollback on simulated crash; no observations/events deleted and zero tombstones created on abort.
  - *Priority 1: Explicit Evidence Authorization Policy (`src/anie/real_models.py`, `src/anie/real_store.py`):*
    - Replaced permissive open source-prefix matching with explicit `TrustedCollectorPolicy`. A source ID is treated as an identifier, not authentication.
    - Removed permissive fallback to `"first_party"` for missing collector identities (`MISSING_COLLECTOR_IDENTITY`).
    - Differentiated epistemic evidence quality: `RAW_PAYLOAD_HASH_VERIFIED` (cryptographic preimage check), `UNAUTHENTICATED_COLLECTOR` (unvetted source), `EVIDENCE_RAW_BYTES_UNAVAILABLE` (retained metadata only), and `CORRUPT_PAYLOAD_DIGEST_MISMATCH`.
  - *Priority 1: Multi-Vector Evidence Binding (`src/anie/cross_vector_correlation.py`, `src/anie/real_publish.py`):*
    - Enforced vector-to-source and observation-context relationships in `CrossVectorCorrelator`: vector summaries must strictly bind to events of matching kind (e.g. DNS to `dns_*`, HTTP to `http_*`, TLS to `tls_*`).
    - Verified release partition verification (`verify_real_release` Section 4c) fails closed on mismatched vector evidence bindings.
    - Updated integration tests to ingest distinct DNS, HTTP, and TLS events.
  - *Priority 1: Tombstone Audit Semantics (`src/anie/retention.py`):*
    - Corrected inaccurate salted-hash claims: tombstones store operator audit identities directly without deriving or retaining credential secrets.
    - Accurately clarified transactional, crash-consistent SQLite audit recording.
  - *Consumer Integration Clarification (`examples/aegis_consumer_v2_example.py`):*
    - Explicitly clarified that the reference client is an offline schema validation fixture against local SQLite stores, and does not constitute production deployment or authenticated-release import into the AEGIS runtime.
- **Phase A — Authoritative Evidence Audit & Retention Hardening (`src/anie/real_store.py`, `src/anie/retention.py`, `src/anie/real_models.py`):**
  - Cryptographic preimage verification: Hardened `verify_evidence_authoritativeness` to verify that retained wire payload bytes match the expected SHA-256 digest (`CORRUPT_PAYLOAD_DIGEST_MISMATCH` emitted on corruption).
  - Deterministic derived index rebuild: `rebuild_derived_indexes(store)` deterministically handles out-of-order, corrected, and superseded records by updating `first_observed_at = min(...)` and `last_observed_at = max(...)`, preserving evidence hashes, and reconstructing intelligence claim nodes and `SUPERSEDES` edges.
  - Deterministic temporal intelligence: Anchored observation windows to the latest observed timestamp during offline replay when `as_of` is omitted, eliminating wall-clock rollover test sensitivity.
- **Phase B — Signed Release Pipeline & Adversarial Fault Injection (`src/anie/real_publish.py`):**
  - Standardized release partition `real_findings.jsonl.gz` in candidate datasets and manifest v2 metadata (`total_findings`).
  - Deterministic detached Ed25519 manifest attestation signing (`sign_manifest_detached`).
  - Independent offline verification engine (`verify_real_release`) enforcing cryptographic signature verification, partition hash integrity, referential evidence linkage against `real_events`, trust policy pinning (`RealReleaseTrust`), and monotonic anti-rollback sequence tracking (`ReleaseSequenceTracker`).
  - Adversarial verification suite: Demonstrated fail-closed rejection on tampered partitions, bit-flipped wire archives, corrupted signature payloads, replay/rollback attempts, and ungrounded evidence references.
- **Phase C — AEGIS Consumer Integration Readiness (`src/anie/consumer_contract.py`):**
  - Frozen `anie.consumer-contract.v2` and `anie.cross-vector-finding-feed.v2` schemas.
  - Frozen deterministic consumer fixture (`tests/fixtures/aegis_consumer_contract_v2_fixture.json`).
  - Standalone reference consumer client demo (`examples/aegis_consumer_v2_example.py`) demonstrating zero-dependency consumption: cursor pagination, competing hypotheses inspection, and authoritative evidence grounding.
  - Verified 100% backward compatibility: Consumer Contract V1 endpoints (`export_canonical_ioc_feed`) operate seamlessly alongside V2 feeds.
  - Epistemic humility enforcement: Findings strictly adhere to epistemic layers (`FACT`, `DERIVED`, `HYPOTHESIS`, `VALIDATED`) with explicit disclaimers that heuristic scores are uncalibrated pattern-corroboration metrics, NOT threat probabilities or maliciousness verdicts.
- **Verification & Operational Envelope:**
  - 19 integration and security tests across `tests/test_m3_10_authoritative_audit.py`, `tests/test_m3_10_signed_release_pipeline.py`, `tests/test_m3_10_aegis_consumer_readiness.py`, and `tests/test_m3_10_security_remediation.py`.
  - 503 total repository tests executed: 502 passed, 0 failed, 1 skipped (`test_schema.py:15` when `jsonschema` library is absent).
  - Repository structural guardrails (`tools/check_repo.py`): PASS.
  - Resource consumption verified within 1 GiB Oracle micro VM budget ($<200\text{ MiB}$ RAM, $<500\text{ MiB}$ disk).
  - Invariants preserved: `anie-collector-01` remains quiescent at ₹0.00 spend; Task Scheduler acquisition runner `ANIE_Ampere_A1_Capacity_Retry` untouched.

## 0.5.0 (M3.9) — Cross-Vector Intelligence Correlation & AEGIS Consumer Integration (2026-11-21)

- **Cross-Vector Intelligence Correlation (`src/anie/cross_vector_correlation.py`):**
  - Implement bounded cross-vector correlation engine synthesizing observations across DNS, TLS, HTTP, and BGP/RDAP telemetry vectors.
  - Epistemic discipline: Strictly distinguishes temporal correlation from causation (`causation_inferred=False`). Co-occurrence in a shared observation window is explicitly flagged as non-causal.
  - Multi-hypothesis evaluation: Evaluates competing infrastructure explanations for observed transitions:
    - *Legitimate CDN Migration:* DNS mapping to Anycast/CDN prefix space, edge TLS termination, and matching proxy headers (`FAVORED` at bounded heuristic score $\ge 0.85$).
    - *Routine Certificate Renewal:* Stable underlying IP infrastructure with consistent Subject Alternative Name coverage (`FAVORED` at $\ge 0.80$).
    - *Shared Hosting / Multi-Tenant Rebalancing:* Dynamic endpoint transitions under high-density multi-tenant environments.
    - *Multi-Vector Divergence:* Mismatched TLS SAN coverage, unaligned routing, or HTTP error status codes (`FAVORED` at $\ge 0.80$).
  - Epistemic abstention: Emits status `INSUFFICIENT_MULTI_VECTOR_COVERAGE` and abstains from cross-vector inference whenever $< 2$ distinct vectors are present.
  - Heuristic score semantics: Scores ($0.0\text{ to }1.0$) are explicitly uncalibrated matching heuristics, accompanied by mandatory disclaimer that novelty/divergence $\neq$ maliciousness.
- **Authoritative Evidence Resolution & Retention Lifecycle (`src/anie/real_store.py`, `src/anie/retention.py`):**
  - Authoritative Evidence Verification Invariant: Every evidence reference must resolve to a verifiable record in `real_events` or `real_observations`. A user-supplied hash alone never authenticates an observation (`UNVERIFIED_EVIDENCE_REFERENCE` emitted for orphaned hashes).
  - Non-destructive retention policy: `allow_destructive_pruning=False` protects all authoritative evidence, collection events, cryptographic attestations, and audit history.
  - Audit tombstone ledger: Pruning actions record cryptographically anchored audit entries in `retention_tombstone_ledger` tracking deleted record IDs, types, and operator authorization tokens.
  - Deterministic index rebuild: `rebuild_derived_indexes(store)` allows derived graph nodes and edges to be completely dropped and reconstructed deterministically from authoritative raw records without evidence degradation.
- **AEGIS Consumer Contract V2 (`src/anie/consumer_contract.py`):**
  - Publish `anie.consumer-contract.v2` and findings feed schema `anie.cross-vector-finding-feed.v2`.
  - 100% backward compatibility: Preserves all V1 methods, schemas, and return formats (`fetch_manifest`, `stream_observations`, `stream_events`, `stream_discrepancy_reports`, `stream_intelligence_claims`).
  - Added client methods: `query_cross_vector_findings(...)`, `get_cross_vector_finding(...)`, `export_normalized_findings_feed(...)`, and `verify_evidence_authoritativeness(...)`.
  - Export feed includes typed epistemic layers (`FACT`, `DERIVED`, `HYPOTHESIS`, `VALIDATED`), supporting/contradicting evidence digests, and historical supersession links.
- **Verification:**
  - 14 new test cases across `tests/test_m3_9_cross_vector_correlation.py`, `tests/test_m3_9_authoritative_evidence_and_retention.py`, `tests/test_m3_9_consumer_contract_v2.py`.
  - 484 total tests executed across the repository (483 passed, 0 failed, 1 skipped; 100% pass rate).
  - Repository structural guardrails (`tools/check_repo.py`): 100% PASS.

## 0.4.1 (M3.8) — Multi-Vector Intelligence, Passive HTTP Metadata & Competing Hypotheses (2026-11-21)

- **Passive HTTP Telemetry (`src/anie/http_enrichment.py`):**
  - Implement bounded HTTP/1.1 wire response header and HTTP/2 pseudo-header parser with zero active crawling or outbound network generation.
  - Require genuine `ObservedHttpEndpointEvidence` (IP, port, host/SNI, observed_at, collector source ID, and 64-char lowercase SHA-256 wire hash).
  - Extract and normalize approved metadata fields: `status_code`, `server`, `via`, `content_type` (MIME media type), HSTS (`strict_transport_security`), and CSP presence.
  - Strict sensitive header scrubbing: permanently discards `Set-Cookie`, `Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, session tokens, query strings, and response bodies (0 bytes retained).
  - Hard bounded resource limits: maximum 64 headers, maximum 1024 bytes per field value, maximum 16 KiB aggregate header block.
  - Epistemic classification: Technology indicators emit `GraphNode` with `NodeType.TECHNOLOGY` and `EpistemicLayer.DERIVED`, linked via `RelationType.USES_TECHNOLOGY` ($0.80$ bounded confidence) with explicit `is_spoofable=True` warnings.
  - Security policy linking: Valid HSTS headers emit `RelationType.PROTECTED_BY_POLICY` edges.
- **Competing Hypothesis Engine (`src/anie/temporal_intelligence.py`):**
  - Implement simultaneous alternative hypothesis evaluation for observed infrastructure phenomena:
    - *Volatile IP Infrastructure:* Legitimate CDN / Anycast Edge Rotation (`FAVORED` / `PLAUSIBLE`) vs. Suspicious Fast-Flux Candidate (`CONTRADICTED` / `FAVORED`).
    - *Resolver Discrepancy:* Upstream Resolver Security Filtering (`FAVORED`) vs. GeoDNS / Multi-Region Route Divergence (`CONTRADICTED`).
  - Strict evidence separation: Partitions `supporting_evidence_hashes` and `contradicting_evidence_hashes` into distinct tuples.
  - Explicit heuristic scoring ($0.0\text{ to }1.0$) with `statistically_calibrated: false` to avoid confusing heuristic matching with frequentist/Bayesian probabilities.
  - Epistemic abstention: Emits status `INSUFFICIENT_EVIDENCE` when observation count is $< 2$ epochs.
  - Historical supersession: Revisions do not overwrite past reasoning; prior hypotheses are marked `valid_until = now_iso` and status `SUPERSEDED` in SQLite table `competing_hypotheses` and linked via graph edge `RelationType.SUPERSEDES`.
- **Knowledge Graph & Obsidian Vault Export (`src/anie/graph_engine.py`):**
  - Add entity types `NodeType.TECHNOLOGY`, `NodeType.HYPOTHESIS`.
  - Add typed directed edges `RelationType.USES_TECHNOLOGY`, `RelationType.PROTECTED_BY_POLICY`, `RelationType.EXPLAINS`, `RelationType.CONTRADICTS`, `RelationType.SUPERSEDES`.
  - Add `vault/technologies/` and `vault/hypotheses/` note generators with YAML frontmatter, wikilinks, and cross-platform filename sanitization.
  - Update `vault/README.md` index with exploration roots for technologies and competing hypotheses.
  - Traversal hardening: Hardened against directory traversal, Windows device names (`CON`, `PRN`, `AUX`, `NUL`), symlinks, and a 500 KB note ceiling.
- **Verification:**
  - 15 new test cases across `tests/test_m3_8_http_enrichment.py`, `tests/test_m3_8_competing_hypotheses.py`, `tests/test_m3_8_knowledge_export_and_hardening.py`.
  - 470 total tests executed across the repository (469 passed, 0 failed, 1 skipped).

## M3.7 — Intelligence Correctness Hardening, RFC 9224/9082 Audit & Passive TLS Correlation (2026-11-21)

- **Passive TLS & X.509 Certificate Correlation (`src/anie/tls_enrichment.py`):**
  - Implement deterministic offline X.509 DER and PEM certificate parser.
  - Cryptographically bind Layer 1 `SERVES_CERTIFICATE` FACT edges strictly to verified live wire connection evidence (`ObservedTlsEndpointEvidence` requiring IP, port, SNI, observed_at, collector source ID, and raw SHA-256 wire hash).
  - Offline certificate parsing alone emits only certificate metadata (`NodeType.CERTIFICATE`, Layer 1 FACT) and Subject Alternative Name linkages (`NAMES_DOMAIN`, Layer 2 DERIVED).
  - Multi-tenant CDN/PaaS guardrails: Automatically flag certificates with $\ge 15$ SANs or known CDN root domains as shared infrastructure to prevent false guilt-by-association.
- **RFC 9224 / RFC 9082 Compliance Audit (`src/anie/rdap_enrichment.py`):**
  - Audit RDAP enrichment to strictly separate IANA registry delegation, RDAP service discovery, IP registration, prefix allocation (`PREFIX_MEMBER`), and BGP origin-AS attribution (`ANNOUNCED_BY`).
  - Epistemic abstention: Strictly prohibit synthetic or unverified ASN node creation.
- **Dynamic DNS & Mixed Anycast False-Positive Controls (`src/anie/temporal_intelligence.py`):**
  - Preserve contradictory evidence in dynamic DNS detection: alert at confidence 0.75 when $\ge 3$ subnets are present.
  - Mixed Anycast/Unicast resolution alerting: alert at confidence 0.85 when Anycast and Unicast co-resolve for the same domain, preventing indiscriminate suppression of legitimate threat indicators.
- **Vault Export Hardening (`src/anie/graph_engine.py`):**
  - Add `vault/certificates/` note exporter with validity windows, SHA-256 fingerprints, and serving endpoint backlinks.
  - Sanitize Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM*`, `LPT*`) and illegal characters.
  - Bounded note size ceiling enforcing a maximum of 500 KB per exported note.

## M3.6 — Autonomous Graph Intelligence, Obsidian Vault Export & RDAP Correlation (2026-11-21)

- **Deterministic Obsidian Markdown Knowledge Vault (`src/anie/graph_engine.py`):**
  - Export complete graph, entities, and claims into human-readable, portable Markdown notes with YAML frontmatter and bidirectional wikilinks.
  - Modular vault directory hierarchy: `vault/domains/`, `vault/ips/`, `vault/asns/`, `vault/prefixes/`, `vault/claims/`, and `vault/README.md`.
  - Cross-platform safe file writing (`_safe_write_vault_note`) with path traversal rejection and symlink attack prevention.
- **RFC 9224 RDAP Registry Correlation (`src/anie/rdap_enrichment.py`):**
  - Implement offline IANA bootstrap registry cache with deterministic longest-prefix matching.
  - Extract BGP allocation prefixes (`NodeType.CDN_PREFIX`) and Autonomous Systems (`NodeType.ASN`).
  - Create temporal directed edges: `PREFIX_MEMBER` and `ANNOUNCED_BY` with raw wire SHA-256 evidence digests.
- **SQLite FTS5 Full-Text Search Memory:**
  - Build real-time indexed search over domains, IPs, ASNs, prefixes, and claims with rank-ordered BM25 relevance and snippet generation.

## Phase 3 — Unattended Oracle Ampere A1 Free Capacity Acquisition & Governor (2026-11-20)

- **Autonomous Capacity Acquisition Engine (`src/anie/capacity_retry.py`):**
  - Implement unattended OCI SDK programmatic provisioning engine targeting Always Free `VM.Standard.A1.Flex` (2 OCPU, 12 GB RAM, 50 GB boot storage, Oracle Linux 9 ARM64).
  - Tenancy inspection: Verify existing tenancy resources, preserving `anie-collector-01` completely at ₹0.00 / $0.00 cost.
  - Rate governor: Strictly enforce a minimum 60-minute interval between provisioning attempts with exponential backoff on API throttling.
  - Windows Task Scheduler automation: Registered persistent scheduled task `ANIE_Ampere_A1_Capacity_Retry` with WakeToRun and 7-day expiration boundary.
  - Idempotency & safety: Reconcile existing launch requests, prevent duplicate instance creation, and securely manage SSH keys.

## M3.5.1 — Consumer Integrity Corrections & Atomic Claims Ingestion (2026-11-20)

- **Atomic V4 Claims Ingestion (`src/anie/real_store.py`):**
  - Update consumer release ingestion so observations, events, discrepancies, intelligence claims, and the release journal commit within a single atomic SQLite transaction (`BEGIN IMMEDIATE`).
  - Replay and crash injection testing: verify safe replay and recovery without duplicated or dropped claims.
- **Signed-Release Evidence Retention Index (`src/anie/retention.py`):**
  - Implement durable, verified release-to-evidence membership index.
  - Prevent pruning of evidence required to independently verify any retained signed release bundle.
  - Keep automated pruning fail-closed and disabled by default until verified.

## M3.5 — First-Party Intelligence Pilot & Consumer Contract V4 (2026-11-20)

- **Production-Grade Intelligence Contract V4 (`schemas/intelligence-v4.schema.json`):**
  - Stable, versioned output interface suitable for AEGIS and third-party consumers.
  - Canonical IOC and infrastructure entity identifiers (`anie:entity:domain:...`, `anie:entity:ip:...`).
  - Immutable source observations, provenance digests, and derived relationships.
  - Epistemic classification: separate empirical wire facts from derived hypotheses and attested assertions.

## M3.4.1 — Intelligence Integrity & Epistemic Abstention (2026-11-20)

- **Strict Falsifiability & Guardrails (`src/anie/temporal_intelligence.py`):**
  - Define explicit falsifiability conditions for all machine-generated intelligence claims.
  - Distinguish uncalibrated heuristic scores from statistically calibrated probabilities.
  - Prohibit inferring malicious intent from infrastructure churn, dynamic DNS, or resolver discrepancies alone.

## M3.4 — Temporal Graph Intelligence & Anomaly Detectors (2026-11-20)

- **Historical Anomaly Detectors:**
  - `INFRASTRUCTURE_TRANSITION`: IP set changes across observation epochs and resolvers.
  - `IP_RELATIONSHIP_EVOLUTION`: Duration, TTL stability, and ephemeral/persistent categorization.
  - `SHARED_INFRASTRUCTURE`: Co-hosted domains on shared vs Anycast edge pools.
  - `RESOLVER_DISCREPANCY_TIMELINE`: Multi-resolver disagreement and security-filtering NXDOMAINs.
  - `FAST_FLUX_INDICATOR`: Rapid IP churn, low TTL, and subnet diversity within 24 hours.
  - `RESOLUTION_DIVERGENCE_INDICATOR`: Sudden transitions between Anycast CDN edge pools and unicast hosts.

## M3.3.2 — Storage Integrity, Readiness & Pruning Verification (2026-11-20)

- **Referential Integrity & Pruning Safety:**
  - Two-phase retention invariants preventing evidence deletion while dependent observations remain.
  - WAL checkpoint verification and database compaction runbooks.

## M3.3.1 — Graph-Native Property Graph & 4-Layer Epistemic Model (2026-11-20)

- **Foundational Graph Models (`src/anie/graph_models.py`):**
  - Entity nodes (`GraphNode`) and temporal directed edges (`GraphEdge`).
  - 4-layer epistemic hierarchy: `FACT`, `DERIVED`, `HYPOTHESIS`, `VALIDATED`.
  - Stable, deterministic URI format (`anie:entity:<type>:<canonical_name>`).
  - Bitemporal tracking: measurement time (`observed_at`) and validity intervals (`valid_from`, `valid_until`).

## M3.2 — First-Party Provenance & Cryptographic Attestations (2026-11-20)

- **Air-Gapped Signing & Detached Attestations (`src/anie/real_publish.py`):**
  - Detached Ed25519 signing CLI (`anie sign-real`) where private keys never reside on collector nodes.
  - Deterministic canonical serialization and byte-for-byte reproducibility via `--published-at`.
  - Four-tier offline consumer verification engine (`src/anie/release_trust.py`).

## M3.1 — Security Specification & Pipeline Memory Sustainability (2026-11-16)

- **Fail-Closed Security Preflight (`src/anie/preflight_hardening.py`):**
  - Tri-state probe classification (`BLOCKED`, `ALLOWED`, `UNVERIFIABLE`).
  - Systemd cgroup BPF `IPAddressDeny=any` enforcement.
  - Memory sustainability assertions guaranteeing peak RSS $<50\text{ MiB}$ under 1 GiB micro VM constraints.
  - Unprivileged sandbox firewall inspection classification.
  - Standardized completion handling sentinel (`/var/lib/anie/pilot_completed.sentinel`).

---

## Historical Releases (Phase 1 & Phase 2 Foundation)

### Phase 2: First-Party Empirical Collection Pilot (2026-11-12)
- RFC 8484 DNS-over-HTTPS (DoH) collection engine (`DohCollector`) and rate governor (`DohRateGovernor`).
- Oracle Cloud deployment runbooks and systemd sandbox templates (`systemd/anie-collector.service`).
- Strict target allowlist limited to `example.com` and `iana.org`.

### 0.4.1 — Exact-Scope Manual DNS Pilot Preflight (2026-11-12)
- Pure RFC 8484 DNS wire A/AAAA query and fail-closed response handling.
- Manually opt-in DoH client with pinned sockets and public IP verification.

### 0.4.0 — Offline Acquisition and Cache Planning (2026-11-12)
- Parse bounded synthetic IANA-style RDAP IPv4/IPv6 bootstrap registries.
- Deterministic TTL-aware offline scheduler.

### 0.3.0 — Offline Synthetic Release Signature Verification (2026-11-12)
- Optional PyCA cryptography Ed25519 signature verification.
- Domain-separated authenticated payload binding manifest hash, git commit, and sequence.

### 0.2.0 — Offline Collection Foundation (2026-11-11)
- Bounded fixture and request budgets; deterministic synthetic DNS response normalization.
- Versioned collection-event schema and append-only SQLite ledger.

### 0.1.0 — Initial Source Prototype (2026-11-11)
- Offline synthetic-only Python prototype with SQLite observations, temporal DNS features, and unsupervised novelty model.

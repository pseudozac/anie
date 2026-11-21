# ANIE Research Plan & Methodological Roadmap

**Project:** Autonomous Network Intelligence Engine (ANIE)  
**Status:** Active Phase 3 Research (Baseline: Milestone M3.8 / Commit `6352bc6`)  
**Core Research Question:** Can first-party temporal internet observations and uncertainty-aware knowledge graphs produce reusable, evidence-backed intelligence more efficiently and reliably than repeated, undirected collection?

---

## 1. Evaluation Before Claims

ANIE operates on a foundational tenet of **epistemic humility**: statistical novelty, temporal drift, or clustering distance indicate changes in empirical observation—**not malicious verdicts, threat classifications, or calibrated intent**.

- **Deterministic Baseline:** Strict change detection without probabilistic models (IP change, nameserver migration, ASN re-attribution, certificate renewal).
- **Temporal Baselines:** Robust nonparametric estimators (kNN distance on normalized DNS/entropy spaces, rolling variance windows) evaluated on strictly time-separated corpora with no future-data leakage.
- **Corpora:**
  - *Synthetic Baseline Corpus:* Programmatically generated multi-epoch fixtures with known infrastructure transitions, adversarial poisoning, and synthetic latency.
  - *Empirical Pilot Corpus:* Strictly authorized first-party measurements collected during the 72-Hour Live Pilot on Oracle Cloud (`anie-collector-01`) under fail-closed preflight hardening.
- **Evaluation Metrics:**
  - Novelty precision/recall at pre-declared calibration thresholds.
  - Historical timeliness and lag to infrastructure state transitions.
  - False attribution rate across legitimate CDN, anycast, dynamic DNS, and shared-hosting providers.
  - Verification cost and storage footprint per validated observation.
  - Epistemic classification accuracy across `FACT`, `DERIVED`, `HYPOTHESIS`, and `VALIDATED` knowledge tiers.
- **Architectural Guardrails:** Missing-data abstention, collector-source provenance isolation, error $\neq$ empty assertion, deterministic JSON canonicalization, air-gapped private keys, and 100% offline verifiable attestation.

---

## 2. Research Increment Progression

```
+---------------------------------------------------------------------------------------------------+
| INCREMENT 1: Offline Foundation & Baseline (v0.1 - v0.4)                                          |
| - Deterministic baseline vs. kNN novelty on time-split synthetic corpora                         |
| - RFC 8484 wire parser and append-only SQLite observation schema                                  |
| - Status: COMPLETED (Nov 2026)                                                                    |
+---------------------------------------------------------------------------------------------------+
                                              |
                                              v
+---------------------------------------------------------------------------------------------------+
| INCREMENT 2: Phase 2 Live Pilot & Authenticated Ingestion (PR #1 - PR #30)                        |
| - 72-Hour live DoH measurement pilot on Oracle Cloud Always Free VM (anie-collector-01)          |
| - Detached Ed25519 signing, anti-rollback monotonic sequence tracking, SHA-256 wire digests        |
| - Status: COMPLETED (Nov 2026)                                                                    |
+---------------------------------------------------------------------------------------------------+
                                              |
                                              v
+---------------------------------------------------------------------------------------------------+
| INCREMENT 3: Phase 3 Epistemic Graph & Multi-Vector Intelligence (M3.1 - M3.8)                     |
| - M3.1: Preflight hardening, tri-state egress probes, sentinel reconciliation (PR #31)            |
| - M3.2: Air-gapped attestation CLI, dual-key rotation, candidate bundle extraction (PR #32)       |
| - M3.3: Multi-resolver discrepancy matrix, DNSSEC validation, Cloudflare/Google/Quad9 (PR #33)   |
| - M3.4: SQLite property graph, temporal intervals (valid_from/valid_until), drift scoring (PR #34)|
| - M3.5/M3.5.1: AEGIS V4 consumer contract, atomic SQLite ingestion, evidence retention (PR #35)  |
| - M3.6: RFC 9224/9082 RDAP bootstrap, BGP ASN attribution, CDN/Anycast false-positive controls    |
| - M3.7: TLS x509 SAN certificate graph, live SERVES_CERTIFICATE fact verification (PR #36)        |
| - M3.8: Passive HTTP metadata, Competing Hypothesis Engine, Obsidian vault export (PR #36)       |
| - Status: COMPLETED (Nov 2026, 470 unit/integration tests passing)                                |
+---------------------------------------------------------------------------------------------------+
                                              |
                                              v
+---------------------------------------------------------------------------------------------------+
| INCREMENT 4: Cross-Vector Synthesis & Autonomous Lifecycle (Phase 4 Planned)                      |
| - Workstream 4.1: Cross-vector discrepancy synthesis (DNS vs BGP vs TLS vs HTTP divergence)       |
| - Workstream 4.2: Continuous temporal anomaly calibration on long-horizon empirical corpora       |
| - Workstream 4.3: AEGIS Consumer Contract V5 with streaming property graph synchronization        |
| - Workstream 4.4: Cryptographic retention management with dual-signature tombstone pruning        |
| - Status: PLANNED / NEXT MILESTONES                                                               |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Detailed Increment History

### Increment 1: Offline Foundation & Baseline Validation (v0.1 – v0.4)
- **Deterministic Baseline vs. Machine Learning:** Demonstrated that deterministic change rules outperform uncalibrated clustering on small corpora, establishing the requirement for strictly time-split benchmarking without future leakage ([docs/TEMPORAL_BENCHMARK.md](file:///c:/Users/aniza/Downloads/anie/docs/TEMPORAL_BENCHMARK.md)).
- **RFC 8484 DoH Protocol Implementation:** Offline RFC 8484 wire-format parser with byte-level length validation and header parsing.
- **Fail-Closed Target Budgeting:** In-memory rate limiting and cache governors restricting collection strictly to operator-authorized targets.

### Increment 2: Phase 2 Live Pilot & Authenticated Ingestion (PR #1 – PR #30)
- **72-Hour Live Pilot on Oracle Cloud:** Executed strictly bounded, 1-query/day DoH measurement across target domains using unprivileged systemd sandboxing on `anie-collector-01` (`VM.Standard.E2.1.Micro`).
- **Cryptographic Provenance Pipeline:** Separated untrusted collector nodes from signing keys. Collector produces unsigned candidate release bundles; air-gapped operator workstation executes detached Ed25519 signing (`anie.attestation.v1`).
- **Anti-Rollback Sequence Enforcement:** High-water mark state tracking preventing re-ingestion of superseded or rolled-back intelligence releases.

### Increment 3: Phase 3 Epistemic Graph & Multi-Vector Intelligence (M3.1 – M3.8)
- **M3.1 (Security Remediation):** Tri-state probe classification (`BLOCKED`, `ALLOWED`, `UNVERIFIABLE`), unprivileged netfilter capability handling, and canonical completion sentinel reconciliation (`/var/lib/anie/pilot_completed.sentinel`).
- **M3.2 (Provenance & Attestation):** Standardized detached Ed25519 attestation manifest (`signature.ed25519.json`), dual-key trust policies, and offline CLI (`anie sign-release`, `anie verify-release`).
- **M3.3 (Multi-Resolver Discrepancy Matrix):** Normalized multi-resolver ingestion across Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), and Quad9 (`9.9.9.9`). Ingested raw DNS wire digests and evaluated quorum verdicts with explicit DNSSEC validation.
- **M3.4 (Temporal Graph Intelligence):** SQLite-backed property graph engine with 7 canonical entity types and 8 typed relationships. Temporal edge intervals (`valid_from`, `valid_until`) and kNN temporal drift scoring with abstention.
- **M3.5 & M3.5.1 (AEGIS Consumer Contract V4 & Atomic Ingestion):** Reversible claim assertions, consumer release journaling, atomic multi-table transaction commits, and signed-release evidence retention guarantees.
- **M3.6 (RDAP Enrichment & BGP Routing):** RFC 9224/9082 bootstrap discovery, IANA IP/ASN delegation parsing, BGP origin-AS attribution, and CDN/Anycast/Dynamic DNS false-positive controls.
- **M3.7 (TLS Certificate Graph):** Passive and active TLS x509 SAN parsing, deterministic `SERVES_CERTIFICATE` fact edges requiring genuinely observed endpoint handshakes, certificate SAN correlation, and path traversal hardening.
- **M3.8 (Passive HTTP Metadata & Competing Hypotheses):** Passive HTTP/1.1 and HTTP/2 response metadata extraction (Server, Via, HSTS, Content-Type), header canonicalization, memory-bounded SHA-256 evidence digests, Competing Hypothesis Engine with corroboration scoring, and Markdown Obsidian knowledge vault export.

---

## 4. Next Increments (Increment 4 / Phase 4 Roadmap)

### Workstream 4.1: Cross-Vector Discrepancy Synthesis
- Synthesize discrepancies across distinct telemetry layers:
  - DNS resolution answers diverging from BGP origin-AS announcements.
  - TLS SAN certificates advertising domains not present in DNS A/AAAA records.
  - HTTP Server/Via headers contradicting RDAP organizational allocations (e.g. cloud provider IPs advertising corporate enterprise reverse proxies).
- Model multi-vector divergence as structured hypothesis trees rather than singular threat assertions.

### Workstream 4.2: Continuous Temporal Anomaly Calibration
- Deploy non-parametric time-series variance tracking on multi-month observation corpora.
- Benchmark abstention rates and calibration curves for sudden ASN migration vs. gradual CDN anycast rotation.
- Guarantee memory footprints stay under 100 MiB during temporal sliding window queries.

### Workstream 4.3: AEGIS Consumer Contract V5 & Streaming Sync
- Introduce delta-stream publication format (`.diff.jsonl.gz`) to supplement full snapshots.
- Enable AEGIS consumer engines to synchronize incremental graph updates without re-indexing historical releases.
- Implement bidirectional schema version negotiation with forward-compatible optional fields.

### Workstream 4.4: Cryptographic Retention Management
- Author a cryptographically verified retention and tombstone mechanism:
  - Dual-signature operator authorization required to expunge expired or revoked observations.
  - Merkle audit log of tombstoned records preserving cryptographic verifiability of signed releases without retaining unneeded raw payloads.
  - Fail-closed pruning prevention for evidence linked to active signed releases.

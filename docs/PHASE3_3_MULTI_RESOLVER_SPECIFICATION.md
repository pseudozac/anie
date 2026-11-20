# ANIE Phase 3.3 — Multi-Resolver Intelligence & Discrepancy Analysis Specification

**Document Version:** 1.0.0  
**Status:** Approved for Implementation (Spec-Driven Development)  
**Baseline Commit:** `3508e0a09a9b0cbea63145f9e6c006545ab86f3d`  
**Target Milestone:** M3.3 — Multi-Resolver Intelligence & Discrepancy Analysis  

---

## 1. Phase A — Security & Architecture Audit

### 1.1. Review of M3.2 Baseline
An independent audit of milestone M3.2 (`3508e0a`) verified that:
- GitHub Actions CI ran successfully on Python 3.10, 3.12, and 3.13 without regression.
- Detached Ed25519 signatures bind manifest SHA-256 and `prev_manifest_sha256` under domain separator `ANIE-REAL-ED25519-RELEASE-V2\x00`.
- Release hash chaining enforces backward continuity across sequential publications.
- The Oracle VM collector (`anie-collector-01`) remains quiescent with timers disabled and collection sentinels locked.

### 1.2. Security Findings & Required Hardening

| Finding ID | Severity | Description | Required Hardening |
| :--- | :--- | :--- | :--- |
| **SEC-3.3-01** | **High** | **`--allow-rollback` Trust Policy Bypass:** In `verify_real_release`, `allow_rollback=True` was an unconstrained caller argument not governed by the operator's pinned `RealReleaseTrust` policy. An untrusted caller could bypass anti-rollback sequence checks even if the operator intended strict enforcement. | Add `allow_rollback: bool = False` to `RealReleaseTrust`. If caller passes `allow_rollback=True` when `not trust.allow_rollback`, verification fails closed. Mark rolled-back verifications as `AUTHENTICATED_HISTORICAL_INSPECTION` with `anti_rollback_verified=False`. |
| **SEC-3.3-02** | **High** | **Consumer Atomicity Gap:** In `AegisReleaseConsumer.verify_and_load`, the sequence tracker was updated in Step 1 before partition records were reconstructed or persisted into the consumer store. A crash during record reading or database ingestion left the tracker advanced, permanently preventing re-ingestion of that release. | Refactor `AegisReleaseConsumer` to execute a two-phase protocol: verify release structures and deserialize all records without mutating tracker state; advance the tracker atomically only after record validation and optional consumer persistence callbacks succeed. |
| **SEC-3.3-03** | **Medium** | **Collector Key Isolation Blind Spots:** `check_no_signing_keys` inspected only `/var/lib/anie` and `/etc/anie`. Sensitive paths such as `/home/anie`, `/tmp`, the application working directory, and environment variables (e.g. `ANIE_PRIVATE_KEY` or SSH agent keys containing private key PEM headers) were not actively asserted. | Extend `check_no_signing_keys` to inspect `/home/anie`, `/tmp/anie*`, the current working tree, and scan `os.environ` for private key PEM headers or variable names matching `*PRIVATE_KEY*` or `*SIGNING_KEY*`. |

---

## 2. Requirements & Trust Boundaries

### 2.1. Trust Boundaries
```
+-----------------------------------------------------------------------------------+
| Domain 1: Collector Host (Quiescent / Untrusted with Signing)                     |
| - Bounded DoH queries across isolated provider adapters (Cloudflare, Google, Quad9)|
| - Zero private keys in storage, memory, or environment                            |
| - Preflight actively asserts air-gap boundaries and missing signing keys          |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Domain 2: Multi-Resolver Normalization & Discrepancy Engine                       |
| - Deterministic answer normalization (RFC 5952 IPv6, sorted RRsets, CNAME chains)  |
| - Discrepancy categorization (Agreement, Expected Divergence, Filtering, Bogus)    |
| - Critical Invariant: Discrepancy NEVER implies maliciousness                     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Domain 3: Air-Gapped Operator Review & Attestation                                |
| - Candidate inspection with 'anie inspect-candidate' (pre-signing review)         |
| - Detached Ed25519 signing under v3 dataset manifest                              |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| Domain 4: AEGIS Consumer (Transactional Ingestion)                                |
| - Independent verification of signatures, hash chains, and referential integrity  |
| - Atomically advances sequence tracker only after complete consumer persistence   |
+-----------------------------------------------------------------------------------+
```

### 2.2. Functional Requirements

#### Multi-Resolver Observation Engine
- **REQ-RES-01:** Provider adapters MUST be implemented for:
  1. `cloudflare`: `https://cloudflare-dns.com/dns-query` (Standard Recursive)
  2. `google`: `https://dns.google/dns-query` (Standard Recursive)
  3. `quad9`: `https://dns.quad9.net/dns-query` (Security-Filtering Recursive)
- **REQ-RES-02:** Resolver metadata MUST distinguish `standard_recursive` from `security_filtering` providers.
- **REQ-RES-03:** All queries MUST be formatted according to RFC 8484 (DoH) with EDNS(0) and DO (DNSSEC OK) bit enabled.
- **REQ-RES-04:** Responses MUST parse answer RRsets, CNAME chains, DNSSEC flags (`AD`, `CD`, `DO`), RCODE, TTL, and Extended DNS Errors (RFC 8914).
- **REQ-RES-05:** Raw wire bytes MUST be hashed with SHA-256 and preserved without modification.

#### Normalization & Discrepancy Engine
- **REQ-DIS-01:** Answers MUST be normalized before comparison:
  - IPv4 addresses formatted canonically `a.b.c.d`.
  - IPv6 addresses formatted canonically according to RFC 5952 (lowercase, compressed).
  - RRsets sorted deterministically by `(type, data)`.
  - CNAME aliases traced to terminal canonical target.
- **REQ-DIS-02:** Discrepancy analysis MUST evaluate multi-resolver responses into one of six mutually exclusive verdicts:
  1. `AGREEMENT`: Identical normalized answers and consistent DNSSEC validation.
  2. `EXPECTED_DIVERGENCE`: Benign divergence attributable to CDN Anycast IP rotation, TTL caching drift, or multi-homed load balancing.
  3. `SECURITY_FILTERING_DETECTED`: Filtering resolver (Quad9) returns policy block (NXDOMAIN, 0.0.0.0, or RFC 8914 EDE 15) while standard resolvers return active answers.
  4. `DNSSEC_DISAGREEMENT`: Resolvers disagree on DNSSEC authenticity (e.g. AD=1 vs SERVFAIL/AD=0).
  5. `UNEXPLAINED_DIVERGENCE`: Conflicting, non-overlapping IP addresses across standard resolvers that cannot be attributed to known CDN infrastructure.
  6. `INCONCLUSIVE`: Fewer than 2 resolvers returned valid responses.
- **REQ-DIS-03 (Core Invariant):** Discrepancy or filtering detection MUST NEVER automatically produce a "malicious" or "threat" verdict.
- **REQ-DIS-04:** Every discrepancy verdict MUST include an evidence-backed human-readable explanation and calibrated numerical confidence $[0.0, 1.0]$.
- **REQ-DIS-05:** Referential integrity: Every discrepancy report MUST reference the exact `observation_id` and `event_id` of every underlying resolver observation.

#### Historical Intelligence & Storage
- **REQ-HIST-01:** SQLite schema MUST persist multi-resolver observations and discrepancy analysis in `real_discrepancies` table with relational foreign keys.
- **REQ-HIST-02:** Minimal historical foundation: provide point-in-time queries for `first_seen`, `last_seen`, value change timelines, and resolver agreement rates without large-scale graph dependencies.
- **REQ-HIST-03:** Deduplication and bounded retention: raw wire evidence is deduplicated by `raw_sha256`; query limits prevent unbounded growth.

#### AEGIS Interoperability & Release Manifest
- **REQ-REL-01:** Dataset manifest schema upgraded to `anie.real-dataset-manifest.v3` (accepting v1 and v2 for backward compatibility).
- **REQ-REL-02:** When discrepancy reports exist, publication bundle MUST include `real_discrepancies.jsonl.gz`.
- **REQ-REL-03:** Verifier and consumer MUST verify referential integrity from discrepancy reports to both observations and events partitions.

---

## 3. Measurable Acceptance Criteria

1. **AC-01 (Rollback Authorization Policy):** Calling `verify_real_release` with `allow_rollback=True` when `trust.allow_rollback` is `False` MUST fail closed with a descriptive `ValueError`.
2. **AC-02 (Transactional Consumer Atomicity):** In `AegisReleaseConsumer`, if record reconstruction or consumer persistence callback raises an exception, the sequence tracker MUST NOT be updated.
3. **AC-03 (Extended Key Isolation):** `check_no_signing_keys` MUST fail closed if a private key file or PEM private header exists in `/home/anie`, `/tmp`, the working directory, or process environment variables.
4. **AC-04 (Multi-Resolver Adapter Support):** Adapters for Cloudflare, Google, and Quad9 MUST construct valid RFC 8484 queries and correctly extract response RCODE, answers, TTL, and DNSSEC flags.
5. **AC-05 (Security Filtering Differentiation):** When Quad9 returns a policy block (EDE 15 / NXDOMAIN) while Google and Cloudflare return valid IPs, the discrepancy engine MUST output `SECURITY_FILTERING_DETECTED` and MUST NOT label the domain as malicious.
6. **AC-06 (CDN Divergence Classification):** When resolvers return differing IP addresses that belong to the same verified CDN Anycast network (e.g. Cloudflare `104.16.x.x`), the discrepancy engine MUST classify the result as `EXPECTED_DIVERGENCE`.
7. **AC-07 (DNSSEC Disagreement Detection):** When one resolver asserts `AD=1` while another returns `SERVFAIL` (bogus) or `AD=0`, the engine MUST classify the result as `DNSSEC_DISAGREEMENT`.
8. **AC-08 (Referential Integrity):** Every record in `real_discrepancies.jsonl.gz` MUST refer exclusively to `observation_id`s and `evidence_id`s present in `real_observations.jsonl.gz` and `real_events.jsonl.gz`.
9. **AC-09 (Deterministic Gzip & Packaging):** Multi-resolver publication bundles containing discrepancies MUST produce bit-for-bit reproducible artifacts when `published_at` and `source_commit` are fixed.
10. **AC-10 (1 GiB Resource Envelope):** Multi-resolver batch execution and discrepancy analysis MUST complete with peak process RSS under 50 MiB and memory usage under 200 MiB.

---

## 4. Schemas & Data Formats

### 4.1. Discrepancy Report Schema (`anie.discrepancy-report.real.v1`)
```json
{
  "schema": "anie.discrepancy-report.real.v1",
  "analysis_id": "discrepancy_9a4f210e7b8...",
  "subject": "example.com",
  "kind": "dns_a",
  "analyzed_at": "2026-11-20T12:00:00Z",
  "verdict": "AGREEMENT",
  "explanation": "All 3 independent resolvers (cloudflare, google, quad9) returned identical normalized A records with verified DNSSEC validation.",
  "confidence": 1.0,
  "participating_resolvers": ["cloudflare", "google", "quad9"],
  "answers_by_resolver": {
    "cloudflare": ["93.184.216.34"],
    "google": ["93.184.216.34"],
    "quad9": ["93.184.216.34"]
  },
  "dnssec_by_resolver": {
    "cloudflare": "secure",
    "google": "secure",
    "quad9": "secure"
  },
  "filtering_metadata": {},
  "observation_ids": {
    "cloudflare": "obs_1234...",
    "google": "obs_5678...",
    "quad9": "obs_9abc..."
  },
  "evidence_ids": {
    "cloudflare": "event_1234...",
    "google": "event_5678...",
    "quad9": "event_9abc..."
  },
  "evidence_hashes": {
    "cloudflare": "4a72d3...",
    "google": "b81e2f...",
    "quad9": "9c12a0..."
  },
  "ruleset_version": "anie.discrepancy-engine.v1"
}
```

### 4.2. Dataset Manifest Schema V3 (`anie.real-dataset-manifest.v3`)
Extends V2 with an optional third partition file `real_discrepancies.jsonl.gz` and summary count `total_discrepancies`.

---

## 5. Implementation Tasks

| Task ID | Component | Description | Acceptance Test |
| :--- | :--- | :--- | :--- |
| **T3.3-01** | `preflight_hardening.py` | Implement SEC-3.3-03: Extend `check_no_signing_keys` to scan `/home/anie`, `/tmp`, and `os.environ`. | `test_preflight_key_isolation_extended` |
| **T3.3-02** | `real_publish.py` | Implement SEC-3.3-01 & SEC-3.3-02: Enforce `trust.allow_rollback` policy and make `AegisReleaseConsumer` two-phase atomic. | `test_trust_policy_allow_rollback`, `test_consumer_two_phase_atomicity` |
| **T3.3-03** | `multi_resolver.py` | Implement resolver adapters for Cloudflare, Google, and Quad9 with RFC 8484 / EDNS / EDE parsing. | `test_multi_resolver_adapters` |
| **T3.3-04** | `discrepancy_models.py` | Implement `RealDiscrepancyReport` dataclass with canonical JSON serialization and deterministic hashing. | `test_discrepancy_model_invariants` |
| **T3.3-05** | `discrepancy_engine.py` | Implement normalized comparison, CDN Anycast heuristics, filtering detection, and DNSSEC consensus analysis. | `test_discrepancy_classification_matrix` |
| **T3.3-06** | `real_store.py` | Add `real_discrepancies` SQLite table, persistence methods, and historical intelligence query interfaces. | `test_real_store_discrepancies_and_history` |
| **T3.3-07** | `real_publish.py` | Upgrade publication, detached signing, and verification to V3 manifests with discrepancy partitions. | `test_v3_publication_with_discrepancies` |
| **T3.3-08** | `cli.py` | Add CLI discrepancy analysis and multi-resolver batch inspection commands. | `test_cli_multi_resolver` |
| **T3.3-09** | `tests/` | Comprehensive test suite: adversarial failure injection, RFC 8914 filtering, CDN drift, and benchmarks. | `test_multi_resolver_intelligence.py` |

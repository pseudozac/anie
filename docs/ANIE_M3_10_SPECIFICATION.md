# ANIE Milestone M3.10 Specification
## End-to-End Intelligence Verification & Consumer Integration Readiness

**Engineering Owner:** Antigravity (Anti)  
**Date:** 2026-11-21  
**Accepted Baseline Commit:** `ba267fcffc0f55a57a006c05eaaabf3231091efa` (M3.9, PR #39)  
**Target Milestone:** Milestone M3.10 — End-to-End Intelligence Verification & Consumer Integration Readiness  
**Standard:** Spec-Driven Development (SDD)  
**Status:** Approved for Implementation  

---

## 1. Executive Summary & Objective

Milestone M3.10 establishes end-to-end intelligence verification, hardening, and downstream consumer readiness across the Autonomous Network Intelligence Engine (ANIE). Rather than introducing architectural churn or premature collection expansions, M3.10 rigorously audits and reinforces the multi-vector intelligence pipeline delivered in M3.9, implements a self-contained signed release and independent verification workflow, freezes the AEGIS Consumer Contract V2, and delivers concrete integration fixtures and an example client for downstream consumers.

```
+---------------------------------------------------------------------------------------------------------+
|                                  ANIE M3.10 WORKSTREAM ARCHITECTURE                                     |
+---------------------------------------------------------------------------------------------------------+
|  Phase A: Correctness Audit & Remediation                                                               |
|  - Cryptographic Payload Preimage Verification (raw_payload SHA-256 assert)                              |
|  - Authorized Collector Whitelist (source_id authentication != regex match)                             |
|  - Crash-Consistent Retention Tombstones (atomic transactions, zero credential leakage, SHA-256 digest) |
|  - Deterministic Out-of-Order Index Rebuilding (min(first_obs), max(last_obs), evidence hash merging)    |
|  - Consumer Contract V1 Frozen Regressions & Skipped Test Reconciliation                                |
|                                                                                                         |
|  Phase B: Signed Release & Independent Verification                                                     |
|  - Cross-Vector Findings Partition: real_findings.jsonl.gz (OPTIONAL_PARTITION_FILES)                   |
|  - Deterministic Dataset Manifest V4/V5 + Ed25519 Detached Attestation                                   |
|  - Standalone Independent Verifier (CLI / Subprocess) with Explicit Trust Policy                         |
|  - Adversarial Fault Injection Matrix (Tampered Payload, Corrupted Signature, Rollback, Broken Hash)     |
|                                                                                                         |
|  Phase C: AEGIS Consumer Integration Readiness                                                          |
|  - Frozen anie.consumer-contract.v2 & anie.cross-vector-finding-feed.v2 Specification                   |
|  - Reference Consumer Client: examples/aegis_consumer_v2_example.py                                     |
|  - Frozen Consumer Test Fixture: tests/fixtures/aegis_consumer_contract_v2_fixture.json                  |
|  - Epistemic Hierarchy Enforcement: FACT vs. DERIVED vs. HYPOTHESIS vs. VALIDATED                       |
|  - Mandatory Score Disclaimer: Heuristic Matching != Calibrated Threat Probability                      |
|                                                                                                         |
|  Phase D: Operational Acceptance & Invariants                                                           |
|  - 1 GiB Oracle Micro VM Budget: RSS <200 MiB, Disk Growth <500 MiB, Zero Subprocess Leaks              |
|  - Zero-Cost Invariants: anie-collector-01 quiescent; ANIE_Ampere_A1_Capacity_Retry untouched           |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. Phase A: M3.9 Correctness Audit & Remediation

### 2.1 Authoritative Evidence Integrity Hardening (`src/anie/real_store.py`)
- **Current Limitation:** In M3.9, `verify_evidence_authoritativeness(hash)` returned `is_authoritative: True` merely if a record existed with matching `event_id` or `raw_sha256`. It did not assert preimage integrity of retained raw bytes, nor did it validate collector authorization.
- **Remediation Invariants:**
  1. **Preimage Hash Verification:** When `raw_payload` is stored, the verifier must recompute `sha256(raw_payload).hexdigest()` and assert equality with `raw_sha256`. If `raw_payload` is missing or mismatched, `status` must be `CORRUPT_PAYLOAD_DIGEST_MISMATCH`.
  2. **Collector Authorization Whitelist:** Source IDs must be checked against an active authorized collector list or pattern (`first_party:doh:*`, `oracle-collector-01:*`, `anie-collector-01:*`, or explicit allowed collectors). Arbitrary unvetted strings are marked `UNAUTHORIZED_COLLECTOR_SOURCE`.
  3. **Factual Verification Invariants:** `raw_evidence_status` must be `'captured'` and factual verification attributes (wire rcode, transport security) must be present.

### 2.2 Retention Tombstone Hardening (`src/anie/retention.py`, `src/anie/real_store.py`)
- **Current Limitations:**
  1. Tombstone records inserted `''` (empty string) for `original_sha256`.
  2. Raw `operator_authorization` strings could persist plaintext operator tokens.
  3. Deletions and tombstone inserts ran in separate chunk iterations, posing crash-inconsistency hazards.
- **Remediation Invariants:**
  1. **Cryptographic Record Digest:** `original_sha256` must store the genuine SHA-256 of the record (for events: `raw_sha256`; for observations: canonical hash of the observation).
  2. **Credential Sanitization:** Raw credentials must never be stored. Store `auth_digest = "auth_sha256_" + sha256(operator_auth.encode()).hexdigest()[:16]`.
  3. **Atomic Crash Consistency:** In `safe_prune_retention`, tombstone insertion and record deletion for each batch must execute inside the same SQLite transaction.
  4. **Cryptographic Entry Digest:** Each tombstone entry must record a deterministic `tombstone_digest` computed over its tuple `(tombstone_id, record_type, original_id, original_sha256, pruned_at, auth_digest, policy_reason)`.

### 2.3 Deterministic Derived-Index Rebuilding (`src/anie/retention.py`)
- **Out-of-Order Convergence:** When processing observations out of chronological order, `graph_nodes` must converge to `first_observed_at = min(first_observed_at, excluded.first_observed_at)` and `last_observed_at = max(last_observed_at, excluded.last_observed_at)`.
- **Evidence Hash Chaining:** `graph_edges` must preserve referenced `evidence_hashes_json` joined from `real_events`, merging new evidence hashes on subsequent observations.
- **Supersession Preservation:** Corrected or superseded observations must reflect `valid_until` bounding without dropping prior audit trails.

### 2.4 Consumer Contract V1 Frozen Regressions & Skipped Test Reconciliation
- **V1 Frozen Fixtures:** Author frozen V1 fixtures to guarantee 100% backward compatibility.
- **Reconciliation of Skipped Test:** Reconcile `test_json_schema_if_dependency_available` in `tests/test_schema.py` which skips gracefully when `jsonschema` is not installed, documenting the rationale and ensuring no production tests are skipped.

---

## 3. Phase B: Signed Release & Independent Verification

### 3.1 Cross-Vector Findings Release Partition
- Extend `export_canonical_dataset` and `publish_real` to support `include_findings: bool = False`.
- When enabled, exports `real_findings.jsonl.gz`, validating referential integrity against exported events and observations.
- Add `real_findings.jsonl.gz` to `OPTIONAL_PARTITION_FILES` in `src/anie/real_publish.py`.

### 3.2 Independent Verifier Architecture
- Standalone verification executable via `python -m anie verify-real` and `verify_real_release`.
- Verifies entirely offline using only:
  1. The exported directory containing manifest, signature, and `.jsonl.gz` partitions.
  2. An explicitly supplied `RealReleaseTrust` policy with the publisher's Ed25519 public key.
  3. An optional monotonic `ReleaseSequenceTracker` state file for anti-rollback verification.

### 3.3 Adversarial Fault Injection Matrix
The test suite must verify fail-closed rejection for:
1. **Tampered Data Partition:** Flipping a single bit in `real_observations.jsonl.gz` or `real_findings.jsonl.gz` triggers `MANIFEST_DIGEST_MISMATCH`.
2. **Corrupted Signature:** Modifying one byte of `signature.ed25519.json` triggers `SIGNATURE_VERIFICATION_FAILED`.
3. **Rollback Replay:** Presenting release sequence $N \le N_{last}$ triggers anti-rollback rejection.
4. **Broken Evidence Linkage:** Findings referencing nonexistent event hashes are rejected during publication or verification.

---

## 4. Phase C: AEGIS Consumer Integration Readiness

### 4.1 Frozen Consumer Contract V2 Specification
- **Contract Identifier:** `anie.consumer-contract.v2`
- **Findings Feed Schema:** `anie.cross-vector-finding-feed.v2`
- **Canonical IOC Feed Schema:** `anie.canonical-ioc-feed.v2`

### 4.2 Epistemic Taxonomy Invariants
All emitted findings and IOCs must preserve the 4-layer epistemic hierarchy:
1. `FACT` (Layer 1): Raw observations, verified wire handshakes, response headers.
2. `DERIVED` (Layer 2): Deterministic graph transformations, parsed SAN names, TTL calculations.
3. `HYPOTHESIS` (Layer 3): Corroborated patterns evaluated via competing hypotheses.
4. `VALIDATED` (Layer 4): Multi-epoch corroborated claims with explicit operator/analyst confirmation.

### 4.3 Uncalibrated Heuristic Scores
Heuristic scores $[0.0, 1.0]$ are explicitly uncalibrated matching distances. Consumers must never treat a high heuristic score as a calibrated probability of maliciousness or compromise.

### 4.4 Reference Consumer Client & Fixtures
- Deliver `examples/aegis_consumer_v2_example.py` demonstrating:
  - Reading from an authenticated release bundle or local store.
  - Streaming normalized findings with cursor pagination.
  - Evaluating competing hypotheses and abstention states.
  - Verifying authoritative evidence references.
- Deliver frozen deterministic fixture: `tests/fixtures/aegis_consumer_contract_v2_fixture.json`.

---

## 5. Phase D: Operational Constraints & Invariants

| Constraint | Limit | Verification Mechanism |
| :--- | :--- | :--- |
| **Collector VM Memory** | $\le 200\text{ MiB}$ Peak RSS | In-process streaming, chunked SQLite iterators, bounded buffers. |
| **Disk Growth** | $\le 500\text{ MiB}$ | Deterministic gzip (mtime=0, level 9), WAL checkpoints, retention pruning. |
| **Collector VM Invariance** | ₹0.00 / $0.00 cost | `anie-collector-01` remains quiescent, timer disabled, sentinel active. |
| **Acquisition Runner Invariance** | Untouched | Windows Task Scheduler `ANIE_Ampere_A1_Capacity_Retry` operating independently. |
| **Zero Network During Verification** | 0 external requests | Verification executes completely offline with local public key and state. |

---

## 6. Acceptance Criteria

1. All Phase A remediations implemented: payload preimage check, authorized collector whitelist, crash-consistent credential-scrubbed tombstones, and out-of-order index rebuild.
2. Phase B end-to-end pipeline produces a signed release with `real_findings.jsonl.gz`, verified offline by independent verifier against adversarial injections.
3. Phase C delivers `examples/aegis_consumer_v2_example.py` and frozen fixtures; all V1 and V2 tests pass.
4. Skipped test accounted for and reconciled against CI logs.
5. Full test suite ($\ge 484$ tests) passes with 0 failures; `tools/check_repo.py` passes.
6. Pull Request created, CI matrix (Python 3.10, 3.12, 3.13) green, squash merged to `main`.

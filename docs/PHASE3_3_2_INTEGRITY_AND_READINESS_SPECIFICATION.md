# ANIE Milestone M3.3.2 Specification: Architecture Integrity & OCI Readiness

**Status:** APPROVED  
**Author:** Primary Autonomous Engineering Agent  
**Baseline:** `8dfa4a4ed5a2e9272b58257dc6eb1e0ac7db1a41`  
**Milestone:** M3.3.2  
**Date:** November 20, 2026  

---

## 1. Context & Objectives

Milestone M3.3.1 established the graph knowledge foundation (ADR 004, Schema v3, and SQLite recursive CTE query engine). Before active multi-resolver discrepancy discovery (M3.4) can be safely activated, M3.3.2 hardens the release ingestion lifecycle, graph data integrity, intelligence trust boundaries, and cloud deployment readiness.

### Core Objectives:
1. **Release Ingestion Correctness:** Eliminate race conditions and partial states between consumer database persistence and sequence tracker advancement. Implement an idempotent, crash-recoverable ingestion protocol with single-boundary transactional consistency or a recovery journal.
2. **Graph Correctness & Hardening:** Enforce automatic, transactionally consistent dual-write graph synchronization. Prevent silent loss of evidence during edge deduplication. Add bounded recursive traversal limits (depth, expanded nodes, max results) and fix ambiguous path-cycle substring matching. Secure Markdown/YAML export against untrusted injection.
3. **Intelligence Trust Model Formalization:** Establish explicit verification states and uncertainty semantics across the 4 epistemic layers. Ground cryptographic attestation as proof of authorship and payload integrity, not external real-world ground truth.
4. **Oracle Cloud Infrastructure Readiness:** Reconcile published Always Free entitlements (2 A1 OCPUs / 12 GB RAM) with tenancy displayed quotas (4 OCPUs / 24 GB RAM). Audit Hyderabad A1 host capacity in read-only mode and preserve existing `anie-collector-01` without mutation.
5. **Scalability Benchmarking:** Extend deterministic synthetic benchmarks to 10,000 and 100,000 observations with repeated updates, cold restart recovery, and OS process RSS profiling.

---

## 2. Technical Specifications

### 2.1 Release Ingestion Correctness & Crash-Recovery Journal

#### Defect Analysis:
In M3.3.1, `AegisReleaseConsumer.verify_and_load_bundle()` executed in three loose phases:
1. Verification of release manifest and attestation (`advance_tracker=False`).
2. Invocation of caller-supplied `persist_callback(observations, events, discrepancies)`.
3. Updating the sequence tracker file (`ReleaseSequenceTracker.update_accepted`).

If the process terminated after phase 2 committed to the consumer database but before phase 3 committed to `sequence_tracker.json`, the store contained release $N$ while the tracker recorded $N-1$. On restart, re-ingestion of release $N$ could cause partial failures or rely on secondary deduplication.

#### Architecture Specification:
1. **Integrated Ingestion Journal:**
   Add a `consumer_releases` table to the consumer SQLite database:
   ```sql
   CREATE TABLE IF NOT EXISTS consumer_releases (
       publisher TEXT NOT NULL,
       release_sequence INTEGER NOT NULL,
       manifest_sha256 TEXT NOT NULL,
       accepted_at TEXT NOT NULL,
       total_observations INTEGER NOT NULL,
       total_events INTEGER NOT NULL,
       total_discrepancies INTEGER NOT NULL,
       status TEXT NOT NULL CHECK(status IN ('COMMITTED', 'INSPECTION')),
       PRIMARY KEY (publisher, release_sequence)
   );
   ```
2. **Single Transactional Boundary:**
   `store.ingest_release_bundle(bundle, publisher, seq, manifest_sha256, is_historical)` executes within a single SQLite transaction:
   - Inserts events, observations, and discrepancies.
   - Automatically synchronizes graph nodes and edges.
   - If `is_historical is False`, records release sequence $N$ in `consumer_releases`.
   - If any step fails or process crashes, SQLite rolls back all mutations atomically.
3. **Two-Way Reconciliation Protocol:**
   `AegisReleaseConsumer` coordinates with `ReleaseSequenceTracker`:
   - If `sequence_tracker` lags behind `consumer_releases` (simulated crash after DB commit but before file tracker write), the tracker is reconciled forward to match the committed database sequence.
   - Idempotent re-ingestion: If an already-committed release $N$ is presented again, it returns the existing bundle safely without duplicate insertions or sequence regressions.
   - Historical inspection isolation: If `allow_rollback=True` is authorized, records are processed without advancing either `consumer_releases` or `ReleaseSequenceTracker`.

---

### 2.2 Graph Correctness, Automatic Sync & Traversal Bounds

#### Defect Analysis:
1. **Silent Loss of Evidence:** In M3.3.1 `insert_edge()` used `INSERT OR IGNORE`. If an edge already existed between source and target with identical `id_material`, incoming evidence hashes in subsequent observations were discarded.
2. **Ambiguous Path-Cycle Detection:** In `get_k_hop_neighborhood()`, the recursive CTE checked:
   `instr(t.path, next_node) = 0`
   Because `instr` performs substring matching, node `anie:entity:domain:example.co` was falsely treated as a cycle if `anie:entity:domain:example.com` was already in `t.path`.
3. **Unbounded Graph Recursion:** Traversal was only bounded by depth. High-fanout graphs could expand unbounded node sets in memory.
4. **Markdown/YAML Injection:** `export_obsidian_markdown()` serialized YAML via string replacement on JSON and concatenated raw domain names into `[[wikilinks]]`. Untrusted labels containing `]]`, `\n`, or `---` could inject Markdown syntax.

#### Architecture Specification:
1. **Evidence Hash Union on Deduplication:**
   When an edge already exists, `upsert_edge()` merges the new evidence hashes into the existing set:
   ```python
   merged_hashes = sorted(set(existing_hashes) | set(edge.evidence_hashes))
   ```
   No evidence digest is ever dropped.
2. **Automatic Transactional Dual-Write Sync:**
   `RealObservationStore.insert_record()` and `insert_discrepancy()` automatically extract and insert graph nodes and edges within the same transaction (`auto_sync_graph=True`).
3. **Graph Rebuildability:**
   Implement `store.rebuild_graph_from_observations()`: truncates graph tables and cleanly re-populates all nodes, edges, and evidence unions from authoritative `real_observations`, `real_events`, and `real_discrepancies`.
4. **Unambiguous Delimited Cycle Detection:**
   Format traversal paths with boundary delimiters:
   ```sql
   ',' || t.path || ','
   instr(',' || t.path || ',', ',' || next_node || ',') = 0
   ```
5. **Bounded Traversal Limits:**
   Enforce hard limits in `get_k_hop_neighborhood()`:
   - `max_depth`: bounded $[0, 5]$ (default 1)
   - `max_nodes`: limit expanded nodes (default 1,000)
   - `max_edges`: limit returned edges (default 2,500)
6. **Bitemporal Transaction Time:**
   Include `tx_time` (system recording timestamp in UTC) in `graph_edges` and `graph_nodes` alongside real-world `observed_at`, `valid_from`, and `valid_until`.
7. **Strict Markdown/YAML Escaping:**
   - Standard YAML key/value formatting with multiline string quoting.
   - Escape `[[`, `]]`, `|`, and `\n` in wikilinks and headers.

---

### 2.3 Intelligence Trust Model & Uncertainty Semantics

#### Core Invariant:
Cryptographic signatures verify **provenance and tamper-evidence**, NOT external real-world ground truth.

#### Architecture Specification:
1. **Explicit Verification States:**
   ```python
   class ClaimVerificationState(str, Enum):
       UNVERIFIED_HYPOTHESIS = "UNVERIFIED_HYPOTHESIS" # Algorithmic inference
       ATTESTED_ASSERTION    = "ATTESTED_ASSERTION"    # Analyst signed (provenance authenticated)
       CONTESTED             = "CONTESTED"             # Conflicting evidence exists
       REVOKED               = "REVOKED"               # Superseded or retracted
   ```
2. **Explicit Uncertainty Attributes:**
   Every `IntelligenceClaim` carries:
   - `verification_state`: `ClaimVerificationState`
   - `confidence`: $[0.0, 1.0]$ calibrated confidence score
   - `falsifiability_condition`: Explicit condition under which the claim would be disproven
   - `supporting_evidence_hashes`: Non-empty tuple of Layer 1 SHA-256 wire digests

---

### 2.4 Oracle Tenancy Reassessment & Capacity

1. **Quota Reconciliation:**
   - Always Free published entitlement: 2 OCPUs and 12 GB RAM for standard Always Free tenancies.
   - Displayed Service Quotas: Tenancy displays 4 OCPUs and 24 GB RAM dynamically available during active Free Trial.
   - Safe Target: `VM.Standard.A1.Flex` with **2 OCPUs and 12 GB RAM**. This adheres to the strict published Always Free baseline, preventing any disruption or charges when the Free Trial expires.
2. **Collector Preservation:**
   - Preserve `anie-collector-01` (`129.225.109.227`, `VM.Standard.E2.1.Micro`) in quiescent state with timers disabled. Zero mutations.

---

## 3. Implementation Plan

1. **Step 1:** Ingestion Correctness (`src/anie/real_store.py`, `src/anie/real_publish.py`).
2. **Step 2:** Graph Correctness & Traversal Bounds (`src/anie/graph_models.py`, `src/anie/graph_engine.py`, `src/anie/real_store.py`).
3. **Step 3:** Trust Model & Uncertainty (`src/anie/graph_models.py`).
4. **Step 4:** Unit Tests & Crash Simulations (`tests/test_ingestion_and_graph_integrity.py`).
5. **Step 5:** Scalability Benchmarks (`tools/graph_benchmark.py`).
6. **Step 6:** Read-only OCI verification and final reporting.

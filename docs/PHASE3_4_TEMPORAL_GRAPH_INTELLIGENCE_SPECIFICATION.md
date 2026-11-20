# ANIE Phase 3.4 — Temporal Graph Intelligence & Scale Validation Specification

**Milestone:** M3.4: Temporal Graph Intelligence & Scale Validation  
**Owner:** Antigravity (Anti)  
**Repository:** `pseudozac/anie`  
**Baseline Commit:** `299b66231d1478def0948a5432f108351ff6364b`  
**Status:** Approved for Implementation

---

## 1. Executive Mission & Scope

Milestone M3.4 evolves ANIE's verified graph architecture into an evidence-based, explainable infrastructure intelligence system. It:
1. **Solves the Query Regression:** Eliminates the 1-hop traversal bottleneck (reducing latency from 51.4 ms to <1.0 ms) by resolving high-degree resolver hub index scans and adding composite `(source_id, target_id)` and `(target_id, source_id)` indexes.
2. **Implements Temporal Graph Intelligence:** Detects infrastructure transitions, domain-to-IP evolution, fast-flux candidate indicators, shared hosting correlation, and discrepancy timelines without inferring maliciousness.
3. **Founds Local Searchable Memory:** Deploys SQLite FTS5 full-text search across entity nodes, temporal claims, and discrepancy reports, maintaining pure in-process zero-daemon operation.
4. **Validates 10k & 100k Scalability:** Benchmarks deterministic synthetic workloads up to 100,000 observations, profiling true process RSS, memory growth, and reconciles single-commit latency with batch throughput.
5. **Prepares OCI ARM64 Production Migration:** Validates zero-external-binary compatibility on Ampere A1 (aarch64), details Always Free sizing (2 OCPUs / 12 GB RAM), and specifies hardened systemd units with memory boundaries.

---

## 2. Scalability Architecture & Query Plan Optimization

### 2.1 Root Cause of 1-Hop Regression
In Milestone M3.3.2, 1-hop neighborhood queries took 0.86 ms at 300 observations, but regressed to 51.40 ms at 10,008 observations.

#### Mechanism:
1. **High-Degree Hub Nodes:** The 3 configured recursive resolvers (`cloudflare`, `google`, `quad9`) are connected via `QUERIED_VIA` edges to every queried domain in the dataset. At 10,008 observations, each resolver node has an in-degree of 3,336 edges.
2. **Single-Column Index Scan:** Previously, indexes on `graph_edges` were:
   - `idx_graph_edges_source(source_id, relation_type)`
   - `idx_graph_edges_target(target_id, relation_type)`
3. **Cartesian Index Filtering:** When querying connecting edges via `WHERE source_id IN (...) AND target_id IN (...)`, SQLite selected `idx_graph_edges_target`. Because the visited nodes included the 3 resolvers, SQLite performed a scan over all 3,336 edges targeting each resolver (10,000+ row scans) and filtered by `source_id` in memory.
4. **Scale Impact:** As $N$ grew from 100 domains to 1,112 domains, row scans scaled linearly from 300 to 10,000+, causing the 50x latency regression.

### 2.2 Optimization Design
1. **Composite B-Tree Indexes:**
   ```sql
   CREATE INDEX IF NOT EXISTS idx_graph_edges_source_target ON graph_edges(source_id, target_id);
   CREATE INDEX IF NOT EXISTS idx_graph_edges_target_source ON graph_edges(target_id, source_id);
   ```
   Enables SQLite to evaluate `WHERE source_id IN (...) AND target_id IN (...)` using index lookups on the composite key rather than scanning all incident edges of hub nodes.
2. **Direct Incident Traversal for Depth 1:**
   For `max_depth == 1`, bypass the recursive CTE entirely and query direct incident edges:
   ```sql
   SELECT payload FROM graph_edges WHERE source_id = ?
   UNION ALL
   SELECT payload FROM graph_edges WHERE target_id = ?;
   ```
   Direct index lookup takes ~0.15 ms on SSD, achieving a >350x latency improvement.
3. **Reconciling Ingestion Throughput vs. Commit Latency:**
   - **Single-Record Commits:** Committing individual transactions (`store.insert_record`) incurs SQLite fsync and WAL frame synchronization overhead of ~7 ms/record ($\approx 140\text{ records/sec}$).
   - **Batch Ingestion:** Atomic grouped transactions (`store.insert_batch`) batch up to 5,000 records per transaction with `executemany` and grouped graph synchronization, achieving **1,500+ records/sec**. Both metrics are valid and describe single-event streaming versus batched collection ingest.

---

## 3. Temporal Graph Intelligence Rulesets

All temporal intelligence findings are emitted as structured `IntelligenceClaim` objects stored in `intelligence_claims` (Layer 4) with explicit provenance:

### 3.1 Detector Specifications

#### 1. Infrastructure Transition (`INFRASTRUCTURE_TRANSITION`)
- **Condition:** Successive observations of domain $D$ across distinct time epochs show changed resolution IP sets ($S_{t_1} \neq S_{t_2}$).
- **Attributes:** `previous_ips`, `new_ips`, `transition_time`, `duration_hours`.
- **Confidence:** 1.0 (empirical fact of divergence).
- **Falsifiability:** Unannounced IP rotation; TTL expiry during intermediate unobserved window.

#### 2. Domain-to-IP Relationship Evolution (`IP_RELATIONSHIP_EVOLUTION`)
- **Condition:** Tracks historical associations between domain $D$ and IP $I$.
- **Attributes:** `first_seen`, `last_seen`, `observation_count`, `ttl_min`, `ttl_max`, `stability_score`.
- **Classification:** `ephemeral` (<24h), `transitional` (1-7d), `persistent` (>7d).

#### 3. Shared Infrastructure Correlation (`SHARED_INFRASTRUCTURE`)
- **Condition:** Multiple distinct domains $D_1, D_2, \dots, D_k$ resolve to identical IP $I$.
- **Classification:**
  - `known_anycast_cdn`: IP falls within verified CDN/Anycast prefixes (Cloudflare, Fastly, CloudFront, etc.).
  - `shared_unicast`: IP belongs to standard hosting provider or enterprise block.
- **Guardrail:** Emits strictly structural correlation. Must explicitly state: "Co-hosting does NOT imply shared ownership, coordinated action, or malicious intent."

#### 4. Resolver Discrepancy Timeline (`RESOLVER_DISCREPANCY_TIMELINE`)
- **Condition:** Domain $D$ has historical discrepancy reports across independent resolvers.
- **Attributes:** `divergence_count`, `filtered_count` (security filtering NXDOMAIN on Quad9), `divergent_resolvers`, `persistent_disagreement` (boolean).

#### 5. Fast-Flux Candidate Indicator (`FAST_FLUX_INDICATOR`)
- **Deterministic Heuristic:**
  1. High unique IP churn: $\ge 5$ distinct IPs observed within a 24-hour window.
  2. Abnormally short TTL: $\text{TTL} \le 300\text{ seconds}$ (p90).
  3. Prefix diversity: IPs span $\ge 2$ distinct `/24` subnets (IPv4) or `/48` subnets (IPv6).
  4. Non-CDN verification: IPs do not belong to known public CDN Anycast blocks.
- **Uncertainty & Falsifiability:**
  - `verification_state`: `UNVERIFIED_HYPOTHESIS`.
  - `confidence`: 0.75.
  - `falsifiability_condition`: "Legitimate Anycast or CDN edge routing pools; dynamic cloud load balancers; GSLB multi-region failover".
  - **Explicit Guardrail:** "Fast-flux indicator represents dynamic DNS volatility, NOT maliciousness."

#### 6. Unexpected Resolution Divergence (`RESOLUTION_DIVERGENCE_INDICATOR`)
- **Condition:** Sudden transition from a known Anycast/CDN pool to a unicast private/unexpected IP, or unannounced divergence across recursive resolvers.

---

## 4. Searchable Knowledge & SQLite FTS5 Architecture

### 4.1 Zero-Daemon Full-Text Search
ANIE integrates SQLite's native FTS5 engine to provide instant full-text search across all graph entities, claims, and discrepancies without external Elasticsearch, Meilisearch, or daemon dependencies.

```sql
CREATE VIRTUAL TABLE IF NOT EXISTS intelligence_fts USING fts5(
    entity_id,
    entity_type,
    title,
    body,
    tags,
    tokenize='unicode61 remove_diacritics 2'
);
```

### 4.2 Synchronization & Search Capabilities
- Indexed entities: `graph_nodes` (domains, resolvers, IPs), `intelligence_claims` (explanations, types, hypotheses), and `real_discrepancies` (verdicts, categories).
- Queries support prefix searches (`target*`), exact phrases (`"fast-flux"`), boolean combinations (`cdn AND fastly`), and rank BM25 scoring.

---

## 5. Bounded 10k and 100k Benchmark Methodology

### 5.1 Benchmark Scales
1. **Small Scale (300 Obs):** 100 domains $\times$ 3 resolvers $\times$ 1 round (functional validation).
2. **10k Scale (10,008 Obs):** 1,112 domains $\times$ 3 resolvers $\times$ 3 rounds (medium scale, memory boundary validation).
3. **100k Scale (100,008 Obs):** 11,112 domains $\times$ 3 resolvers $\times$ 3 rounds (stress scale, throughput and WAL growth profiling).

### 5.2 Metrics Captured
- **Ingestion:** Elapsed time, batch throughput (records/sec), single-commit latency (ms), node/edge counts, evidence union deduplication counts.
- **Storage:** Database file size (KB), WAL file size (KB), bytes/record footprint.
- **Query Latencies (p50, p95, p99):** 1-hop, 2-hop, co-hosting, evidence lineage, historical timeline, FTS5 search, Obsidian export.
- **Process Memory:** Baseline RSS, Peak RSS, Final RSS, checks against 1 GiB Micro VM (<50 MiB) and 12 GB ARM64 VM envelopes.
- **Cold Restart & Recovery:** Checkpoint WAL, close store, reopen, query 1-hop, verify SQLite `PRAGMA integrity_check`.

---

## 6. Oracle Cloud Infrastructure (OCI) Deployment Specification

### 6.1 Hardware Topology & Always Free Sizing
- **Shape:** `VM.Standard.A1.Flex` (Ampere Altra aarch64).
- **Approved Configurations:**
  - **Standard Always Free Allocation (Recommended):** 2 OCPUs, 12 GB RAM, 50 GB Boot Volume (Balance of tenancy quota).
  - **Minimal Partitioned Allocation:** 1 OCPU, 6 GB RAM.
- **Preserved Existing Asset:** `anie-collector-01` (`129.225.109.227`, `VM.Standard.E2.1.Micro`, 1 OCPU, 1 GiB RAM). Remains unmutated and available as emergency fallback.

### 6.2 Hardened Systemd Service Profile
```ini
[Unit]
Description=ANIE Autonomous DNS Intelligence Engine (M3.4)
Documentation=https://github.com/pseudozac/anie
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=anie
Group=anie
WorkingDirectory=/opt/anie
ExecStart=/opt/anie/.venv/bin/python -m anie.cli collector run-batch --config /etc/anie/collector.yaml

# Security Hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=

# Resource Constraints (2 OCPU / 12 GB Shape)
CPUQuota=200%
MemoryMax=8G
MemoryHigh=6G
TimeoutStartSec=180
```

---

## 7. Implementation Tasks & Measurable Acceptance Criteria

1. **Task 1: Composite Index & Query Plan Optimization:** Add `idx_graph_edges_source_target` and direct depth-1 incident traversal. Verify 1-hop latency drops from ~55 ms to <1.0 ms.
2. **Task 2: Temporal Intelligence Subsystem:** Implement `TemporalIntelligenceEngine` in `src/anie/temporal_intelligence.py` with all 6 detectors and strict guardrails.
3. **Task 3: Local Searchable Memory:** Implement FTS5 table and search APIs in `src/anie/real_store.py` and `src/anie/graph_engine.py`.
4. **Task 4: Obsidian Vault Exporter:** Implement batch Obsidian vault markdown note generation with wikilinks and lineage anchors.
5. **Task 5: Scalability Benchmarks:** Extend `tools/graph_benchmark.py` to benchmark FTS5 search, query latencies, memory footprint, and run bounded 10k/100k benchmarks.
6. **Task 6: Verification & CI:** Full test suite across Python 3.10, 3.12, 3.13 green.

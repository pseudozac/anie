# ANIE — Milestone 3.5 Specification
## First-Party Intelligence Pilot & Consumer Contract

- **Engineering Owner:** Antigravity (Anti)
- **Repository:** `pseudozac/anie`
- **Milestone:** M3.5
- **Status:** Approved for Implementation (Spec-Driven Development)
- **Baseline Commit:** `8d43c3a594b02f168fa37068ecd88877076d8b0a`
- **Security Boundaries:** Fail-closed, zero host DNS resolution, zero cloud resource mutation, no AEGIS internal dependencies.

---

## 1. Executive Summary & Architecture Principles

Milestone 3.5 transitions ANIE from synthetic research validation into a production-grade, independently verifiable internet intelligence engine.

### Strict Scope Invariants
1. **Decoupled Consumer Contract:** ANIE produces self-contained, cryptographically authenticated, versioned intelligence artifacts. It has zero dependency on AEGIS's internal database, schemas, or authentication mechanisms.
2. **Epistemic Truthfulness:** Empirical detector accuracy (measured against ground-truth datasets) is strictly separated from heuristic confidence scores. Heuristic scores are explicitly disclaimed as non-calibrated.
3. **Evidence-Preserving Retention:** Retention policies can prune aged raw observations and forensic events, but **never** discard evidence referenced by active or validated claims, discrepancy analyses, signed release manifests, or audit trails.
4. **Zero-Mutation Cloud Safety:** Cloud infrastructure (`anie-collector-01` at `129.225.109.227`) remains unmutated. All cloud migration runbooks are created offline with formal activation gates requiring explicit human owner authorization.

```
+---------------------------------------------------------------------------------------------------+
|                                     ANIE INTELLIGENCE ARCHITECTURE                                |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [ Layer 1: Authoritative Evidence ]                                                             |
|    - real_events (raw forensic payloads, SHA-256)                                                |
|    - real_observations (normalized DNS observations, foreign key to events)                      |
|                                                                                                   |
|  [ Layer 2: Explainable Intelligence ]                                                            |
|    - real_discrepancies (multi-resolver consensus & filtering reports)                           |
|    - graph_nodes & graph_edges (canonical entity URIs & relationships)                            |
|    - intelligence_claims (hypotheses, epistemic status, evidence hashes)                          |
|                                                                                                   |
|  [ Layer 3: Storage Sustainability & Retention ]                                                 |
|    - safe_prune_retention() (purges aged records EXCEPT those referenced by claims/releases)      |
|    - safe compaction (incremental vacuum + WAL truncate)                                         |
|                                                                                                   |
|  [ Layer 4: Consumer Contract & Publication ]                                                     |
|    - Canonical Entity URIs (domain:, ipv4:, ipv6:, asn:, cidr:, resolver:)                        |
|    - Release Bundle v4 (real_observations, real_events, real_discrepancies, real_claims)          |
|    - AnieIntelligenceClient / AegisIntelligenceConsumer (bounded cursor pagination, IOC feed)    |
|    - Ed25519 Detached Manifest Signatures & Monotonic Anti-Rollback Tracker                       |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Component 1: Intelligence Quality Evaluation Framework

### 2.1 Benchmark Scenarios with Labeled Ground Truth

To objectively measure detection accuracy, ANIE provides an offline dataset generator creating 7 distinct scenarios with known ground truth:

1. **`legitimate_cdn_rotation`**:
   - *Behavior:* Short TTLs ($\le 300\text{s}$), rotation across multiple IPs within known CDN prefix maps (Cloudflare, Fastly, Akamai), multi-resolver consistency.
   - *Ground Truth:* Benign infrastructure change.
   - *Expected Outcome:* `HISTORICAL_DNS_CHANGE` may be noted, but `FAST_FLUX_INDICATOR` must **not** fire (0 false positives).
2. **`legitimate_round_robin`**:
   - *Behavior:* Consistent set of 2–4 IPs within the same corporate /24 subnet, alternating across queries.
   - *Ground Truth:* Benign load balancing.
   - *Expected Outcome:* Stable relationship evolution, 0 anomaly claims.
3. **`resolver_filtering`**:
   - *Behavior:* Quad9 or CleanBrowsing returns `0.0.0.0` or `NXDOMAIN`, while Cloudflare and Google return authoritative IP addresses.
   - *Ground Truth:* Policy/security filtering or sinkholing.
   - *Expected Outcome:* `DiscrepancyEngine` emits `SUSPECTED_BLOCKING` or `SECURITY_FILTERING` with 100% agreement between validating resolvers.
4. **`infrastructure_migration`**:
   - *Behavior:* Domain permanently updates from an on-premise ASN/subnet to a cloud provider over a multi-day timeline.
   - *Ground Truth:* Legitimate infrastructure transition.
   - *Expected Outcome:* `HISTORICAL_DNS_CHANGE` and `DOMAIN_IP_EVOLUTION` detectors identify distinct operational epochs.
5. **`fast_flux_botnet`**:
   - *Behavior:* Domain resolves to 10+ distinct IPs across 7 disparate /24 or /48 subnets within 24 hours, with short TTLs ($\le 300\text{s}$) and non-CDN infrastructure.
   - *Ground Truth:* Suspicious fast-flux infrastructure.
   - *Expected Outcome:* `FAST_FLUX_INDICATOR` detector emits `UNVERIFIED_HYPOTHESIS` with evidence links to all 10 observations.
6. **`unexpected_resolution_flip`**:
   - *Behavior:* Sudden flip to an unrelated unannounced IP block accompanied by intermittent errors or SERVFAILs.
   - *Ground Truth:* Suspicious hijacking or severe misconfiguration.
   - *Expected Outcome:* `UNEXPECTED_RESOLUTION_CHANGE` emitted with confidence and explanation.
7. **`stable_baseline`**:
   - *Behavior:* Identical answers across resolvers and time for canonical corporate infrastructure.
   - *Ground Truth:* Benign baseline.
   - *Expected Outcome:* 0 anomalies, `AGREEMENT` verdict across all resolvers.

### 2.2 Evaluation Metrics & Separation from Confidence

The evaluation framework computes:
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}, \quad \text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
$$\text{False Positive Rate (FPR)} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$
$$\text{Evidence Completeness} = \frac{\text{Claims with Valid Evidence Hashes and Node URIs}}{\text{Total Emitted Claims}}$$

*Epistemic Invariant:* The evaluation framework records empirical test precision and recall alongside claims, while explicitly annotating:
`"confidence_type": "heuristic_uncalibrated"` on heuristic detector scores.

---

## 3. Component 2: Production-Grade Intelligence Consumer Contract

### 3.1 Canonical IOC & Infrastructure Entity Identifiers

All entities in the knowledge graph and consumer interfaces follow strict URI syntax:

| Entity Type | Canonical URI Syntax | Example | Validation Rule |
| :--- | :--- | :--- | :--- |
| **Domain** | `domain:<fqdn>` | `domain:example.com` | Lowercased, punycode-normalized, no trailing dot |
| **IPv4 Address** | `ipv4:<ip>` | `ipv4:93.184.216.34` | Dotted-quad, valid 0–255 octets |
| **IPv6 Address** | `ipv6:<ip>` | `ipv6:2606:2800:220:1:248:1893:25c8:1946` | RFC 5952 canonical compressed format |
| **Autonomous System** | `asn:AS<number>` | `asn:AS15133` | Uppercase prefix `AS` followed by decimal |
| **CIDR Network** | `cidr:<network>/<prefix>` | `cidr:192.0.2.0/24` | Valid network boundary and prefix length |
| **Resolver** | `resolver:<name>` | `resolver:cloudflare` | Lowercase alphanumeric |
| **Claim** | `claim:<claim_id>` | `claim:claim_5d60427...` | Valid claim identifier |
| **Discrepancy** | `discrepancy:<analysis_id>`| `discrepancy_1859c46...` | Valid discrepancy identifier |

### 3.2 Dataset Release Schema v4

We introduce `anie.real-dataset-manifest.v4` extending the publication contract to include intelligence claims:
- **Required Partitions:** `real_observations.jsonl.gz`, `real_events.jsonl.gz`
- **Optional Partitions:** `real_discrepancies.jsonl.gz`, `real_claims.jsonl.gz`
- **Backward Compatibility:** All existing v1, v2, v3 release manifests continue to be verified and consumed without modification.

### 3.3 Consumer Query API (`AnieIntelligenceClient`)

A self-contained query engine providing bounded, paginated access:
- `query_entities(entity_type=None, search_term=None, limit=50, cursor=None) -> PaginatedEntities`
- `query_claims(subject_uri=None, layer=None, epistemic_status=None, min_confidence=0.0, as_of=None, limit=50, cursor=None) -> PaginatedClaims`
- `query_relationships(source_uri=None, target_uri=None, relation_type=None, as_of=None, limit=50, cursor=None) -> PaginatedEdges`
- `get_entity_provenance(entity_id: str) -> EntityProvenanceBundle`: Returns node properties, connected claims, underlying observations, and raw forensic events.
- `export_canonical_ioc_feed(as_of=None, min_confidence=0.0, layer=None) -> CanonicalIocFeed`: Exports structured threat intelligence indicators with explicit uncertainty, observation references, and ruleset versions.
- **Cursor Encoding:** Deterministic Base64 string composed of `f"{order_key_value}|{entity_id}"` preventing pagination skips during concurrent inserts. Default limit: 50, Maximum limit: 500.

---

## 4. Component 3: Storage Sustainability & Evidence-Preserving Retention

### 4.1 Safe Retention Engine Invariants

1. **Non-Destruction of Referenced Evidence:**
   $$\text{Observations}_{\text{purge}} = \{ o \in \text{Observations} \mid o.\text{observed\_at} < T_{\text{obs\_cutoff}} \} \setminus \text{ProtectedObs}$$
   $$\text{ProtectedObs} = \{ o \in \text{Observations} \mid o.\text{observation\_id} \in \text{ClaimRefs} \cup \text{DiscrepancyRefs} \cup \text{ReleaseRefs} \}$$
   $$\text{Events}_{\text{purge}} = \{ e \in \text{Events} \mid e.\text{observed\_at} < T_{\text{evt\_cutoff}} \land e.\text{event\_id} \notin \text{ActiveObsEvidence} \land e.\text{raw\_sha256} \notin \text{ClaimEvidenceHashes} \}$$
2. **Referential Integrity Verification:** Every retention run verifies foreign key constraints (`PRAGMA foreign_key_check`) fail-closed.
3. **Safe Reclaim / Compaction:** Runs `PRAGMA wal_checkpoint(TRUNCATE)` and incremental vacuum to return unused pages to the filesystem.

### 4.2 Storage Growth Models

Calculates storage requirements across 30, 90, 180, and 365 days for:
- **Pilot Scale:** 25 domains, 4 queries/day (100 obs/day)
- **Production Scale:** 100 domains, 24 queries/day (2,400 obs/day)
- **High-Throughput Scale:** 1,000 domains, 24 queries/day (24,000 obs/day)

---

## 5. Component 4: OCI Deployment Runbook & Cost Model

- **Infrastructure:** Oracle Cloud Infrastructure Always Free tier in Hyderabad (`ap-hyderabad-1`).
- **Resource Allocation:** 2 Ampere A1 OCPUs, 12 GiB RAM, 50 GB NVMe boot volume.
- **Cost:** ₹0.00 / $0.00 per month (100% within the 4 OCPU / 24 GB Always Free allowance).
- **Isolation Policy:** Current collector `anie-collector-01` (`129.225.109.227`) remains untouched. New node operates under strict nftables egress firewall allowing only outbound TCP/443 to pinned DoH resolvers.
- **Runbook:** Documented in [docs/OCI_DEPLOYMENT_RUNBOOK.md](file:///c:/Users/aniza/Downloads/anie/docs/OCI_DEPLOYMENT_RUNBOOK.md).

---

## 6. Component 5: Real-World Pilot Governance & Operational Activation Gate

- **Scope:** Narrow target allowlist of authoritative internet infrastructure (root nameservers, TLD nameservers, major CDN providers, public recursive resolvers).
- **Rate Limits:** Strictly $\le 1$ query/sec per resolver, 10 queries/hour per domain.
- **Activation Gate:** Requires human operator authorization via `ANIE_LIVE_COLLECTION_AUTHORIZED=1` and signed operational directive.
- **Scope & Policy:** Documented in [docs/PILOT_SCOPE_AND_COLLECTION_POLICY.md](file:///c:/Users/aniza/Downloads/anie/docs/PILOT_SCOPE_AND_COLLECTION_POLICY.md).

---

## 7. Acceptance Criteria

- [ ] Labeled intelligence evaluation dataset with measured precision, recall, and false positive rates.
- [ ] Canonical entity URI parser and validator covering domains, IPs, ASNs, CIDRs, and resolvers.
- [ ] Versioned consumer contract (`AnieIntelligenceClient`) with cursor pagination, provenance bundling, and IOC feed export.
- [ ] Release bundle v4 supporting `real_claims.jsonl.gz` with full backward compatibility for v1–v3.
- [ ] Evidence-preserving retention engine (`safe_prune_retention()`) with zero data loss for claimed evidence.
- [ ] Storage growth projection models for 30–365 days.
- [ ] Complete OCI deployment runbook, cost analysis, and pilot collection policy documents.
- [ ] All tests passing cleanly in offline CI across Python 3.10, 3.12, 3.13.

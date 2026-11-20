# ANIE Phase 3.1 Security Remediation & Hardening Specification

**Status:** APPROVED / IN PROGRESS  
**Target Milestone:** Phase 3.1 (M3.1)  
**Repository:** `pseudozac/anie`  
**Base Commit:** `b3e93fc6a82fd4dedc40e7ffe4854898a98dbbf9` (`main`)  
**Feature Branch:** `feat/phase3.1-security-remediation`  
**Reference Artifacts:** `docs/THREAT_MODEL.md`, `docs/PHASE3_ARCHITECTURE_REVISION.md`  

---

## 1. Context & Objective

Following the successful execution, acceptance, and permanent closure of the Phase 2 72-Hour Live Pilot on Oracle Cloud (`anie-collector-01`), the production collection timer was disabled and the canonical completion barrier (`pilot_completed.sentinel`) was engaged.

Phase 3.1 initiates engineering under **Spec-Driven Development (SDD)** to remediate operational security ambiguities discovered during Phase 2, harden fail-closed runtime controls, and establish durable resource boundaries on the 1 GiB Oracle Cloud collector environment before any future collection expansion is considered.

---

## 2. Formal Requirements (RFC 2119)

### 2.1. Network & Execution Safeguards (Fail-Closed)
- **REQ-SEC-01 (Egress Sandbox Enforcement):** Preflight MUST actively verify that arbitrary outbound network egress is prohibited by the kernel. Probing an unauthorized IP (e.g. `198.51.100.1`) MUST return a tri-state classification: `BLOCKED`, `ALLOWED`, or `UNVERIFIABLE`.
- **REQ-SEC-02 (Prohibition of False Verification via Silent Timeout):** Preflight MUST NOT interpret a socket timeout to RFC 5737 `198.51.100.1` as positive proof of active egress filtering, as non-routable documentation ranges time out on unhardened networks. When a probe is `UNVERIFIABLE`, preflight MUST require direct verification of host/systemd egress policy (`IPAddressDeny=any`).
- **REQ-SEC-03 (IMDS Absolute Isolation):** Preflight MUST assert that the Oracle Instance Metadata Service (`169.254.169.254:80`) is unreachable. If a TCP handshake completes to IMDS, preflight MUST fail closed immediately and terminate execution.

### 2.2. Host Netfilter & Sandbox Diagnostics
- **REQ-SEC-04 (Sandbox Netfilter Error Classification):** Preflight MUST distinguish between an absent kernel firewall rule (`MISSING`) and unprivileged service sandbox protocol restrictions (`INACCESSIBLE`). Protocol errors (e.g. `Address family not supported by protocol`, `Failed to initialize nft`, `Permission denied`) caused by systemd sandbox restrictions (`ProtectKernelTunables=yes`, empty `CapabilityBoundingSet`) MUST NOT be classified as missing firewall rules.
- **REQ-SEC-05 (Privileged vs. Runtime Firewall Assertion):** In privileged deployment mode (`require_firewall_rule=True`), inaccessible netfilter inspection MUST fail closed. In unprivileged runtime execution (`require_firewall_rule=False`), inaccessible netfilter inspection MUST be logged as advisory without failing closed, provided cgroup BPF isolation is confirmed.

### 2.3. Durable Request Budgets & Cooldown Controls
- **REQ-SEC-06 (Strict Pilot Query Envelope):** Active DNS requests MUST remain strictly bounded to the authorized envelope: maximum 1 batch attempt per UTC calendar date, maximum 2 queries per batch, and deterministic query alternation across the 3 calendar dates.
- **REQ-SEC-07 (Per-Target Cooldown Margin):** The governor MUST maintain a minimum 4-hour per-domain cooldown (enforcing 48x safety margin against public DoH rate limits).

### 2.4. Memory & Resource Safety (1 GiB VM Footprint)
- **REQ-SEC-08 (Memory Budget):** The collector process peak RSS MUST remain strictly below 200 MiB (established threshold: <100 MiB nominal). Preflight MUST assert at least 200 MiB free host memory before initiating any execution.
- **REQ-SEC-09 (Storage Budget & WAL Management):** Preflight MUST assert at least 500 MiB free disk space. Database connections MUST use SQLite WAL mode with synchronous=NORMAL and periodic checkpointing to prevent disk exhaustion.

### 2.5. Evidence Integrity & Reproducibility
- **REQ-SEC-10 (Cryptographic Wire Evidence):** Every DNS response payload MUST be stored alongside its computed SHA-256 digest in `real_intelligence.sqlite`.
- **REQ-SEC-11 (Detached Air-Gapped Provenance):** No private signing keys (Ed25519) MAY reside on the collector instance. Collector releases MUST be exported as unsigned candidate bundles verified via SHA-256 manifests.

### 2.6. Recovery, Rollback & Completion Correctness
- **REQ-SEC-12 (Atomic Pre-Sentinel Reconciliation):** When the authorization window expires (`today > end_d`), the governor MUST atomically reconcile all stale `PLANNED` crash reservations to `FAILED` and all skipped calendar dates to `MISSED` in SQLite before generating `pilot_completed.sentinel`.
- **REQ-SEC-13 (Canonical Sentinel Barrier):** The sentinel `/var/lib/anie/pilot_completed.sentinel` MUST permanently halt all future collection attempts. Any execution attempted with the sentinel present MUST raise `ScopeDenied` without mutating database state.

---

## 3. Technical Architecture & Component Design

```
+--------------------------------------------------------------------------+
|                        PREFLIGHT HARDENING ENGINE                        |
|                     (src/anie/preflight_hardening.py)                    |
+--------------------------------------------------------------------------+
|  1. IMDS Probe: 169.254.169.254:80                                       |
|     -> Positive rejection (ECONNREFUSED/EPERM) => BLOCKED                |
|     -> Successful connect => ALLOWED (CRITICAL SECURITY FAILURE)         |
|     -> Timeout/OS error => UNVERIFIABLE                                  |
|                                                                          |
|  2. Egress Probe: 198.51.100.1:80                                        |
|     -> Positive rejection (EPERM/ECONNREFUSED/ENETUNREACH) => BLOCKED    |
|     -> Successful connect => ALLOWED (CRITICAL SECURITY FAILURE)         |
|     -> Timeout => UNVERIFIABLE (cannot prove isolation alone)           |
|                                                                          |
|  3. Systemd Network Policy Inspection:                                   |
|     -> Query: systemctl show <unit> -p IPAddressDeny -p IPAddressAllow   |
|     -> Confirms BPF cgroup filter satisfies UNVERIFIABLE probes          |
|                                                                          |
|  4. Netfilter Inspection:                                                |
|     -> Exit code 0 => VERIFIED                                           |
|     -> Address family / permission error => INACCESSIBLE                 |
|     -> Explicit missing rule error => MISSING                            |
+--------------------------------------------------------------------------+
```

```
+--------------------------------------------------------------------------+
|                         PILOT GOVERNOR LIFECYCLE                         |
|                       (src/anie/pilot_governor.py)                       |
+--------------------------------------------------------------------------+
|  check_and_plan_pilot_batch(now_dt):                                     |
|    - Fast check: sentinel_path.exists() => Raise ScopeDenied             |
|    - Begin Immediate SQLite Transaction                                  |
|    - Check start date anchor in pilot_metadata (immutable)               |
|    - IF today < start_d: Raise ScopeDenied (Window not started)          |
|    - IF today > end_d:                                                   |
|        * Reconcile stale PLANNED runs -> FAILED                          |
|        * Reconcile unattempted window dates -> MISSED                    |
|        * Commit SQLite Transaction                                       |
|        * write_completion_sentinel()                                     |
|        * Raise ScopeDenied (Window expired)                              |
|    - IF today in window:                                                 |
|        * Check anti-duplication (max 1 batch/day)                        |
|        * Reconcile past days -> MISSED                                   |
|        * Reserve PLANNED run with deterministic queries                  |
|        * Commit SQLite Transaction                                       |
+--------------------------------------------------------------------------+
```

---

## 4. Implementation Tasks & Verification Matrix

| Task ID | Component | Description | Acceptance Test |
| :--- | :--- | :--- | :--- |
| **T3.1-01** | `preflight_hardening.py` | Implement `NetworkProbeStatus` enum (`BLOCKED`, `ALLOWED`, `UNVERIFIABLE`) and tri-state probing. | `test_egress_demonstrably_allowed_fails_preflight`, `test_egress_filter_active_when_unauthorized_ip_blocked` |
| **T3.1-02** | `preflight_hardening.py` | Add `check_systemd_network_policy()` to inspect `IPAddressDeny` cgroup BPF properties. | `test_systemd_network_policy_inspection`, `test_unverifiable_egress_satisfied_by_systemd_policy` |
| **T3.1-03** | `preflight_hardening.py` | Implement `FirewallInspectionStatus` enum (`VERIFIED`, `MISSING`, `INACCESSIBLE`) classifying sandbox address-family protocol errors. | `test_firewall_inaccessible_nft_classified_correctly`, `test_firewall_inaccessible_fails_when_rule_required`, `test_firewall_inaccessible_passes_when_rule_advisory` |
| **T3.1-04** | `preflight_hardening.py` | Enforce fail-closed preflight evaluation when probes are unverifiable without separate verified controls. | `test_unverifiable_egress_fails_without_systemd_policy` |
| **T3.1-05** | `pilot_governor.py` | Reconcile stale `PLANNED` crash reservations and unexecuted calendar dates to `FAILED`/`MISSED` prior to sealing completion sentinel upon window expiration. | `test_16_interrupted_final_day_creates_sentinel_on_subsequent_invocation`, `test_17_missed_final_day_creates_sentinel_on_subsequent_invocation` |
| **T3.1-06** | `pilot_governor.py` | Enforce idempotent sentinel barrier denying execution without database mutation. | `test_15_failed_final_day_creates_sentinel_and_denies_further_runs`, `test_18_idempotent_sentinel_enforcement` |
| **T3.1-07** | `docs/` | Author Phase 3 architecture revision and formal security specification. | `docs/PHASE3_ARCHITECTURE_REVISION.md`, `docs/PHASE3_1_SECURITY_SPECIFICATION.md` |

---

## 5. Measurable Acceptance Criteria

1. **AC-01 (Preflight Fail-Closed Egress):** Simulated connection success to `198.51.100.1:80` MUST cause `run_security_preflight()` to return `passed=False` with reason stating unauthorized egress is demonstrably permitted.
2. **AC-02 (Timeout Egress Handling):** Socket timeout to `198.51.100.1` without verified systemd cgroup policy MUST fail closed (`passed=False`). With verified `IPAddressDeny=any`, it MUST pass (`passed=True`).
3. **AC-03 (Firewall Sandbox Classification):** Netfilter stderr containing `"Address family not supported by protocol"` or `"Failed to initialize nft"` MUST return `status=INACCESSIBLE` and `verified=None`, never `MISSING` (`False`).
4. **AC-04 (Final-Day Crash Reconciliation):** If Day 3 crashes in `PLANNED` state, the first invocation after Day 3 MUST mark the run `FAILED`, record `failed_attempts: 1`, commit SQLite state, and write `pilot_completed.sentinel`.
5. **AC-05 (Final-Day Missed Reconciliation):** If Day 3 is unattempted, the first invocation after Day 3 MUST insert a `MISSED` record for Day 3, record `missed_days: 1`, commit SQLite state, and write `pilot_completed.sentinel`.
6. **AC-06 (Sentinel Immutability):** With `pilot_completed.sentinel` present on disk, calling `check_and_plan_pilot_batch()` MUST raise `ScopeDenied` within 5 ms and produce exactly 0 database mutations.
7. **AC-07 (Deterministic Offline Test Suite):** 100% of unit and integration tests (306+ tests) MUST pass offline with zero network connectivity.
8. **AC-08 (Resource Footprint):** Memory allocation for preflight and governor assertions MUST complete within <20 ms with peak memory increase <2 MiB.

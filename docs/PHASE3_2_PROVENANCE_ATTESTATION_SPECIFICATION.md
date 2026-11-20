# ANIE Phase 3.2: Independent Attestation & Provenance Specification

**Status:** APPROVED FOR IMPLEMENTATION  
**Milestone:** Phase 3.2 (M3.2)  
**Repository:** `pseudozac/anie`  
**Base Commit:** `69b45a4968e5f826418655ad796d401261c3bf65` (`main`)  
**Feature Branch:** `feat/phase3.2-provenance-attestation`  
**Reference Standards:** RFC 8032 (Ed25519), RFC 8785 (JSON Canonicalization Scheme)  

---

## 1. Executive Summary & Objective

In Phase 3.2, ANIE establishes an end-to-end **cryptographic provenance, deterministic candidate release, and independent attestation pipeline** bridging autonomous cloud collection and downstream consumers (such as the AEGIS framework).

The primary objective is to guarantee that network intelligence observations cannot be forged, replayed, downgraded, or tampered with in transit, while strictly preventing private signing credentials from ever existing on untrusted collection nodes.

---

## 2. Threat Model & Trust Boundaries

ANIE enforces four strictly separated trust domains:

```
+-------------------------------------------------------------------------------------------------+
|                                    ANIE TRUST DOMAINS & BOUNDARIES                               |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|  [ DOMAIN 1: COLLECTOR VM ] (Untrusted with Signing)                                            |
|  - Host: anie-collector-01 (Oracle Cloud)                                                       |
|  - Executes bounded daily collection under systemd IPAddressDeny=any and pilot governor.         |
|  - Holds NO private keys; zero access to signing key material.                                 |
|  - Produces: Unsigned candidate release bundle (manifest.json, *.jsonl.gz).                     |
|                                                                                                 |
|                              | (Manual Pull / Air-Gap Transfer)                                  |
|                              v                                                                  |
|                                                                                                 |
|  [ DOMAIN 2: AIR-GAPPED OPERATOR ] (Trusted Signing Environment)                                 |
|  - Host: Isolated operator workstation (offline / air-gapped).                                  |
|  - Holds: Ed25519 private key (operator-2026-key.priv, mode 0600).                               |
|  - Inspects candidate evidence (anie inspect-candidate / verify-real --integrity-only).         |
|  - Produces: Detached attestation (signature.ed25519.json) binding manifest hash & sequence.   |
|                                                                                                 |
|                              | (Public Distribution)                                            |
|                              v                                                                  |
|                                                                                                 |
|  [ DOMAIN 3: DISTRIBUTION TRANSPORT ] (Untrusted)                                                |
|  - Transport: Static web server, GitHub releases, object storage, public mirrors.               |
|  - Threat: Man-in-the-middle tampering, truncated files, historical replay, sequence downgrade.  |
|                                                                                                 |
|                              | (Offline Verification)                                            |
|                              v                                                                  |
|                                                                                                 |
|  [ DOMAIN 4: AEGIS CONSUMER ] (Independent Downstream Investigator)                              |
|  - Host: Consumer workstation / private investigation infrastructure.                           |
|  - Holds: Operator public key (operator-2026-key.pub) & local sequence tracker state.            |
|  - Verifies: Signatures, partition digests, referential integrity, anti-rollback, hash chain.   |
|  - Privacy Guarantee: Zero network callbacks to ANIE; ANIE learns zero AEGIS target context.    |
|                                                                                                 |
+-------------------------------------------------------------------------------------------------+
```

### 2.1. Threat Vectors & Defenses

| Threat Vector | Description | Architectural Defense |
| :--- | :--- | :--- |
| **T-01: Collector VM Compromise** | Attacker compromises Oracle VM to forge signed intelligence. | **Zero Signing Authority on Collector:** Private key is never installed on or accessible to collector. Collector produces unsigned candidate bundles only. Compromise yields no signing capability. |
| **T-02: Content Tampering** | Attacker modifies observation records or payload bytes in distribution mirror. | **Deterministic Gzip + SHA-256 Manifest + Ed25519 Signature:** Partition hashes are sealed in `manifest.json`; manifest hash is sealed in `signature.ed25519.json`. Any byte change invalidates verification. |
| **T-03: Replay & Rollback Attack** | Attacker serves historical, validly signed release to revert consumer to stale state. | **Monotonic Sequence Tracker + Hash Chaining:** Consumer rejects any release with `sequence <= last_accepted_sequence` and verifies `prev_manifest_sha256` continuity. |
| **T-04: Truncation / Omission** | Attacker truncates gzip archive to omit evidence. | **Exact Byte & Record Count Binding:** Manifest specifies exact compressed byte size, uncompressed byte limits, and exact record counts verified during streaming decompression. |
| **T-05: Consumer Context Exfiltration** | Verification calls home or leaks consumer case queries to ANIE. | **100% Offline Consumer Contract:** Verification requires zero network calls and relies entirely on local public key pinning. |

---

## 3. Formal Requirements (RFC 2119)

### 3.1. Deterministic Candidate Release Generation
- **REQ-REL-01 (Reproducible Serialization):** Candidate release archives MUST use canonical JSON encoding (`canonical_json`) and fixed gzip headers (`mtime=0`, `compresslevel=9`, empty filename) ensuring byte-for-byte reproducibility across runs.
- **REQ-REL-02 (Manifest Metadata Binding):** `manifest.json` MUST explicitly bind:
  1. `schema`: `"anie.real-dataset-manifest.v2"` (supporting hash chaining)
  2. `dataset_type`: `"first_party_intelligence"`
  3. `publisher`: Publisher identity string
  4. `release_sequence`: Monotonically increasing positive integer (`>= 1`)
  5. `prev_manifest_sha256`: SHA-256 hex digest of sequence `N-1` manifest (or `null` for sequence 1)
  6. `as_of`: UTC ISO timestamp cutoff of observations
  7. `published_at`: UTC ISO timestamp of publication
  8. `source_commit`: 40-character hex Git commit hash
  9. `files`: Partition metadata array (filename, sha256, record count, byte size)
  10. `total_observations`, `total_events`: Integer record totals
- **REQ-REL-03 (Strict Pipeline Anti-Contamination):** Candidate generation MUST unconditionally reject synthetic observations, synthetic collection methods, or synthetic source IDs.

### 3.2. Offline Ed25519 Detached Signing & Key Management
- **REQ-KEY-01 (Air-Gapped Key Generation):** The CLI MUST provide `anie keygen` to generate 32-byte Ed25519 keypairs locally using cryptographically secure operating system randomness. Private keys MUST be written with strict file permissions (`0600` on POSIX systems).
- **REQ-KEY-02 (Key Material Isolation):** Private keys MUST NEVER enter the collector VM, repository history, application logs, test fixtures, or CI environments.
- **REQ-KEY-03 (Candidate Evidence Review):** The CLI MUST provide `anie inspect-candidate` enabling operators to review record counts, observation dates, domain scopes, and integrity hashes prior to executing `anie sign-real`.
- **REQ-SIG-01 (Detached Attestation Schema):** The signature MUST be stored in `signature.ed25519.json` adhering to schema `"anie.real-ed25519-attestation.v2"`.
- **REQ-SIG-02 (Domain Separation):** Signatures MUST apply domain separation prefix `b"ANIE-REAL-ED25519-RELEASE-V2\x00"` to prevent cross-protocol signature re-use.
- **REQ-SIG-03 (Hash Chaining in Payload):** The signed payload MUST explicitly include `prev_manifest_sha256` matching the manifest.

### 3.3. AEGIS-Compatible Offline Consumer Verification
- **REQ-VER-01 (Multi-Tier Verification):** Consumer verification MUST report:
  - `structural_valid`: Archive format and manifest adhere to bounded limits.
  - `evidence_integrity_valid`: Hashes match, records reconstruct through strict data models, and referential integrity holds.
  - `publisher_authenticated`: Ed25519 signature verified with pinned public key.
  - `anti_rollback_verified`: Sequence strictly exceeds previously accepted sequence for that publisher.
  - `hash_chain_verified`: `prev_manifest_sha256` strictly matches previous release manifest SHA-256.
- **REQ-VER-02 (Durable Sequence & Digest Tracking):** `ReleaseSequenceTracker` MUST durably record both the highest sequence integer AND the manifest SHA-256 for each publisher using crash-safe atomic replace.
- **REQ-VER-03 (Transactional Consumer Ingestion):** An `AegisReleaseConsumer` interface MUST verify the entire release fail-closed before making data available or updating sequence tracking state.
- **REQ-VER-04 (Zero Network Connectivity):** Verification MUST execute completely offline without network sockets or external service lookups.

---

## 4. Technical Architecture & Schemas

### 4.1. Manifest Schema (`anie.real-dataset-manifest.v2`)

```json
{
  "schema": "anie.real-dataset-manifest.v2",
  "dataset_type": "first_party_intelligence",
  "publisher": "anie-first-party",
  "release_sequence": 2,
  "prev_manifest_sha256": "4a72d3...64_hex_chars...",
  "as_of": "2026-11-16T06:15:00Z",
  "published_at": "2026-11-20T12:00:00Z",
  "source_commit": "69b45a4968e5f826418655ad796d401261c3bf65",
  "files": [
    {
      "file": "real_observations.jsonl.gz",
      "sha256": "...",
      "records": 6,
      "bytes": 512
    },
    {
      "file": "real_events.jsonl.gz",
      "sha256": "...",
      "records": 6,
      "bytes": 580
    }
  ],
  "total_observations": 6,
  "total_events": 6,
  "integrity": "unsigned_candidate_manifest",
  "notice": "First-party empirical intelligence observations collected under strict policy governance. Authenticates publisher provenance, not absolute external truth."
}
```

### 4.2. Attestation Schema (`anie.real-ed25519-attestation.v2`)

```json
{
  "schema": "anie.real-ed25519-attestation.v2",
  "key_id": "operator-2026-key",
  "key_fingerprint": "54e004aeff5a78e8748fc945c0637b3134309d42b6495154d0878595c6636ab4",
  "payload": {
    "schema": "anie.real-release-attestation.v2",
    "publisher": "anie-first-party",
    "key_id": "operator-2026-key",
    "key_fingerprint": "54e004aeff5a78e8748fc945c0637b3134309d42b6495154d0878595c6636ab4",
    "dataset_type": "first_party_intelligence",
    "manifest_sha256": "9b0d1fd5434e9187614cebe4aff58ef8227be9d75d00fa1531ba8082aaddb285",
    "prev_manifest_sha256": "4a72d3...64_hex_chars...",
    "release_sequence": 2,
    "source_commit": "69b45a4968e5f826418655ad796d401261c3bf65",
    "issued_at": "2026-11-20T12:05:00Z",
    "expires_at": "2026-12-20T12:05:00Z"
  },
  "signature_base64": "..."
}
```

### 4.3. Sequence & Digest Tracker Schema (`anie.verifier-sequence-tracker.v2`)

```json
{
  "schema": "anie.verifier-sequence-tracker.v2",
  "initialized_at": "2026-11-20T12:00:00Z",
  "updated_at": "2026-11-20T12:10:00Z",
  "publishers": {
    "anie-first-party": {
      "last_sequence": 2,
      "last_manifest_sha256": "9b0d1fd5434e9187614cebe4aff58ef8227be9d75d00fa1531ba8082aaddb285"
    }
  }
}
```

---

## 5. Implementation Tasks

| Task ID | Component | Description | Acceptance Test |
| :--- | :--- | :--- | :--- |
| **T3.2-01** | `real_publish.py` | Add `prev_manifest_sha256` parameter to `publish_real` and support v1 and v2 manifest schemas with strict hash chaining. | `test_manifest_hash_chain_binding` |
| **T3.2-02** | `real_publish.py` | Update `sign_manifest_detached` to bind and sign `prev_manifest_sha256` under v2 attestation schema. | `test_signed_attestation_v2_binds_chain` |
| **T3.2-03** | `real_publish.py` | Upgrade `ReleaseSequenceTracker` to v2 schema tracking both sequence and manifest digest; support backwards-compatible v1 migration. | `test_tracker_v2_records_digest_and_sequence`, `test_tracker_v1_migration` |
| **T3.2-04** | `real_publish.py` | Update `verify_real_release` to enforce `prev_manifest_sha256` continuity against tracker's `last_manifest_sha256`. | `test_broken_hash_chain_fails_closed` |
| **T3.2-05** | `real_publish.py` | Implement `AegisReleaseConsumer` class providing transactional, crash-safe release ingestion into AEGIS. | `test_aegis_consumer_transactional_ingestion` |
| **T3.2-06** | `cli.py` | Add `anie keygen` CLI command with strict file permissions (`0600`) and metadata output. | `test_cli_keygen_command` |
| **T3.2-07** | `cli.py` | Add `anie inspect-candidate` CLI command providing human-readable pre-signing review. | `test_cli_inspect_candidate` |
| **T3.2-08** | `cli.py` | Add `--prev-manifest` flag to `publish-real` and `sign-real` to support hash chain automation. | `test_cli_hash_chain_roundtrip` |
| **T3.2-09** | `tests/` | Comprehensive failure injection: tampered manifests, modified partitions, downgraded sequences, broken hash chains, corrupted gzip bombs, expired keys. | `test_publication_trust_boundaries.py` |

---

## 6. Measurable Acceptance Criteria

1. **AC-01 (Hash Chain Continuity):** A release with `sequence > 1` whose `prev_manifest_sha256` does not match the verifier's recorded manifest hash MUST be rejected fail-closed with error mentioning hash chain broken.
2. **AC-02 (Air-Gapped Keygen):** `anie keygen` MUST create private key file with mode `0600` (on POSIX) and output public key PEM and metadata with zero network queries.
3. **AC-03 (Candidate Pre-Signing Inspection):** `anie inspect-candidate` MUST parse candidate bundles, verify evidence hashes, and summarize observation counts without requiring private keys or modifying files.
4. **AC-04 (Rollback & Replay Rejection):** Attempting to verify a release with `sequence <= last_accepted_sequence` MUST fail closed unless `--allow-rollback` is explicitly provided.
5. **AC-05 (Deterministic Gzip & Manifest):** Publishing the identical dataset twice with identical `published_at` and `source_commit` MUST produce bit-for-bit identical gzip files and SHA-256 hashes.
6. **AC-06 (AEGIS Consumer Transactional Acceptance):** `AegisReleaseConsumer` MUST NOT record the sequence or digest if any partition file or model validation fails.
7. **AC-07 (Decompression Bomb Protection):** A partition exceeding 50 MiB compressed or 100 MiB uncompressed, or a single record exceeding 500 KiB, MUST be rejected during streaming read without memory exhaustion (<50 MiB RSS).
8. **AC-08 (Collector Isolation Invariant):** The batch collector runtime (`src/anie/orchestrator.py`, `src/anie/doh_collector.py`) MUST NOT import or reference signing keys or private key loaders.

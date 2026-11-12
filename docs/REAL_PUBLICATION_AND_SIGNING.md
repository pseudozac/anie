# ANIE Authenticated Real-Data Publication & Detached Signing Guide

Part of ANIE Phase 2 PR 4: Authenticated First-Party Intelligence Publication.

## 1. Architectural Overview & Boundaries

The ANIE Real-Data Publication pipeline produces deterministic, independently verifiable, cryptographically authenticated releases of genuine first-party internet intelligence measurements.

```mermaid
flowchart TD
    subgraph Collector_VM["anie-collector-01 (Untrusted with Private Keys)"]
        Store[("real_intelligence.sqlite")] -->|export_canonical_dataset| CanonicalExport["Canonical Export (Observations + Events)"]
        CanonicalExport -->|publish_real| UnsignedCandidate["Unsigned Candidate Release<br/>(real_observations.jsonl.gz,<br/>real_events.jsonl.gz,<br/>manifest.json)"]
    end

    subgraph Secure_Operator["Detached Air-Gapped Signing Environment"]
        PrivKey[("Ed25519 Private Key<br/>(operator-pinned, NEVER on VM)")]
        UnsignedCandidate -.->|Transferred via secure artifact channel| SignEngine["sign_manifest_detached()"]
        PrivKey --> SignEngine
        SignEngine --> Attestation["signature.ed25519.json<br/>(Binds key_id, manifest_sha256, sequence)"]
    end

    subgraph Consumer_Verification["Independent Intelligence Consumer"]
        Attestation & UnsignedCandidate --> VerifyEngine["verify_real_release()"]
        TrustedKeys[("Pinned Public Keys & Trust Config")] --> VerifyEngine
        StateFile[("High-Water Mark State<br/>(Rollback Protection)")] <--> VerifyEngine
        VerifyEngine --> VerifiedDataset["Verified Empirical Intelligence"]
    end
```

### Core Security Invariants
1. **Air-Gapped Private Keys:** Primary Ed25519 private keys (`Ed25519PrivateKey`) **never reside on the collector VM** (`anie-collector-01`). The collector VM only produces unsigned candidate releases and manifest digests.
2. **Deterministic Reproducibility:** Data partitions are formatted in canonical JSON, strictly sorted (`observed_at ASC, observation_id ASC`), and compressed with fixed gzip headers (`mtime=0`, `compresslevel=9`). Two independent builds from the same database snapshot produce byte-for-byte identical archives.
3. **Anti-Contamination Enforcement:** Synthetic fixtures (`synthetic=True`, `method="synthetic"`, `source_id="synthetic:..."`) are unconditionally rejected by the real-data publication engine with `PermissionError`.
4. **Forensic Evidence Linking:** Observations maintain strict referential integrity with immutable collection events. Embedded raw wire-format DNS evidence (`raw_payload_b64`) is cryptographically verified against `raw_sha256`.
5. **Authenticates Publisher, Not External Truth:** A valid Ed25519 signature authenticates that the release was assembled and published by the authorized keyholder without tampering; it does not attest to the absolute truth of third-party DNS authoritative answers.

---

## 2. Replay & Rollback Protection

### The Stateless Verification Limitation
**Stateless cryptographic signature verification alone cannot prevent replay or rollback attacks.**
If an attacker intercepts or caches a previously signed genuine release (e.g. sequence 4), the cryptographic signature over sequence 4 will remain mathematically valid indefinitely (until `expires_at`). An attacker could present this historical release to downgrade a consumer's active intelligence view.

### The Solution: Monotonic Sequences and Persistent State
ANIE implements defense-in-depth rollback protection:
1. **Monotonically Increasing Release Sequence:** Every signed release binds an integer `release_sequence` (strictly $\ge 1$).
2. **Persistent Verifier High-Water Mark (`ReleaseSequenceTracker`):** The consumer verifier maintains a local state file recording the highest accepted sequence for each publisher channel:
   - When a release is verified, `release_sequence` must be strictly greater than the recorded sequence (`sequence > last_accepted`).
   - If `sequence <= last_accepted`, verification fails closed with a rollback rejection error:
     ```
     ValueError: release sequence 4 is replayed or downgraded (last accepted sequence was 5); rejection enforced for rollback protection
     ```
3. **Controlled Historical Auditing (`--allow-rollback`):** When historical forensic auditing is deliberately required, consumers can pass `--allow-rollback`, which permits historical verification without mutating the persistent high-water mark.

---

## 3. Detached Operator Signing Runbook

### Step 1: Export Unsigned Candidate on the Collector VM
On `anie-collector-01`:
```bash
anie publish-real \
    --db /var/lib/anie/real_intelligence.sqlite \
    --out /var/lib/anie/releases/release-2026-11-12 \
    --as-of "2026-11-12T12:00:00Z" \
    --sequence 1 \
    --publisher "anie-first-party"
```
The output directory contains:
- `real_observations.jsonl.gz`
- `real_events.jsonl.gz`
- `manifest.json` (unsigned candidate manifest)

### Step 2: Transfer Candidate Manifest to Secure Signing Workstation
Transfer `manifest.json` or the release archive to the isolated operator machine via secure transfer (e.g. `scp`, SFTP, or staged artifact repository).

### Step 3: Detached Signing in Trusted Environment
On the operator signing machine (holding the Ed25519 private key):
```bash
python -m anie.real_publish \
    sign \
    --dir /path/to/release-2026-11-12 \
    --key-file /secure/keys/operator-2026a.key \
    --key-id "operator-key-2026a" \
    --sequence 1 \
    --valid-days 30
```
Or programmatically using the Python API:
```python
from anie.real_publish import sign_manifest_detached

sign_manifest_detached(
    release_dir,
    private_key,
    key_id="operator-key-2026a",
    release_sequence=1,
    issued_at="2026-11-12T12:05:00Z",
    expires_at="2026-12-12T12:05:00Z",
)
```
This writes `signature.ed25519.json` into the release directory without touching private keys on the collector host.

---

## 4. Consumer Verification Runbook

### Independent Verification via CLI
Consumers verify downloaded release bundles using an operator-pinned public key:
```bash
anie verify-real \
    --dir /path/to/downloaded/release-2026-11-12 \
    --key-file /etc/anie/trusted_keys/operator-2026a.pub \
    --key-id "operator-key-2026a" \
    --state-file /var/lib/anie/verifier_state.json
```

Output:
```json
{
  "verified": true,
  "dataset_type": "first_party_intelligence",
  "release_sequence": 1,
  "total_observations": 120,
  "total_events": 120,
  "manifest_sha256": "4b82d4...",
  "publisher_signature_verified": true,
  "publisher_identity": "anie-first-party",
  "key_id": "operator-key-2026a",
  "key_fingerprint": "8a3f91...",
  "safe_to_autonomously_act": false,
  "publisher_real_world_identity_verified": false
}
```

---

## 5. Key Rotation & Revocation Procedures

### Multi-Key Trust Configuration
To rotate keys without invalidating historical releases, `RealReleaseTrust` maintains a map of multiple authorized keys with distinct validity windows:

```python
from anie.real_publish import RealReleaseTrust, TrustedKey

trust = RealReleaseTrust(
    trusted_keys={
        "operator-key-2026a": TrustedKey(
            key_id="operator-key-2026a",
            public_key_raw=key_2026a_pub,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-07-01T00:00:00Z",
        ),
        "operator-key-2026b": TrustedKey(
            key_id="operator-key-2026b",
            public_key_raw=key_2026b_pub,
            valid_from="2026-06-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
        ),
    },
    revoked_key_ids=frozenset({"compromised-key-id"}),
    revoked_fingerprints=frozenset({"compromised_sha256_fingerprint"}),
)
```

### Emergency Revocation
If a signing private key is compromised:
1. Immediately add the compromised `key_id` to `revoked_key_ids` and its SHA-256 fingerprint to `revoked_fingerprints`.
2. Any candidate release signed by the revoked key will be rejected unconditionally with `ValueError: signing key_id '...' has been revoked by operator trust policy`.

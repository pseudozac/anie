# ANIE — Oracle Cloud Infrastructure (OCI) Deployment Runbook
## Ampere A1 Engine Migration & Safe Collector Transition

- **Document Version:** 1.1 (Milestone 3.5.1)
- **Target Region:** `ap-hyderabad-1` (Hyderabad, India)
- **Instance Profile:** `VM.Standard.A1.Flex` (ARM64 Ampere Altra)
- **Target Allocation:** 2 OCPUs, 12 GiB RAM, 50 GB Boot Volume
- **Cost Impact:** $0.00 / ₹0.00 per month *only when strictly within Always Free tenancy allowances* (consumes 50% of the tenancy's 4 OCPU / 24 GiB Ampere allowance). Standard paid rates apply if allowances are exceeded.
- **Preservation Mandate:** Current collector `anie-collector-01` (`129.225.109.227`, E2.1.Micro) must remain completely untouched during staging. Zero live mutations or collection runs on host.

---

## 1. Pre-Deployment Entitlement & Capacity Verification

Before launching any compute instance, verify that your tenancy retains Always Free entitlements and that capacity exists in Availability Domain 1 (`AD-1`):

```bash
# 1. Verify Tenancy Limits and Free-Tier Ampere Usage
oci limits value list \
  --compartment-id <compartment_ocid> \
  --service-name compute \
  --query "data[?contains(name, 'standard-a1-core-count')].{Name:name, Value:value}"

# 2. Verify Capacity in ap-hyderabad-1 AD-1 (read-only shape check)
oci compute shape list \
  --compartment-id <compartment_ocid> \
  --availability-domain "<ad_name>" \
  --query "data[?shape=='VM.Standard.A1.Flex']"
```

*Rule:* If OCI returns `Out of host capacity`, do NOT retry in a loop. Wait for normal off-peak capacity replenishment.

---

## 2. Hardened Host Provisioning & Network Security Architecture

### 2.1 Security List & Network Security Group (NSG) Rules
The instance must exist in a private or strictly protected public subnet.
- **Inbound Rules:**
  - SSH (TCP/22): Restricted strictly to operator VPN / bastion IP address. No `0.0.0.0/0`.
  - All other inbound ports: **DROP / BLOCKED**.
- **Outbound (Egress) Rules:**
  - Egress strictly limited to DNS-over-HTTPS (DoH) endpoints on TCP/443:
    - Cloudflare: `1.1.1.1:443`, `1.0.0.1:443`, `2606:4700:4700::1111:443`
    - Google Public DNS: `8.8.8.8:443`, `8.8.4.4:443`, `2001:4860:4860::8888:443`
    - Quad9: `9.9.9.9:443`, `149.112.112.112:443`, `2620:fe::fe:443`
  - Direct outbound port 53 (UDP/TCP) is blocked by fail-closed host firewall.

### 2.2 Host Firewall (`nftables.conf`)
Deploy the following `/etc/nftables.conf` to guarantee fail-closed egress:

```nftables
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport 22 ip saddr { <OPERATOR_BASTION_IP> } accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state established,related accept
        
        # Outbound DoH to authorized resolvers only
        ip daddr { 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112 } tcp dport 443 accept
        ip6 daddr { 2606:4700:4700::1111, 2001:4860:4860::8888, 2620:fe::fe } tcp dport 443 accept
        
        # System updates (disabled during production collection runs)
        # tcp dport 443 accept
    }
}
```

---

## 3. Systemd Hardened Service Configuration

Create `/etc/systemd/system/anie-engine.service` for deterministic batch execution:

```ini
[Unit]
Description=ANIE First-Party Intelligence Engine Batch Execution
After=network.target network-online.target
Wants=network-online.target
Documentation=https://github.com/pseudozac/anie

[Service]
Type=oneshot
User=anie
Group=anie
WorkingDirectory=/opt/anie
Environment="PYTHONPATH=/opt/anie/src"
Environment="ANIE_LIVE_COLLECTION_AUTHORIZED=0"
ExecStart=/opt/anie/.venv/bin/python -m anie.cli collect-batch \
    --mode dry_run \
    --quota-db /var/lib/anie/quota.sqlite \
    --store-db /var/lib/anie/store.sqlite \
    --log-file /var/log/anie/collector.jsonl

# Process Sandboxing & Hardening
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# Read/Write File System Paths
ReadWritePaths=/var/lib/anie /var/log/anie
ReadOnlyPaths=/opt/anie

# Resource Quotas (for 2 OCPU / 12 GiB instance)
MemoryMax=4G
MemoryHigh=3G
CPUQuota=150%
TimeoutStartSec=60s
TimeoutStopSec=15s
KillMode=control-group
Restart=no
```

---

## 4. Migration & Coexistence Plan

To prevent any disruption or loss of pilot state:

```
[ Phase A: Parallel Staging ]
  - Existing collector (anie-collector-01, 129.225.109.227) continues running under existing governor.
  - New A1 engine node (anie-engine-01) is provisioned offline without live authorization.
  - Test suites and 100k benchmarks are executed on A1 to verify ARM64 NEON and SQLite FTS5 performance.

[ Phase B: State Replication & Validation ]
  - Export evidence backup from anie-collector-01 using `create_evidence_backup()`.
  - Validate backup checksum and signature offline.
  - Restore backup onto anie-engine-01 using `restore_evidence_backup()`.
  - Execute `reindex_fts()` and `verify_fts_integrity()`.

[ Phase C: Cutover & Activation Gate ]
  - Obtain written authorization from repository owner.
  - Disable cron/timer on anie-collector-01 (`systemctl disable --now anie-collector.timer`).
  - Set `ANIE_LIVE_COLLECTION_AUTHORIZED=1` on anie-engine-01.
  - Enable systemd timer on anie-engine-01.
```

---

## 5. Tenancy Allowance, Tier Architecture & Cost Governance

### 5.1 Free Allowance vs. Paid Tier Differentiation

OCI provisions different Always Free allowances by compute architecture:

| Tier / Shape Profile | Free Tenancy Allowance | Allocation in ANIE Staging | Tenancy Allowance Impact |
| :--- | :--- | :--- | :--- |
| **Ampere A1 (`VM.Standard.A1.Flex`)** | 4 OCPUs & 24 GiB RAM total per tenancy | 2 OCPUs & 12 GiB RAM (`anie-engine-01`) | **Consumes 50%** of tenancy A1 allowance. |
| **AMD Micro (`VM.Standard.E2.1.Micro`)** | 2 instances (1/8 OCPU, 1 GiB RAM each) | 1 instance (`anie-collector-01`, `129.225.109.227`) | **Consumes 50%** of tenancy AMD micro allowance. |
| **Block Volume Storage** | 200 GB total boot/block storage | 50 GB boot volume | **Consumes 25%** of tenancy storage allowance. |
| **Paid / Trial / PAYG Tiers** | Standard hourly meter after trial credits expire | None | $0 charges only while remaining within Free Tier allowances. |

> [!WARNING]
> **No Unconditional $0 Guarantee:** Zero billing is not unconditional or automatic. It is strictly contingent upon:
> 1. Total tenancy compute allocation remaining within the combined 4 OCPU / 24 GiB limit for Ampere and 2 instances for AMD.
> 2. Total boot and block volumes remaining $\le 200$ GB across all compartments.
> 3. Not attaching billable resources (e.g. paid NAT gateways, secondary IPv4 addresses, cross-region transfers).

### 5.2 Critical Billing Governance: OCI Budgets Are Alert-Only

> [!CAUTION]
> **OCI Budgets Do NOT Prevent Charges:**
> OCI Budgets and Quotas are **alerting mechanisms only**. They send email or SNS notifications when actual or forecasted spend reaches a threshold (e.g. $1.00).
> **OCI Budgets do NOT:**
> - Automatically halt, stop, or suspend compute instances.
> - Detach or delete billable block storage.
> - Cap billing or prevent overage charges.
>
> If an operator provisions resources beyond Always Free allowances or if account status transitions to standard paid rates, charges will accrue continuously until the operator manually terminates the instances. Continuous, proactive tenancy audit via OCI CLI or console is mandatory.

### 5.3 Staged Resource Cost Matrix (Within Allowance)

| Resource | Shape / Allocation | Monthly Usage | Allowance Status | Nominal Cost |
| :--- | :--- | :--- | :--- | :--- |
| **Compute Core (Ampere A1)** | 2 OCPUs | 1,488 OCPU-hours | Within 3,000 OCPU-hr Free Limit | ₹0.00 / $0.00 |
| **Memory (Ampere A1)** | 12 GiB RAM | 8,928 GB-hours | Within 18,000 GB-hr Free Limit | ₹0.00 / $0.00 |
| **Boot Volume** | 50 GB Balanced NVMe | 50 GB-months | Within 200 GB-month Free Limit | ₹0.00 / $0.00 |
| **Outbound Data Transfer** | ~500 MB / month DoH | 0.5 GB | Within 10 TB Free Limit | ₹0.00 / $0.00 |
| **Public IPv4** | 1 Ephemeral | 744 hours | Free for active compute instance | ₹0.00 / $0.00 |
| **Total Net Cost** | — | — | **Contingent on Free Eligibility** | **₹0.00 / $0.00** |

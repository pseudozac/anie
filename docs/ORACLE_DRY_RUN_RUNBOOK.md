# ANIE Oracle Cloud Pilot Deployment & Dry-Run Runbook

**Target Host:** `anie-collector-01` (Oracle Cloud Infrastructure `VM.Standard.E2.1.Micro`, 1 OCPU, 1 GiB usable RAM, Oracle Linux 9 / Ubuntu 24.04 LTS).  
**Phase:** Phase 2 Operational Deployment Gate (Pre-Execution Staging & Dry-Run Verification).  
**Security Boundary:** Air-Gapped / Semi-Isolated Collector. **Private Ed25519 signing keys NEVER reside on this host.**

---

## 1. Supported Dry-Run CLI Interface

When executing a manual dry run on the collector host, the **exact supported CLI interface** implemented in `src/anie/cli.py` must be used:

```bash
/opt/anie/venv/bin/python -m anie collect-batch \
  --mode dry_run \
  --quota-db /var/lib/anie/doh_quota.sqlite \
  --store-db /var/lib/anie/real_intelligence.sqlite \
  --log-file /var/log/anie/collector.jsonl \
  --lock-file /var/lib/anie/collector.lock
```

> [!CAUTION]
> **Do not execute this command yet.** Operational staging requires explicit operator verification of host prerequisites and administrative approval before executing any command on `anie-collector-01`.

### Expected Dry-Run Output Contract
When executed in dry-run mode, the orchestrator performs preflight host resource validation and query planning, but executes **zero** network socket operations and persists **zero** database records.

Expected JSON output on stdout:
```json
{
  "batch_id": "batch_...",
  "started_at": "2026-11-...Z",
  "completed_at": "2026-11-...Z",
  "duration_seconds": 0.015,
  "mode": "dry_run",
  "outcome": "SUCCESS",
  "reason": null,
  "scope": {
    "queries": [
      ["example.com", "dns_a"],
      ["iana.org", "dns_a"]
    ]
  },
  "preflight": {
    "passed": true,
    "mem_available_mb": 650,
    "disk_available_mb": 35000,
    "checks": {
      "memory_mb": "650 (min: 200)",
      "disk_mb": "35000 (min: 500)",
      "quota_db_integrity": "database file does not yet exist (will be initialized)",
      "store_db_integrity": "database file does not yet exist (will be initialized)"
    },
    "failure_reason": null,
    "operational_error": false
  },
  "queries_planned": 2,
  "queries_attempted": 0,
  "queries_succeeded": 0,
  "queries_failed": 0,
  "queries_skipped": 0,
  "records_persisted": {
    "observation_ids": [],
    "event_ids": []
  }
}
```

### Telemetry Invariants
1. `queries_planned`: Exactly 2 planned queries (`example.com`, `iana.org`).
2. `queries_attempted`: Exactly `0`.
3. `queries_succeeded`: Exactly `0`.
4. `queries_failed`: Exactly `0`.
5. `records_persisted`: Empty lists for `observation_ids` and `event_ids`.
6. Zero outbound TLS or DoH network connections attempted.

---

## 2. Host Layout, Directory Structure & User Permissions

To enforce the principle of least privilege and strict filesystem sandboxing, the host environment must adhere to the following directory layout:

| Path | Owner:Group | Mode | Access Policy | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `/opt/anie` | `root:root` | `0755` | Read-Only (`ReadOnlyPaths=/opt/anie`) | ANIE application source code and scripts. |
| `/opt/anie/venv` | `root:root` | `0755` | Read-Only (`ReadOnlyPaths=/opt/anie`) | Dedicated Python virtual environment. |
| `/var/lib/anie` | `anie:anie` | `0750` | Read-Write (`ReadWritePaths=/var/lib/anie`) | SQLite databases (`real_intelligence.sqlite`, `doh_quota.sqlite`) and advisory lock (`collector.lock`). |
| `/var/log/anie` | `anie:anie` | `0750` | Read-Write (`ReadWritePaths=/var/log/anie`) | Structured JSONL execution telemetry (`collector.jsonl`). |
| `/etc/default/anie-collector` | `root:anie` | `0600` | Read-Only (Root-managed) | Environment file for live collection authorization. |

### Dedicated Service User Creation
```bash
# Create dedicated unprivileged system group and user without login shell
sudo groupadd --system anie
sudo useradd --system --gid anie --home-dir /var/lib/anie --no-create-home --shell /usr/sbin/nologin anie

# Create state and telemetry directories with restrictive permissions
sudo mkdir -p /var/lib/anie /var/log/anie /opt/anie
sudo chown -R anie:anie /var/lib/anie /var/log/anie
sudo chmod 0750 /var/lib/anie /var/log/anie
```

### Isolated Python Virtual Environment Installation
ANIE requires Python 3.10, 3.12, or 3.13. On the host:
```bash
# 1. Create root-owned virtual environment in /opt/anie/venv
sudo python3.12 -m venv /opt/anie/venv
sudo /opt/anie/venv/bin/pip install --upgrade pip setuptools wheel

# 2. Deploy ANIE code to /opt/anie
# Source code must be owned by root so the service user 'anie' cannot modify code or binaries
sudo chown -R root:root /opt/anie
sudo chmod -R 0755 /opt/anie

# 3. Install ANIE into venv
sudo /opt/anie/venv/bin/pip install -e /opt/anie
```

---

## 3. Systemd Sandboxing & Service Architecture

Systemd provides external watchdog supervision, cgroup isolation, resource limits, and capability stripping for batch execution.

### Service Unit (`/etc/systemd/system/anie-collector.service`)
```ini
[Unit]
Description=ANIE First-Party Intelligence Bounded Batch Collector
Documentation=file:///opt/anie/systemd/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=anie
Group=anie
WorkingDirectory=/var/lib/anie

# Optional environment configuration for authorization and flags
EnvironmentFile=-/etc/default/anie-collector

# Default execution is safe offline dry-run; live collection requires
# explicit operator configuration in /etc/default/anie-collector
# (ANIE_LIVE_COLLECTION_AUTHORIZED=1 and EXTRA_OPTS="--live")
ExecStart=/opt/anie/venv/bin/python -m anie collect-batch \
    --mode dry_run \
    --quota-db /var/lib/anie/doh_quota.sqlite \
    --store-db /var/lib/anie/real_intelligence.sqlite \
    --log-file /var/log/anie/collector.jsonl \
    --lock-file /var/lib/anie/collector.lock \
    $EXTRA_OPTS

# Strict supervisor timeouts (RuntimeMaxSec does NOT apply to Type=oneshot)
TimeoutStartSec=30s
TimeoutStopSec=15s
KillMode=control-group
Restart=no

# Host resource boundaries (designed for Oracle Cloud 1 GiB micro VM)
MemoryMax=128M
MemoryHigh=96M
CPUQuota=20%
Nice=19

# Security sandbox and filesystem boundaries
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
NoNewPrivileges=yes

# Explicit read/write storage access
ReadWritePaths=/var/lib/anie /var/log/anie
ReadOnlyPaths=/opt/anie

# Journal logging
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Timer Unit (`/etc/systemd/system/anie-collector.timer`)
```ini
[Unit]
Description=ANIE First-Party Intelligence Batch Collection Timer
Documentation=file:///opt/anie/systemd/README.md
ConditionPathExists=/etc/systemd/system/anie-collector.service

[Timer]
# Conservative Daily schedule: runs once per day at 06:00 UTC
OnCalendar=*-*-* 06:00:00 UTC
RandomizedDelaySec=300s
Persistent=false

[Install]
WantedBy=timers.target
```

---

## 4. Acceptance Evidence Claims & Resource Model Corrections

To ensure empirical fidelity and avoid overstating offline benchmark evidence, the following distinctions and operational boundaries must be maintained:

### 1. Linux `VmHWM` vs Cgroup Memory Accounting
- **Process Peak RSS (`VmHWM`):** Measured via `/proc/self/status` or `getrusage(RUSAGE_SELF).ru_maxrss`. This reflects strictly the resident physical memory pages mapped directly into the single collector Python process's page table.
- **Cgroup Resident Memory (`memory.current`, `memory.peak`):** Measured via Linux cgroups v2 (`/sys/fs/cgroup/.../memory.peak`). Cgroup accounting tracks the aggregate footprint of the entire control group, including:
  1. The Python process RSS.
  2. Isolated child processes (e.g. the subprocess resolver invoked by `DohRateGovernor`).
  3. **Kernel Page Cache:** Clean and dirty disk pages cached by the Linux kernel on behalf of SQLite database reads/writes (`real_intelligence.sqlite`, WAL files, journal files), Python bytecode files, and shared libraries.
  4. **Kernel memory:** Page tables, socket buffers, and slab allocations.
- **Impact:** Cgroup memory will always exceed standalone process RSS (`VmHWM`) under active I/O. Benchmark figures reporting `VmHWM` (e.g. 35.2 MiB at $N=200$, 65.3 MiB at $N=3{,}000$) do NOT equal total cgroup usage.

### 2. `MemoryHigh` Throttling vs `MemoryMax` OOM Kill
- **`MemoryHigh=96M` is a reclaim throttle, NOT a process ceiling:** When total cgroup memory exceeds 96 MiB, systemd and the Linux kernel do not kill the process. Instead, the kernel throttles memory allocation and triggers aggressive asynchronous background reclaim of inactive page cache.
- **`MemoryMax=128M` is the hard limit:** If cgroup memory cannot be reclaimed below 128 MiB (e.g. unevictable anonymous heap allocations), the Linux kernel out-of-memory (OOM) killer fires and sends `SIGKILL` to all processes in the cgroup.
- **Safe Operating Envelope:** For the pilot envelope ($N \le 1{,}000$ records), process RSS is $\le 45.8\text{ MiB}$, providing $> 50\text{ MiB}$ of headroom below `MemoryHigh` for page cache and kernel buffers.

### 3. Mocked Execution Latency vs Actual Network Latency
- **Mocked Test Suite Latency ($\approx 32\text{ ms}$):** In the offline acceptance runner (`tools/phase2_acceptance_runner.py`), DoH HTTP/TLS exchanges are mocked in-memory, completing in milliseconds.
- **Real-World Network Latency ($\approx 0.5\text{s} - 2.5\text{s}$ per query):** Live network requests involve TCP connection establishment, TLS 1.3 handshake, Cloudflare DoH round-trip, and socket buffer processing.
- **Headroom Guarantee:** ANIE bounds each query at 5.0 seconds and the entire batch at $\le 25.0$ seconds. This provides generous slack before systemd's supervisor `TimeoutStartSec=30s` deadline while strictly terminating stalled queries.

### 4. Idealized Simulations vs Real-World Retries and Jitter
- **Idealized Discrete Simulation:** Assumes clock ticks at exact mathematical intervals, zero packet loss, zero resolver downtime, and continuous uptime.
- **Real-World Operational Factors:**
  - `RandomizedDelaySec=300s` introduces up to 5 minutes of uniform random jitter per execution to avoid synchronized query bursts.
  - The SQLite-backed `DohRateGovernor` enforces monotonic hourly and daily ceilings across process restarts; if a query fails or retries, quota consumption is recorded durably.
  - System clock adjustments (NTP/chrony steps) do not violate deadlines because batch execution uses monotonic time (`time.monotonic()`).

### 5. Differing Record Counts: Daily vs 4-Hour Schedule
- **Daily Cadence (`06:00:00 UTC`):**
  - Batches: 1 batch/day.
  - Queries: 2 queries/day (alternating 1 A, 1 AAAA).
  - Monthly Total: 60 records/month (30 A, 30 AAAA).
  - Quota Headroom: Uses 2 of 16 allowed daily queries (12.5% utilization), leaving **+14 queries/day of slack** for manual preflight checks or retries.
  - Recommended for initial pilot to minimize host overhead.
- **4-Hour Cadence (`every 4 hours`):**
  - Batches: 6 batches/day.
  - Queries: 12 queries/day (alternating 6 A, 6 AAAA).
  - Monthly Total: 360 records/month (180 A, 180 AAAA).
  - Quota Headroom: Uses 12 of 16 allowed daily queries (75.0% utilization), leaving **+4 queries/day of slack**.

### 6. Cgroup Verification Evidentiary Standard
- **Rule:** Do **NOT** claim active cgroup verification unless evidence includes actual cgroup file attributes retrieved from the Linux kernel sysfs interface on a systemd host (e.g. `/sys/fs/cgroup/system.slice/anie-collector.service/memory.peak` or `systemctl show anie-collector.service -p MemoryCurrent`).
- Process RSS measurements on Windows or WSL only verify user-space process consumption, not cgroup hierarchy enforcement.

---

## 5. Rollback & Emergency Teardown Procedures

If anomalous network behavior, rate limit exhaustion, database lock contention, or memory pressure is detected on `anie-collector-01`:

```bash
# 1. Immediately disable and stop the systemd timer
sudo systemctl disable --now anie-collector.timer

# 2. Terminate any currently running batch collector process
sudo systemctl stop anie-collector.service

# 3. Revoke live execution authorization immediately
sudo rm -f /etc/default/anie-collector

# 4. Verify all collector processes have been reaped
pgrep -u anie -l
# If any orphan remains, force terminate:
sudo pkill -9 -u anie

# 5. Check cgroup status to ensure the control group is empty
systemd-cgls /system.slice/anie-collector.service

# 6. Inspect recent error journals
sudo journalctl -u anie-collector.service -n 50 --no-pager
```

### Database Rollback & Quarantine (If Data Corruption Occurs)
```bash
# Backup existing database state for forensic analysis
sudo cp -a /var/lib/anie /var/lib/anie.corrupt-backup-$(date +%s)

# Re-initialize clean SQLite databases
sudo rm -f /var/lib/anie/*.sqlite* /var/lib/anie/*.lock
sudo -u anie touch /var/lib/anie/real_intelligence.sqlite /var/lib/anie/doh_quota.sqlite
```

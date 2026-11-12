# ANIE Systemd Batch Orchestration & Hardening Guide

This directory contains systemd unit templates for bounded, resource-governed batch execution of ANIE's first-party intelligence collector on resource-constrained hosts (specifically Oracle Cloud `VM.Standard.E2.1.Micro` with 1 GiB RAM).

## 1. Unit Architecture and Timeout Semantics

### Why `Type=oneshot` and `TimeoutStartSec`?

A critical operational requirement for batch execution is enforcing an outer hard ceiling on service execution time to prevent runaway background processes from exhausting CPU or memory.

In systemd, the service unit is configured with:
```ini
Type=oneshot
TimeoutStartSec=30s
TimeoutStopSec=15s
KillMode=control-group
Restart=no
```

#### The `RuntimeMaxSec` Pitfall
In systemd, `RuntimeMaxSec` applies **only** while a service is in the `active` (running) state. For a service of `Type=oneshot`, the service transitions directly from `activating` (running `ExecStart`) to `inactive` (or `failed`) once `ExecStart` completes. It never enters a steady `active` state. Consequently:
- **`RuntimeMaxSec` is completely ignored by systemd for `Type=oneshot` units.**
- Relying on `RuntimeMaxSec` for a one-shot batch script leaves the service without any systemd-enforced execution deadline.

#### Correct Mechanism: `TimeoutStartSec`
For `Type=oneshot` services, `TimeoutStartSec` defines the maximum allowable wall-clock duration for `ExecStart` to execute. If `ExecStart` does not exit within `TimeoutStartSec` (configured here as `30s`), systemd considers the startup timed out and initiates termination.

### Process Termination Escalation

When `TimeoutStartSec` expires:
1. **Control-Group Scope (`KillMode=control-group`)**: Systemd delivers a `SIGTERM` signal to the primary Python process and **all child processes** within the unit's control group (including any isolated DNS resolver child processes spawned by `DohRateGovernor`).
2. **Graceful Teardown Window (`TimeoutStopSec=15s`)**: The process is granted up to 15 seconds to flush buffers, release file locks, and cleanly close SQLite WAL journal files.
3. **Forced Termination (`SIGKILL`)**: If any process in the cgroup remains alive after `TimeoutStopSec`, systemd sends `SIGKILL` to forcefully terminate all remaining processes in the cgroup.

### Important OS Caveat: Uninterruptible Sleep (`TASK_UNINTERRUPTIBLE` / D-State)

While systemd's cgroup kill escalation is robust against CPU loops and user-space deadlocks:
- **No POSIX signal, including `SIGKILL`, can terminate a thread or process in Linux `TASK_UNINTERRUPTIBLE` (D-state).**
- D-state occurs when a process is blocked in kernel space awaiting hardware or remote I/O (for example, remote iSCSI/NFS block volume hangs or kernel page lock contention under severe memory pressure).
- If an Oracle Cloud block storage stall puts an SQLite write into D-state, the process will remain visible in `ps` / `top` until the underlying block I/O request finishes or fails at the kernel level.
- ANIE mitigates this risk by performing preflight checks (ensuring >= 200 MiB free RAM and >= 500 MiB free disk) and enforcing SQLite busy timeouts before invoking disk I/O.

---

## 2. Schedule Cadence: Daily vs 4-Hour

The timer `anie-collector.timer` is provided disabled by default. Administrators can choose between two operational schedules depending on surveillance requirements.

| Cadence | Schedule Expression | Queries / Day | Cooldown Margin | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Daily (Default Template)** | `*-*-* 06:00:00 UTC` | 2 queries / day | 24 hours (>> 30 min) | Lowest host overhead, maximum margin for rate limits. |
| **4-Hour Cadence** | `*-*-* 00,04,08,12,16,20:00:00 UTC` | 12 queries / day | 4 hours (>> 30 min) | Higher temporal resolution for DNS changes and TTL expiration. |

Both schedules:
- Stay well below the daily rate-governor ceiling of 50 queries/day.
- Strictly respect the 30-minute per-domain cooldown because queries are spaced by hours.
- Utilize `RandomizedDelaySec=300s` to add up to 5 minutes of uniform jitter, preventing synchronized collection spikes against public DoH endpoints.

### Switching to 4-Hour Cadence
To select the 4-hour cadence, create a systemd override or edit `/etc/systemd/system/anie-collector.timer`:
```ini
[Timer]
OnCalendar=
OnCalendar=*-*-* 00,04,08,12,16,20:00:00 UTC
RandomizedDelaySec=300s
```

---

## 3. Host Hardening & Sandboxing

The service unit enforces defense-in-depth isolation suitable for a shared or minimal VM:
- **Resource Caps**: `MemoryMax=128M`, `MemoryHigh=96M`, `CPUQuota=20%`, `Nice=19`.
- **Filesystem Isolation**: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`. Only `/var/lib/anie` (databases) and `/var/log/anie` (telemetry) are writable. The application code `/opt/anie` is strictly read-only (`ReadOnlyPaths=/opt/anie`).
- **Kernel & Capability Stripping**: `CapabilityBoundingSet=` (drops all Linux root capabilities), `NoNewPrivileges=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `RestrictRealtime=yes`.
- **Network Family Filter**: `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (prevents raw sockets or packet sniffing).

---

## 4. Administrative Runbook

### Pre-Deployment Verification
Before staging the service on a live host:
```bash
# 1. Verify systemd unit syntax and sanity
systemd-analyze verify systemd/anie-collector.service systemd/anie-collector.timer

# 2. Confirm required paths exist and have correct permissions
ls -ld /opt/anie /var/lib/anie /var/log/anie
```

### Installation
```bash
# 1. Copy unit and timer definitions
sudo cp systemd/anie-collector.service /etc/systemd/system/
sudo cp systemd/anie-collector.timer /etc/systemd/system/

# 2. Reload systemd daemon
sudo systemctl daemon-reload
```

### Dry-Run Validation (Offline Mode)
By default, the service executes in safe offline dry-run mode without making network calls.
```bash
# Execute a single one-shot batch under systemd
sudo systemctl start anie-collector.service

# Check execution status and journal output
sudo systemctl status anie-collector.service
sudo journalctl -u anie-collector.service -n 50 --no-pager

# Verify telemetry log output
sudo tail -n 5 /var/log/anie/collector.jsonl
```

### Authorizing and Activating Live Collection
Live collection is strictly gated by dual authorization (`--live` argument AND `ANIE_LIVE_COLLECTION_AUTHORIZED=1` environment variable).

To authorize live batch execution:
1. Create or edit `/etc/default/anie-collector`:
   ```bash
   sudo mkdir -p /etc/default
   sudo tee /etc/default/anie-collector << 'EOF'
   ANIE_LIVE_COLLECTION_AUTHORIZED=1
   EXTRA_OPTS="--live"
   EOF
   sudo chmod 0600 /etc/default/anie-collector
   ```
2. Test one live execution manually:
   ```bash
   sudo systemctl start anie-collector.service
   sudo journalctl -u anie-collector.service -n 30 --no-pager
   ```
3. Enable and start the timer:
   ```bash
   sudo systemctl enable --now anie-collector.timer
   sudo systemctl list-timers --all | grep anie-collector
   ```

### Emergency Rollback and Disable Procedure
If anomalous network traffic, disk consumption, or host memory pressure occurs:
```bash
# 1. Immediately disable and stop the timer
sudo systemctl disable --now anie-collector.timer

# 2. Stop any actively executing service instance
sudo systemctl stop anie-collector.service

# 3. Revoke live authorization
sudo rm -f /etc/default/anie-collector

# 4. Verify no anie processes remain
pgrep -u anie -l
```

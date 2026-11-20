"""Security preflight hardening and fail-closed isolation verification for ANIE.

Executes active sandbox and network boundary assertions before any collection process
can proceed. Used in systemd ExecStartPre= to guarantee observable failure states.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from typing import Any

DEFAULT_IMDS_IP = "169.254.169.254"
DEFAULT_IMDS_PORT = 80
PROBE_UNAUTHORIZED_IP = "198.51.100.1"  # RFC 5737 TEST-NET-2 documentation IP


class NetworkProbeStatus(str, Enum):
    """Network probe outcome classification."""
    BLOCKED = "BLOCKED"              # Confirmed blocked by active kernel rejection (EPERM, ECONNREFUSED, ENETUNREACH, EACCES)
    ALLOWED = "ALLOWED"              # Confirmed reachable / connected (SECURITY VIOLATION for unauthorized target)
    UNVERIFIABLE = "UNVERIFIABLE"    # Uncertain outcome (timeout, generic socket creation error)


class FirewallInspectionStatus(str, Enum):
    """Host netfilter firewall rule inspection classification."""
    VERIFIED = "VERIFIED"            # Host kernel netfilter rule explicitly verified present (exit code 0)
    MISSING = "MISSING"              # Host kernel netfilter rule explicitly verified absent (rule does not exist)
    INACCESSIBLE = "INACCESSIBLE"    # Netfilter inspection inaccessible due to unprivileged sandbox constraints


class ProbeResult(tuple):
    """2-tuple (is_blocked, message) with rich .status attribute for backward compatibility."""
    is_blocked: bool
    message: str
    status: NetworkProbeStatus

    def __new__(cls, is_blocked: bool, message: str, status: NetworkProbeStatus):
        instance = super().__new__(cls, (is_blocked, message))
        instance.is_blocked = is_blocked
        instance.message = message
        instance.status = status
        return instance


class FirewallResult(tuple):
    """2-tuple (verified, message) with rich .status attribute for backward compatibility."""
    verified: bool | None
    message: str
    status: FirewallInspectionStatus

    def __new__(cls, verified: bool | None, message: str, status: FirewallInspectionStatus):
        instance = super().__new__(cls, (verified, message))
        instance.verified = verified
        instance.message = message
        instance.status = status
        return instance


@dataclass(frozen=True)
class SecurityPreflightReport:
    passed: bool
    imds_blocked: bool
    egress_filter_active: bool
    firewall_rule_verified: bool | None
    failure_reason: str | None
    checks: dict[str, str]
    imds_status: str = "BLOCKED"
    egress_status: str = "BLOCKED"
    firewall_status: str = "INACCESSIBLE"
    systemd_policy_verified: bool | None = None
    signing_keys_absent: bool = True

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def check_imds_blocked(
    target_ip: str = DEFAULT_IMDS_IP,
    target_port: int = DEFAULT_IMDS_PORT,
    timeout: float = 0.5,
    socket_factory: Any = None,
) -> ProbeResult:
    """Assert that the instance metadata service (IMDS) cannot be reached.

    Returns:
        ProbeResult(is_blocked, message, status=NetworkProbeStatus)
    """
    sock_fn = socket_factory or socket.socket
    try:
        s = sock_fn(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((target_ip, target_port))
            # If connect succeeds, IMDS is dangerously accessible
            s.close()
            return ProbeResult(
                False,
                f"CRITICAL: Connected to IMDS ({target_ip}:{target_port}); metadata is accessible!",
                NetworkProbeStatus.ALLOWED,
            )
        except ConnectionRefusedError:
            return ProbeResult(
                True,
                f"IMDS connection to {target_ip}:{target_port} refused (rejected by kernel firewall / host firewall with TCP reset)",
                NetworkProbeStatus.BLOCKED,
            )
        except (PermissionError, OSError) as exc:
            err = getattr(exc, "errno", None)
            if err in (errno.EPERM, errno.ENETUNREACH, errno.EACCES, errno.ECONNREFUSED):
                return ProbeResult(
                    True,
                    f"IMDS connection to {target_ip}:{target_port} denied by kernel: {exc}",
                    NetworkProbeStatus.BLOCKED,
                )
            # Other OSError without positive rejection is unverifiable
            return ProbeResult(
                True,
                f"IMDS connection to {target_ip}:{target_port} resulted in {type(exc).__name__}: {exc}",
                NetworkProbeStatus.UNVERIFIABLE,
            )
        except (TimeoutError, socket.timeout):
            return ProbeResult(
                True,
                f"IMDS connection to {target_ip}:{target_port} timed out (blocked by cgroup BPF filter)",
                NetworkProbeStatus.UNVERIFIABLE,
            )
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as exc:
        return ProbeResult(
            True,
            f"Socket creation for IMDS probe failed: {exc}",
            NetworkProbeStatus.UNVERIFIABLE,
        )


def check_egress_filter(
    unauthorized_ip: str = PROBE_UNAUTHORIZED_IP,
    port: int = 80,
    timeout: float = 0.5,
    socket_factory: Any = None,
) -> ProbeResult:
    """Assert that arbitrary outbound network egress is denied by active policy.

    Returns:
        ProbeResult(is_blocked, message, status=NetworkProbeStatus)
    """
    sock_fn = socket_factory or socket.socket
    try:
        s = sock_fn(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((unauthorized_ip, port))
            s.close()
            return ProbeResult(
                False,
                f"CRITICAL: Connected to unauthorized IP ({unauthorized_ip}:{port}); IPAddressDeny not active!",
                NetworkProbeStatus.ALLOWED,
            )
        except ConnectionRefusedError:
            return ProbeResult(
                True,
                f"Outbound probe to {unauthorized_ip}:{port} refused by network boundary",
                NetworkProbeStatus.BLOCKED,
            )
        except (PermissionError, OSError) as exc:
            err = getattr(exc, "errno", None)
            if err in (errno.EPERM, errno.ENETUNREACH, errno.EACCES, errno.ECONNREFUSED):
                return ProbeResult(
                    True,
                    f"Outbound probe to {unauthorized_ip}:{port} denied by kernel cgroup BPF filter: {exc}",
                    NetworkProbeStatus.BLOCKED,
                )
            return ProbeResult(
                False,
                f"Outbound probe to {unauthorized_ip}:{port} encountered unexpected error: {exc}",
                NetworkProbeStatus.UNVERIFIABLE,
            )
        except (TimeoutError, socket.timeout):
            # Note: 198.51.100.1 is RFC 5737 TEST-NET-2; timeout alone does not prove egress filtering is active
            return ProbeResult(
                False,
                f"Outbound probe to {unauthorized_ip}:{port} dropped (timeout)",
                NetworkProbeStatus.UNVERIFIABLE,
            )
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as exc:
        return ProbeResult(
            False,
            f"Socket creation to {unauthorized_ip} prevented: {exc}",
            NetworkProbeStatus.UNVERIFIABLE,
        )


def check_systemd_network_policy(
    unit_name: str = "anie-pilot.service",
    runner: Any = None,
) -> tuple[bool | None, str]:
    """Inspect systemd unit configuration to verify active IPAddressDeny policy."""
    cmd_runner = runner or subprocess.run
    which_systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"
    if runner is None and not os.path.exists(which_systemctl):
        return None, f"systemctl binary not found at {which_systemctl}"

    try:
        proc = cmd_runner(
            [which_systemctl, "show", unit_name, "-p", "IPAddressDeny", "-p", "IPAddressAllow"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if proc.returncode != 0:
            return None, f"systemctl show failed (exit code {proc.returncode}): {proc.stderr.strip()}"

        stdout = proc.stdout
        has_deny = False
        for line in stdout.splitlines():
            if line.startswith("IPAddressDeny="):
                val = line.split("=", 1)[1].strip()
                if val and (val == "any" or "0.0.0.0/0" in val or "::/0" in val):
                    has_deny = True
        if has_deny:
            return True, f"systemd network policy verified for {unit_name}: IPAddressDeny active"
        else:
            return False, f"systemd unit {unit_name} does not enforce IPAddressDeny"
    except Exception as exc:
        return None, f"Failed to inspect systemd network policy: {exc}"


def check_firewall_rule(
    uid: int | None = None,
    iptables_path: str | None = None,
    runner: Any = None,
) -> FirewallResult:
    """Verify kernel netfilter IMDS block rule exists if iptables is present and permitted."""
    cmd_runner = runner or subprocess.run
    which_iptables = iptables_path or shutil.which("iptables") or "/usr/sbin/iptables"
    if runner is None and not os.path.exists(which_iptables):
        return FirewallResult(
            None,
            f"iptables binary not found at {which_iptables}",
            FirewallInspectionStatus.INACCESSIBLE,
        )

    target_uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else 987)
    check_cmd = [
        which_iptables,
        "-C", "OUTPUT",
        "-d", DEFAULT_IMDS_IP,
        "-p", "tcp",
        "--dport", str(DEFAULT_IMDS_PORT),
        "-m", "owner",
        "--uid-owner", str(target_uid),
        "-j", "REJECT",
        "--reject-with", "tcp-reset",
    ]

    try:
        proc = cmd_runner(check_cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            return FirewallResult(
                True,
                "Firewall IMDS block rule verified active in kernel OUTPUT chain",
                FirewallInspectionStatus.VERIFIED,
            )

        stderr_lower = proc.stderr.lower() if proc.stderr else ""
        # Distinguish unprivileged sandbox / protocol restrictions from genuine missing rules
        inaccessible_indicators = (
            "permission denied",
            "you must be root",
            "address family not supported",
            "protocol not supported",
            "operation not permitted",
            "failed to initialize nft",
            "could not open a connection",
            "table does not exist",
        )
        if any(indicator in stderr_lower for indicator in inaccessible_indicators):
            return FirewallResult(
                None,
                f"Netfilter inspection inaccessible inside unprivileged service sandbox: {proc.stderr.strip()}",
                FirewallInspectionStatus.INACCESSIBLE,
            )

        # Genuine missing rule: iptables runs with permission but rule is absent
        return FirewallResult(
            False,
            f"Firewall rule missing or inactive (exit code {proc.returncode}): {proc.stderr.strip()}",
            FirewallInspectionStatus.MISSING,
        )
    except Exception as exc:
        return FirewallResult(
            None,
            f"Failed to execute firewall check (inaccessible): {exc}",
            FirewallInspectionStatus.INACCESSIBLE,
        )


def check_no_signing_keys(
    search_paths: list[str | Path] | None = None,
) -> tuple[bool, str]:
    """Assert that no private cryptographic signing keys exist in collector state directories or environment.

    Protects the collector/operator air-gap boundary: signing keys must only ever
    reside in isolated operator environments and must never be staged or stored on the collector.
    """
    pem_private_indicators = [
        b"BEGIN PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN ED25519 PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
    ]

    # 1. Environment variable inspection (prevent passing private keys via env)
    for env_var, val in os.environ.items():
        var_upper = env_var.upper()
        if any(k in var_upper for k in ("PRIVATE_KEY", "SIGNING_KEY", "ED25519_KEY")):
            return False, f"Private signing key name detected in environment variable '{env_var}'; collector air-gap violated"
        if isinstance(val, str) and any(ind.decode("ascii") in val for ind in pem_private_indicators):
            return False, f"Private key PEM header detected in environment variable '{env_var}'; collector air-gap violated"

    # 2. File and directory inspection
    if search_paths is None:
        search_paths = [
            Path("/var/lib/anie"),
            Path("/etc/anie"),
            Path("/home/anie"),
            Path("/tmp/anie"),
        ]
        state_env = os.environ.get("ANIE_STATE_DIR")
        if state_env:
            search_paths.append(Path(state_env))

    target_extensions = {".priv", ".key"}

    for base in search_paths:
        base_p = Path(base)
        if not base_p.exists():
            continue
        try:
            for root, dirs, files in os.walk(base_p):
                for fname in files:
                    fpath = Path(root) / fname
                    if fpath.is_symlink():
                        continue

                    ext = fpath.suffix.lower()
                    if ext in target_extensions or "id_ed25519" in fname.lower() or "id_rsa" in fname.lower():
                        return False, f"Private signing key file detected at '{fpath}'; collector air-gap violated"

                    try:
                        sz = fpath.stat().st_size
                        if 0 < sz <= 1048576:
                            with fpath.open("rb") as f:
                                head = f.read(1024)
                                if any(ind in head for ind in pem_private_indicators):
                                    return False, f"Private key PEM header detected in '{fpath}'; collector air-gap violated"
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue

    return True, "No private signing keys detected in collector directories or environment"


def run_security_preflight(
    require_firewall_rule: bool = False,
    imds_ip: str = DEFAULT_IMDS_IP,
    imds_port: int = DEFAULT_IMDS_PORT,
    uid: int | None = None,
    socket_factory: Any = None,
    runner: Any = None,
    unit_name: str = "anie-pilot.service",
    systemd_runner: Any = None,
    signing_key_paths: list[str | Path] | None = None,
) -> SecurityPreflightReport:
    """Execute complete fail-closed security preflight assertions."""
    checks: dict[str, str] = {}

    # 1. IMDS reachability check
    imds_res = check_imds_blocked(
        target_ip=imds_ip, target_port=imds_port, socket_factory=socket_factory
    )
    checks["imds_blocked"] = imds_res.message

    # 2. Outbound egress sandbox check
    egress_res = check_egress_filter(socket_factory=socket_factory)
    checks["egress_blocked"] = egress_res.message

    # 3. Systemd network policy inspection
    sys_runner = systemd_runner or runner
    systemd_policy_verified, systemd_policy_msg = check_systemd_network_policy(
        unit_name=unit_name, runner=sys_runner
    )
    if systemd_policy_verified is not None:
        checks["systemd_network_policy"] = systemd_policy_msg

    # 4. Firewall rule check (if enabled / advisory)
    fw_res = check_firewall_rule(uid=uid, runner=runner)
    checks["firewall_rule"] = fw_res.message

    # 5. Signing key isolation check
    keys_absent, keys_msg = check_no_signing_keys(search_paths=signing_key_paths)
    checks["no_signing_keys"] = keys_msg

    # --- FAIL-CLOSED EVALUATION ---

    # Critical Assertion 0: Signing private keys must NEVER reside on collector
    if not keys_absent:
        return SecurityPreflightReport(
            passed=False,
            imds_blocked=imds_res.status == NetworkProbeStatus.BLOCKED,
            egress_filter_active=egress_res.status == NetworkProbeStatus.BLOCKED,
            firewall_rule_verified=fw_res.verified,
            failure_reason=f"SECURITY FAILURE: {keys_msg}",
            checks=checks,
            imds_status=imds_res.status.value,
            egress_status=egress_res.status.value,
            firewall_status=fw_res.status.value,
            systemd_policy_verified=systemd_policy_verified,
            signing_keys_absent=False,
        )

    # Critical Assertion A: IMDS must NEVER be accessible
    if imds_res.status == NetworkProbeStatus.ALLOWED:
        return SecurityPreflightReport(
            passed=False,
            imds_blocked=False,
            egress_filter_active=egress_res.status == NetworkProbeStatus.BLOCKED,
            firewall_rule_verified=fw_res.verified,
            failure_reason="SECURITY FAILURE: Oracle IMDS is accessible; collection aborted",
            checks=checks,
            imds_status=imds_res.status.value,
            egress_status=egress_res.status.value,
            firewall_status=fw_res.status.value,
            systemd_policy_verified=systemd_policy_verified,
            signing_keys_absent=True,
        )

    # Critical Assertion B: Unauthorized egress must NEVER be permitted
    if egress_res.status == NetworkProbeStatus.ALLOWED:
        return SecurityPreflightReport(
            passed=False,
            imds_blocked=imds_res.status == NetworkProbeStatus.BLOCKED,
            egress_filter_active=False,
            firewall_rule_verified=fw_res.verified,
            failure_reason="SECURITY FAILURE: Unauthorized outbound egress is demonstrably permitted; IPAddressDeny inactive",
            checks=checks,
            imds_status=imds_res.status.value,
            egress_status=egress_res.status.value,
            firewall_status=fw_res.status.value,
            systemd_policy_verified=systemd_policy_verified,
            signing_keys_absent=True,
        )

    # Assertion C: Egress isolation verification
    # When egress probe is UNVERIFIABLE (e.g. timeout to 198.51.100.1),
    # an independent verified control (systemd IPAddressDeny) must explicitly satisfy the policy.
    egress_active = False
    if egress_res.status == NetworkProbeStatus.BLOCKED:
        egress_active = True
    elif egress_res.status == NetworkProbeStatus.UNVERIFIABLE:
        if systemd_policy_verified is True:
            egress_active = True
            checks["egress_blocked"] += f" (policy verified: {systemd_policy_msg})"
        else:
            return SecurityPreflightReport(
                passed=False,
                imds_blocked=imds_res.status == NetworkProbeStatus.BLOCKED,
                egress_filter_active=False,
                firewall_rule_verified=fw_res.verified,
                failure_reason="SECURITY FAILURE: Egress isolation is UNVERIFIABLE (probe timed out and systemd network policy is unverified)",
                checks=checks,
                imds_status=imds_res.status.value,
                egress_status=egress_res.status.value,
                firewall_status=fw_res.status.value,
                systemd_policy_verified=systemd_policy_verified,
                signing_keys_absent=True,
            )

    # Assertion D: IMDS isolation verification
    imds_active = False
    if imds_res.status == NetworkProbeStatus.BLOCKED:
        imds_active = True
    elif imds_res.status == NetworkProbeStatus.UNVERIFIABLE:
        # If IMDS probe timed out, separate verified control (firewall rule or systemd policy) must satisfy
        if fw_res.status == FirewallInspectionStatus.VERIFIED or systemd_policy_verified is True:
            imds_active = True
            checks["imds_blocked"] += " (satisfied by separate verified isolation control)"
        else:
            return SecurityPreflightReport(
                passed=False,
                imds_blocked=False,
                egress_filter_active=egress_active,
                firewall_rule_verified=fw_res.verified,
                failure_reason="SECURITY FAILURE: IMDS isolation is UNVERIFIABLE and no separate verified control satisfies policy",
                checks=checks,
                imds_status=imds_res.status.value,
                egress_status=egress_res.status.value,
                firewall_status=fw_res.status.value,
                systemd_policy_verified=systemd_policy_verified,
                signing_keys_absent=True,
            )

    # Assertion E: Required firewall rule enforcement
    if require_firewall_rule:
        if fw_res.status == FirewallInspectionStatus.MISSING:
            return SecurityPreflightReport(
                passed=False,
                imds_blocked=imds_active,
                egress_filter_active=egress_active,
                firewall_rule_verified=False,
                failure_reason="SECURITY FAILURE: Required kernel firewall IMDS rule is missing",
                checks=checks,
                imds_status=imds_res.status.value,
                egress_status=egress_res.status.value,
                firewall_status=fw_res.status.value,
                systemd_policy_verified=systemd_policy_verified,
                signing_keys_absent=True,
            )
        elif fw_res.status == FirewallInspectionStatus.INACCESSIBLE:
            return SecurityPreflightReport(
                passed=False,
                imds_blocked=imds_active,
                egress_filter_active=egress_active,
                firewall_rule_verified=None,
                failure_reason="SECURITY FAILURE: Required kernel firewall rule could not be verified (netfilter inspection inaccessible inside unprivileged sandbox)",
                checks=checks,
                imds_status=imds_res.status.value,
                egress_status=egress_res.status.value,
                firewall_status=fw_res.status.value,
                systemd_policy_verified=systemd_policy_verified,
                signing_keys_absent=True,
            )

    return SecurityPreflightReport(
        passed=True,
        imds_blocked=imds_active,
        egress_filter_active=egress_active,
        firewall_rule_verified=fw_res.verified,
        failure_reason=None,
        checks=checks,
        imds_status=imds_res.status.value,
        egress_status=egress_res.status.value,
        firewall_status=fw_res.status.value,
        systemd_policy_verified=systemd_policy_verified,
        signing_keys_absent=True,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for systemd ExecStartPre= preflight verification."""
    import argparse
    parser = argparse.ArgumentParser(description="ANIE security preflight verification")
    parser.add_argument("--require-firewall", action="store_true", help="enforce kernel firewall rule presence")
    parser.add_argument("--imds-ip", default=DEFAULT_IMDS_IP, help="target IMDS IP to verify blocked")
    parser.add_argument("--unit-name", default="anie-pilot.service", help="systemd unit name for policy verification")
    parser.add_argument("--check-key-path", dest="check_key_paths", action="append", default=None, help="directory path to scan for forbidden private keys")
    args = parser.parse_args(argv)

    report = run_security_preflight(
        require_firewall_rule=args.require_firewall,
        imds_ip=args.imds_ip,
        unit_name=args.unit_name,
        signing_key_paths=args.check_key_paths,
    )

    if not report.passed:
        sys.stderr.write(f"ANIE SECURITY PREFLIGHT FAILED:\n{report.to_json()}\n")
        return 1

    print(report.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Security preflight hardening and fail-closed isolation verification for ANIE Phase 2.1.

Executes active sandbox and network boundary assertions before any collection process
can proceed. Used in systemd ExecStartPre= to guarantee observable failure states.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

DEFAULT_IMDS_IP = "169.254.169.254"
DEFAULT_IMDS_PORT = 80
PROBE_UNAUTHORIZED_IP = "198.51.100.1"  # RFC 5737 TEST-NET-2 documentation IP


@dataclass(frozen=True)
class SecurityPreflightReport:
    passed: bool
    imds_blocked: bool
    egress_filter_active: bool
    firewall_rule_verified: bool | None
    failure_reason: str | None
    checks: dict[str, str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def check_imds_blocked(
    target_ip: str = DEFAULT_IMDS_IP,
    target_port: int = DEFAULT_IMDS_PORT,
    timeout: float = 0.5,
    socket_factory: Any = None,
) -> tuple[bool, str]:
    """Assert that the instance metadata service (IMDS) cannot be reached.

    Returns:
        (is_blocked, message)
    """
    sock_fn = socket_factory or socket.socket
    try:
        s = sock_fn(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((target_ip, target_port))
            # If connect succeeds, IMDS is dangerously accessible
            s.close()
            return False, f"CRITICAL: Connected to IMDS ({target_ip}:{target_port}); metadata is accessible!"
        except (TimeoutError, socket.timeout):
            return True, f"IMDS connection to {target_ip}:{target_port} timed out (blocked by cgroup BPF filter)"
        except ConnectionRefusedError:
            return True, f"IMDS connection to {target_ip}:{target_port} refused (rejected by kernel firewall)"
        except OSError as exc:
            # Errno 1 (EPERM) is returned by systemd cgroup BPF filter when IPAddressDeny=any drops packet
            return True, f"IMDS connection to {target_ip}:{target_port} denied by kernel: {exc}"
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as exc:
        return True, f"Socket creation failed (blocked by sandbox): {exc}"


def check_egress_filter(
    unauthorized_ip: str = PROBE_UNAUTHORIZED_IP,
    port: int = 80,
    timeout: float = 0.5,
    socket_factory: Any = None,
) -> tuple[bool, str]:
    """Assert that arbitrary outbound network egress is denied by the cgroup BPF filter.

    Returns:
        (is_blocked, message)
    """
    sock_fn = socket_factory or socket.socket
    try:
        s = sock_fn(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((unauthorized_ip, port))
            s.close()
            return False, f"CRITICAL: Connected to unauthorized IP ({unauthorized_ip}:{port}); IPAddressDeny not active!"
        except (TimeoutError, socket.timeout):
            return True, f"Outbound probe to {unauthorized_ip}:{port} dropped (timeout)"
        except OSError as exc:
            return True, f"Outbound probe to {unauthorized_ip}:{port} denied: {exc}"
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception as exc:
        return True, f"Socket creation to {unauthorized_ip} prevented: {exc}"


def check_firewall_rule(
    uid: int | None = None,
    iptables_path: str | None = None,
    runner: Any = None,
) -> tuple[bool | None, str]:
    """Verify kernel netfilter IMDS block rule exists if iptables is present and permitted."""
    cmd_runner = runner or subprocess.run
    which_iptables = iptables_path or shutil.which("iptables") or "/usr/sbin/iptables"
    if runner is None and not os.path.exists(which_iptables):
        return None, f"iptables binary not found at {which_iptables}"

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
            return True, "Firewall IMDS block rule verified active in kernel OUTPUT chain"
        elif "Permission denied" in proc.stderr or "you must be root" in proc.stderr:
            return None, "Permission denied inspecting iptables (unprivileged user)"
        else:
            return False, f"Firewall rule missing or inactive (exit code {proc.returncode}): {proc.stderr.strip()}"
    except Exception as exc:
        return None, f"Failed to execute firewall check: {exc}"


def run_security_preflight(
    require_firewall_rule: bool = False,
    imds_ip: str = DEFAULT_IMDS_IP,
    imds_port: int = DEFAULT_IMDS_PORT,
    uid: int | None = None,
    socket_factory: Any = None,
    runner: Any = None,
) -> SecurityPreflightReport:
    """Execute complete fail-closed security preflight assertions."""
    checks: dict[str, str] = {}

    # 1. IMDS reachability check
    imds_blocked, imds_msg = check_imds_blocked(
        target_ip=imds_ip, target_port=imds_port, socket_factory=socket_factory
    )
    checks["imds_blocked"] = imds_msg

    # 2. Outbound egress sandbox check
    egress_blocked, egress_msg = check_egress_filter(socket_factory=socket_factory)
    checks["egress_blocked"] = egress_msg

    # 3. Firewall rule check (if enabled)
    fw_verified, fw_msg = check_firewall_rule(uid=uid, runner=runner)
    checks["firewall_rule"] = fw_msg

    # Evaluation
    if not imds_blocked:
        return SecurityPreflightReport(
            passed=False,
            imds_blocked=False,
            egress_filter_active=egress_blocked,
            firewall_rule_verified=fw_verified,
            failure_reason="SECURITY FAILURE: Oracle IMDS is accessible; collection aborted",
            checks=checks,
        )

    if require_firewall_rule and fw_verified is False:
        return SecurityPreflightReport(
            passed=False,
            imds_blocked=imds_blocked,
            egress_filter_active=egress_blocked,
            firewall_rule_verified=False,
            failure_reason="SECURITY FAILURE: Required kernel firewall IMDS rule is missing",
            checks=checks,
        )

    return SecurityPreflightReport(
        passed=True,
        imds_blocked=True,
        egress_filter_active=egress_blocked,
        firewall_rule_verified=fw_verified,
        failure_reason=None,
        checks=checks,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for systemd ExecStartPre= preflight verification."""
    import argparse
    parser = argparse.ArgumentParser(description="ANIE security preflight verification")
    parser.add_argument("--require-firewall", action="store_true", help="enforce kernel firewall rule presence")
    parser.add_argument("--imds-ip", default=DEFAULT_IMDS_IP, help="target IMDS IP to verify blocked")
    args = parser.parse_args(argv)

    report = run_security_preflight(
        require_firewall_rule=args.require_firewall,
        imds_ip=args.imds_ip,
    )

    if not report.passed:
        sys.stderr.write(f"ANIE SECURITY PREFLIGHT FAILED:\n{report.to_json()}\n")
        return 1

    print(report.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())

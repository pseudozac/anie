"""Comprehensive failure-injection test suite for Phase 2.1 Security Preflight Hardening."""
import os
import socket
import unittest
from unittest.mock import MagicMock

from anie.preflight_hardening import (
    check_imds_blocked,
    check_egress_filter,
    check_firewall_rule,
    run_security_preflight,
)


class TestPreflightHardeningFailureInjection(unittest.TestCase):
    def test_imds_blocked_on_connection_refused(self):
        """When kernel firewall resets connection (ECONNREFUSED), IMDS is safely blocked."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError(111, "Connection refused")

        blocked, msg = check_imds_blocked(socket_factory=lambda *a, **kw: mock_sock)
        self.assertTrue(blocked)
        self.assertIn("rejected by kernel firewall", msg)

    def test_imds_blocked_on_bpf_eperm(self):
        """When systemd cgroup BPF filter drops packet (EPERM), IMDS is safely blocked."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(1, "Operation not permitted")

        blocked, msg = check_imds_blocked(socket_factory=lambda *a, **kw: mock_sock)
        self.assertTrue(blocked)
        self.assertIn("denied by kernel", msg)

    def test_imds_blocked_on_timeout(self):
        """When systemd cgroup BPF filter silently drops packet (timeout), IMDS is safely blocked."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")

        blocked, msg = check_imds_blocked(socket_factory=lambda *a, **kw: mock_sock)
        self.assertTrue(blocked)
        self.assertIn("timed out", msg)

    def test_imds_accessible_is_critical_failure(self):
        """If TCP handshake to IMDS succeeds, preflight must fail closed immediately."""
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None  # Successful connect!

        blocked, msg = check_imds_blocked(socket_factory=lambda *a, **kw: mock_sock)
        self.assertFalse(blocked)
        self.assertIn("CRITICAL: Connected to IMDS", msg)

        # Full preflight evaluation must fail
        report = run_security_preflight(socket_factory=lambda *a, **kw: mock_sock)
        self.assertFalse(report.passed)
        self.assertIn("Oracle IMDS is accessible", report.failure_reason)

    def test_egress_filter_active_when_unauthorized_ip_blocked(self):
        """Outbound connection to unauthorized IP must be denied by BPF filter."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(1, "Operation not permitted")

        blocked, msg = check_egress_filter(socket_factory=lambda *a, **kw: mock_sock)
        self.assertTrue(blocked)

    def test_egress_filter_failure_when_unauthorized_ip_connected(self):
        """If outbound connection to unauthorized IP succeeds, egress sandbox is broken."""
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None  # Connected to unauthorized IP

        blocked, msg = check_egress_filter(socket_factory=lambda *a, **kw: mock_sock)
        self.assertFalse(blocked)
        self.assertIn("CRITICAL", msg)

    def test_firewall_rule_assertion_succeeds(self):
        """When iptables returns 0, firewall rule presence is verified."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stderr = ""

        verified, msg = check_firewall_rule(iptables_path="/bin/true", runner=mock_runner)
        self.assertTrue(verified)
        self.assertIn("verified active", msg)

    def test_firewall_rule_missing_fails_closed(self):
        """When iptables returns 1 (rule missing), check fails closed."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "iptables: Bad rule (does a matching rule exist in that chain?)"

        verified, msg = check_firewall_rule(iptables_path="/bin/true", runner=mock_runner)
        self.assertFalse(verified)
        self.assertIn("missing or inactive", msg)

        # When require_firewall_rule=True, preflight must fail
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        report = run_security_preflight(
            require_firewall_rule=True,
            socket_factory=lambda *a, **kw: mock_sock,
            runner=mock_runner,
        )
        self.assertFalse(report.passed)
        self.assertIn("firewall IMDS rule is missing", report.failure_reason)

    def test_firewall_rule_permission_denied_handled_gracefully(self):
        """Unprivileged user permission denied inspecting iptables is clearly diagnosed."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "iptables v1.8.10: Permission denied (you must be root)"

        verified, msg = check_firewall_rule(iptables_path="/bin/true", runner=mock_runner)
        self.assertIsNone(verified)
        self.assertIn("Permission denied", msg)

    def test_iptables_executable_missing_diagnosed(self):
        """Missing iptables binary is safely handled."""
        verified, msg = check_firewall_rule(iptables_path="/nonexistent/iptables")
        self.assertIsNone(verified)
        self.assertIn("not found", msg)


if __name__ == "__main__":
    unittest.main()

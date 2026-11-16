"""Comprehensive failure-injection test suite for Phase 2.1 Security Preflight Hardening."""
import os
import socket
import unittest
from unittest.mock import MagicMock

from anie.preflight_hardening import (
    DEFAULT_IMDS_IP,
    FirewallInspectionStatus,
    FirewallResult,
    NetworkProbeStatus,
    ProbeResult,
    check_egress_filter,
    check_firewall_rule,
    check_imds_blocked,
    check_systemd_network_policy,
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

    def test_egress_demonstrably_allowed_fails_preflight(self):
        """If outbound connection to unauthorized IP succeeds, preflight fails closed."""
        def mock_connect(addr):
            ip, port = addr
            if ip == DEFAULT_IMDS_IP:
                raise ConnectionRefusedError(111, "Connection refused")
            return None  # Egress allowed

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = mock_connect

        report = run_security_preflight(socket_factory=lambda *a, **kw: mock_sock)
        self.assertFalse(report.passed)
        self.assertTrue(report.imds_blocked)
        self.assertEqual(report.egress_status, NetworkProbeStatus.ALLOWED.value)
        self.assertIn("Unauthorized outbound egress is demonstrably permitted", report.failure_reason)

    def test_firewall_inaccessible_nft_classified_correctly(self):
        """Address family error inside systemd sandbox is classified as INACCESSIBLE, not MISSING."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "iptables: Failed to initialize nft: Address family not supported by protocol"

        res = check_firewall_rule(iptables_path="/bin/true", runner=mock_runner)
        self.assertIsNone(res.verified)
        self.assertEqual(res.status, FirewallInspectionStatus.INACCESSIBLE)
        self.assertIn("inaccessible inside unprivileged service sandbox", res.message)

    def test_firewall_inaccessible_fails_when_rule_required(self):
        """When require_firewall_rule=True, an inaccessible netfilter inspection fails preflight closed."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "iptables: Failed to initialize nft: Address family not supported by protocol"

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError(111, "Connection refused")

        report = run_security_preflight(
            require_firewall_rule=True,
            socket_factory=lambda *a, **kw: mock_sock,
            runner=mock_runner,
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.firewall_status, FirewallInspectionStatus.INACCESSIBLE.value)
        self.assertIn("netfilter inspection inaccessible", report.failure_reason)

    def test_firewall_inaccessible_passes_when_rule_advisory(self):
        """When require_firewall_rule=False, inaccessible inspection does not abort if probes are blocked."""
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "iptables: Failed to initialize nft: Address family not supported by protocol"

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError(111, "Connection refused")

        report = run_security_preflight(
            require_firewall_rule=False,
            socket_factory=lambda *a, **kw: mock_sock,
            runner=mock_runner,
        )
        self.assertTrue(report.passed)
        self.assertEqual(report.firewall_status, FirewallInspectionStatus.INACCESSIBLE.value)
        self.assertIsNone(report.firewall_rule_verified)

    def test_systemd_network_policy_inspection(self):
        """check_systemd_network_policy inspects systemctl output correctly."""
        # Active IPAddressDeny=any
        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = "IPAddressDeny=any\nIPAddressAllow=none\n"
        verified, msg = check_systemd_network_policy(runner=mock_runner)
        self.assertTrue(verified)
        self.assertIn("IPAddressDeny active", msg)

        # Inactive / empty IPAddressDeny
        mock_runner.return_value.stdout = "IPAddressDeny=\nIPAddressAllow=\n"
        verified, msg = check_systemd_network_policy(runner=mock_runner)
        self.assertFalse(verified)
        self.assertIn("does not enforce IPAddressDeny", msg)

        # systemctl command failure
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "Failed to get properties: Unit not found."
        verified, msg = check_systemd_network_policy(runner=mock_runner)
        self.assertIsNone(verified)
        self.assertIn("systemctl show failed", msg)

    def test_unverifiable_egress_satisfied_by_systemd_policy(self):
        """When egress probe times out, verified systemd policy satisfies preflight."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")

        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 0
        mock_runner.return_value.stdout = "IPAddressDeny=any\nIPAddressAllow=none\n"

        report = run_security_preflight(
            socket_factory=lambda *a, **kw: mock_sock,
            runner=mock_runner,
        )
        self.assertTrue(report.passed)
        self.assertTrue(report.egress_filter_active)
        self.assertTrue(report.systemd_policy_verified)
        self.assertEqual(report.egress_status, NetworkProbeStatus.UNVERIFIABLE.value)

    def test_unverifiable_egress_fails_without_systemd_policy(self):
        """When egress probe times out and systemd policy cannot be verified, preflight fails closed."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")

        mock_runner = MagicMock()
        mock_runner.return_value.returncode = 1
        mock_runner.return_value.stderr = "Unit not found"

        report = run_security_preflight(
            socket_factory=lambda *a, **kw: mock_sock,
            runner=mock_runner,
        )
        self.assertFalse(report.passed)
        self.assertFalse(report.egress_filter_active)
        self.assertIn("Egress isolation is UNVERIFIABLE", report.failure_reason)

    def test_probe_result_and_firewall_result_backward_compatibility(self):
        """ProbeResult and FirewallResult behave as standard 2-tuples while exposing rich status."""
        probe = ProbeResult(True, "kernel denied", NetworkProbeStatus.BLOCKED)
        self.assertIsInstance(probe, tuple)
        self.assertEqual(len(probe), 2)
        is_blocked, msg = probe
        self.assertTrue(is_blocked)
        self.assertEqual(msg, "kernel denied")
        self.assertEqual(probe.status, NetworkProbeStatus.BLOCKED)

        fw = FirewallResult(None, "inaccessible sandbox", FirewallInspectionStatus.INACCESSIBLE)
        self.assertIsInstance(fw, tuple)
        self.assertEqual(len(fw), 2)
        verified, fw_msg = fw
        self.assertIsNone(verified)
        self.assertEqual(fw_msg, "inaccessible sandbox")
        self.assertEqual(fw.status, FirewallInspectionStatus.INACCESSIBLE)


if __name__ == "__main__":
    unittest.main()

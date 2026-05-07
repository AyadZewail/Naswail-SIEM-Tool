# tests/test_windows_network_admin.py

import pytest
from unittest.mock import Mock

from plugins.incident_response.network_engines.WindowsNetworkAdmin import WindowsNetworkAdmin


@pytest.fixture
def mock_exec():
    return Mock()


@pytest.fixture
def admin(mock_exec):
    return WindowsNetworkAdmin(executor=mock_exec)


# ─────────────────────────────
# IP BLOCK / UNBLOCK
# ─────────────────────────────

def test_block_ip_sends_correct_command(admin, mock_exec):
    admin.block_ip("10.10.10.10")

    args = mock_exec.call_args[0][0]
    cmd = args[2]

    assert "10.10.10.10" in cmd
    assert "New-NetFirewallRule" in cmd


def test_unblock_ip_sends_correct_command(admin, mock_exec):
    admin.unblock_ip("10.10.10.10")

    cmd = mock_exec.call_args[0][0][2]

    assert "Remove-NetFirewallRule" in cmd
    assert "10.10.10.10" in cmd


# ─────────────────────────────
# PORT BLOCK / UNBLOCK
# ─────────────────────────────

def test_block_port_sends_correct_command(admin, mock_exec):
    admin.block_port(443)

    cmd = mock_exec.call_args[0][0][2]

    assert "443" in cmd
    assert "LocalPort" in cmd


def test_unblock_port_sends_correct_command(admin, mock_exec):
    admin.unblock_port(443)

    cmd = mock_exec.call_args[0][0][2]

    assert "443" in cmd
    assert "Remove-NetFirewallRule" in cmd


# ─────────────────────────────
# RATE LIMIT
# ─────────────────────────────

def test_limit_rate_scales_correctly(admin, mock_exec):
    admin.limit_rate("10.10.10.10", 5)

    cmd = mock_exec.call_args[0][0][2]

    assert "10.10.10.10" in cmd
    assert "ThrottleRateActionBitsPerSecond" in cmd


def test_reset_rate_limit_includes_ip(admin, mock_exec):
    admin.reset_rate_limit("10.10.10.10")

    cmd = mock_exec.call_args[0][0][2]

    assert "Throttle_10.10.10.10" in cmd


# ─────────────────────────────
# EXECUTOR STRUCTURE SAFETY
# ─────────────────────────────

def test_executor_called_with_powershell(admin, mock_exec):
    admin.block_ip("1.2.3.4")

    args = mock_exec.call_args[0][0]

    assert args[0] == "powershell"
    assert args[1] == "-Command"
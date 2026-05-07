import pytest
from unittest.mock import Mock

from plugins.incident_response.network_engines.LinuxNetworkAdmin import LinuxNetworkAdmin


# =====================================================
# 1. Command Builder Tests (pure unit tests)
# =====================================================

def test_build_block_ip():
    admin = LinuxNetworkAdmin()
    cmd = admin._build_block_ip("1.2.3.4")

    assert cmd == "iptables -A INPUT -s 1.2.3.4 -j DROP"


def test_build_unblock_ip():
    admin = LinuxNetworkAdmin()
    cmd = admin._build_unblock_ip("1.2.3.4")

    assert cmd == "iptables -D INPUT -s 1.2.3.4 -j DROP"


def test_build_block_port():
    admin = LinuxNetworkAdmin()
    cmd = admin._build_block_port(80)

    assert cmd == "iptables -A INPUT -p tcp --dport 80 -j DROP"


def test_build_unblock_port():
    admin = LinuxNetworkAdmin()
    cmd = admin._build_unblock_port(443)

    assert cmd == "iptables -D INPUT -p tcp --dport 443 -j DROP"


def test_build_limit_rate():
    admin = LinuxNetworkAdmin()
    cmd = admin._build_limit_rate("1.2.3.4", 100)

    assert isinstance(cmd, list)
    assert "iptables" in cmd
    assert "1.2.3.4" in cmd
    assert "100/sec" in cmd


def test_build_reset_rate_limit():
    admin = LinuxNetworkAdmin()
    cmd = admin._build_reset_rate_limit("1.2.3.4")

    assert isinstance(cmd, list)
    assert "-D" in cmd
    assert "1.2.3.4" in cmd


# =====================================================
# 2. Execution Tests (mock subprocess via injected executor)
# =====================================================

def test_block_ip_executes_command():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.block_ip("1.2.3.4")

    mock_exec.assert_called_once()


def test_unblock_ip_executes_command():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.unblock_ip("1.2.3.4")

    mock_exec.assert_called_once()


def test_block_port_executes_command():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.block_port(22)

    mock_exec.assert_called_once()


def test_limit_rate_executes_command():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.limit_rate("1.2.3.4", 50)

    mock_exec.assert_called_once()


def test_reset_rate_limit_executes_command():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.reset_rate_limit("1.2.3.4")

    mock_exec.assert_called_once()


# =====================================================
# 3. Behavioral / correctness tests
# =====================================================

def test_executor_receives_correct_ip():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.block_ip("10.10.10.10")

    args = mock_exec.call_args[0][0]
    command_string = args[3]

    assert "10.10.10.10" in command_string
    assert "iptables" in command_string
    assert "-A INPUT" in command_string


def test_executor_receives_rate_limit_structure():
    mock_exec = Mock()
    admin = LinuxNetworkAdmin(executor=mock_exec)

    admin.limit_rate("1.2.3.4", 25)

    args = mock_exec.call_args[0][0]

    assert isinstance(args, list)
    assert "--hashlimit" in " ".join(args)
    assert "1.2.3.4" in args
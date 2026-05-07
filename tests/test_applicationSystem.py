import pytest
import psutil

from plugins.home.ApplicationSystem import BasicApplicationSystem


@pytest.fixture(scope="module")
def app_system():
    return BasicApplicationSystem()


@pytest.fixture(scope="module")
def app_data(app_system):
    result = app_system.get_active_applications()

    if not result:
        pytest.skip("no active applications found")

    return result


# ── basic behavior ────────────────────────────────────

def test_returns_list(app_data):
    assert isinstance(app_data, list)


def test_entries_are_dicts(app_data):
    assert all(isinstance(entry, dict) for entry in app_data)


def test_required_keys_exist(app_data):
    required_keys = {
        "Application",
        "IP",
        "Port",
        "Status",
        "CPU",
        "Memory",
    }

    for entry in app_data:
        assert required_keys.issubset(entry.keys())


# ── value types ───────────────────────────────────────

def test_application_name_is_string(app_data):
    assert all(isinstance(entry["Application"], str) for entry in app_data)


def test_ip_is_string(app_data):
    assert all(isinstance(entry["IP"], str) for entry in app_data)


def test_port_is_int(app_data):
    assert all(isinstance(entry["Port"], int) for entry in app_data)


def test_status_is_string(app_data):
    assert all(isinstance(entry["Status"], str) for entry in app_data)


def test_cpu_is_numeric(app_data):
    assert all(isinstance(entry["CPU"], (int, float)) for entry in app_data)


def test_memory_is_numeric(app_data):
    assert all(isinstance(entry["Memory"], (int, float)) for entry in app_data)


# ── edge cases ────────────────────────────────────────

def test_no_crash_when_called_multiple_times(app_system):
    result1 = app_system.get_active_applications()
    result2 = app_system.get_active_applications()

    assert isinstance(result1, list)
    assert isinstance(result2, list)


def test_ports_are_valid_range(app_data):
    for entry in app_data:
        assert 0 <= entry["Port"] <= 65535


def test_ip_not_empty(app_data):
    for entry in app_data:
        assert entry["IP"] != ""


# ── resilience tests ──────────────────────────────────

def test_handles_access_denied(monkeypatch, app_system):
    def fake_process_iter(*args, **kwargs):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "process_iter", fake_process_iter)

    with pytest.raises(psutil.AccessDenied):
        app_system.get_active_applications()
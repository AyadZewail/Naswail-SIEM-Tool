import os
import pytest
from scapy.all import IP, TCP
from collections import defaultdict

from plugins.home.AnomalyDetector import SnortAnomalyDetector


# portable paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RULES_PATH = "C:\\Snort\\rules\\custom.rules"
LOG_PATH = "C:\\Snort\\log\\alert.ids"


# ── helper fixtures ───────────────────────────────────

@pytest.fixture
def rules_file():
    content = (
        'alert tcp any any -> any any '
        '(msg:"SQL Injection"; sid:1000001; rev:1;)\n'
        'alert tcp any any -> any any '
        '(msg:"Port Scan"; sid:1000002; rev:1;)\n'
    )

    with open(RULES_PATH, "w") as f:
        f.write(content)

    yield RULES_PATH

    # if os.path.exists(RULES_PATH):
    #     os.remove(RULES_PATH)


@pytest.fixture
def log_file():
    with open(LOG_PATH, "w") as f:
        f.write("")

    yield LOG_PATH

    # if os.path.exists(LOG_PATH):
    #     os.remove(LOG_PATH)


@pytest.fixture
def detector(monkeypatch, rules_file, log_file):
    # prevent actual monitoring thread from starting
    class DummyThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(
        "plugins.home.AnomalyDetector.Thread",
        DummyThread
    )

    return SnortAnomalyDetector(rules_file, log_file)


# ── rule loading ──────────────────────────────────────

def test_rules_loaded(detector):
    assert len(detector.snort_rules) == 2


def test_sid_mapping(detector):
    assert detector.snort_rules[1000001] == "SQL Injection"
    assert detector.snort_rules[1000002] == "Port Scan"


# ── check() behavior ──────────────────────────────────

def test_check_returns_none_when_no_alert(detector):
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP()

    result = detector.check(pkt)

    assert result is None


def test_check_returns_attack_name(detector):
    detector.snort_alerts[("1.1.1.1", "2.2.2.2")].append(
        "SQL Injection"
    )

    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP()

    result = detector.check(pkt)

    assert result == "SQL Injection"


def test_check_returns_first_alert(detector):
    detector.snort_alerts[("1.1.1.1", "2.2.2.2")].append(
        "SQL Injection"
    )

    detector.snort_alerts[("1.1.1.1", "2.2.2.2")].append(
        "Port Scan"
    )

    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP()

    result = detector.check(pkt)

    assert result == "SQL Injection"


# ── packet edge cases ─────────────────────────────────

def test_check_non_ip_packet_returns_none(detector):
    pkt = TCP()

    result = detector.check(pkt)

    assert result is None


def test_check_none_packet_returns_none(detector):
    result = detector.check(None)

    assert result is None


# ── malformed rules ───────────────────────────────────

def test_empty_rules_file(monkeypatch, log_file):
    empty_rules = os.path.join(BASE_DIR, "empty.rules")

    with open(empty_rules, "w") as f:
        f.write("")

    class DummyThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(
        "plugins.home.AnomalyDetector.Thread",
        DummyThread
    )

    detector = SnortAnomalyDetector(empty_rules, log_file)

    assert detector.snort_rules == {}

    os.remove(empty_rules)


# ── internal alert storage ────────────────────────────

def test_alerts_structure(detector):
    detector.snort_alerts[("10.0.0.1", "8.8.8.8")].append(
        "Port Scan"
    )

    assert isinstance(detector.snort_alerts, defaultdict)

    assert detector.snort_alerts[
        ("10.0.0.1", "8.8.8.8")
    ] == ["Port Scan"]


# ── file errors ───────────────────────────────────────

def test_missing_rules_file_raises(monkeypatch, log_file):
    class DummyThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(
        "plugins.home.AnomalyDetector.Thread",
        DummyThread
    )

    with pytest.raises(FileNotFoundError):
        SnortAnomalyDetector(
            "does_not_exist.rules",
            log_file
        )
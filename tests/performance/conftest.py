"""Performance-test fixtures: headless HomeController, PCAP generation, QApplication."""

from __future__ import annotations

import sys
from collections import deque
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from controllers.Home_Controller import HomeController
from plugins.home.ErrorChecker import BasicErrorChecker
from plugins.home.PacketFilter import BasicPacketFilter
from plugins.home.ProtocolExtractor import BasicProtocolExtractor

from tests.performance.helpers import make_synthetic_packets, write_pcap

GENERATED_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "generated"

pytestmark = pytest.mark.performance


def pytest_collection_modifyitems(config, items):
    """Hard pytest timeouts derived from PERF_DURATION_SECONDS (not unbounded runs)."""
    import os

    duration = int(os.environ.get("PERF_DURATION_SECONDS", "60"))
    default_cap = int(os.environ.get("PERF_TEST_TIMEOUT", str(duration + 15)))
    micro = int(os.environ.get("PERF_MICROBENCH_SECONDS", "5")) + 10
    soak = int(os.environ.get("PERF_SOAK_SECONDS", "60")) + 30

    for item in items:
        nodeid = item.nodeid
        if "/performance/" not in nodeid.replace("\\", "/"):
            continue
        if "soak" in item.keywords:
            item.add_marker(pytest.mark.timeout(soak))
        elif "cpu_under_load" in nodeid:
            item.add_marker(pytest.mark.timeout(default_cap))
        elif "micro" in nodeid or "microbench" in nodeid:
            item.add_marker(pytest.mark.timeout(micro))
        elif "ingest" in nodeid or "queue" in nodeid or "timer_accurate" in nodeid:
            item.add_marker(pytest.mark.timeout(30))
        elif "max_pipeline" in nodeid:
            item.add_marker(pytest.mark.timeout(45))


@pytest.fixture(autouse=True)
def _block_scapy_network():
    """Prevent Scapy ARP/broadcast during checksum/raw (avoids multi-second stalls)."""
    with patch("scapy.sendrecv.srp1", return_value=None):
        yield


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


def _default_packet_stats() -> dict:
    return {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "other": 0,
        "http": 0,
        "https": 0,
        "dns": 0,
        "dhcp": 0,
        "ftp": 0,
        "telnet": 0,
    }


def _mock_table_item(*_args, **_kwargs) -> MagicMock:
    item = MagicMock()
    item.setBackground = MagicMock()
    item.setForeground = MagicMock()
    return item


def _build_mock_ui() -> MagicMock:
    ui = MagicMock()
    ui.tableWidget.rowCount.return_value = 0
    ui.tableWidget_4.rowCount.return_value = 0
    ui.tableWidget_3 = MagicMock()
    ui.listView_3 = MagicMock()
    ui.listView_4 = MagicMock()
    ui.listView_5 = MagicMock()
    ui.label_6 = MagicMock()
    ui.graphicsView_2 = MagicMock()
    return ui


@pytest.fixture
def headless_home_controller(qapp):
    """
    HomeController with real home plugins, mocked Snort/UI/background threads.
    Uses production-like bounded deques for queues.
    """
    corrupted: list = []
    network_log: list = []
    anomalies: list = []
    packet_stats = _default_packet_stats()

    mock_anomaly = MagicMock()
    mock_anomaly.check.return_value = None

    with (
        patch("controllers.Home_Controller.PacketSnifferThread.start"),
        patch("controllers.Home_Controller.HomeController.draw_gauge"),
        patch("controllers.Home_Controller.threading.Thread"),
        patch("controllers.Home_Controller.threading.Timer"),
        patch("controllers.Home_Controller.QTableWidgetItem", side_effect=_mock_table_item),
        patch("controllers.Home_Controller.QColor", MagicMock),
    ):
        protocol_extractor = BasicProtocolExtractor()
        controller = HomeController(
            ui=_build_mock_ui(),
            packet_decoder=MagicMock(),
            packet_details=MagicMock(),
            protocol_extractor=protocol_extractor,
            error_checker=BasicErrorChecker(
                corrupted_packet_list=corrupted,
                logger=network_log,
            ),
            packet_statistics=MagicMock(),
            anomaly_detector=mock_anomaly,
            anomaly_detector_2=MagicMock(),
            packet_filter=BasicPacketFilter(protocol_extractor=protocol_extractor),
            corrupted_packet_list=corrupted,
            network_log=network_log,
            anomalies=anomalies,
            blacklist=[],
            blocked_ports=[],
            list_of_activity=[],
            qued_packets=deque(maxlen=15000),
            packets=deque(maxlen=15000),
            time_series={},
            sen_info=MagicMock(),
            sensor_system=MagicMock(),
            application_system=MagicMock(),
            packet_exporter=MagicMock(),
            scene=MagicMock(),
            totINpacekts=0,
            totOUTpacekts=0,
            packetStats=packet_stats,
            bandwidthData=[],
        )
        controller.capture = -1
        controller.packetInput = 0
        controller.filterapplied = False
        controller.senFlag = -1
        controller.singleSenFlag = -1
        controller.application_filter_flag = False
        controller.get_row_color = lambda _packet: "transparent"
        yield controller


@pytest.fixture
def synthetic_packets(perf_thresholds):
    count = perf_thresholds["packet_count_small"]
    return make_synthetic_packets(count)


@pytest.fixture
def synthetic_packets_small(perf_thresholds):
    """Small pool for timed micro-benchmarks (cycles in a loop)."""
    return make_synthetic_packets(min(100, perf_thresholds["packet_count_drain"]))


@pytest.fixture
def synthetic_packets_medium(perf_thresholds):
    return make_synthetic_packets(perf_thresholds["packet_count_medium"])


@pytest.fixture
def synthetic_packets_drain(perf_thresholds):
    """Small set for process_packet drain benchmarks (Qt table path is costly)."""
    return make_synthetic_packets(perf_thresholds["packet_count_drain"])


@pytest.fixture
def synthetic_packets_large(perf_thresholds):
    return make_synthetic_packets(perf_thresholds["packet_count_large"])


@pytest.fixture(scope="module")
def generated_pcap_small():
    path = GENERATED_DIR / "synthetic_1k.pcap"
    if not path.exists() or path.stat().st_size < 100:
        write_pcap(path, make_synthetic_packets(1000))
    return path


@pytest.fixture(scope="module")
def generated_pcap_medium():
    path = GENERATED_DIR / "synthetic_2k.pcap"
    if not path.exists():
        write_pcap(path, make_synthetic_packets(2000))
    return path

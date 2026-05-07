import os
import pytest
from scapy.utils import rdpcap

from plugins.home.SensorSystem import BasicSensorSystem


# portable relative path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BASE_DIR, "testingPackets.pcap")


@pytest.fixture
def sensor_system():
    return BasicSensorSystem()


@pytest.fixture
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("pcap file not found")

    pkts = rdpcap(PCAP_PATH)

    if len(pkts) == 0:
        pytest.skip("pcap contains no packets")

    return pkts


@pytest.fixture
def ethernet_packet(packets):
    pkt = next((p for p in packets if p.haslayer("Ethernet")), None)

    if pkt is None:
        pytest.skip("no Ethernet packets found")

    return pkt


# ── add sensor ────────────────────────────────────────

def test_add_sensor(sensor_system):
    sensor_system.add_sensor("Sensor1", "aa:bb:cc:dd:ee:ff")

    sensors = sensor_system.list_sensors()

    assert "Sensor1" in sensors
    assert sensors["Sensor1"] == "aa:bb:cc:dd:ee:ff"


# ── remove sensor ─────────────────────────────────────

def test_remove_sensor(sensor_system):
    sensor_system.add_sensor("Sensor1", "aa:bb:cc:dd:ee:ff")

    sensor_system.remove_sensor("Sensor1")

    sensors = sensor_system.list_sensors()

    assert "Sensor1" not in sensors


def test_remove_nonexistent_sensor(sensor_system):
    sensor_system.remove_sensor("DoesNotExist")

    assert sensor_system.list_sensors() == {}


# ── list sensors ──────────────────────────────────────

def test_list_sensors_returns_copy(sensor_system):
    sensor_system.add_sensor("Sensor1", "aa:bb:cc:dd:ee:ff")

    sensors = sensor_system.list_sensors()

    sensors["Fake"] = "11:11:11:11:11:11"

    # original should not change
    assert "Fake" not in sensor_system.list_sensors()


# ── reset ─────────────────────────────────────────────

def test_reset_clears_sensors(sensor_system):
    sensor_system.add_sensor("Sensor1", "aa:bb:cc:dd:ee:ff")
    sensor_system.add_sensor("Sensor2", "11:22:33:44:55:66")

    sensor_system.reset()

    assert sensor_system.list_sensors() == {}


# ── sensor packet detection ───────────────────────────

def test_is_sensor_packet_true(sensor_system, ethernet_packet):
    mac = ethernet_packet["Ethernet"].src

    sensor_system.add_sensor("Sensor1", mac)

    result = sensor_system.is_sensor_packet(ethernet_packet)

    assert result is True


def test_is_sensor_packet_false(sensor_system, ethernet_packet):
    sensor_system.add_sensor("Sensor1", "00:00:00:00:00:00")

    result = sensor_system.is_sensor_packet(ethernet_packet)

    assert result is False


def test_is_sensor_packet_non_ethernet(sensor_system):
    class FakePacket:
        def haslayer(self, layer):
            return False

    result = sensor_system.is_sensor_packet(FakePacket())

    assert result is False


# ── sensor name lookup ────────────────────────────────

def test_get_sensor_name(sensor_system):
    sensor_system.add_sensor("Camera1", "aa:bb:cc:dd:ee:ff")

    result = sensor_system.get_sensor_name("aa:bb:cc:dd:ee:ff")

    assert result == "Camera1"


def test_get_unknown_sensor_name(sensor_system):
    result = sensor_system.get_sensor_name("11:22:33:44:55:66")

    assert result == "Unknown"


# ── sensor mac lookup ─────────────────────────────────

def test_get_sensor_mac(sensor_system):
    sensor_system.add_sensor("Camera1", "aa:bb:cc:dd:ee:ff")

    result = sensor_system.get_sensor_mac("Camera1")

    assert result == "aa:bb:cc:dd:ee:ff"


def test_get_unknown_sensor_mac(sensor_system):
    result = sensor_system.get_sensor_mac("DoesNotExist")

    assert result == "Unknown"
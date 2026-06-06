import pytest
import os
import sys
from unittest.mock import MagicMock, patch
from scapy.all import rdpcap
from PyQt6.QtWidgets import QApplication

from controllers.Home_Controller import HomeController

# PyQt6 will instantly crash the Python process with exit code 1 if you try to 
# instantiate QColor or QTableWidgetItem without a QApplication running. 
# This fixture ensures one exists before the test runs!
@pytest.fixture(scope="module", autouse=True)
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app

@patch('controllers.Home_Controller.PacketSnifferThread.start')
@patch('controllers.Home_Controller.HomeController.draw_gauge')
@patch('controllers.Home_Controller.threading.Thread')
@patch('controllers.Home_Controller.threading.Timer')
def test_home_orchestration_dataflow(mock_timer, mock_thread, mock_draw_gauge, mock_sniffer_start):
    # ==========================================================
    # ARRANGE
    # ==========================================================
    
    mock_error_checker = MagicMock()
    mock_error_checker.is_corrupted.return_value = False
    
    mock_protocol_extractor = MagicMock()
    mock_protocol_extractor.extract_protocol.return_value = "tcp"
    
    mock_anomaly_detector = MagicMock()
    mock_anomaly_detector.check.return_value = None
    
    test_packet_stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}
    
    controller = HomeController(
        ui=MagicMock(),
        packet_decoder=MagicMock(),
        packet_details=MagicMock(),
        protocol_extractor=mock_protocol_extractor,
        error_checker=mock_error_checker,
        packet_statistics=MagicMock(),
        anomaly_detector=mock_anomaly_detector,
        anomaly_detector_2=MagicMock(),
        packet_filter=MagicMock(),
        corrupted_packet_list=[],
        network_log=[],
        anomalies=[],
        blacklist=[],
        blocked_ports=[],
        list_of_activity=[],
        qued_packets=[],
        packets=[],
        time_series={},
        sen_info=MagicMock(),
        sensor_system=MagicMock(),
        application_system=MagicMock(),
        packet_exporter=MagicMock(),
        scene=MagicMock(),
        totINpacekts=0,
        totOUTpacekts=0,
        packetStats=test_packet_stats,
        bandwidthData=MagicMock()
    )
    
    # Load the first packet from the real PCAP file as requested
    pcap_path = os.path.join(os.path.dirname(__file__), "..", "packet_file6.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip(f"PCAP file not found at {pcap_path}")
        
    # Read just the very first packet
    real_packet = rdpcap(pcap_path, count=1)[0]
    
    # Inject it into the queue
    controller.qued_packets = [real_packet]
    controller.process_packet_index = 0
    controller.packetInput = 0
    controller.flag_process_packet = False
    
    # ==========================================================
    # ACT
    # ==========================================================
    
    controller.process_packet()
    
    # ==========================================================
    # ASSERT
    # ==========================================================
    
    mock_error_checker.is_corrupted.assert_called_once_with(real_packet)
    mock_protocol_extractor.extract_protocol.assert_called_with(real_packet)
    mock_anomaly_detector.check.assert_called_once_with(real_packet)
    
    assert test_packet_stats["total"] == 1

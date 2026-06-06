import pandas as pd
from unittest.mock import patch, Mock

from plugins.home.AEAnomalyDetector import CloudAnomalyDetector


class TestCloudAnomalyDetectorIntegration:

    def test_happy_path_enrichment_pipeline(self):
        """
        Verifies:
        - ML and DL detector outputs are combined
        - Normal flows are filtered out
        - Flow indices map correctly into NFStreamer rows
        - Enrichment adds IPs, ports, and protocol
        - Duplicate flows are removed
        """

        ml_response = Mock()
        ml_response.json.return_value = {
            "results":
                "Flow 1000: Normal\n"
                "Flow 1001: DDoS"
        }

        dl_response = Mock()
        dl_response.json.return_value = {
            "results":
                "Anomaly at flow idx 1001\n"
                "Anomaly at flow idx 1002"
        }

        fake_df = pd.DataFrame([
            {
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "DNS"
            },
            {
                "src_ip": "10.0.0.2",
                "src_port": 5678,
                "dst_ip": "1.1.1.1",
                "dst_port": 80,
                "protocol": "TCP"
            },
            {
                "src_ip": "10.0.0.3",
                "src_port": 9999,
                "dst_ip": "4.4.4.4",
                "dst_port": 443,
                "protocol": "TCP"
            }
        ])

        mock_streamer = Mock()
        mock_streamer.to_pandas.return_value = fake_df

        with patch("requests.post") as mock_post, \
             patch("plugins.home.AEAnomalyDetector.NFStreamer", return_value=mock_streamer), \
             patch("builtins.open", create=True) as mock_file:

            mock_post.side_effect = [
                ml_response,
                dl_response
            ]

            mock_file.return_value.__enter__.return_value.read.return_value = b"fake_pcap"

            detector = CloudAnomalyDetector("http://fake-server")
            results = detector.check("dummy.pcap")

        assert len(results) == 2

        assert results[0]["flow"] == 1001
        assert results[0]["src_ip"] == "10.0.0.1"
        assert results[0]["dst_ip"] == "8.8.8.8"
        assert results[0]["src_port"] == 1234
        assert results[0]["dst_port"] == 53
        assert results[0]["protocol"] == "DNS"

        assert results[1]["flow"] == 1002
        assert results[1]["src_ip"] == "10.0.0.2"
        assert results[1]["dst_ip"] == "1.1.1.1"
        assert results[1]["src_port"] == 5678
        assert results[1]["dst_port"] == 80
        assert results[1]["protocol"] == "TCP"

    def test_flow_index_mapping_offset(self):
        """
        Verifies the critical mapping logic:

        flow_idx = flow - first_idx

        Example:
            flow 1948 -> df row 0
            flow 1950 -> df row 2
        """

        ml_response = Mock()
        ml_response.json.return_value = {
            "results": ""
        }

        dl_response = Mock()
        dl_response.json.return_value = {
            "results":
                "Anomaly at flow idx 1948\n"
                "Anomaly at flow idx 1950"
        }

        fake_df = pd.DataFrame([
            {
                "src_ip": "192.168.1.1",
                "src_port": 1000,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "DNS"
            },
            {
                "src_ip": "192.168.1.2",
                "src_port": 2000,
                "dst_ip": "8.8.4.4",
                "dst_port": 53,
                "protocol": "DNS"
            },
            {
                "src_ip": "192.168.1.3",
                "src_port": 3000,
                "dst_ip": "1.1.1.1",
                "dst_port": 443,
                "protocol": "TCP"
            }
        ])

        mock_streamer = Mock()
        mock_streamer.to_pandas.return_value = fake_df

        with patch("requests.post") as mock_post, \
             patch("plugins.home.AEAnomalyDetector.NFStreamer", return_value=mock_streamer), \
             patch("builtins.open", create=True) as mock_file:

            mock_post.side_effect = [
                ml_response,
                dl_response
            ]

            mock_file.return_value.__enter__.return_value.read.return_value = b"fake_pcap"

            detector = CloudAnomalyDetector("http://fake-server")
            results = detector.check("dummy.pcap")

        flow_1948 = next(x for x in results if x["flow"] == 1948)
        flow_1950 = next(x for x in results if x["flow"] == 1950)

        assert flow_1948["src_ip"] == "192.168.1.1"
        assert flow_1948["src_port"] == 1000

        assert flow_1950["src_ip"] == "192.168.1.3"
        assert flow_1950["src_port"] == 3000

    def test_missing_dataframe_row_adds_error_field(self):
        """
        Verifies that anomalies whose mapped flow
        is not found in the dataframe are not lost.
        """

        ml_response = Mock()
        ml_response.json.return_value = {
            "results": ""
        }

        dl_response = Mock()
        dl_response.json.return_value = {
            "results":
                "Anomaly at flow idx 1000\n"
                "Anomaly at flow idx 1005"
        }

        fake_df = pd.DataFrame([
            {
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "protocol": "DNS"
            }
        ])

        mock_streamer = Mock()
        mock_streamer.to_pandas.return_value = fake_df

        with patch("requests.post") as mock_post, \
             patch("plugins.home.AEAnomalyDetector.NFStreamer", return_value=mock_streamer), \
             patch("builtins.open", create=True) as mock_file:

            mock_post.side_effect = [
                ml_response,
                dl_response
            ]

            mock_file.return_value.__enter__.return_value.read.return_value = b"fake_pcap"

            detector = CloudAnomalyDetector("http://fake-server")
            results = detector.check("dummy.pcap")

        missing_flow = next(x for x in results if x["flow"] == 1005)

        assert missing_flow["error"] == "flow_not_found_in_dataframe"
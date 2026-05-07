import pytest
import os
from scapy.utils import rdpcap
from collections import defaultdict

from plugins.tools.TrafficPredictor import BasicRegressionPredictor


PCAP_PATH = os.path.join(
    os.path.dirname(__file__),
    "testingPackets.pcap"
)


# -------------------------
# Fixture: load PCAP once
# -------------------------

@pytest.fixture(scope="module")
def packets():
    if not os.path.exists(PCAP_PATH):
        pytest.skip("PCAP file not found")

    return rdpcap(PCAP_PATH)


# -------------------------
# Convert PCAP → time series
# (packets per second)
# -------------------------

@pytest.fixture(scope="module")
def time_series(packets):
    ts = defaultdict(int)

    for pkt in packets:
        if hasattr(pkt, "time"):
            sec = int(float(pkt.time))
            ts[sec] += 1

    # ensure enough data for training (>10 points requirement)
    if len(ts) <= 10:
        pytest.skip("Not enough time-series data in PCAP")

    return dict(sorted(ts.items()))


# -------------------------
# Tests
# -------------------------

def test_training_from_pcap(time_series):
    predictor = BasicRegressionPredictor()

    predictor.train(time_series=time_series)

    assert predictor.is_trained is True


def test_metrics_generated_from_pcap(time_series):
    predictor = BasicRegressionPredictor()

    predictor.train(time_series=time_series)

    metrics = predictor.get_metrics()

    assert isinstance(metrics, dict)

    if "r2" in metrics:
        assert isinstance(metrics["r2"], float)


def test_predict_after_pcap_training(time_series):
    predictor = BasicRegressionPredictor()

    predictor.train(time_series=time_series)

    result = predictor.predict(
        hours_ahead=1,
        current_packet_count=0,
        intervals=[1, 2, 3]
    )

    assert isinstance(result, list)
    assert len(result) == 4
    assert all(isinstance(x, (int, float)) for x in result)
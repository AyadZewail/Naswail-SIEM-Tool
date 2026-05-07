from collections import deque

from plugins.home.PacketDecoder import BasicPacketDecoder
from plugins.home.PacketDetails import BasicPacketDetails
from plugins.home.ProtocolExtractor import BasicProtocolExtractor
from plugins.home.ErrorChecker import BasicErrorChecker
from plugins.home.PacketStatistics import BasicPacketStatistics
from plugins.home.AnomalyDetector import SnortAnomalyDetector
from plugins.home.AEAnomalyDetector import CloudAnomalyDetector
from plugins.home.PacketFilter import BasicPacketFilter
from plugins.home.SensorSystem import BasicSensorSystem
from plugins.home.ApplicationSystem import BasicApplicationSystem
from plugins.home.PacketsExporter import BasicPacketExporter

from plugins.incident_response.scrapers import BingSearcher, YouTubeSearcher, DeepSeekSearcher
from plugins.incident_response.IntelPreprocessor import SimpleIntelPreprocessor
from plugins.incident_response.DeepSeekPreprocessor import LLMIntelPreprocessor
from plugins.incident_response.ThreatIntelligence import ThreatIntelligence
from plugins.incident_response.AutopilotEngine import KaggleLLMEngine as Autopilot
from plugins.incident_response.network_engines import WindowsNetworkAdmin as AdminImpl

from plugins.tools.NetworkActivityAnalyzer import NetworkActivityAnalyzer
from plugins.tools.TrafficPredictor import BasicRegressionPredictor

from plugins.analysis.GeoMapper import MaxMindGeoMapper
import geoip2.database
import requests
import subprocess


class ServiceContainer:
    def __init__(self):
        self._singletons = {}

    def register_singleton(self, key, instance):
        self._singletons[key] = instance

    def resolve(self, key):
        if key not in self._singletons:
            raise ValueError(f"Service not registered: {key}")
        return self._singletons[key]


# Global container instance
container = ServiceContainer()

# ===== Shared instances from old PacketSystem =====
container.register_singleton("protocol_extractor", BasicProtocolExtractor())
container.register_singleton("corrupted_packet_list", [])
container.register_singleton("network_log", [])
container.register_singleton("anomalies", [])
container.register_singleton("blacklist", [])
container.register_singleton("blocked_ports", [])
container.register_singleton("list_of_activity", [])
container.register_singleton("qued_packets", deque(maxlen=15000))
container.register_singleton("packets", deque(maxlen=15000))
container.register_singleton("time_series", {})
container.register_singleton("sen_info", [])
container.register_singleton("packet_stats", {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0,"http":0,"https":0,"dns":0,"dhcp":0,"ftp":0,"telnet":0})
container.register_singleton("total_inside_packets", 0)
container.register_singleton("total_outside_packets", 0)
container.register_singleton("bandwidth_data", [])

# ===== Home related =====
container.register_singleton("packet_decoder", BasicPacketDecoder())
container.register_singleton("packet_details", BasicPacketDetails())
container.register_singleton("packet_statistics", BasicPacketStatistics())

container.register_singleton(
    "error_checker",
    BasicErrorChecker(
        corrupted_packet_list=container.resolve("corrupted_packet_list"),
        logger=container.resolve("network_log")
    )
)

container.register_singleton(
    "anomaly_detector",
    SnortAnomalyDetector(
        rules_file="C:\\Snort\\rules\\custom.rules",
        log_file="C:\\Snort\\log\\alert.ids"
    )
)

container.register_singleton(
    "anomaly_detector_2",
    CloudAnomalyDetector(
        "http://101.46.64.170:8080"
    )
)

container.register_singleton(
    "packet_filter",
    BasicPacketFilter(
        protocol_extractor=container.resolve("protocol_extractor")
    )
)

container.register_singleton("packet_exporter", BasicPacketExporter())

container.register_singleton("sensor_system", BasicSensorSystem())

container.register_singleton("application_system", BasicApplicationSystem())

# ===== Threat Intelligence related =====
container.register_singleton("bing_searcher", BingSearcher())
container.register_singleton("yt_searcher", YouTubeSearcher())
# container.register_singleton("deepseek_searcher", DeepSeekSearcher("https://api-ap-southeast-1.modelarts-maas.com/v1/chat/completions", 
#                                                                    "fce64bd1-948b-4b4d-b998-729fc4c12db8_8947A6A7229BA554F81256D428EB618303FE2E35A63A8C29FF0F98F7EAAB85CA",
#                                                                    "deepseek-v3.1"))
container.register_singleton("simple_intel_preprocessor", SimpleIntelPreprocessor())
# container.register_singleton("deepseek_intel_preprocessor", LLMIntelPreprocessor("https://api-ap-southeast-1.modelarts-maas.com/v1/chat/completions", 
#                                                                                  "fce64bd1-948b-4b4d-b998-729fc4c12db8_8947A6A7229BA554F81256D428EB618303FE2E35A63A8C29FF0F98F7EAAB85CA",
#                                                                                  "deepseek-v3.1"))
container.register_singleton(
    "threat_intelligence",
    ThreatIntelligence(
        searchers=[container.resolve("bing_searcher"), container.resolve("yt_searcher")],#, container.resolve("deepseek_searcher")],
        preprocessor=container.resolve("simple_intel_preprocessor")
    )
)

# ===== Net Admin implementation (used by controller) =====
container.register_singleton("ThreatMitigationEngine", AdminImpl(subprocess.run))

# ===== Autopilot =====
container.register_singleton(
    "autopilot",
    Autopilot("https://7f7f-34-80-211-129.ngrok-free.app")
)

container.register_singleton("network_activity_analyzer", NetworkActivityAnalyzer())

container.register_singleton("regression_predictor", BasicRegressionPredictor())

def geoip_reader_factory():
    return geoip2.database.Reader("resources/GeoLite2-City.mmdb")


http_client = requests


container.register_singleton(
    "geo_mapper",
    MaxMindGeoMapper(
        geoip_reader_factory=geoip_reader_factory,
        http_client=http_client
    )
)
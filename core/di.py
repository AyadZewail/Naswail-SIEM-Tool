from core.interfaces import IPacketSystem
from plugins.home.PacketDecoder import BasicPacketDecoder
from plugins.home.PacketDetails import BasicPacketDetails
from plugins.home.ProtocolExtractor import BasicProtocolExtractor
from plugins.home.ErrorChecker import BasicErrorChecker
from plugins.home.PacketStatistics import BasicPacketStatistics
from plugins.home.AnomalyDetector import SnortAnomalyDetector
from plugins.home.PacketFilter import BasicPacketFilter
from plugins.home.SensorSystem import BasicSensorSystem
from plugins.home.ApplicationSystem import BasicApplicationSystem
from plugins.incident_response.network_engines import WindowsNetworkAdmin
# from Code_Main import PacketSystem, SensorSystem, ApplicationsSystem
# from Code_IncidentResponse import ThreatMitigationEngine#, ThreatIntelligence, Autopilot

class ServiceContainer:
    def __init__(self):
        self._singletons = {}

    def register_singleton(self, key, instance):
        """
        Register a singleton service instance directly by key.
        """
        self._singletons[key] = instance

    def resolve(self, key):
        """
        Get the registered singleton instance by key.
        Raises if not registered.
        """
        if key not in self._singletons:
            raise ValueError(f"Service not registered: {key}")
        return self._singletons[key]


# Global container instance
container = ServiceContainer()

protocol_extractor=BasicProtocolExtractor()
corrupted_packet_list = []
network_log = []

# def create_packet_system():
#     return PacketSystem(
#         packet_decoder=BasicPacketDecoder(),
#         packet_details=BasicPacketDetails(),
#         protocol_extractor=protocol_extractor,
#         error_checker=BasicErrorChecker(
#             corrupted_packet_list=corrupted_packet_list,
#             logger=network_log
#         ),
#         packet_statistics=BasicPacketStatistics(),
#         anomaly_detector=SnortAnomalyDetector(
#             rules_file="C:\\Snort\\rules\\custom.rules",
#             log_file="C:\\Snort\\log\\alert.ids"
#         ),
#         packet_filter=BasicPacketFilter(
#             protocol_extractor=protocol_extractor
#         ),
#         corrupted_packet_list=corrupted_packet_list,
#         network_log=network_log
#     )

# def create_sensor_system():
#     sensor_impl = BasicSensorSystem()
#     pkt_filter = BasicPacketFilter(protocol_extractor)

#     return SensorSystem(
#         sensor_system=sensor_impl,
#         protocol_extractor=protocol_extractor,
#         packet_filter=pkt_filter
#     )

# def create_applications_system():
#     app_impl = BasicApplicationSystem()
#     return ApplicationsSystem(application_system=app_impl)

# def create_threat_mitigation_engine():
#     packet_system = container.resolve("PacketSystem")
#     netadmin_impl = WindowsNetworkAdmin()
#     return ThreatMitigationEngine(net_admin=netadmin_impl, blacklist=packet_system.blacklist, blocked_ports=packet_system.blocked_ports, network_log=packet_system.networkLog)

# container.register_singleton("ThreatMitigationEngine", create_threat_mitigation_engine())
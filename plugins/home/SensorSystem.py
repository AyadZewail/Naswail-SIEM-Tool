from core.interfaces import ISensorSystem
from scapy.packet import Packet

class BasicSensorSystem(ISensorSystem):
    def __init__(self):
        self.sensors = {}  # name -> mac

    def add_sensor(self, name: str, mac_address: str) -> None:
        self.sensors[name] = mac_address

    def remove_sensor(self, name: str) -> None:
        print(f"[SensorSystem] Removing sensor '{name}' with MAC {self.sensors[name]}")
        self.sensors.pop(name, None)

    def list_sensors(self) -> dict:
        return dict(self.sensors)

    def reset(self) -> None:
        self.sensors.clear()

    def is_sensor_packet(self, packet: Packet) -> bool:
        if not packet.haslayer("Ethernet"):
            return False
        mac_src = packet["Ethernet"].src
        return mac_src in self.sensors.values()

    def get_sensor_name(self, mac_address: str) -> str:
        for name, mac in self.sensors.items():
            if mac == mac_address:
                return name
        return "Unknown"

    def get_sensor_mac(self, name: str) -> str:
        return self.sensors.get(name, "Unknown")

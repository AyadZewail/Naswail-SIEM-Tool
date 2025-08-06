# plugins/analysis/application_system.py
import psutil
from core.interfaces import IApplicationSystem

class BasicApplicationSystem(IApplicationSystem):
    def get_active_applications(self) -> list[dict]:
        apps_with_ports = []

        for proc in psutil.process_iter(attrs=['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                app_name = proc.info['name']
                app_status = proc.info['status']
                app_cpu = proc.info['cpu_percent']
                app_mem = proc.memory_percent()

                connections = psutil.Process(pid).net_connections(kind='inet')

                for conn in connections:
                    if conn.laddr:
                        local_ip, local_port = conn.laddr
                        entry = {
                            "Application": app_name,
                            "IP": local_ip,
                            "Port": local_port,
                            "Status": app_status,
                            "CPU": app_cpu,
                            "Memory": app_mem,
                        }
                        apps_with_ports.append(entry)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        return apps_with_ports

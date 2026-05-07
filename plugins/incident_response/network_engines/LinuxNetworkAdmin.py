import subprocess
from core.interfaces import INetworkAdministration


class LinuxNetworkAdmin(INetworkAdministration):
    def __init__(self, executor=None):
        # dependency injection for testability
        self.executor = executor or subprocess.run

    # -------------------------
    # Command builders (pure)
    # -------------------------

    def _build_block_ip(self, ip):
        return f"iptables -A INPUT -s {ip} -j DROP"

    def _build_unblock_ip(self, ip):
        return f"iptables -D INPUT -s {ip} -j DROP"

    def _build_block_port(self, port):
        return f"iptables -A INPUT -p tcp --dport {port} -j DROP"

    def _build_unblock_port(self, port):
        return f"iptables -D INPUT -p tcp --dport {port} -j DROP"

    def _build_limit_rate(self, ip, rate):
        return [
            "sudo", "iptables", "-A", "FORWARD", "-s", ip,
            "-m", "hashlimit", "--hashlimit-name", f"rate_{ip}",
            "--hashlimit-above", f"{rate}/sec",
            "--hashlimit-mode", "srcip",
            "-j", "DROP"
        ]

    def _build_reset_rate_limit(self, ip):
        return [
            "sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"
        ]

    # -------------------------
    # Execution layer
    # -------------------------

    def block_ip(self, ip):
        cmd = self._build_block_ip(ip)
        self.executor(["sudo", "sh", "-c", cmd], check=True)

    def unblock_ip(self, ip):
        cmd = self._build_unblock_ip(ip)
        self.executor(["sudo", "sh", "-c", cmd], check=True)

    def block_port(self, port):
        cmd = self._build_block_port(port)
        self.executor(["sudo", "sh", "-c", cmd], check=True)

    def unblock_port(self, port):
        cmd = self._build_unblock_port(port)
        self.executor(["sudo", "sh", "-c", cmd], check=True)

    def limit_rate(self, ip, rate):
        cmd = self._build_limit_rate(ip, rate)
        self.executor(cmd, check=True)

    def reset_rate_limit(self, ip):
        cmd = self._build_reset_rate_limit(ip)
        self.executor(cmd, check=False)

    def terminate_processes(self, identifier):
        pass

    def broadcast_termination(self, pid):
        pass
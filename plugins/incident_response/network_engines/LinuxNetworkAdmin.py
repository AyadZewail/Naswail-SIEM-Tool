import subprocess
from core.interfaces import INetworkAdministration

class LinuxNetworkAdmin(INetworkAdministration):
    def block_ip(self, ip):
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)
    
    def unblock_ip(self, ip):
        cmd = f"iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)
    
    def block_port(self, port):
        cmd = f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)

    def unblock_port(self, port):
        cmd = f"iptables -D INPUT -p tcp --dport {port} -j DROP"
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)

    def limit_rate(self, ip, rate):
        cmd = [
            "sudo", "iptables", "-A", "FORWARD", "-s", ip,
            "-m", "hashlimit", "--hashlimit-name", f"rate_{ip}",
            "--hashlimit-above", f"{rate}/sec", "--hashlimit-mode", "srcip", "-j", "DROP"
        ]
        subprocess.run(cmd, check=True)

    def reset_rate_limit(self, ip):
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)

    def terminate_processes(self, identifier): pass  # Copy logic from your original method
    def broadcast_termination(self, pid): pass  # Same here

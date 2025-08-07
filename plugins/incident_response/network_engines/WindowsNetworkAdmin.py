import subprocess
from core.interfaces import INetworkAdministration

class WindowsNetworkAdmin(INetworkAdministration):
    def block_ip(self, ip):
        cmd = f"New-NetFirewallRule -DisplayName 'Block-IP-{ip}' -Direction Inbound -Action Block -RemoteAddress {ip}"
        subprocess.run(["powershell", "-Command", cmd], check=True)
    
    def unblock_ip(self, ip):
        cmd = f"Remove-NetFirewallRule -DisplayName 'Block-IP-{ip}' -ErrorAction SilentlyContinue"
        subprocess.run(["powershell", "-Command", cmd], check=True)

    def block_port(self, port):
        cmd = f"New-NetFirewallRule -DisplayName 'Block-Port-{port}' -Direction Inbound -Action Block -Protocol TCP -LocalPort {port}"
        subprocess.run(["powershell", "-Command", cmd], check=True)

    def unblock_port(self, port):
        cmd = f"Remove-NetFirewallRule -DisplayName 'Block-Port-{port}' -ErrorAction SilentlyContinue"
        subprocess.run(["powershell", "-Command", cmd], check=True)

    def limit_rate(self, ip, rate):
        rate = max(int(rate) * 1000, 8000)
        ps = f"""
        Remove-NetQosPolicy -Name "Throttle_{ip}" -Confirm:$false -ErrorAction SilentlyContinue
        New-NetQosPolicy -Name "Throttle_{ip}" -IPSrcPrefixMatchCondition "{ip}/32" `
        -ThrottleRateActionBitsPerSecond {rate} -NetworkProfile All
        """
        subprocess.run(["powershell", "-Command", ps], check=True)

    def reset_rate_limit(self, ip):
        ps = f"""
        $policy = Get-NetQosPolicy -Name "Throttle_{ip}" -ErrorAction SilentlyContinue
        if ($policy) {{ Remove-NetQosPolicy -Name "Throttle_{ip}" -Confirm:$false }}
        """
        subprocess.run(["powershell", "-Command", ps], check=True)

    def terminate_processes(self, identifier): pass
    def broadcast_termination(self, pid): pass

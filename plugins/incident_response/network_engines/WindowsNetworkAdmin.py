# plugins/home/WindowsNetworkAdmin.py

from core.interfaces import INetworkAdministration


class WindowsNetworkAdmin(INetworkAdministration):
    def __init__(self, executor):
        self.executor = executor

    def block_ip(self, ip: str):
        cmd = (
            f"New-NetFirewallRule -DisplayName 'Block-IP-{ip}' "
            f"-Direction Inbound -Action Block -RemoteAddress {ip}"
        )
        self.executor(["powershell", "-Command", cmd])

    def unblock_ip(self, ip: str):
        cmd = (
            f"Remove-NetFirewallRule -DisplayName 'Block-IP-{ip}' "
            f"-ErrorAction SilentlyContinue"
        )
        self.executor(["powershell", "-Command", cmd])

    def block_port(self, port: int):
        cmd = (
            f"New-NetFirewallRule -DisplayName 'Block-Port-{port}' "
            f"-Direction Inbound -Action Block -Protocol TCP -LocalPort {port}"
        )
        self.executor(["powershell", "-Command", cmd])

    def unblock_port(self, port: int):
        cmd = (
            f"Remove-NetFirewallRule -DisplayName 'Block-Port-{port}' "
            f"-ErrorAction SilentlyContinue"
        )
        self.executor(["powershell", "-Command", cmd])

    def limit_rate(self, ip: str, rate: int):
        rate = max(int(rate) * 1000, 8000)

        ps = f"""
        Remove-NetQosPolicy -Name "Throttle_{ip}" -Confirm:$false -ErrorAction SilentlyContinue
        New-NetQosPolicy -Name "Throttle_{ip}" -IPSrcPrefixMatchCondition "{ip}/32"
        -ThrottleRateActionBitsPerSecond {rate} -NetworkProfile All
        """
        self.executor(["powershell", "-Command", ps])

    def reset_rate_limit(self, ip: str):
        ps = f"""
        $policy = Get-NetQosPolicy -Name "Throttle_{ip}" -ErrorAction SilentlyContinue
        if ($policy) {{ Remove-NetQosPolicy -Name "Throttle_{ip}" -Confirm:$false }}
        """
        self.executor(["powershell", "-Command", ps])

    def terminate_processes(self, identifier): 
        pass

    def broadcast_termination(self, pid): 
        pass
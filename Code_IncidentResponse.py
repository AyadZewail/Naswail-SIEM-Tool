import sys
import os
import gzip
import psutil
import platform
import subprocess
import json
import re
import requests
import time
import geoip2.database
import socket
import paramiko
import base64
import urllib.parse
import binascii
import codecs
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from UI_IncidentResponse import Ui_IncidentResponse

import multiprocessing
#!/usr/bin/env python
# snort -i 5 -c C:\Snort\etc\snort.conf -l C:\Snort\log -A fast
# type C:\Snort\log\alert.ids
# echo. > C:\Snort\log\alert.ids
# ping -n 4 8.8.8.8

# Initialize process pool at module level for reuse
process_pool = None

def initialize_process_pool(processes=2):
    global process_pool
    if process_pool is None:
        process_pool = multiprocessing.Pool(processes=processes)
    return process_pool

# Function to be executed by the process pool
def run_scrap_instructions(attack_name, system):
    try:
        if system == "Linux":
            cmd = [
                r"/home/hamada/Downloads/Naswail-SIEM-Tool-main/.venv/bin/python",
                "/home/hamada/Downloads/Naswail-SIEM-Tool-main/scrapInstructions.py",
                f"{attack_name} mitigation and response"
            ]
        elif system == "Windows":
            cmd = [
                r"python",
                "scrapInstructions.py",
                f"{attack_name} mitigation and response"
            ]
            
        
        # Set high priority
        if system == "Windows":
            # Windows-specific high priority execution
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # HIGH_PRIORITY_CLASS = 0x00000080
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=startupinfo,
                creationflags=0x00000080,  # HIGH_PRIORITY_CLASS
                shell=False
            )
        else:
            # Linux execution with nice -n -20 (highest priority)
            nice_cmd = ["nice", "-n", "-20"] + cmd
            result = subprocess.run(
                nice_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                preexec_fn=os.setpgrp  # Run in separate process group
            )
        
        return result.stdout, result.stderr
    except Exception as e:
        return "", str(e)

# ======= Modified Stop Criteria =======

class KaggleLLMClient:
    def __init__(self, ngrok_url, LogAP):
        self.api_url = f"{ngrok_url}/generate"
        self.logModel = LogAP
        
    def send_prompt(self, prompt):
        try:
            response = requests.post(
                self.api_url,
                json={"prompt": prompt},
                timeout=300
            )
            return response.json()['response']
        except Exception as e:
            self.logModel.log_step(f"Failed to Prompt LLM; Analyst Intervention Required")
            return f"Error: {str(e)}"
class Autopilot:
    def __init__(self, MitEng, LogAP):
        self.MitEng = MitEng
        self.logModel = LogAP
        self.TTR = 0
        self.mitigation_success = False
        
    def setup(self, prompt, ip, port, scrapetime):
        start_time = time.time()
        NGROK_URL = "https://3c3b-35-234-63-106.ngrok-free.app"
        client = KaggleLLMClient(NGROK_URL, self.logModel)
        
        prompt_text = prompt
        
        self.logModel.log_step("Prompting LLM...")
        response = client.send_prompt(prompt_text)
        print("Model Response:", response)
        
        # Check for valid response
        if not response or "Error:" in response:
            self.logModel.log_step("Failed to get valid response from LLM")
            end_time = time.time()
            self.TTR = scrapetime + end_time - start_time
            print(f"\nTotal execution time: {self.TTR:.2f} seconds")
            self.logModel.log_step(f"Mitigation failed. Execution in {self.TTR:.2f} seconds")
            return
            
        # Try to extract and execute the function
        success = self.extract_function_and_params(response, ip, port)
        
        # Calculate and display total time
        end_time = time.time()
        self.TTR = scrapetime + end_time - start_time
        print(f"\nTotal execution time: {self.TTR:.2f} seconds")
        
        # Only log success if both prompt and execution succeeded
        if success:
            self.logModel.log_step(f"Threat mitigated successfully in {self.TTR:.2f} seconds")
        else:
            self.logModel.log_step(f"Execution completed in {self.TTR:.2f} seconds, but mitigation failed")

    def extract_function_and_params(self, model_output, ip, port):
        try:
            match = re.search(r'\{.*\}', model_output, re.DOTALL)
            if not match:
                self.logModel.log_step("Failed to extract function from LLM response")
                return False
            
            json_text = match.group(0)
            data = json.loads(json_text)

            values = list(data.values()) if isinstance(data, dict) else None
            if not values:
                self.logModel.log_step("Invalid function format in LLM response")
                return False
                
            if values[0] == "block_ip":
                values.append(ip)
            elif values[0] == "limit_rate":
                values.append(ip)
                values.append("8")
            elif values[0] == "block_port":
                values.append(port)
            self.logModel.log_step(f"Executing {values[0]} for {values[1:]}")
            
            # Execute the function and capture its result
            result = self.execute_function(self.MitEng, values[0], *values[1:])
            return result
        except json.JSONDecodeError:
            self.logModel.log_step(f"Failed to Read LLM Instruction; Analyst Intervention Required")
            return False
        except Exception as e:
            self.logModel.log_step(f"Error during function extraction: {str(e)}")
            return False

    def execute_function(self, obj, function_name, *args, **kwargs):
        func = getattr(obj, function_name, None)
        if callable(func):
            try:
                func(*args, **kwargs)
                return True
            except Exception as e:
                self.logModel.log_step(f"Function execution failed: {str(e)}")
                return False
        else:
            self.logModel.log_step(f"Failed to Mitigate Threat; Analyst Intervention Required")
            print(f"Function '{function_name}' not found.")
            return False

class WorkerSignals(QObject):
    finished = pyqtSignal(str)  # Emits final result
    error = pyqtSignal(str)     # Emits error messages

# Async task runner
class SubprocessWorker(QRunnable):
    def __init__(self, attack_name):
        super().__init__()
        self.attack_name = attack_name
        self.signals = WorkerSignals()
        # Initialize process pool if not already initialized
        initialize_process_pool()

    @pyqtSlot()
    def run(self):
        try:
            system = platform.system()
            print(f"Starting subprocess with high priority on {system}")
            
            # Use the process pool for execution
            stdout, stderr = process_pool.apply(
                run_scrap_instructions, 
                args=(self.attack_name, system)
            )
            
            output = ""
            if stdout:
                stdout_lines = stdout.strip().split("\n")
                # Find the line containing the header
                header_index = next(
                    (i for i, line in enumerate(stdout_lines) 
                    if "Extracted Mitigation Strategy:" in line),
                    -1
                )
                
                if header_index != -1:
                    # Get all lines AFTER the header (including potential multi-line content)
                    mitigation_lines = stdout_lines[header_index+1:]
                    output = " ".join(line.strip() for line in mitigation_lines if line.strip())
            
            if not output and stderr:
                raise Exception(f"Error in script execution: {stderr}")
                
            self.signals.finished.emit(output)
        except Exception as e:
            self.signals.error.emit(str(e))

class AnomalousPackets():
    def __init__(self, ui, anomalies, packet, AI, log):
        self.ui = ui
        self.AIobj = AI
        self.anomalies = anomalies
        self.packetobj = packet
        self.filterapplied = False
        self.filtered_packets = []
        self.threadpool = QThreadPool()
        self.geoip_db_path = "GeoLite2-City.mmdb"
        self.logModel = log
        self.unique_anomalies = set()  # Track unique (src_ip, dst_ip, attack_name) tuples
        #self.preprocess_threat_for_AI("A Distributed Denial-of-Service (DDoS) attack overwhelms a network, service, or server with excessive traffic, disrupting legitimate user access. To effectively mitigate such attacks, consider the following strategies:Develop a DDoS Response Plan:Establish a comprehensive incident response plan that outlines roles, responsibilities, and procedures to follow during a DDoS attack. This proactive preparation ensures swift and coordinated action.esecurityplanet.comImplement Network Redundancies:Distribute resources across multiple data centers and networks to prevent single points of failure. This approach enhances resilience against DDoS attacks by ensuring that if one location is targeted, others can maintain operations. ")
    
# Example usage
      # Replace with actual process name or PID
    def display(self, main_window):
        try:
            if self.filterapplied == False:
                self.ui.tableWidget.setRowCount(0)
                displayed_anomalies = set()  # Track already displayed anomalies
                
                for packet in self.anomalies:
                    src_ip = packet["IP"].src if packet.haslayer(IP) else "N/A"
                    dst_ip = packet["IP"].dst if packet.haslayer(IP) else "N/A"
                    
                    # Get attack family from the main window's table
                    attack_family = None
                    for row in range(main_window.tableWidget_4.rowCount()):
                        if (main_window.tableWidget_4.item(row, 1) and 
                            main_window.tableWidget_4.item(row, 2) and
                            main_window.tableWidget_4.item(row, 1).text() == src_ip and
                            main_window.tableWidget_4.item(row, 2).text() == dst_ip):
                            attack_family = main_window.tableWidget_4.item(row, 3).text()
                            break
                    
                    if not attack_family:
                        continue  # Skip if we can't determine the attack family
                        
                    # Create a unique signature for this attack
                    anomaly_signature = (src_ip, dst_ip, attack_family)
                    
                    # Skip if we've already displayed this signature
                    if anomaly_signature in displayed_anomalies:
                        continue
                        
                    displayed_anomalies.add(anomaly_signature)
                    self.attack_family = attack_family
                    
                    sport = None
                    dport = None
                    if packet.haslayer("TCP"):
                        sport = packet["TCP"].sport
                        dport = packet["TCP"].dport
                    elif packet.haslayer("UDP"):
                        sport = packet["UDP"].sport
                        dport = packet["UDP"].dport
                    protocol = self.packetobj.get_protocol(packet)

                    row_position = self.ui.tableWidget.rowCount()
                    self.ui.tableWidget.insertRow(row_position)
                    self.ui.tableWidget.setItem(row_position, 0, QTableWidgetItem(datetime.fromtimestamp(float(packet.time)).strftime("%I:%M:%S %p")))
                    self.ui.tableWidget.setItem(row_position, 1, QTableWidgetItem(src_ip))
                    self.ui.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst_ip))
                    self.ui.tableWidget.setItem(row_position, 3, QTableWidgetItem(str(sport)))
                    self.ui.tableWidget.setItem(row_position, 4, QTableWidgetItem(str(dport)))
                    self.ui.tableWidget.setItem(row_position, 5, QTableWidgetItem(protocol))
                    self.ui.tableWidget.setItem(row_position, 6, QTableWidgetItem(attack_family))
        except Exception as e:
            print(e)

    def decode_payload(self, payload):
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="your_font_module")
        if isinstance(payload, bytes):
            payload = payload.decode(errors="ignore")  #UTF-8 decoding
        
        decoded_versions = set()
        decoded_versions.add(payload)

        #Base64 Decoding
        try:
            payload_stripped = ''.join(filter(lambda x: x in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", payload))
            decoded_b64 = base64.b64decode(payload_stripped).decode(errors="ignore")
            decoded_versions.add(decoded_b64)
        except (binascii.Error, UnicodeDecodeError):
            pass

        #URL Decoding
        decoded_url = urllib.parse.unquote(payload)
        decoded_versions.add(decoded_url)

        #Hex Decoding
        try:
            decoded_hex = bytes.fromhex(payload).decode(errors="ignore")
            decoded_versions.add(decoded_hex)
        except (ValueError, UnicodeDecodeError):
            pass

        #ROT13 Decoding
        decoded_rot13 = codecs.decode(payload, "rot_13")
        decoded_versions.add(decoded_rot13)

        #Gzip Decompression
        try:
            decoded_gzip = gzip.decompress(payload.encode()).decode(errors="ignore")
            decoded_versions.add(decoded_gzip)
        except (OSError, UnicodeDecodeError):
            pass

        # Return the most readable version
        return max(decoded_versions, key=len)
    
    def get_location(self, ip):
        try:
            with geoip2.database.Reader(self.geoip_db_path) as reader:
                response = reader.city(ip)
                country = response.country.name 
                return country
        except geoip2.errors.AddressNotFoundError:
            return 'Egypt'
    
    def extractThreatIntelligence(self, row):
        try:
            attack_name = self.attack_family
            self.stime = time.time()
            worker = SubprocessWorker(attack_name)
            worker.signals.finished.connect(self.on_result)
            worker.signals.error.connect(self.on_error)
            self.threadpool.start(worker)
            target = self.anomalies[row]
            self.src_ip = target[IP].src if target.haslayer(IP) else "N/A"
            dst_ip = target[IP].dst if target.haslayer(IP) else "N/A"
            protocol = self.packetobj.get_protocol(target)
            macsrc = target[Ether].src if target.haslayer(Ether) else "N/A"
            macdst = target[Ether].dst if target.haslayer(Ether) else "N/A"
            packet_length = int(len(target))
            payload = target["Raw"].load if target.haslayer("Raw") else "N/A"
            decoded_payload = self.decode_payload(payload)
            sport = None
            self.dport = None
            if target.haslayer("TCP"):
                sport = target["TCP"].sport
                self.dport = target["TCP"].dport
            elif target.haslayer("UDP"):
                sport = target["UDP"].sport
                self.dport = target["UDP"].dport
            flow_key = tuple(sorted([(self.src_ip, sport), (dst_ip, self.dport)])) + (protocol,)
            attack_entry = f"{datetime.fromtimestamp(float(target.time)).strftime("%I:%M:%S %p")} - {self.attack_family} - {str(flow_key)}"
            self.logModel.log_attack(attack_entry)
            self.logModel.log_step("Performing web scraping...")
            

            self.ui.tableWidget_3.setRowCount(0)
            row_position = 0
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Attack Name"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem())
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("CVE ID"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem())
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Flow Key"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem(str(flow_key)))
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Decoded Payload"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem(str(decoded_payload)))
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Origin Country"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem(self.get_location(self.src_ip)))
            row_position += 1
            self.ui.tableWidget_3.insertRow(row_position)
            self.ui.tableWidget_3.setItem(row_position, 0, QTableWidgetItem("Instruction"))
            self.ui.tableWidget_3.setItem(row_position, 1, QTableWidgetItem("Searching"))
        except Exception as e:
            print(e)
    
    def on_result(self, output):
        print("✅ Result:", output)
        self.etime = time.time()
        tTime = self.etime - self.stime
        print(f"##########################\nTotal Runtime for Scraping: {self.etime - self.stime:.2f} seconds\n")
        self.logModel.log_step("Recieved instructions (expand to see)")
        self.logModel.log_details(output)
        self.ui.tableWidget_3.setItem(5, 1, QTableWidgetItem(output))
        self.AIobj.setup(output, self.src_ip, self.dport, tTime)

        
    def on_error(self, error_msg):
        print("❌ Error:", error_msg)
        self.logModel.log_step(f"Failed to Procure Intelligence; Analyst Intervention Required")
        self.ui.tableWidget_3.setItem(5, 1, QTableWidgetItem(error_msg))




class LogWindow(QMainWindow):
    def __init__(self, model):
        self.logModel = model
        self.attack_entry = None
        self.child = None

    def log_attack(self, entry):
        self.attack_entry = QStandardItem(entry)
        self.logModel.appendRow(self.attack_entry)

    def log_step(self, description):
        self.child = QStandardItem(description)
        self.attack_entry.appendRow(self.child)

    def log_details(self, description):
        self.child.appendRow(QStandardItem(description))

class ThreatMitigationEngine():
    def __init__(self, ui, blacklist, blocked_ports, packetsysobj):
        self.ui = ui
        self.blacklist = blacklist
        self.blocked_ports = blocked_ports
        self.packetsysobj = packetsysobj
        self.networkLog = packetsysobj.networkLog
        #self.terminate_processes("firefox.exe")#add the process id which can be found in the task manager
        threading.Thread(target=self.terminate_processes, args=("8592",), daemon=True).start()
        self.listener_thread = threading.Thread(target=self.listen_for_termination, daemon=True)
        self.listener_thread.start()
    

    def limit_rate(self, ip, rate):
        try:
            system = platform.system()
            if system == "Linux":
                rate_str = f"{rate}/sec"
                # Use FORWARD chain to control traffic passing through the router
                subprocess.run([
                    "sudo", "iptables", "-A", "FORWARD", "-s", ip,
                    "-m", "hashlimit",
                    "--hashlimit-name", f"rate_{ip}",
                    "--hashlimit-above", rate_str,
                    "--hashlimit-mode", "srcip",
                    "-j", "DROP"
                ], check=True)
                print(f"Rate limit set for {ip} on FORWARD chain.")   
            elif system == "Windows":
                print("Setting rate limit for Windows...")
                rate = int(rate)
                rate=rate*1000
                if rate < 8000:
                    # Minimum rate must be 8Kbps
                    rate = 8000

                ps_script = f'''
    $ErrorActionPreference = "Stop"
    Try {{
        Remove-NetQosPolicy -Name "Throttle_{ip}" -Confirm:$false -ErrorAction SilentlyContinue
        New-NetQosPolicy -Name "Throttle_{ip}" `
            -IPSrcPrefixMatchCondition "{ip}/32" `
            -ThrottleRateActionBitsPerSecond {rate} `
            -NetworkProfile All
            
        Get-NetQosPolicy -Name "Throttle_{ip}"
    }} Catch {{
        Write-Error $_.Exception.Message
        exit 1
    }}
    '''

                result = subprocess.run(
                    ["powershell", "-Command", ps_script],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print(result.stdout)
            else:
                print("Unsupported OS")
        except subprocess.CalledProcessError as e:
            print(f"PowerShell Error ({e.returncode}):")
            print(e.stderr if e.stderr else "No error details")
        except Exception as e:
            print(f"General error: {str(e)}")

    def reset_rate_limit(self,ip):
        try:
            system = platform.system()
            if system == "Linux":
                # Remove iptables rules added with hashlimit
                # Example original rule: iptables -A INPUT -s {ip} -m hashlimit ... -j ACCEPT
                # To delete, match the exact rule (use --hashlimit-name to simplify cleanup)
                subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-m", "hashlimit", 
                    "--hashlimit-name", "rate_limit", "-j", "ACCEPT"],
                    check=True
                )
                # Drop rule (if added)
                subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=False  # Allow failure if the rule doesn't exist
                )
            elif system == "Windows":
                # Remove QoS policy (if it exists)
                ps_script = f'''
                $policy = Get-NetQosPolicy -Name "Throttle_{ip}" -ErrorAction SilentlyContinue
                if ($policy) {{ Remove-NetQosPolicy -Name "Throttle_{ip}" -Confirm:$false }}
                '''
                subprocess.run(["powershell", "-Command", ps_script], check=True)
            else:
                print("Unsupported OS")
        except subprocess.CalledProcessError as e:
            print(f"Failed to reset rules for {ip}. The rule may not exist.")
        except Exception as e:
            print(f"Unexpected error: {e}")
            print(traceback.format_exc())

    # Example: Limit 192.168.1.100 to 1Mbps
  
    def terminate_processes(self, identifier):
        try:
            system = platform.system()
            target_pid = None

            # Determine if identifier is PID or name
            try:
                target_pid = int(identifier)
                identifier_type = "pid"
            except ValueError:
                identifier_type = "name"
                if system == "Linux":
                    identifier = identifier.replace('.exe', '')  # Strip .exe for Linux

            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    match = False
                    # Cross-platform name comparison
                    proc_name = proc.info['name'].lower()
                    if system == "Linux":
                        proc_name = proc_name.replace('.exe', '')
                        
                    if identifier_type == "pid":
                        if proc.info['pid'] == target_pid:
                            match = True
                    else:
                        if proc_name == identifier.lower():
                            match = True

                    if match:
                        print(f"Terminating {proc.info['name']} (PID: {proc.info['pid']})...")
                        proc.terminate()
                        
                        # Wait and force kill if needed
                        try:
                            proc.wait(timeout=2)
                        except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                            if system == "Linux":
                                os.kill(proc.info['pid'], 9)
                            elif system == "Windows":
                                subprocess.run(f"taskkill /F /PID {proc.info['pid']}", shell=True)
                        
                        self.broadcast_termination(proc.info['pid'])

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            print(f"Termination error: {str(e)}")

    def listen_for_termination(self):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind(("0.0.0.0", 5005))
            udp_socket.settimeout(1)

            while True:
                try:
                    data, addr = udp_socket.recvfrom(1024)
                    if b'terminate process' in data:
                        # Extract either PID or process name
                        payload = data.decode().strip()
                        identifier = payload.split()[-1]
                        
                        # Create temporary process killer
                        temp_killer = psutil.Process()
                        try:
                            if identifier.isdigit():
                                temp_killer = psutil.Process(int(identifier))
                            else:
                                # Find by name
                                for p in psutil.process_iter(['name']):
                                    if p.info['name'].lower() == identifier.lower():
                                        temp_killer = p
                                        break
                            
                            temp_killer.terminate()
                            try:
                                temp_killer.wait(timeout=2)
                            except psutil.TimeoutExpired:
                                temp_killer.kill()
                        except Exception as e:
                            print(f"Remote termination failed: {str(e)}")

                except socket.timeout:
                    continue

        except Exception as e:
            print(f"Listener error: {str(e)}")
        finally:
            udp_socket.close()

  
  # Required for Linux signal handling

    def broadcast_termination(self, pid):
        try:
            system = platform.system()
            if system == "Windows":
                message = f"terminate process {pid}"
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                udp_socket.sendto(message.encode(), ("255.255.255.255", 5005))
                udp_socket.close()
                print(f"Broadcasted: {message}")
            elif system == "Linux":
                message = f"terminate process {pid}"
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                # Use generic broadcast address (same as Windows)
                udp_socket.sendto(message.encode(), ("255.255.255.255", 5005))
                udp_socket.close()
                print(f"Broadcasted: {message}")
        except Exception as e:
            print(f"Error: {e}")
    def get_gateway(self):
        """Retrieve the current default gateway dynamically."""
        system = platform.system()
        
        if system == "Linux":
            try:
                result = subprocess.check_output("ip route | grep default", shell=True).decode()
                gateway = result.split()[2]
                return gateway
            except Exception as e:
                print(f"Error retrieving Linux gateway: {e}")
                return None

        elif system == "Windows":
            try:
                result = subprocess.check_output("powershell -Command \"(Get-NetRoute -DestinationPrefix 0.0.0.0/0).NextHop\"", shell=True).decode().strip()
                return result
            except Exception as e:
                print(f"Error retrieving Windows gateway: {e}")
                return None
        else:
            print("Unsupported OS")
            return None

    def block_ip(self, ip):
        firewall_command = f"iptables -A INPUT -s {ip} -j DROP; iptables -A FORWARD -s {ip} -j DROP"
        self.firewallConfiguration(ip, firewall_command)

    def unblock_ip(self, ip):
        firewall_command = f"iptables -D INPUT -s {ip} -j DROP; iptables -D FORWARD -s {ip} -j DROP"
        self.firewallConfiguration(ip, firewall_command)

    def block_port(self, port):
        firewall_command = f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        self.firewallConfiguration(port, firewall_command)
    
    def unblock_port(self, port):
        firewall_command = f"iptables -D INPUT -p tcp --dport {port} -j DROP"
        self.firewallConfiguration(port, firewall_command)
    
    def firewallConfiguration(self, entity, firewall_command, username="admin", password=None):
        """SSH into the router and block a malicious IP."""
        gateway = self.get_gateway()
        if not gateway:
            print("Failed to find the gateway.")
            return
        system = platform.system()
        
        if system == "Linux":
            try:
                ssh_command = f"sshpass -p {password} ssh {username}@{gateway} '{firewall_command}'"
                subprocess.run(ssh_command, shell=True, check=True)
                print(f"Blocked {entity} on router firewall (Linux).")
            except Exception as e:
                print(f"Error blocking IP on Linux router: {e}")

        elif system == "Windows":
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(gateway, username = username, password = password)

                stdin, stdout, stderr = client.exec_command(firewall_command)
                output = stdout.read().decode()
                error = stderr.read().decode()

                if error:
                    print(f"Error blocking IP on Windows router: {error}")
                else:
                    print(f"Blocked {entity} on router firewall (Windows).")

                client.close()
            except Exception as e:
                print(f"Error connecting via SSH on Windows: {e}")
        else:
            print("Unsupported OS")
    
    def updateBlacklist(self, f):
        try:
            ip = self.ui.lineEdit.text().strip()
            if(f == 1):
                self.blacklist.append(ip)
                self.block_ip(ip)
                self.packetsysobj.networkLog+="Blocked IP: "+ip+"\n"
            else:
                self.blacklist.remove(ip)
                self.unblock_ip(ip)
                self.packetsysobj.networkLog+="Unblocked IP: "+ip+"\n"
               
            model = QStringListModel()
            model.setStringList(self.blacklist)
            self.ui.listView.setModel(model)
        except Exception as e:
            print(f"Error updating blacklist: {e}")
    
    def updateBlockedPorts(self, f):
        try:
            port = self.ui.lineEdit_2.text().strip()
            if f == 1:  # Block port
                if port not in self.blocked_ports:  # Avoid duplicate entries
                    self.blocked_ports.append(port)
                    self.block_port(port)
                    self.packetsysobj.networkLog+="Blocked Port: "+port+"\n"
                    row_position = self.ui.tableWidget_2.rowCount()
                    self.ui.tableWidget_2.insertRow(row_position)
                    self.ui.tableWidget_2.setItem(row_position, 0, QTableWidgetItem(str(port)))
                    self.ui.tableWidget_2.setItem(row_position, 1, QTableWidgetItem("Blocked"))
            else:  # Unblock port
                if port in self.blocked_ports:
                    self.blocked_ports.remove(port)
                    self.unblock_port(port)
                    self.packetsysobj.networkLog+="Unblocked Port: "+port+"\n"
                    self.remove_port_from_table(port)  # Remove from table

        except Exception as e:
            print(f"Error updating port blocked: {e}")

    def remove_port_from_table(self, port):
        for row in range(self.ui.tableWidget_2.rowCount()):
            if self.ui.tableWidget_2.item(row, 0) and self.ui.tableWidget_2.item(row, 0).text() == str(port):
                self.ui.tableWidget_2.removeRow(row)
                break  # Stop after removing the first matching row

class IncidentResponse(QWidget, Ui_IncidentResponse):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.ui = Ui_IncidentResponse()
        self.ui.setupUi(self)
        
        # Initialize process pool early during startup
        initialize_process_pool(processes=2)
        
        self.showMaximized()
        self.ui.pushButton_8.clicked.connect(self.show_main_window)
        self.ui.pushButton_7.clicked.connect(self.show_analysis_window)
        self.ui.pushButton_6.clicked.connect(self.show_tools_window)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.ttTime)
        self.timer.start(1000)  # Call every 1000 milliseconds (1 second)
        self.sec = 0

        self.model = QStandardItemModel()
        self.model.setHeaderData(0, Qt.Orientation.Horizontal, "Attack Log")
        self.ui.treeView.setModel(self.model)
        self.ui.treeView.setWordWrap(True)
        self.ui.treeView.setUniformRowHeights(False)
        self.ui.treeView.expandAll()
        
        self.logAutopilot = LogWindow(self.model)
        self.threatMitEngine = ThreatMitigationEngine(self.ui, self.main_window.PacketSystemobj.blacklist, self.main_window.PacketSystemobj.blocked_ports, self.main_window.PacketSystemobj)
        self.autopilotobj=Autopilot(self.threatMitEngine, self.logAutopilot)
        self.anomalousPacketsObj = AnomalousPackets(self.ui, self.main_window.PacketSystemobj.anomalies, self.main_window.PacketSystemobj, self.autopilotobj, self.logAutopilot)
        self.ui.tableWidget.setColumnCount(7)
        self.ui.tableWidget.setHorizontalHeaderLabels(
            ["Timestamp", "Source IP", "Destination IP", "Src Port", "Dst Port", "Protocol", "Attack"]
        )
        self.ui.tableWidget.cellClicked.connect(self.anomalousPacketsObj.extractThreatIntelligence)

        self.ui.tableWidget_2.setColumnCount(2)
        self.ui.tableWidget_2.setHorizontalHeaderLabels(["Port Number", "Status"])
        
        self.ui.tableWidget_3.setWordWrap(True)
        self.ui.tableWidget_3.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ui.tableWidget_3.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.ui.tableWidget_3.horizontalHeader().setVisible(False)
        self.ui.tableWidget_3.verticalHeader().setVisible(False)
        self.ui.tableWidget_3.setRowCount(10)
        self.ui.tableWidget_3.setColumnCount(2)
        self.ui.tableWidget_3.setColumnWidth(0, 120)
        self.ui.tableWidget_3.setColumnWidth(1, 351)

        self.ui.pushButton.clicked.connect(lambda: self.threatMitEngine.updateBlacklist(1))
        self.ui.pushButton_9.clicked.connect(lambda: self.threatMitEngine.updateBlacklist(0))

        self.ui.pushButton_10.clicked.connect(lambda: self.threatMitEngine.updateBlockedPorts(1))
        self.ui.pushButton_11.clicked.connect(lambda: self.threatMitEngine.updateBlockedPorts(0))
        self.ui.terminateButton.clicked.connect(self.action_terminate)
        self.ui.applyLimitButton.clicked.connect(self.action_apply_limit)
        self.ui.resetbutton.clicked.connect(self.action_reset_limit)
        self.pid=""#terminatd processes
        self.ips_limited=[]
    def action_reset_limit(self):
        try:
            ip=self.ui.ipLineEdit.text()
            self.threatMitEngine.reset_rate_limit(ip)
            self.ips_limited.pop(self.ips_limited.index(ip))
            model=QStringListModel()
            model.setStringList(self.ips_limited)
            self.ui.limitedIPsList.setModel(model)
        except Exception as e:
            print(e)
    def action_apply_limit(self):
        try:
            self.threatMitEngine.limit_rate(self.ui.ipLineEdit.text(), self.ui.rateLineEdit.text())
            self.ips_limited.append(self.ui.ipLineEdit.text())
            model=QStringListModel()
            model.setStringList(self.ips_limited)
            self.ui.limitedIPsList.setModel(model)
            
        except Exception as e:
            print(e)
    def action_terminate(self):
        try:
            self.pid+=self.ui.processLineEdit.text()+"\n"
            self.threatMitEngine.terminate_processes(self.pid)
            model = QStringListModel()
            model.setStringList([self.pid])
            self.ui.terminatedList.setModel(model)
        except Exception as e:
            print(e)
            tb=traceback.format_exc()
            print(tb)
    def ttTime(self):
        self.anomalousPacketsObj.display(self.main_window)
    
    def show_analysis_window(self):
        try:
            self.secondary_widget = self.main_window.open_analysis()
            self.hide()
        except Exception as e:
            print(e)

    def show_main_window(self):
        try:
            self.main_window.show()
            self.hide()
        except Exception as e:
            print(e)

    def show_tools_window(self):
        try:
            self.secondary_widget = self.main_window.open_tool()
            self.hide()
        except Exception as e:
            print(e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IncidentResponse()
    window.show()
    sys.exit(app.exec())

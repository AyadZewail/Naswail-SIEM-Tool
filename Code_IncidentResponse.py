import sys
import os
import gzip
import psutil
import platform
import subprocess
import json
import re
import requests
import geoip2.database
import socket
import paramiko
import base64
import urllib.parse
import binascii
import codecs
import threading
import asyncio
import concurrent.futures
import functools
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import logging
import time
from sentence_transformers import SentenceTransformer, util
import spacy
import torch
import pandas as pd
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import random
from tenacity import retry, stop_after_attempt, wait_exponential
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from views.UI_IncidentResponse import Ui_IncidentResponse

from core import di

#!/usr/bin/env python
# snort -i 5 -c C:\Snort\etc\snort.conf -l C:\Snort\log -A fast
# type C:\Snort\log\alert.ids
# echo. > C:\Snort\log\alert.ids
# ping -n 4 8.8.8.8

# Initialize thread pool at module level for immediate availability
# Using ThreadPoolExecutor instead of ProcessPool for faster I/O bound operations
thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)

# Cache for expensive function calls
function_cache = {}

# Function decorator for caching results
# def cache_result(func):
#     @functools.wraps(func)
#     def wrapper(*args, **kwargs):
#         key = str(args) + str(kwargs)
#         if key not in function_cache:
#             function_cache[key] = func(*args, **kwargs)
#         return function_cache[key]
#     return wrapper

# # Optimized function for scraping instructions
# @cache_result

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

class WorkerSignals(QObject):
    finished = pyqtSignal(str)  # Emits final result
    error = pyqtSignal(str)     # Emits error messages

class ScraperWorker(QRunnable):
    def __init__(self, query, threatIntel):
        super().__init__()
        self.query = query
        self.threatIntel = threatIntel
        self.signals = WorkerSignals()
        self.start_time = None

    @pyqtSlot()
    def run(self):
        try:
            self.start_time = time.time()
            print(f"[WORKER] Starting scraper for {self.query} at {self.start_time}")
            # Run the scraper in a thread (blocking call)
            processed = asyncio.run(self.threatIntel.gather(self.query))
            print(f"[WORKER] Scraper completed in {time.time() - self.start_time:.3f}s")
            output = processed["mitigation"]
            if not output:
                output = f"No mitigation found."
            print(f"[WORKER] Extracted output length: {len(output)} characters")
            self.signals.finished.emit(output)
        except Exception as e:
            error_msg = f"Worker error after {time.time() - self.start_time:.3f}s: {str(e)}"
            print(f"[WORKER] {error_msg}")
            self.signals.error.emit(error_msg)

class IncidentResponseController():
    def __init__(
        self,
        ui,
        anomalies,
        protocol_extractor,
        autopilot_engine,
        threat_intel,
        blacklist,
        blocked_ports,
        network_log,
        mitigation_engine,
        autopilot_log,
        main_window
    ):
        #======================================================================================
        #======================================================================================
        #                               Variable Instantiation
        #======================================================================================
        #======================================================================================
        # self.packet
        self.pid=""#terminatd processes
        self.ips_limited=[]
        self.anomalies = anomalies
        self.protocolExtractor = protocol_extractor
        self.autopilotEngine = autopilot_engine
        self.threatIntel = threat_intel
        self.blacklist = blacklist
        self.blocked_ports = blocked_ports
        self.networkLog = network_log
        self.MitEng = mitigation_engine
        self.logModel = autopilot_log
        self.main_window = main_window
        self.TTR = 0
        self.filterapplied = False
        self.threadpool = QThreadPool()
        self.geoip_db_path = "resources/GeoLite2-City.mmdb"
        self.unique_anomalies = set()
        
        threading.Thread(target=self.terminate_processes, args=("8592",), daemon=True).start()
        threading.Thread(target=self.listen_for_termination, daemon=True).start()

        #======================================================================================
        #======================================================================================
        #                                 UI Mapping
        #======================================================================================
        #======================================================================================
        self.ui = ui
        self.ui.pushButton_8.clicked.connect(self.show_main_window)
        self.ui.pushButton_7.clicked.connect(self.show_analysis_window)
        self.ui.pushButton_6.clicked.connect(self.show_tools_window)
        self.ui.pushButton.clicked.connect(lambda: self.updateBlacklist(1))
        self.ui.pushButton_9.clicked.connect(lambda: self.updateBlacklist(0))
        self.ui.pushButton_10.clicked.connect(lambda: self.updateBlockedPorts(1))
        self.ui.pushButton_11.clicked.connect(lambda: self.updateBlockedPorts(0))
        self.ui.terminateButton.clicked.connect(self.action_terminate)
        self.ui.applyLimitButton.clicked.connect(self.action_apply_limit)
        self.ui.resetbutton.clicked.connect(self.action_reset_limit)

          # Call every 1000 milliseconds (1 second)
        self.sec = 0
        self.ui.tableWidget.setColumnCount(7)
        self.ui.tableWidget.setHorizontalHeaderLabels(["Timestamp", "Source IP", "Destination IP", "Src Port", "Dst Port", "Protocol", "Attack"])
        self.ui.tableWidget.cellClicked.connect(self.extractThreatIntelligence)
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
        
        # Apply text elide mode to ensure wrapping
        for i in range(10):
            for j in range(2):
                item = QTableWidgetItem()
                item.setTextAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
                self.ui.tableWidget_3.setItem(i, j, item)
        
        self.ui.tableWidget_3.setStyleSheet("""
            QTableWidget {
                gridline-color: #31363b;
                background-color: #232629;
            }
            QTableWidget::item {
                padding: 4px;
                border: none;
            }
        """)

    #======================================================================================
    #======================================================================================
    #                                 Autopilot Handling
    #======================================================================================
    #======================================================================================
    def mitigate(self, prompt, ip, port, scrapetime):
        start_time = time.time()

        self.logModel.log_step("Gathering decision from autopilot engine...")
        action, log = self.autopilotEngine.decide(prompt)
        self.logModel.log_step(log)

        end_time = time.time()
        self.TTR = scrapetime + (end_time - start_time)

        if not action:
            self.logModel.log_step(f"Mitigation failed. Execution in {self.TTR:.2f} seconds")
            return

        if action == "block_ip":
            args = [ip]
        elif action == "limit_rate":
            args = [ip, "8"]
        elif action == "block_port":
            args = [port]
        else:
            self.logModel.log_step(f"Unknown action received: {action}")
            return

        success = self.execute_function(action, *args)

        if success:
            self.logModel.log_step(f"Threat mitigated successfully in {self.TTR:.2f} seconds")
        else:
            self.logModel.log_step(f"Mitigation failed. Execution in {self.TTR:.2f} seconds")

    def execute_function(self, function_name, *args):
        func = getattr(self.MitEng, function_name, None)
        if callable(func):
            try:
                func(*args)
                return True
            except Exception as e:
                self.logModel.log_step(f"Execution failed: {str(e)}")
        else:
            self.logModel.log_step(f"Function {function_name} not found")
        return False
    
    #======================================================================================
    #======================================================================================
    #                            Anomalous Packets Handling
    #======================================================================================
    #======================================================================================
    def display_anomalies(self, main_window):
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
                    protocol = self.protocolExtractor.extract_protocol(packet)

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
            search_query = {"query": attack_name + " mitigation and response"}
            self.stime = time.time()
            worker = ScraperWorker(search_query, self.threatIntel)
            worker.signals.finished.connect(self.on_result)
            worker.signals.error.connect(self.on_error)
            self.threadpool.start(worker)
            target = self.anomalies[row]
            self.src_ip = target[IP].src if target.haslayer(IP) else "N/A"
            dst_ip = target[IP].dst if target.haslayer(IP) else "N/A"
            protocol = self.protocolExtractor.extract_protocol(target)
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
            
            # Refresh the table to apply word wrap and resize properties
            self.ui.tableWidget_3.resizeRowsToContents()
        except Exception as e:
            print(e)
    
    def on_result(self, output):
        print("✅ Result:", output)
        self.etime = time.time()
        tTime = self.etime - self.stime
        print(f"##########################\nTotal Runtime for Scraping: {self.etime - self.stime:.2f} seconds\n")
        self.logModel.log_step("Recieved instructions (expand to see)")
        self.logModel.log_details(output)
        item = QTableWidgetItem(output)
        item.setTextAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.ui.tableWidget_3.setItem(5, 1, item)
        self.ui.tableWidget_3.resizeRowsToContents()
        self.mitigate(output, self.src_ip, self.dport, tTime)

        
    def on_error(self, error_msg):
        print("❌ Error:", error_msg)
        self.logModel.log_step(f"Failed to Procure Intelligence; Analyst Intervention Required")
        self.ui.tableWidget_3.setItem(5, 1, QTableWidgetItem(error_msg))
    
    #======================================================================================
    #======================================================================================
    #                        Threat Mitigation Engine Handling
    #======================================================================================
    #======================================================================================
    def block_ip(self, ip):
        self.MitEng.block_ip(ip)

    def unblock_ip(self, ip):
        self.MitEng.unblock_ip(ip)

    def block_port(self, port):
        self.MitEng.block_port(port)

    def unblock_port(self, port):
        self.MitEng.unblock_port(port)

    def limit_rate(self, ip, rate):
        self.MitEng.limit_rate(ip, rate)

    def reset_rate_limit(self, ip):
        self.MitEng.reset_rate_limit(ip)

    def updateBlacklist(self, f):
        try:
            ip = self.ui.lineEdit.text().strip()
            if f == 1:
                self.blacklist.append(ip)
                self.block_ip(ip)
                self.networkLog += "Blocked IP: " + ip + "\n"
            else:
                self.blacklist.remove(ip)
                self.unblock_ip(ip)
                self.networkLog += "Unblocked IP: " + ip + "\n"
            model = QStringListModel()
            model.setStringList(self.blacklist)
            self.ui.listView.setModel(model)
        except Exception as e:
            print(f"Error updating blacklist: {e}")

    def updateBlockedPorts(self, f):
        try:
            port = self.ui.lineEdit_2.text().strip()
            if f == 1:
                if port not in self.blocked_ports:
                    self.blocked_ports.append(port)
                    self.block_port(port)
                    self.networkLog += "Blocked Port: " + port + "\n"
                    row_position = self.ui.tableWidget_2.rowCount()
                    self.ui.tableWidget_2.insertRow(row_position)
                    self.ui.tableWidget_2.setItem(row_position, 0, QTableWidgetItem(str(port)))
                    self.ui.tableWidget_2.setItem(row_position, 1, QTableWidgetItem("Blocked"))
            else:
                if port in self.blocked_ports:
                    self.blocked_ports.remove(port)
                    self.unblock_port(port)
                    self.networkLog += "Unblocked Port: " + port + "\n"
                    self.remove_port_from_table(port)
        except Exception as e:
            print(f"Error updating port blocked: {e}")

    def remove_port_from_table(self, port):
        for row in range(self.ui.tableWidget_2.rowCount()):
            if self.ui.tableWidget_2.item(row, 0) and self.ui.tableWidget_2.item(row, 0).text() == str(port):
                self.ui.tableWidget_2.removeRow(row)
                break

    def terminate_processes(self, identifier):
        try:
            system = platform.system()
            target_pid = None
            try:
                target_pid = int(identifier)
                identifier_type = "pid"
            except ValueError:
                identifier_type = "name"
                if system == "Linux":
                    identifier = identifier.replace('.exe', '')
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    match = False
                    proc_name = proc.info['name'].lower()
                    if system == "Linux":
                        proc_name = proc_name.replace('.exe', '')
                    if identifier_type == "pid" and proc.info['pid'] == target_pid:
                        match = True
                    elif identifier_type == "name" and proc_name == identifier.lower():
                        match = True
                    if match:
                        print(f"Terminating {proc.info['name']} (PID: {proc.info['pid']})...")
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                            if system == "Linux":
                                os.kill(proc.info['pid'], 9)
                            else:
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
                        payload = data.decode().strip()
                        identifier = payload.split()[-1]
                        temp_killer = psutil.Process()
                        try:
                            if identifier.isdigit():
                                temp_killer = psutil.Process(int(identifier))
                            else:
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

    def broadcast_termination(self, pid):
        try:
            message = f"terminate process {pid}"
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udp_socket.sendto(message.encode(), ("255.255.255.255", 5005))
            udp_socket.close()
            print(f"Broadcasted: {message}")
        except Exception as e:
            print(f"Error: {e}")
    #======================================================================================
    #======================================================================================
    #                                 Misc Handling
    #======================================================================================
    #======================================================================================
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
        self.display_anomalies(self.main_window)
    
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


        

class IncidentResponse(QWidget, Ui_IncidentResponse):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.ui = Ui_IncidentResponse()
        self.ui.setupUi(self)
        self.showMaximized()

        self.model = QStandardItemModel()
        self.model.setHeaderData(0, Qt.Orientation.Horizontal, "Attack Log")
        self.ui.treeView.setModel(self.model)
        self.ui.treeView.setWordWrap(True)
        self.ui.treeView.setUniformRowHeights(False)
        self.ui.treeView.expandAll()
        self.logAutopilot = LogWindow(self.model)

        self.controller = IncidentResponseController(
            ui = self.ui,
            anomalies = di.container.resolve("anomalies"),
            protocol_extractor = di.container.resolve("protocol_extractor"),
            autopilot_engine = di.container.resolve("autopilot"),
            threat_intel = di.container.resolve("threat_intelligence"),
            blacklist = di.container.resolve("blacklist"),
            blocked_ports = di.container.resolve("blocked_ports"),
            network_log = di.container.resolve("network_log"),
            mitigation_engine = di.container.resolve("ThreatMitigationEngine"),
            autopilot_log = self.logAutopilot,
            main_window = self.main_window
        )

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.controller.ttTime)
        self.timer.start(1000)
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IncidentResponse()
    window.show()
    sys.exit(app.exec())
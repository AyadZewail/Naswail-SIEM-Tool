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
from UI_IncidentResponse import Ui_IncidentResponse

import multiprocessing
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
class ScraperComponent:
    # Pool of User-Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 Edg/126.0.2592.39",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 OPR/112.0.0.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 Edg/126.0.2592.39",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 Brave/126.0.6478.57",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 Vivaldi/6.7",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 Whale/3.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 Maxthon/7.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36 360Browser/13.1"
    ]
    BING_SEARCH_URL = "https://www.bing.com/search"
    MAX_RETRIES = 3
    MAX_CONCURRENT_REQUESTS = 3
    TIMEOUT = aiohttp.ClientTimeout(total=30)
    BLACKLIST = ["bing.com", "go.microsoft.com", "microsoft.com/en-us", "support.microsoft.com"]
    mit_emb_file = "data/mitigation_embeddings.pt"
    selenium_driver = None
    key_words = {"block", "blocking", "reject", "disable", "restrict", "terminate", "limit", "limiting", "rate", "rate-limiting"}
    logger = logging.getLogger("ScraperComponent")

    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.nlp = spacy.load("en_core_web_sm", disable=["parser", "ner"])
        self.nlp.add_pipe("sentencizer")
        self.key_lemmas = {token.lemma_.lower() for token in self.nlp(" ".join(self.key_words))}

    @staticmethod
    def get_random_user_agent():
        return random.choice(ScraperComponent.USER_AGENTS)

    @staticmethod
    def clean_url(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.split('&')[0]

    @classmethod
    def init_selenium_driver(cls):
        if cls.selenium_driver is None:
            options = Options()
            options.add_argument("--headless=new")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--log-level=3")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-notifications")
            options.add_argument("--disable-application-cache")
            options.add_argument("--disable-logging")
            options.add_argument("--output=/dev/null")
            options.add_argument("--disk-cache-size=0")
            options.add_argument("--disable-features=DiskCache")
            options.add_argument("--blink-settings=imagesEnabled=false")
            options.add_argument("--dns-prefetch-disable")
            options.add_argument("--disable-popup-blocking")
            options.add_argument("--disable-component-update")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("--disable-infobars")
            options.add_argument("--disable-notifications")
            options.add_argument("--disable-popup-blocking")
            options.add_argument("--disable-save-password-bubble")
            options.add_argument("--disable-translate")
            options.add_argument("--disable-web-security")
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--start-maximized")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-plugins-discovery")
            options.add_argument("--disable-plugins")
            options.add_argument("--disable-javascript")
            prefs = {"profile.managed_default_content_settings.images": 2}
            options.add_experimental_option("prefs", prefs)
            options.add_experimental_option('excludeSwitches', ['enable-logging'])
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            options.add_argument(f"user-agent={user_agent}")
            options.page_load_strategy = "eager"
            cls.selenium_driver = webdriver.Chrome(options=options)
            cls.selenium_driver.set_page_load_timeout(8)
            cls.logger.info("Initialized Selenium driver")

    @staticmethod
    def is_valid(url):
        return url.startswith(('http://', 'https://')) and \
            not any(ext in url.lower() for ext in ('.pdf', '.jpg', '.png', '.doc', '.ppt')) and \
            not url.startswith('mailto:')

    @classmethod
    @retry(stop=stop_after_attempt(MAX_RETRIES), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def scrape_bing_results(cls, keyword):
        try:
            headers = {"User-Agent": cls.get_random_user_agent()}
            async with aiohttp.ClientSession(headers=headers, timeout=cls.TIMEOUT) as session:
                encoded_query = quote_plus(keyword)
                url = f"{cls.BING_SEARCH_URL}?q={encoded_query}"
                async with session.get(url) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    results = []
                    for result in soup.select("li.b_algo"):
                        link = result.select_one("h2 a")
                        if link and link.get("href"):
                            url = link["href"]
                            if cls.is_valid(url) and not any(b in url for b in cls.BLACKLIST):
                                results.append(cls.clean_url(url))
                    if not results:
                        results = await cls.scrape_with_selenium_fallback(keyword)
                        if not results:
                            raise Exception("No results found from both aiohttp and Selenium")
                    return results[:10]
        except Exception as e:
            cls.logger.error(f"Error during scraping attempt: {str(e)}")
            raise

    @classmethod
    async def scrape_with_selenium_fallback(cls, keyword):
        try:
            cls.init_selenium_driver()
            cls.selenium_driver.get(f"{cls.BING_SEARCH_URL}?q={quote_plus(keyword)}")
            time.sleep(2)
            elements = cls.selenium_driver.find_elements(By.CSS_SELECTOR, "li.b_algo h2 a")
            urls = []
            for el in elements:
                href = el.get_attribute("href")
                if href and cls.is_valid(href) and not any(b in href for b in cls.BLACKLIST):
                    clean_href = cls.clean_url(href)
                    if clean_href not in urls:
                        urls.append(clean_href)
            return urls[:10]
        except Exception as e:
            cls.logger.error(f"Selenium fallback failed: {str(e)}")
            return []

    @classmethod
    @retry(stop=stop_after_attempt(MAX_RETRIES), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def extract_text(cls, session, link):
        try:
            async with session.get(link, timeout=cls.TIMEOUT) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type:
                        return link, ""
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    paragraphs = soup.find_all('p')
                    text = "\n".join([p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)])
                    return link, text if len(text) > 200 else None
        except Exception as e:
            cls.logger.error(f"Error processing {link}: {str(e)}")
            raise

    @classmethod
    async def process_urls(cls, urls):
        connector = aiohttp.TCPConnector(limit=cls.MAX_CONCURRENT_REQUESTS)
        async with aiohttp.ClientSession(
            headers={"User-Agent": cls.get_random_user_agent()},
            timeout=cls.TIMEOUT,
            connector=connector
        ) as session:
            tasks = []
            for url in urls:
                tasks.append(cls.extract_text(session, url))
                await asyncio.sleep(0.5)
            results = await asyncio.gather(*tasks)
            return [result for result in results if result is not None]

    def save_to_csv(self, data):
        df = pd.DataFrame(data, columns=["URL", "Extracted Text"])
        df.to_csv("data/output.csv", index=False)

    def get_mitigation(self):
        try:
            mitigation_embeddings = torch.load(self.mit_emb_file, map_location='cpu')
        except FileNotFoundError:
            with open("data/mit_refs.txt", "r") as f:
                mitigation_refs = [line.strip() for line in f.readlines()]
            mitigation_embeddings = self.model.encode(mitigation_refs, convert_to_tensor=True)
            torch.save(mitigation_embeddings, self.mit_emb_file, _use_new_zipfile_serialization=False)
        data = pd.read_csv("data/output.csv")
        docs = data["Extracted Text"].tolist()
        docs = list(self.nlp.pipe(docs, batch_size=256))
        sentences = [sent.text.strip() for doc in docs for sent in doc.sents]
        mitigation_sentence, score = self.extract_mitigation_sentences(sentences, mitigation_embeddings)
        return mitigation_sentence, score

    def extract_mitigation_sentences(self, sentences, mitigation_embeddings):
        if not sentences:
            return "No sentences were retrieved", 0.0
        embeddings = self.model.encode(sentences, convert_to_tensor=True)
        scores = util.pytorch_cos_sim(embeddings, mitigation_embeddings).max(dim=1)[0]
        mask = scores > 0.7
        filtered_sentences = [sentences[i] for i in np.where(mask)[0]]
        filtered_scores = scores[mask]
        docs = list(self.nlp.pipe(filtered_sentences, batch_size=64))
        filtered = []
        for sent, score, doc in zip(filtered_sentences, filtered_scores, docs):
            sent_lemmas = {token.lemma_.lower() for token in doc}
            has_key = not self.key_lemmas.isdisjoint(sent_lemmas)
            final_score = score + 0.2 if (has_key) else score
            filtered.append((sent, final_score))
        if not filtered:
            filtered = list(zip(filtered_sentences, filtered_scores))
        sorted_sentences = sorted(filtered, key=lambda x: x[1].item() if hasattr(x[1], 'item') else x[1], reverse=True)
        top_entries = sorted_sentences[:1]
        top_sentences = [sent for sent, _ in top_entries]
        avg_score = torch.mean(torch.stack([s for _, s in top_entries])) if top_entries else 0.0
        return ' '.join(top_sentences), avg_score.item() if hasattr(avg_score, 'item') else avg_score

    async def run_async(self, search_query):
        start_time = time.time()
        retry_count = 0
        max_retries = 3
        while retry_count < max_retries:
            try:
                self.logger.info(f"Searching Bing for: {search_query}")
                links = await self.scrape_bing_results(search_query)
                if not links:
                    raise Exception("No search results found")
                end_time = time.time()
                print(f"##########################\nScraping Runtime: {end_time - start_time:.2f} seconds\n")
                print(f"Extracting content from {len(links)} pages...")
                results = await self.process_urls(links)
                if not results:
                    raise Exception("No content extracted from links")
                print("\n=== Results ===")
                for url, paragraphs in results:
                    print(f"URL: {url}")
                extracted_data = [(url, text) for url, text in results if text]
                if not extracted_data:
                    raise Exception("No valid content extracted")
                self.save_to_csv(extracted_data)
                end_time = time.time()
                print(f"##########################\nFile Processing Runtime: {end_time - start_time:.2f} seconds\n")
                print("Analyzing content for mitigation strategies...")
                mitigation_sentence, score = self.get_mitigation()
                end_time = time.time()
                print(f"\nTotal Runtime: {end_time - start_time:.2f} seconds")
                print(f"\nRelevance Score: {score:.2f}")
                print("\nExtracted Mitigation Strategy:")
                print(mitigation_sentence)
                return mitigation_sentence, score
            except Exception as e:
                retry_count += 1
                self.logger.error(f"Attempt {retry_count} failed: {str(e)}")
                if retry_count < max_retries:
                    wait_time = 2 ** retry_count
                    self.logger.info(f"Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.error("All retry attempts failed")
                    print("Failed to retrieve results after multiple attempts. Please try again later.")
                    return None, 0.0

    def run(self, search_query):
        return asyncio.run(self.run_async(search_query))

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
        NGROK_URL = "https://382d-34-53-70-81.ngrok-free.app"
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

class AnomalousPackets():
    def __init__(self, ui, anomalies, packet, AI, log, scraper):
        self.ui = ui
        self.AIobj = AI
        self.anomalies = anomalies
        self.packetobj = packet
        self.filterapplied = False
        self.filtered_packets = []
        self.threadpool = QThreadPool()
        self.geoip_db_path = "resources/GeoLite2-City.mmdb"
        self.logModel = log
        self.unique_anomalies = set()  # Track unique (src_ip, dst_ip, attack_name) tuples
        self.scraper = scraper
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
            worker = ScraperWorker(attack_name, self.scraper)
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

    def block_ip(self, ip):
        system = platform.system()
        if system == "Linux":
            firewall_command = f"iptables -A INPUT -s {ip} -j DROP"
            self.firewallConfiguration(ip, firewall_command)
        elif system == "Windows":
            firewall_command = f"New-NetFirewallRule -DisplayName 'Block-IP-{ip}' -Direction Inbound -Action Block -RemoteAddress {ip}"
            self.firewallConfiguration(ip, firewall_command)
        else:
            print("Unsupported OS")

    def unblock_ip(self, ip):
        system = platform.system()
        if system == "Linux":
            firewall_command = f"iptables -D INPUT -s {ip} -j DROP"
            self.firewallConfiguration(ip, firewall_command)
        elif system == "Windows":
            firewall_command = f"Remove-NetFirewallRule -DisplayName 'Block-IP-{ip}' -ErrorAction SilentlyContinue"
            self.firewallConfiguration(ip, firewall_command)
        else:
            print("Unsupported OS")

    def block_port(self, port):
        system = platform.system()
        if system == "Linux":
            firewall_command = f"iptables -A INPUT -p tcp --dport {port} -j DROP"
            self.firewallConfiguration(port, firewall_command)
        elif system == "Windows":
            firewall_command = f"New-NetFirewallRule -DisplayName 'Block-Port-{port}' -Direction Inbound -Action Block -Protocol TCP -LocalPort {port}"
            self.firewallConfiguration(port, firewall_command)
        else:
            print("Unsupported OS")
    
    def unblock_port(self, port):
        system = platform.system()
        if system == "Linux":
            firewall_command = f"iptables -D INPUT -p tcp --dport {port} -j DROP"
            self.firewallConfiguration(port, firewall_command)
        elif system == "Windows":
            firewall_command = f"Remove-NetFirewallRule -DisplayName 'Block-Port-{port}' -ErrorAction SilentlyContinue"
            self.firewallConfiguration(port, firewall_command)
        else:
            print("Unsupported OS")
    
    def firewallConfiguration(self, entity, firewall_command):
        """Execute firewall commands directly on the host system."""
        system = platform.system()
        
        try:
            if system == "Linux":
                # For Linux, use sudo to execute iptables command
                cmd = ["sudo", "sh", "-c", firewall_command]
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                print(f"Firewall rule applied for {entity} on host (Linux)")
            elif system == "Windows":
                # For Windows, use PowerShell to execute firewall commands
                ps_cmd = f"powershell -Command \"{firewall_command}\""
                result = subprocess.run(ps_cmd, check=True, capture_output=True, text=True, shell=True)
                print(f"Firewall rule applied for {entity} on host (Windows)")
            else:
                print("Unsupported OS")
                return
                
            if result.stderr:
                print(f"Warning: {result.stderr}")
                
        except subprocess.CalledProcessError as e:
            print(f"Error applying firewall rule: {e}")
            if e.stderr:
                print(f"Error details: {e.stderr}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            
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

class WorkerSignals(QObject):
    finished = pyqtSignal(str)  # Emits final result
    error = pyqtSignal(str)     # Emits error messages

class ScraperWorker(QRunnable):
    def __init__(self, attack_name, scraper):
        super().__init__()
        self.attack_name = attack_name
        self.scraper = scraper
        self.signals = WorkerSignals()
        self.start_time = None

    @pyqtSlot()
    def run(self):
        try:
            self.start_time = time.time()
            print(f"[WORKER] Starting scraper for {self.attack_name} at {self.start_time}")
            # Run the scraper in a thread (blocking call)
            mitigation_sentence, score = self.scraper.run(f"{self.attack_name} mitigation and response")
            print(f"[WORKER] Scraper completed in {time.time() - self.start_time:.3f}s")
            output = mitigation_sentence if mitigation_sentence else ""
            if not output:
                output = f"No mitigation found. Score: {score}"
            print(f"[WORKER] Extracted output length: {len(output)} characters")
            self.signals.finished.emit(output)
        except Exception as e:
            error_msg = f"Worker error after {time.time() - self.start_time:.3f}s: {str(e)}"
            print(f"[WORKER] {error_msg}")
            self.signals.error.emit(error_msg)

class IncidentResponse(QWidget, Ui_IncidentResponse):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.ui = Ui_IncidentResponse()
        self.ui.setupUi(self)
        
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
        self.scraper = ScraperComponent()  # Initialize ONCE
        self.autopilotobj=Autopilot(self.threatMitEngine, self.logAutopilot)
        self.anomalousPacketsObj = AnomalousPackets(self.ui, self.main_window.PacketSystemobj.anomalies, self.main_window.PacketSystemobj, self.autopilotobj, self.logAutopilot, self.scraper)
        self.ui.tableWidget.setColumnCount(7)
        self.ui.tableWidget.setHorizontalHeaderLabels(
            ["Timestamp", "Source IP", "Destination IP", "Src Port", "Dst Port", "Protocol", "Attack"]
        )
        self.ui.tableWidget.cellClicked.connect(self.anomalousPacketsObj.extractThreatIntelligence)

        self.ui.tableWidget_2.setColumnCount(2)
        self.ui.tableWidget_2.setHorizontalHeaderLabels(["Port Number", "Status"])
        
        # Set up Attack Intelligence table with improved word wrap and text display
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
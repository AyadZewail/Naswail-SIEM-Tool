import aiohttp
import asyncio
import random
import time
import logging

from urllib.parse import quote_plus
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from tenacity import retry, stop_after_attempt, wait_exponential

from plugins.incident_response.interfaces import ISourceSearcher

class BingSearcher(ISourceSearcher):
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

    def __init__(self):
        self.logger = logging.getLogger("BingSearcher")
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.driver = None  # Dedicated per instance (per source)

    def get_random_user_agent(self):
        return random.choice(self.USER_AGENTS)

    def clean_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.split('&')[0]

    def is_valid(self, url):
        return url.startswith(('http://', 'https://')) and \
            not any(ext in url.lower() for ext in ('.pdf', '.jpg', '.png', '.doc', '.ppt')) and \
            not url.startswith('mailto:')

    def init_driver(self):
        if self.driver is not None:
            return

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

        self.driver = webdriver.Chrome(options=options)
        self.driver.set_page_load_timeout(8)
        self.logger.info("Initialized Selenium driver for BingSearcher")

    @retry(stop=stop_after_attempt(MAX_RETRIES), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def scrape_bing_results(self, keyword):
        try:
            headers = {"User-Agent": self.get_random_user_agent()}
            async with aiohttp.ClientSession(headers=headers, timeout=self.TIMEOUT) as session:
                encoded_query = quote_plus(keyword)
                url = f"{self.BING_SEARCH_URL}?q={encoded_query}"
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
                            if self.is_valid(url) and not any(b in url for b in self.BLACKLIST):
                                results.append(self.clean_url(url))
                    if not results:
                        results = await self.scrape_with_selenium_fallback(keyword)
                        if not results:
                            raise Exception("No results from aiohttp or Selenium")
                    return results[:10]
        except Exception as e:
            self.logger.error(f"Error during Bing scrape: {e}")
            raise

    async def scrape_with_selenium_fallback(self, keyword):
        try:
            self.init_driver()
            self.driver.get(f"{self.BING_SEARCH_URL}?q={quote_plus(keyword)}")
            time.sleep(2)
            elements = self.driver.find_elements(By.CSS_SELECTOR, "li.b_algo h2 a")
            urls = []
            for el in elements:
                href = el.get_attribute("href")
                if href and self.is_valid(href) and not any(b in href for b in self.BLACKLIST):
                    clean_href = self.clean_url(href)
                    if clean_href not in urls:
                        urls.append(clean_href)
            return urls[:10]
        except Exception as e:
            self.logger.error(f"Selenium fallback failed: {str(e)}")
            return []

    @retry(stop=stop_after_attempt(MAX_RETRIES), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def extract_text(self, session, link):
        try:
            async with session.get(link, timeout=self.TIMEOUT) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type:
                        return None
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    paragraphs = soup.find_all('p')
                    text = "\n".join([p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True)])
                    return text if len(text) > 200 else None
        except Exception as e:
            self.logger.error(f"Error extracting {link}: {e}")
            return None

    async def process_urls(self, urls):
        connector = aiohttp.TCPConnector(limit=self.MAX_CONCURRENT_REQUESTS)
        async with aiohttp.ClientSession(
            headers={"User-Agent": self.get_random_user_agent()},
            timeout=self.TIMEOUT,
            connector=connector
        ) as session:
            tasks = []
            for url in urls:
                tasks.append(self.extract_text(session, url))
                await asyncio.sleep(0.5)
            results = await asyncio.gather(*tasks)
            return [text for text in results if text]

    async def search(self, query: str) -> dict:
        try:
            self.logger.info(f"BingSearcher searching for: {query}")
            urls = await self.scrape_bing_results(query.get("query", ''))
            if not urls:
                return {"source": "bing", "raw_data": ""}

            extracted_texts = await self.process_urls(urls)

            combined_text = "\n\n".join(extracted_texts)

            return {
                "source": "bing",
                "raw_data": combined_text
            }
        except Exception as e:
            self.logger.error(f"Bing search failed: {e}")
            return {"source": "bing", "raw_data": ""}
from abc import ABC, abstractmethod
from typing import Dict, List
import asyncio
from playwright.async_api import async_playwright
import random
import logging
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from tenacity import retry, stop_after_attempt, wait_exponential
# from plugins.incident_response.interfaces import ISourceSearcher
class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        pass
class BingSearcher(ISourceSearcher):
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
    selenium_driver = None
    logger = logging.getLogger("BingSearcher")

    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def search(self, query: Dict) -> Dict:
        """
        Perform a Bing search and scrape content from results.

        Args:
            query (Dict): Should contain 'search_query' key with the search term.
                         Optional: 'max_results' (default: 10)

        Returns:
            Dict: Contains 'success' (bool), 'urls' (list), 'results' (list of dicts with url and text),
                  'error' (str, if failed)
        """
        search_query = query.get('search_query', '')
        max_results = query.get('max_results', 10)
        
        if not search_query:
            return {
                'success': False,
                'error': 'No search query provided',
                'urls': [],
                'results': []
            }
        
        return asyncio.run(self._search_async(search_query, max_results))

    async def _search_async(self, search_query: str, max_results: int = 10) -> Dict:
        """Internal async search implementation"""
        retry_count = 0
        
        while retry_count < self.MAX_RETRIES:
            try:
                self.logger.info(f"Searching Bing for: {search_query}")
                links = await self.scrape_bing_results(search_query, max_results)
                
                if not links:
                    raise Exception("No search results found")
                
                self.logger.info(f"Extracting content from {len(links)} pages...")
                results = await self.process_urls(links)
                
                if not results:
                    raise Exception("No content extracted from links")
                
                # Format results
                extracted_data = [
                    {'url': url, 'text': text} 
                    for url, text in results if text
                ]
                
                return {
                    'success': True,
                    'urls': [r['url'] for r in extracted_data],
                    'results': extracted_data,
                    'count': len(extracted_data)
                }
                
            except Exception as e:
                retry_count += 1
                self.logger.error(f"Attempt {retry_count} failed: {str(e)}")
                
                if retry_count < self.MAX_RETRIES:
                    wait_time = 2 ** retry_count
                    self.logger.info(f"Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.error("All retry attempts failed")
                    return {
                        'success': False,
                        'error': str(e),
                        'urls': [],
                        'results': []
                    }

    @staticmethod
    def get_random_user_agent():
        return random.choice(BingSearcher.USER_AGENTS)

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
            options.add_argument("--disable-infobars")
            options.add_argument("--disable-save-password-bubble")
            options.add_argument("--disable-translate")
            options.add_argument("--disable-web-security")
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--start-maximized")
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
    async def scrape_bing_results(cls, keyword, max_results=10):
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
                        results = await cls.scrape_with_selenium_fallback(keyword, max_results)
                        if not results:
                            raise Exception("No results found from both aiohttp and Selenium")
                    return results[:max_results]
        except Exception as e:
            cls.logger.error(f"Error during scraping attempt: {str(e)}")
            raise

    @classmethod
    async def scrape_with_selenium_fallback(cls, keyword, max_results=10):
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
            return urls[:max_results]
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
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [result for result in results if result is not None and not isinstance(result, Exception)]



def main():
    """
    Test function for BingSearcher with DoS attack query
    """
    # Initialize the searcher
    searcher = BingSearcher()
    
    # Define the search query for DoS attacks
    query = {
        'search_query': 'DoS attack mitigation techniques',
        'max_results': 5  # Limit to 5 results for testing
    }
    
    print("=" * 80)
    print("Testing BingSearcher with DoS Attack Query")
    print("=" * 80)
    print(f"Search Query: {query['search_query']}")
    print(f"Max Results: {query['max_results']}")
    print("=" * 80)
    print("\nSearching...\n")
    
    # Perform the search
    result = searcher.search(query)
    
    # Check if search was successful
    if result['success']:
        print(f"✓ Search completed successfully!")
        print(f"✓ Found {result['count']} results\n")
        print("=" * 80)
        print("RESULTS:")
        print("=" * 80)
        
        # Display each result
        for idx, item in enumerate(result['results'], 1):
            print(f"\n[Result {idx}]")
            print(f"URL: {item['url']}")
            print(f"Text Preview (first 300 chars):")
            print("-" * 80)
            # Display first 300 characters of extracted text
            preview = item['text'][:300] if len(item['text']) > 300 else item['text']
            print(preview)
            if len(item['text']) > 300:
                print("...")
            print("-" * 80)
        
        print(f"\n{'=' * 80}")
        print("SUMMARY:")
        print(f"{'=' * 80}")
        print(f"Total URLs found: {len(result['urls'])}")
        print("\nAll URLs:")
        for idx, url in enumerate(result['urls'], 1):
            print(f"  {idx}. {url}")
            
    else:
        print(f"✗ Search failed!")
        print(f"Error: {result.get('error', 'Unknown error')}")
        print(f"URLs found: {len(result['urls'])}")
        print(f"Results extracted: {len(result['results'])}")
    
    print("\n" + "=" * 80)
    print("Test completed")
    print("=" * 80)


if __name__ == "__main__":
    # Set logging level to see progress
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nTest failed with exception: {str(e)}")
        import traceback
        traceback.print_exc()
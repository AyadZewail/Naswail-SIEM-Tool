from abc import ABC, abstractmethod
from typing import Dict, List
import asyncio
from urllib.parse import quote_plus
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import random
import time
import logging

LOG = logging.getLogger("BingSearcher")
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        pass


class BingSearcher(ISourceSearcher):
    MAX_RESULTS = 10
    BLACKLIST = ["bing.com", "microsoft.com", "support.microsoft.com"]

    def __init__(self, headless: bool = False):
        # headless=False recommended (we'll run headful but off-screen for reliability)
        self.headless = headless

    def _random_user_agent(self) -> str:
        major = random.randint(100, 150)
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"

    def is_valid_url(self, url: str) -> bool:
        return url.startswith("http") and not any(b in url for b in self.BLACKLIST)

    async def _human_mouse_walk(self, page, duration_s: float = 1.0):
        """
        Move the mouse in small random steps over the viewport for duration_s seconds.
        Helps appear human to basic detectors.
        """
        try:
            width = await page.evaluate("() => window.innerWidth")
            height = await page.evaluate("() => window.innerHeight")
            steps = max(3, int(duration_s * 6))
            for _ in range(steps):
                x = random.randint(50, max(50, width - 50))
                y = random.randint(50, max(50, height - 50))
                await page.mouse.move(x, y, steps=random.randint(5, 15))
                await asyncio.sleep(random.uniform(0.05, 0.25))
        except Exception:
            # non-fatal
            pass

    async def _human_scroll(self, page, parts: int = 3):
        """
        Scroll the page in a few parts with small pauses to mimic reading.
        """
        try:
            for i in range(parts):
                # scroll by a fraction of the viewport
                await page.evaluate(
                    "(p) => window.scrollBy(0, Math.floor(window.innerHeight * p));", parts * 0.2
                )
                await asyncio.sleep(random.uniform(0.4, 1.1))
        except Exception:
            pass

    async def _fetch_search_results(self, page, query: str) -> List[str]:
        # Navigate to Bing search results (we build URL directly for reliability)
        search_url = f"https://www.bing.com/search?q={quote_plus(query)}"
        await page.goto(search_url, timeout=30000)
        # small human-like actions before scraping
        await asyncio.sleep(random.uniform(0.6, 1.2))
        await self._human_mouse_walk(page, duration_s=random.uniform(0.8, 1.6))
        await self._human_scroll(page, parts=random.randint(2, 4))

        # Wait for a result to be present
        await page.wait_for_selector("li.b_algo h2 a", timeout=15000)
        elements = await page.query_selector_all("li.b_algo h2 a")
        urls = []
        for el in elements[: self.MAX_RESULTS * 2]:  # look a bit further to allow filtering
            try:
                href = await el.get_attribute("href")
                if href and self.is_valid_url(href):
                    if href not in urls:
                        urls.append(href)
                if len(urls) >= self.MAX_RESULTS:
                    break
            except Exception:
                continue
        # small randomized pause after collecting links
        await asyncio.sleep(random.uniform(0.3, 0.9))
        return urls

    async def _extract_page_text(self, context, url: str) -> str:
        """
        Open a new page under given context, emulate human reading, then extract paragraphs.
        """
        page = await context.new_page()
        try:
            await page.goto(url, timeout=25000)
            # let page render some JS
            await asyncio.sleep(random.uniform(0.8, 2.0))

            # human-like behavior on target page
            await self._human_mouse_walk(page, duration_s=random.uniform(0.6, 1.4))
            # scroll slowly down the page
            viewport_height = await page.evaluate("() => window.innerHeight")
            # scroll in several small increments
            increments = random.randint(2, 5)
            for _ in range(increments):
                await page.evaluate("() => window.scrollBy(0, Math.floor(window.innerHeight/3))")
                await asyncio.sleep(random.uniform(0.6, 1.6))

            # small click on body (safe) to simulate focus changes
            try:
                await page.click("body", timeout=2000)
            except Exception:
                pass

            # extract HTML and parse
            content = await page.content()
            soup = BeautifulSoup(content, "html.parser")
            paragraphs = soup.find_all("p")
            text = "\n".join(p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True))
            return text if len(text) > 50 else ""
        except Exception:
            return ""
        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def _search_async(self, query_text: str) -> Dict:
        """
        Main async workflow with human-like behaviors and a small stealth init script.
        """
        try:
            async with async_playwright() as p:
                # launch in headful but off-screen (favored for reliability)
                args = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-infobars",
                    "--window-size=1200,800",
                    "--window-position=-10000,-10000",
                ]

                browser = await p.chromium.launch(headless=self.headless, args=args)

                # new context with randomized UA and small init script to mask automation flags
                ua = self._random_user_agent()
                context = await browser.new_context(user_agent=ua, viewport={"width": 1200, "height": 800})
                await context.add_init_script(
                    """
                    Object.defineProperty(navigator, 'webdriver', { get: () => false });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
                    window.chrome = window.chrome || { runtime: {} };
                    """
                )

                page = await context.new_page()
                page.set_default_navigation_timeout(30000)
                page.set_default_timeout(15000)

                # perform search and gather result URLs with human-like touches
                urls = await self._fetch_search_results(page, query_text)

                # visit each url and extract page paragraphs (human-like pacing)
                all_text = []
                for url in urls:
                    # small random wait before opening next site (simulate reading/searching)
                    await asyncio.sleep(random.uniform(0.7, 2.2))
                    text = await self._extract_page_text(context, url)
                    if text:
                        all_text.append(text)

                # cleanup
                try:
                    await context.close()
                except Exception:
                    pass
                try:
                    await browser.close()
                except Exception:
                    pass

                return {"source": "bing", "raw_data": "\n\n".join(all_text)}
        except Exception as e:
            LOG.exception("Unexpected error in BingSearcher: %s", e)
            return {"source": "bing", "raw_data": ""}

    def search(self, query: Dict) -> Dict:
        query_text = query.get("query", "")
        if not query_text:
            return {"source": "bing", "raw_data": ""}
        return asyncio.run(self._search_async(query_text))


# Example usage
if __name__ == "__main__":
    s = BingSearcher(headless=False)
    r = s.search({"query": "DDoS mitigation"})
    print(r["source"])
    print(r["raw_data"][:500], "...")

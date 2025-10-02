from abc import ABC, abstractmethod
from typing import Dict, List
import asyncio
import random
import time
from urllib.parse import quote_plus

from playwright.async_api import async_playwright, Browser, BrowserContext
from bs4 import BeautifulSoup


class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        pass


class GoogleSearcher(ISourceSearcher):
    MAX_RESULTS = 8
    BLACKLIST = ["google.com", "webcache.googleusercontent.com"]

    def __init__(self, headful_offscreen: bool = True):
        """
        headful_offscreen = True launches a visible browser but positioned off-screen so Google renders normally.
        """
        self.headful_offscreen = headful_offscreen

    def _random_user_agent(self) -> str:
        # minimal UA rotation; you can expand this list
        major = random.randint(100, 120)
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"

    async def _make_stealth_context(self, p) -> (Browser, BrowserContext):
        """
        Launch a chromium browser and create a context patched for basic stealth.
        """
        args = [
            # keep headful so Google treats it as normal; move off-screen instead of headless
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-infobars",
            "--window-size=1200,800",
            "--window-position=-10000,-10000",
        ]

        browser = await p.chromium.launch(headless=False if self.headful_offscreen else True, args=args)

        ua = self._random_user_agent()
        context = await browser.new_context(
            user_agent=ua,
            viewport={"width": 1200, "height": 800},
            locale="en-US",
        )

        # Add init script to override navigator.webdriver and some fingerprints
        stealth_script = """
        // Pass the Chrome Test.
        Object.defineProperty(navigator, 'webdriver', {get: () => false});
        // Languages
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
        // Plugins
        Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
        // mock chrome runtime
        window.chrome = { runtime: {} };
        // permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
        );
        """
        # apply to every page in this context
        await context.add_init_script(stealth_script)

        return browser, context

    async def _human_like_search(self, page, query: str):
        """
        Perform a human-like Google search interaction to reduce detection risk.
        """
        await page.goto("https://www.google.com", timeout=30000)
        # accept cookies if dialog shows (best-effort)
        try:
            # common consent button selectors; ignore if not found
            for sel in ["button#L2AGLb", "button[aria-label='Accept all']", "form[action*='consent'] button"]:
                btn = await page.query_selector(sel)
                if btn:
                    await btn.click()
                    await asyncio.sleep(random.uniform(0.3, 0.8))
                    break
        except Exception:
            pass

        # find the search box and type like a real user
        # google search input can be input[name=q] or textarea[name=q]
        qsel = "input[name='q'], textarea[name='q']"
        await page.wait_for_selector(qsel, timeout=10000)
        await page.click(qsel)
        # type with delay to mimic human typing
        await page.type(qsel, query, delay=random.randint(80, 160))
        await asyncio.sleep(random.uniform(0.3, 0.7))
        await page.keyboard.press("Enter")
        # wait for results
        await page.wait_for_selector("div#search", timeout=15000)
        # small randomized scroll
        await page.evaluate("window.scrollBy(0, Math.floor(window.innerHeight/3));")
        await asyncio.sleep(random.uniform(0.5, 1.5))

    async def _get_result_urls(self, page) -> List[str]:
        """
        Extracts result URLs from the search results area.
        Uses robust selector: h3 titles under result containers, then parent anchor href.
        """
        urls = []
        # Use the visible results within #search
        elements = await page.query_selector_all("div#search a > h3")
        for el in elements:
            try:
                # get parent <a> href
                url = await el.evaluate("(h) => h.parentElement.href")
                if url and url.startswith("http") and not any(b in url for b in self.BLACKLIST):
                    if url not in urls:
                        urls.append(url)
                if len(urls) >= self.MAX_RESULTS:
                    break
            except Exception:
                continue
        return urls

    async def _extract_ai_overview(self, page) -> str:
        """
        Grabs Google AI Overview if present. Attempt multiple strategies.
        """
        ai_text = ""
        try:
            el = await page.query_selector("div.rPeykc")
            if el:
                ai_text = (await el.inner_text()) or ""
            else:
                # sometimes AI card is in different container; fallback attempt
                alt = await page.query_selector("div[jscontroller] .ayqGOc, div[data-attrid='wa:/description']")
                if alt:
                    ai_text = (await alt.inner_text()) or ""
        except Exception:
            ai_text = ""
        # clean whitespace
        return " ".join(ai_text.split())

    async def _extract_page_paragraphs(self, browser_context: Browser, url: str) -> str:
        """
        Open a new page under the given context and extract <p> text.
        Return a single string (joined paragraphs) or empty string.
        """
        page = await browser_context.new_page()
        try:
            await page.goto(url, timeout=25000)
            # wait small amount for content to render
            await asyncio.sleep(random.uniform(0.6, 1.4))
            content = await page.content()
            soup = BeautifulSoup(content, "html.parser")
            paragraphs = [p.get_text(strip=True) for p in soup.find_all("p") if p.get_text(strip=True)]
            text = "\n".join(paragraphs)
            # short pages are ignored
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
        Main async search routine. Mirrors other searchers' shape and returns:
            { "source": "google", "raw_data": "<ai+pages concatenated>" }
        """
        async with async_playwright() as p:
            browser, context = await self._make_stealth_context(p)

            page = await context.new_page()
            # perform human-like search
            await self._human_like_search(page, query_text)

            # try get ai overview
            ai_text = await self._extract_ai_overview(page)
            # get result urls
            urls = await self._get_result_urls(page)

            # iterate results and extract paragraphs
            all_texts: List[str] = []
            if ai_text:
                all_texts.append(ai_text)

            for url in urls:
                # small delay between visits
                await asyncio.sleep(random.uniform(0.6, 1.6))
                txt = await self._extract_page_paragraphs(context, url)
                if txt:
                    all_texts.append(txt)

            await context.close()
            await browser.close()
            combined = "\n\n".join(all_texts).strip()
            return {"source": "google", "raw_data": combined}

    def search(self, query: Dict) -> Dict:
        query_text = query.get("query", "")
        if not query_text:
            return {"source": "google", "raw_data": ""}
        # run the async pipeline
        return asyncio.run(self._search_async(query_text))


# Example usage:
if __name__ == "__main__":
    searcher = GoogleSearcher(headful_offscreen=True)
    result = searcher.search({"query": "DDoS mitigation"})
    print(result["source"])
    print(result["raw_data"][:1000], "...")

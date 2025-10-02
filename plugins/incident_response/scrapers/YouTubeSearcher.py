from abc import ABC, abstractmethod
from typing import Dict, List
import asyncio
from playwright.async_api import async_playwright
import random
# from plugins.incident_response.interfaces import ISourceSearcher


class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        pass


class YouTubeSearcher(ISourceSearcher):
    def __init__(self, headless: bool = False):
        """
        headless=False but browser will be minimized/off-screen for background execution.
        """
        self.headless = headless

    async def _fetch_video_links(self, page, search_query: str, max_results: int = 5) -> List[str]:
        search_url = f"https://www.youtube.com/results?search_query={search_query.replace(' ', '+')}"
        await page.goto(search_url)
        await page.wait_for_selector("a#video-title")
        video_elements = await page.query_selector_all("a#video-title")
        links = []
        for el in video_elements[:max_results]:
            href = await el.get_attribute("href")
            if href:
                links.append("https://www.youtube.com" + href)
        return links

    async def _extract_transcript(self, page, video_url: str) -> str:
        await page.goto(video_url)
        await asyncio.sleep(random.uniform(2, 4))

        # Click "Show more" if available
        show_more_btn = await page.query_selector("tp-yt-paper-button#expand")
        if show_more_btn:
            try:
                await show_more_btn.click()
                await asyncio.sleep(random.uniform(0.5, 1.0))
            except Exception:
                pass

        # Click "Show transcript" button
        transcript_button = await page.query_selector("button[aria-label='Show transcript']")
        if transcript_button:
            try:
                await transcript_button.click()
                await asyncio.sleep(random.uniform(1, 2))
                lines_elements = await page.query_selector_all("yt-formatted-string.segment-text")
                lines = [await el.inner_text() for el in lines_elements]
                return " ".join(lines)
            except Exception:
                return ""
        else:
            return ""

    async def _search_async(self, query_text: str) -> Dict:
        async with async_playwright() as p:
            # Launch headful but off-screen
            browser = await p.chromium.launch(
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-infobars",
                    "--window-size=800,600",
                    "--window-position=0, 0"  # move browser off-screen
                ]
            )
            context = await browser.new_context()
            page = await context.new_page()

            video_links = await self._fetch_video_links(page, query_text)

            all_text = []
            for link in video_links:
                text = await self._extract_transcript(page, link)
                if text:
                    all_text.append(text)
                await asyncio.sleep(random.uniform(1, 3))

            await browser.close()
            return {"source": "YouTube", "raw_data": " ".join(all_text)}

    async def search(self, query: Dict) -> Dict:
        query_text = query.get("query", "")
        if not query_text:
            return {"source": "YouTube", "raw_data": ""}
        return await self._search_async(query_text)


# Example usage:
if __name__ == "__main__":
    searcher = YouTubeSearcher(headless=False)  # still headful, but invisible
    
    async def main():
        result = await searcher.search({"query": "DDoS mitigation"})
        print(result["source"])
        print(result["raw_data"], "...")

    asyncio.run(main())

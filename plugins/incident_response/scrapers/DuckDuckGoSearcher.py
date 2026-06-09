import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from urllib.parse import unquote, urlparse, parse_qs

import httpx
import trafilatura
from bs4 import BeautifulSoup


# ── Interface ─────────────────────────────────────────────────────────────────

class ISourceSearcher(ABC):
    @abstractmethod
    def search(self, query: Dict) -> Dict:
        """
        Perform a source-specific search using the provided query.

        Args:
            query (Dict): Structured data with relevant search parameters.

        Returns:
            Dict: Raw result or data extracted from the source.
        """
        pass


# ── Implementation ────────────────────────────────────────────────────────────

class DDGSearcher(ISourceSearcher):
    """
    Searches DuckDuckGo via its HTML endpoint (html.duckduckgo.com/html/),
    then concurrently fetches every result page and extracts clean body text
    via trafilatura.

    Return shape:
        {
            "duckassist": str | None,       # zero-click summary if DDG provides one
            "urls":    List[str],            # ordered list of result URLs
            "results": List[{               # full result objects
                "title":   str,
                "url":     str,
                "snippet": str,
            }],
            "content": str,                 # duckassist + all page text, concatenated
        }
    """

    _URL = "https://html.duckduckgo.com/html/"

    # A realistic browser UA avoids most soft-blocks
    _HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type":    "application/x-www-form-urlencoded",
        "Referer":         "https://duckduckgo.com/",
    }

    def __init__(self, max_results: int = 10):
        self.max_results = max_results

    # ── Public interface ──────────────────────────────────────────────────────

    def search(self, query: Dict) -> Dict:
        return asyncio.run(self._search(query))

    # ── Async core ────────────────────────────────────────────────────────────

    async def _search(self, query: Dict) -> Dict:
        q = query.get("query", "")
        async with httpx.AsyncClient(
            headers=self._HEADERS,
            follow_redirects=True,
            timeout=15.0,
        ) as client:
            resp = await client.post(
                self._URL,
                data={"q": q, "b": "", "kl": "us-en"},
            )
            resp.raise_for_status()
        parsed = self._parse(resp.text)
        parsed["content"] = await self._build_content(parsed)
        return parsed

    # ── Page fetching ─────────────────────────────────────────────────────────

    async def _build_content(self, parsed: Dict) -> str:
        """Concatenate duckassist (if any) with all scraped page text."""
        parts = []
        if parsed.get("duckassist"):
            parts.append(parsed["duckassist"])
        page_text = await self._fetch_pages(parsed["urls"])
        if page_text:
            parts.append(page_text)
        return "\n\n".join(parts)

    async def _fetch_pages(self, urls: List[str]) -> str:
        """Fetch all URLs concurrently (max 5 in-flight) and extract body text."""
        sem = asyncio.Semaphore(5)
        async with httpx.AsyncClient(
            headers=self._HEADERS,
            follow_redirects=True,
            timeout=15.0,
        ) as client:
            tasks = [self._fetch_one(client, url, sem) for url in urls]
            texts = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [t for t in texts if isinstance(t, str) and t.strip()]
        return "\n\n".join(valid)

    @staticmethod
    async def _fetch_one(
        client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore
    ) -> Optional[str]:
        """Fetch a single page and return trafilatura-extracted text, or None on failure."""
        try:
            async with sem:
                resp = await client.get(url)
                resp.raise_for_status()
            return trafilatura.extract(resp.text, include_comments=False, no_fallback=False)
        except Exception:
            return None

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse(self, html: str) -> Dict:
        soup = BeautifulSoup(html, "html.parser")
        results: List[Dict] = []

        for tag in soup.find_all("a", class_="result__a"):
            if len(results) >= self.max_results:
                break
            url = self._extract_url(tag.get("href", ""))
            if not url:
                continue
            results.append({
                "title":   tag.get_text(strip=True),
                "url":     url,
                "snippet": self._get_snippet(tag),
            })

        return {
            "duckassist": self._get_duckassist(soup),
            "urls":       [r["url"] for r in results],
            "results":    results,
        }

    @staticmethod
    def _get_duckassist(soup: BeautifulSoup) -> Optional[str]:
        """
        The HTML endpoint surfaces zero-click info (DDG's AI answer equivalent)
        in a <div class="zci__result"> block, not the React data-testid attribute
        from the SPA (which httpx can't reach anyway).
        """
        zero_click = soup.find("div", class_="zci__result")
        if zero_click:
            return zero_click.get_text(separator=" ", strip=True)
        return None

    @staticmethod
    def _get_snippet(link_tag) -> str:
        body = link_tag.find_parent("div", class_="result__body")
        if not body:
            return ""
        snippet = body.find("a", class_="result__snippet")
        return snippet.get_text(strip=True) if snippet else ""

    @staticmethod
    def _extract_url(href: str) -> Optional[str]:
        """
        DDG wraps every result in a redirect:
            /l/?uddg=https%3A%2F%2Fexample.com%2F&rut=abc123
        Decode it to get the real URL.
        """
        if not href:
            return None
        # Already a direct URL (edge case)
        if href.startswith("http") and "duckduckgo.com/l/" not in href:
            return href
        # Decode redirect
        if "uddg=" in href:
            try:
                full = href if href.startswith("http") else f"https://duckduckgo.com{href}"
                params = parse_qs(urlparse(full).query)
                uddg = params.get("uddg", [None])[0]
                return unquote(uddg) if uddg else None
            except Exception:
                return None
        return None


# ── Quick smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    searcher = DDGSearcher(max_results=10)
    result = searcher.search({"query": "DDoS mitigation"})

    print(f"DuckAssist: {result['duckassist']}\n")
    for i, r in enumerate(result["results"], 1):
        print(f"{i}. {r['title']}")
        print(f"   {r['url']}")
        print(f"   {r['snippet'][:120]}...\n")
    print(f"--- content preview (first 500 chars) ---\n{result['content']}")
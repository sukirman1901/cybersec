"""
Dork Scanner — execute dorks via DuckDuckGo + Bing search engines.

Multi-engine approach to avoid Google CAPTCHA. Scrapes HTML results from
DuckDuckGo (html.duckduckgo.com) and Bing (www.bing.com).

New implementation with robust error handling and working sync versions for testing.
"""

import asyncio
import os
import re
from typing import Any, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_HEADERS = {"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"}
_ENGINES = ["ddg", "bing"]

# Ad / redirect domains to drop from search results
_AD_DOMAINS = (
    "duckduckgo.com/y.js",
    "bing.com/aclick",
    "udemy.com",
    "jetbrains.com",
    "alison.com",
    "elegantthemes.com",
)


def _unwrap_search_url(url: str) -> Optional[str]:
    """Resolve DuckDuckGo/Bing redirect wrappers to the destination URL."""
    if not url:
        return None
    parsed = urlparse(url)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        uddg = parse_qs(parsed.query).get("uddg", [None])[0]
        if uddg:
            return unquote(uddg)
        return None
    if "bing.com" in parsed.netloc and "aclick" in parsed.path:
        for key in ("u", "url"):
            target = parse_qs(parsed.query).get(key, [None])[0]
            if target:
                return unquote(target)
        return None
    if any(ad in url.lower() for ad in _AD_DOMAINS):
        return None
    return url


async def _scan_serpapi(query: str, max_results: int, client: httpx.AsyncClient) -> list[dict]:
    """Search via SerpAPI (set SERPAPI_API_KEY)."""
    api_key = os.environ.get("SERPAPI_API_KEY", "")
    if not api_key:
        return []
    results = []
    try:
        resp = await client.get(
            "https://serpapi.com/search.json",
            params={"engine": "google", "q": query, "api_key": api_key, "num": max_results},
            timeout=30,
        )
        if resp.status_code != 200:
            return results
        data = resp.json()
        for item in data.get("organic_results", [])[:max_results]:
            url = item.get("link")
            if url:
                results.append({
                    "url": url,
                    "title": item.get("title", ""),
                    "engine": "serpapi",
                    "dork": query,
                })
    except Exception:
        pass
    return results


async def _scan_ddg(query: str, max_results: int, client: httpx.AsyncClient) -> list[dict]:
    """Scrape DuckDuckGo HTML version for results (POST required)."""
    results = []
    try:
        resp = await client.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query, "b": "", "kl": ""},
            headers={**_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
        )
        if resp.status_code != 200:
            return results

        links = re.findall(
            r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            resp.text,
            re.DOTALL,
        )
        for href, title in links[:max_results]:
            title_clean = re.sub(r"<[^>]+>", "", title).strip()
            if href.startswith("http"):
                actual_url = href
            elif href.startswith("//"):
                actual_url = "https:" + href
            elif href.startswith("/"):
                actual_url = "https://html.duckduckgo.com" + href
            else:
                continue
            actual_url = _unwrap_search_url(actual_url)
            if actual_url:
                results.append({
                    "url": actual_url,
                    "title": title_clean,
                    "engine": "duckduckgo",
                    "dork": query,
                })
    except Exception:
        pass
    return results


async def _scan_bing(query: str, max_results: int, client: httpx.AsyncClient) -> list[dict]:
    """Scrape Bing search results."""
    results = []
    try:
        url = f"https://www.bing.com/search?q={quote(query)}&count={max_results}"
        resp = await client.get(url, headers=_HEADERS, timeout=20)
        if resp.status_code != 200:
            return results

        # Bing results: <li class="b_algo"><h2><a href="...">
        links = re.findall(r'<li[^>]*class="[^"]*b_algo[^"]*"[^>]*>.*?<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', resp.text, re.DOTALL)
        for href, title in links[:max_results]:
            title_clean = re.sub(r'<[^>]+>', '', title).strip()
            if href.startswith("http"):
                href = _unwrap_search_url(href)
                if href:
                    results.append({
                        "url": href,
                        "title": title_clean,
                        "engine": "bing",
                        "dork": query,
                    })
    except Exception:
        pass
    return results


def _scan_ddg_sync(query: str, max_results: int) -> list[dict]:
    """Sync version of DDG scanner for quick testing."""
    results = []
    try:
        with httpx.Client(headers=_HEADERS, timeout=20, follow_redirects=True, verify=False) as client:
            resp = client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query, "b": "", "kl": ""},
                headers={**_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                return results

            links = re.findall(
                r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
                resp.text,
                re.DOTALL,
            )
            for href, title in links[:max_results]:
                title_clean = re.sub(r"<[^>]+>", "", title).strip()
                if href.startswith("http"):
                    actual_url = href
                elif href.startswith("//"):
                    actual_url = "https:" + href
                elif href.startswith("/"):
                    actual_url = "https://html.duckduckgo.com" + href
                else:
                    continue
                actual_url = _unwrap_search_url(actual_url)
                if actual_url:
                    results.append({
                        "url": actual_url,
                        "title": title_clean,
                        "engine": "duckduckgo",
                        "dork": query,
                    })
    except Exception:
        pass
    return results


def _scan_bing_sync(query: str, max_results: int) -> list[dict]:
    """Sync version of Bing scanner."""
    results = []
    try:
        url = f"https://www.bing.com/search?q={quote(query)}&count={max_results}"
        with httpx.Client(headers=_HEADERS, timeout=20, verify=False) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return results

            links = re.findall(r'<li[^>]*class="[^"]*b_algo[^"]*"[^>]*>.*?<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', resp.text, re.DOTALL)
            for href, title in links[:max_results]:
                title_clean = re.sub(r'<[^>]+>', '', title).strip()
                if href.startswith("http"):
                    href = _unwrap_search_url(href)
                    if href:
                        results.append({
                            "url": href,
                            "title": title_clean,
                            "engine": "bing",
                            "dork": query,
                        })
    except Exception:
        pass
    return results


def quick_dork_scan(dork: str, engines: str = "ddg,bing", max_results: int = 5) -> list[dict]:
    """Quick sync version for interactive testing."""
    def _scan_one_sync(engine: str):
        if engine == "ddg":
            return _scan_ddg_sync(dork, max_results)
        elif engine == "bing":
            return _scan_bing_sync(dork, max_results)
        return []

    results = []
    engines_list = [e.strip() for e in engines.split(",") if e.strip()]
    for engine in engines_list:
        results.extend(_scan_one_sync(engine))
    return results


# Used by dork_hunt pipeline
_ENGINE_MAP = {
    "ddg": _scan_ddg,
    "duckduckgo": _scan_ddg,
    "bing": _scan_bing,
    "serpapi": _scan_serpapi,
    "google": _scan_serpapi,
}


async def dork_scan(dorks: str = "", engines: str = "ddg,bing", max_results: int = 20, delay: float = 1.0, timeout: int = 15) -> list[dict]:
    """Execute dork queries via multiple search engines.
    
    Args:
        dorks: Comma-separated dork queries
        engines: Comma-separated engine names (ddg, bing)
        max_results: Max results per dork per engine
        delay: Delay between requests in seconds
        timeout: HTTP timeout in seconds
    
    Returns:
        List of result dicts with url, title, engine, dork fields
    """
    engine_list = [e.strip() for e in engines.split(",") if e.strip()]
    dork_list = [d.strip() for d in dorks.split("\n") if d.strip()]
    if not dork_list:
        dork_list = [dorks] if dorks else []
    
    async def _scan_engine(client, query, engine):
        if engine in _ENGINE_MAP:
            return await _ENGINE_MAP[engine](query, max_results, client)
        return []
    
    results = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        for dork in dork_list:
            for engine in engine_list:
                res = await _scan_engine(client, dork, engine)
                results.extend(res)
                if delay and len(engine_list) > 1:
                    await asyncio.sleep(delay)
    return results

# Helper for quick testing (single dork)
async def test_single_dork_sync(dork: str, engine: str = "ddg") -> list[dict]:
    """Test a single dork with sync version."""
    if engine == "ddg":
        return _scan_ddg_sync(dork, 5)
    elif engine == "bing":
        return _scan_bing_sync(dork, 5)
    return []


__all__ = ["quick_dork_scan", "test_single_dork_sync"]
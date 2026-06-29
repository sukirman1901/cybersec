"""
Dork Scanner — execute dorks via DuckDuckGo + Bing search engines.

Multi-engine approach to avoid Google CAPTCHA. Scrapes HTML results from
DuckDuckGo (html.duckduckgo.com) and Bing (www.bing.com).
"""

import asyncio
import re
from typing import Any
from urllib.parse import quote, urljoin

import httpx

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_HEADERS = {"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"}


async def _scan_ddg(query: str, max_results: int, client: httpx.AsyncClient) -> list[dict]:
    """Scrape DuckDuckGo HTML version for results."""
    results = []
    try:
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        resp = await client.get(url, headers=_HEADERS)
        if resp.status_code != 200:
            return results

        # DDG HTML results: <a class="result__a" href="...">
        links = re.findall(r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]*)"[^>]*>(.*?)</a>', resp.text, re.DOTALL)
        for href, title in links[:max_results]:
            title_clean = re.sub(r'<[^>]+>', '', title).strip()
            # DDG wraps URLs in redirect: //duckduckgo.com/l/?uddg=ENCODED_URL
            actual_url = href
            uddg_match = re.search(r'uddg=([^&]+)', href)
            if uddg_match:
                from urllib.parse import unquote
                actual_url = unquote(uddg_match.group(1))
            elif href.startswith("//"):
                actual_url = "https:" + href
            elif href.startswith("/"):
                actual_url = "https://html.duckduckgo.com" + href

            if actual_url.startswith("http"):
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
        resp = await client.get(url, headers=_HEADERS)
        if resp.status_code != 200:
            return results

        # Bing results: <li class="b_algo"><h2><a href="...">
        links = re.findall(r'<li[^>]*class="[^"]*b_algo[^"]*"[^>]*>.*?<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', resp.text, re.DOTALL)
        for href, title in links[:max_results]:
            title_clean = re.sub(r'<[^>]+>', '', title).strip()
            if href.startswith("http"):
                results.append({
                    "url": href,
                    "title": title_clean,
                    "engine": "bing",
                    "dork": query,
                })
    except Exception:
        pass
    return results


async def _scan_google(query: str, max_results: int, client: httpx.AsyncClient) -> list[dict]:
    """Scrape Google search results (may hit CAPTCHA)."""
    results = []
    try:
        url = f"https://www.google.com/search?q={quote(query)}&num={min(max_results, 10)}"
        resp = await client.get(url, headers=_HEADERS)
        if resp.status_code != 200:
            return results

        # Google results: <a href="/url?q=...">
        links = re.findall(r'<a[^>]*href="/url\?q=([^&"]+)', resp.text)
        titles = re.findall(r'<a[^>]*href="/url\?q=[^"]*"[^>]*>(.*?)</a>', resp.text, re.DOTALL)

        for i, href in enumerate(links[:max_results]):
            from urllib.parse import unquote
            actual_url = unquote(href)
            title_clean = re.sub(r'<[^>]+>', '', titles[i]).strip() if i < len(titles) else ""
            if actual_url.startswith("http"):
                results.append({
                    "url": actual_url,
                    "title": title_clean,
                    "engine": "google",
                    "dork": query,
                })
    except Exception:
        pass
    return results


_ENGINE_MAP = {
    "ddg": _scan_ddg,
    "duckduckgo": _scan_ddg,
    "bing": _scan_bing,
    "google": _scan_google,
}


async def dork_scan(
    dorks: str = "",
    engines: str = "ddg,bing",
    max_results: int = 20,
    delay: float = 1.0,
    timeout: int = 15,
) -> dict:
    """Execute dork queries via multiple search engines.

    Args:
        dorks:       Newline or comma-separated dork queries to execute.
        engines:     Comma-separated engine names — ``"ddg"``, ``"bing"``, ``"google"``
                      (default ``"ddg,bing"``).
        max_results: Max results per dork per engine (default 20).
        delay:       Delay between requests in seconds to avoid rate limiting (default 1.0).
        timeout:     HTTP timeout per request (default 15s).

    Returns:
        A dict with results list, total count, dorks executed, engines used, error.
    """
    result: dict[str, Any] = {
        "results": [],
        "total_count": 0,
        "dorks_executed": 0,
        "engines_used": [],
        "error": None,
    }

    if not dorks:
        result["error"] = "dorks parameter is required (newline or comma-separated)."
        return result

    # Parse dorks
    dork_list = [d.strip() for d in dorks.replace(",", "\n").split("\n") if d.strip()]
    if not dork_list:
        result["error"] = "No valid dorks found in input."
        return result

    # Parse engines
    engine_list = [e.strip().lower() for e in engines.split(",") if e.strip()]
    for e in engine_list:
        if e not in _ENGINE_MAP:
            result["error"] = f"Unknown engine: '{e}'. Available: {', '.join(sorted(_ENGINE_MAP))}"
            return result
    result["engines_used"] = engine_list

    seen_urls = set()
    all_results: list[dict] = []

    async with httpx.AsyncClient(timeout=float(timeout), verify=False, follow_redirects=True) as client:
        for dork in dork_list:
            result["dorks_executed"] += 1

            # Run engines sequentially (avoid parallel CAPTCHA trigger)
            for engine in engine_list:
                scan_fn = _ENGINE_MAP[engine]
                try:
                    engine_results = await scan_fn(dork, max_results, client)
                    for r in engine_results:
                        if r["url"] not in seen_urls:
                            seen_urls.add(r["url"])
                            all_results.append(r)
                except Exception:
                    pass

                if delay > 0:
                    await asyncio.sleep(delay)

    result["results"] = all_results
    result["total_count"] = len(all_results)
    return result

"""Google dorking via HTTP search."""

import urllib.request
import urllib.parse
import re
import ssl
from html import unescape
from .ghdb_search import _text

ctx = ssl.create_default_context()

COVERAGE = ('One search response, at most 1 MiB and five results; matches do not establish '
            'target vulnerability or authorization. Provider completeness unverified.')


def _error(message, invalid=False, truncated=False):
    # Legacy list contract requires a diagnostic entry; it is not a search match.
    return [{"error": message, "record_type": "error", "count": 0,
             "assessment": "incomplete", "coverage_complete": False,
             "execution_status": "invalid_input" if invalid else "partial",
             "truncated": truncated, "coverage": COVERAGE}]

def google_dork(query: str) -> list[dict]:
    """Perform Google dork search and return results."""
    results = []
    if (not isinstance(query, str) or not query.strip() or len(query) > 2048
            or any(ord(c) < 32 or ord(c) == 127 for c in query)):
        return _error('Invalid query', invalid=True)
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://www.google.com/search?q={encoded}&num=5"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html",
        })
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read(1048577)
        if len(body) > 1048576:
            return _error('Provider response exceeds byte limit', truncated=True)
        html = body.decode("utf-8", errors="replace")
        for match in re.finditer(r'<a\b[^>]*href="/url\?q=(.*?)&[^>]*>(.*?)</a>', html, re.S | re.I):
            url = urllib.parse.unquote(unescape(match.group(1)))
            parsed = urllib.parse.urlsplit(url)
            title = _text(match.group(2))
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or len(url) > 4096 or len(title) > 2048:
                continue
            results.append({"url": _text(url), "title": title, "record_type": "search_match",
                            "assessment": "provider_records", "coverage": COVERAGE,
                            "coverage_complete": False})
            if len(results) >= 6:
                break
        if len(results) > 5:
            results = results[:5]
            for result in results:
                result['truncated'] = True
        if not results and 'did not match any documents' not in html.lower():
            return _error('Unrecognized provider response')
    except Exception as e:
        return _error(type(e).__name__)
    return results

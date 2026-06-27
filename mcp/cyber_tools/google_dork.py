"""Google dorking via HTTP search."""

import urllib.request
import urllib.parse
import re
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def google_dork(query: str) -> list[dict]:
    """Perform Google dork search and return results."""
    results = []
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://www.google.com/search?q={encoded}&num=5"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html",
        })
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        html = resp.read().decode("utf-8", errors="replace")
        resp.close()
        for match in re.finditer(r'<a href="/url\?q=(.*?)&.*?>(.*?)</a>', html):
            url = urllib.parse.unquote(match.group(1))
            title = re.sub(r'<.*?>', '', match.group(2))
            if not url.startswith("http"):
                continue
            results.append({"url": url, "title": title})
            if len(results) >= 5:
                break
    except Exception as e:
        results.append({"error": str(e)})
    return results

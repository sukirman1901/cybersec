"""Directory and file brute-forcing using Python urllib."""

import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def dir_bust(target: str, wordlist: list[str], extensions: list[str] = ["", ".php", ".html", ".bak", ".txt"]) -> list[dict]:
    """Brute force directories and files."""
    target = target.rstrip("/")
    if not target.startswith("http"):
        target = f"https://{target}"
    results = []
    for word in wordlist:
        for ext in extensions:
            path = f"{word}{ext}"
            url = f"{target}/{path}"
            try:
                req = urllib.request.Request(url, method="HEAD" if not ext else "GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = urllib.request.urlopen(req, timeout=3, context=ctx)
                if resp.status < 400 or resp.status == 401 or resp.status == 403:
                    results.append({"url": url, "status": resp.status, "size": resp.length or 0})
                resp.close()
            except urllib.error.HTTPError as e:
                if e.code in [401, 403]:
                    results.append({"url": url, "status": e.code, "size": 0})
            except Exception:
                pass
    return results

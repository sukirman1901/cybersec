"""Bounded Telegram page observations; no identity confirmation or metadata export."""

import asyncio
import re
import httpx

_MAX_REQUEST_SECONDS = 60


async def telegram_osint(username: str, timeout: int = 15) -> dict:
    """Observe a public page. A username mention is only a candidate match.

    Personal metadata is deliberately omitted. Generated links are redacted
    templates, never evidence of history, ownership or a related identity.
    """
    result = {
        "username": "[redacted]", "user_id": None, "bio": "",
        "profile_photo": "", "exists": None, "identity_confirmed": False,
        "username_history_links": [], "search_links": [], "raw_meta": {},
        "status": "incomplete", "status_code": 0, "error": None,
        "metadata_omitted": True,
    }
    if not isinstance(username, str) or len(username) > 33:
        result["error"] = "Invalid Telegram username."
        return result
    username = username.strip().removeprefix("@")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", username):
        result["error"] = "Invalid Telegram username."
        return result
    if type(timeout) is not int or not 1 <= timeout <= 60:
        result["error"] = "timeout must be 1..60 seconds."
        return result

    try:
        async with asyncio.timeout(min(timeout, _MAX_REQUEST_SECONDS)), httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            async with client.stream("GET", f"https://t.me/{username}") as resp:
                result["status_code"] = resp.status_code
                if resp.status_code in (404, 410):
                    result.update(exists=False, status="not_found")
                    return result
                if resp.status_code != 200:
                    result["error"] = "Provider response inconclusive."
                    return result
                body = bytearray()
                async for chunk in resp.aiter_bytes(chunk_size=4096):
                    if len(body) + len(chunk) > 65536:
                        result["error"] = "Response exceeds 65536 bytes."
                        return result
                    body.extend(chunk)
                html = body.decode("utf-8", "replace")
                mention = re.search(r"(?<![\w])" + re.escape(username) + r"(?![\w])", html, re.I)
                if mention and 'tgme_page_title' in html:
                    result["status"] = "candidate"
                    result["observation"] = "username_mention_in_profile_page"
                    result["search_links"] = [{
                        "service": "Google Search", "url": "https://www.google.com/search?q=[redacted]+telegram",
                        "observed": False, "kind": "generated_template_redacted",
                    }]
    except (TimeoutError, httpx.TimeoutException):
        result.update(status="incomplete", exists=None)
        result["error"] = "Provider request timed out."
    except Exception:
        result["error"] = "Provider request failed."
    return result

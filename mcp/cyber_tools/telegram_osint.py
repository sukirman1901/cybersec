"""
Telegram OSINT — gather public info about Telegram users via scraping t.me.

No Telegram API required. Scrapes public t.me profile pages for:
- User ID (from meta tags)
- Bio/description
- Profile photo URL
- Username history links (SangMata, TGStat)
- Related search links
"""

import re
from typing import Any
from urllib.parse import quote

import httpx

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_HEADERS = {"User-Agent": _UA, "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"}


async def telegram_osint(
    username: str,
    timeout: int = 15,
) -> dict:
    """Gather public information about a Telegram user.

    Scrapes the public t.me/@username profile page for user ID, bio,
    profile photo, and generates links to username history services.

    Args:
        username: Telegram username (with or without @).
        timeout:  HTTP timeout (default 15s).

    Returns:
        A dict with user_id, bio, profile_photo, username_history_links,
        search_links, exists, and error.
    """
    result: dict[str, Any] = {
        "username": username,
        "user_id": None,
        "bio": "",
        "profile_photo": "",
        "exists": False,
        "username_history_links": [],
        "search_links": [],
        "raw_meta": {},
        "error": None,
    }

    if not username:
        result["error"] = "username is required."
        return result

    username = username.strip().lstrip("@")
    profile_url = f"https://t.me/{username}"

    try:
        async with httpx.AsyncClient(
            timeout=float(timeout),
            verify=False,
            follow_redirects=True,
            headers=_HEADERS,
        ) as client:
            resp = await client.get(profile_url)

            if resp.status_code == 200:
                html = resp.text
                result["exists"] = True

                # Extract user ID from og:description meta tag or data attributes
                # Telegram embeds user ID in the page as tgme_widget_user_id
                uid_match = re.search(r'data-user-id="(\d+)"', html)
                if uid_match:
                    result["user_id"] = uid_match.group(1)

                # Also try meta tag: <meta property="og:image" content="...user_id=123...">
                if not result["user_id"]:
                    uid_match2 = re.search(r'user_id["\']?\s*[:=]\s*["\']?(\d+)', html)
                    if uid_match2:
                        result["user_id"] = uid_match2.group(1)

                # Extract bio/description from og:description
                bio_match = re.search(r'<meta\s+property="og:description"\s+content="([^"]*)"', html)
                if bio_match:
                    result["bio"] = bio_match.group(1)

                # Extract profile photo from og:image
                photo_match = re.search(r'<meta\s+property="og:image"\s+content="([^"]*)"', html)
                if photo_match:
                    result["profile_photo"] = photo_match.group(1)

                # Extract additional meta data
                title_match = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', html)
                if title_match:
                    result["raw_meta"]["title"] = title_match.group(1)

                # Check if it's a bot
                if "bot" in html.lower() and "BotBot" in html:
                    result["raw_meta"]["is_bot"] = True

            elif resp.status_code == 404 or "tme_widget_iframe" not in resp.text:
                # Page doesn't exist or is not a profile
                if "If you have Telegram, you can contact" not in resp.text:
                    result["exists"] = False
                    result["error"] = f"Telegram user @{username} not found."
                    return result

    except httpx.TimeoutException:
        result["error"] = f"Request timed out after {timeout}s."
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    # Generate username history and lookup links
    if result["exists"]:
        result["username_history_links"] = [
            {
                "service": "SangMata (username history)",
                "url": f"https://t.me/SangMata_bot?start={username}",
                "description": "Track username changes for this Telegram user",
            },
            {
                "service": "TGStat",
                "url": f"https://tgstat.com/en/user/@{username}",
                "description": "Telegram statistics and activity",
            },
            {
                "service": "Telemetr",
                "url": f"https://telemetr.io/en/channel/@{username}",
                "description": "Telegram channel analytics",
            },
            {
                "service": "TelegramDB",
                "url": f"https://telegramdb.org/users/{username}",
                "description": "Telegram user database search",
            },
        ]

        result["search_links"] = [
            {
                "service": "Google Search",
                "url": f"https://www.google.com/search?q=%22{quote(username)}%22+telegram",
                "description": "Search for this username on Google",
            },
            {
                "service": "Google Search (site:telegram)",
                "url": f"https://www.google.com/search?q=site:t.me+{quote(username)}",
                "description": "Search Telegram pages indexed by Google",
            },
            {
                "service": "Google Search (phone/ID)",
                "url": f"https://www.google.com/search?q=%22{quote(username)}%22+%22phone%22",
                "description": "Search for associated phone number",
            },
        ]

        if result["user_id"]:
            result["search_links"].append({
                "service": "Google Search (user ID)",
                "url": f"https://www.google.com/search?q=%22{result['user_id']}%22",
                "description": f"Search for Telegram user ID {result['user_id']}",
            })
            result["username_history_links"].append({
                "service": "SangMata (by user ID)",
                "url": f"https://t.me/SangMata_bot?start={result['user_id']}",
                "description": "Track username changes by user ID",
            })

    return result

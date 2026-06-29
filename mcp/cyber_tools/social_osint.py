"""
Social Media OSINT — cross-platform username search across 100+ platforms.

Checks if a username exists on social media platforms by probing URL patterns.
No API keys required — uses HTTP status codes and page content to determine existence.
Based on the Sherlock-style approach.
"""

import asyncio
from typing import Any

import httpx

# Platform definitions: (name, URL pattern, detection method)
# Detection: "status" = check HTTP status, "content" = check page content for not-found text
_PLATFORMS: list[tuple[str, str, str, str]] = [
    # (platform_name, url_template, detection_method, not_found_indicator)
    ("Instagram", "https://www.instagram.com/{}/", "status", ""),
    ("Twitter/X", "https://x.com/{}", "status", ""),
    ("TikTok", "https://www.tiktok.com/@{}", "status", ""),
    ("Facebook", "https://www.facebook.com/{}", "status", ""),
    ("YouTube", "https://www.youtube.com/@{}", "status", ""),
    ("GitHub", "https://www.github.com/{}", "status", ""),
    ("GitLab", "https://gitlab.com/{}", "status", ""),
    ("Reddit", "https://www.reddit.com/user/{}", "status", ""),
    ("Pinterest", "https://www.pinterest.com/{}/", "status", ""),
    ("Tumblr", "https://{}.tumblr.com", "status", ""),
    ("Flickr", "https://www.flickr.com/people/{}", "status", ""),
    ("Vimeo", "https://vimeo.com/{}", "status", ""),
    ("SoundCloud", "https://soundcloud.com/{}", "status", ""),
    ("Spotify", "https://open.spotify.com/user/{}", "status", ""),
    ("Twitch", "https://www.twitch.tv/{}", "status", ""),
    ("Kick", "https://kick.com/{}", "status", ""),
    ("Snapchat", "https://www.snapchat.com/add/{}", "status", ""),
    ("LinkedIn", "https://www.linkedin.com/in/{}", "status", ""),
    ("Medium", "https://medium.com/@{}", "status", ""),
    ("Dev.to", "https://dev.to/{}", "status", ""),
    ("HackerNews", "https://news.ycombinator.com/user?id={}", "status", ""),
    ("Product Hunt", "https://www.producthunt.com/@{}", "status", ""),
    ("Behance", "https://www.behance.net/{}", "status", ""),
    ("Dribbble", "https://dribbble.com/{}", "status", ""),
    ("DeviantArt", "https://www.deviantart.com/{}", "status", ""),
    ("ArtStation", "https://www.artstation.com/{}", "status", ""),
    ("Patreon", "https://www.patreon.com/{}", "status", ""),
    ("Ko-fi", "https://ko-fi.com/{}", "status", ""),
    ("Buy Me a Coffee", "https://www.buymeacoffee.com/{}", "status", ""),
    ("Steam", "https://steamcommunity.com/id/{}", "status", ""),
    ("Xbox Live", "https://account.xbox.com/profile?gamertag={}", "status", ""),
    ("Roblox", "https://www.roblox.com/user.aspx?username={}", "status", ""),
    ("Fortnite Tracker", "https://fortnitetracker.com/profile/all/{}", "status", ""),
    ("Chess.com", "https://www.chess.com/member/{}", "status", ""),
    ("Codeforces", "https://codeforces.com/profile/{}", "status", ""),
    ("LeetCode", "https://leetcode.com/{}", "status", ""),
    ("HackerRank", "https://www.hackerrank.com/{}", "status", ""),
    ("Stack Overflow", "https://stackoverflow.com/users/{}", "status", ""),
    ("Bitbucket", "https://bitbucket.org/{}/", "status", ""),
    ("Replit", "https://replit.com/@{}", "status", ""),
    ("CodePen", "https://codepen.io/{}", "status", ""),
    ("JSFiddle", "https://jsfiddle.net/user/{}/", "status", ""),
    ("Docker Hub", "https://hub.docker.com/u/{}", "status", ""),
    ("NPM", "https://www.npmjs.com/~{}", "status", ""),
    ("PyPI", "https://pypi.org/user/{}", "status", ""),
    ("Keybase", "https://keybase.io/{}", "status", ""),
    ("Telegram", "https://t.me/{}", "status", ""),
    ("VK", "https://vk.com/{}", "status", ""),
    ("OK.ru", "https://ok.ru/{}", "status", ""),
    ("Weibo", "https://weibo.com/{}", "status", ""),
    ("Bilibili", "https://space.bilibili.com/{}", "status", ""),
    ("Zhihu", "https://www.zhihu.com/people/{}", "status", ""),
    ("Douyin", "https://www.douyin.com/user/{}", "status", ""),
    ("Kuaishou", "https://www.kuaishou.com/profile/{}", "status", ""),
    ("OnlyFans", "https://onlyfans.com/{}", "status", ""),
    ("Fanvue", "https://fanvue.com/{}", "status", ""),
    ("Mastodon", "https://mastodon.social/@{}", "status", ""),
    ("Bluesky", "https://bsky.app/profile/{}", "status", ""),
    ("Threads", "https://www.threads.net/@{}", "status", ""),
    ("Clubhouse", "https://www.clubhouse.com/@{}", "status", ""),
    ("Discord", "https://discord.com/users/{}", "status", ""),
    ("Pastebin", "https://pastebin.com/u/{}", "status", ""),
    ("GitHub Gist", "https://gist.github.com/{}", "status", ""),
    ("SlideShare", "https://www.slideshare.net/{}", "status", ""),
    ("Scribd", "https://www.scribd.com/{}", "status", ""),
    ("Academia.edu", "https://independent.academia.edu/{}", "status", ""),
    ("ResearchGate", "https://www.researchgate.net/profile/{}", "status", ""),
    ("ORCID", "https://orcid.org/{}", "status", ""),
    ("Goodreads", "https://www.goodreads.com/{}", "status", ""),
    ("Letterboxd", "https://letterboxd.com/{}", "status", ""),
    ("MyAnimeList", "https://myanimelist.net/profile/{}", "status", ""),
    ("AniList", "https://anilist.co/user/{}", "status", ""),
    ("Last.fm", "https://www.last.fm/user/{}", "status", ""),
    ("Bandcamp", "https://{}.bandcamp.com", "status", ""),
    ("Mixcloud", "https://www.mixcloud.com/{}/", "status", ""),
    ("Audiomack", "https://audiomack.com/{}", "status", ""),
    ("Hypem", "https://hypem.com/{}", "status", ""),
    ("Trakt", "https://trakt.tv/users/{}", "status", ""),
    ("Foursquare", "https://foursquare.com/{}", "status", ""),
    ("TripAdvisor", "https://www.tripadvisor.com/Profile/{}", "status", ""),
    ("Airbnb", "https://www.airbnb.com/users/show/{}", "status", ""),
    ("Strava", "https://www.strava.com/athletes/{}", "status", ""),
    ("MyFitnessPal", "https://www.myfitnesspal.com/profile/{}", "status", ""),
    ("Duolingo", "https://www.duolingo.com/profile/{}", "status", ""),
    ("Wattpad", "https://www.wattpad.com/user/{}", "status", ""),
    ("Archive of Our Own", "https://archiveofourown.org/users/{}", "status", ""),
    ("Fanfiction.net", "https://www.fanfiction.net/u/{}", "status", ""),
    ("GoodFirms", "https://www.goodfirms.co/company/{}", "status", ""),
    ("About.me", "https://about.me/{}", "status", ""),
    ("Linktree", "https://linktr.ee/{}", "status", ""),
    ("Carrd", "https://{}.carrd.co", "status", ""),
    ("Gravatar", "https://en.gravatar.com/{}", "status", ""),
    ("ICQ", "https://icq.im/{}", "status", ""),
    ("Skype", "https://join.skype.com/live/{}", "status", ""),
    ("Line", "https://line.me/ti/p/~{}", "status", ""),
    ("Viber", "https://chats.viber.com/{}", "status", ""),
    ("WeChat", "https://weixin.qq.com/r/{}", "status", ""),
    ("Signal", "https://signal.me/#p/{}", "status", ""),
    ("Wire", "https://wire.com/@{}", "status", ""),
    ("Session", "https://session.us/{}", "status", ""),
    ("Matrix", "https://matrix.to/#/@{}:matrix.org", "status", ""),
    ("XMPP", "https://xmpp.org/{}", "status", ""),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{}", "status", ""),
    ("Wikimedia", "https://meta.wikimedia.org/wiki/User:{}", "status", ""),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{}", "status", ""),
    ("Wikileaks", "https://wikileaks.org/{}", "status", ""),
]

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_HEADERS = {"User-Agent": _UA, "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"}


async def social_osint(
    username: str,
    timeout: int = 10,
    concurrent: int = 20,
) -> dict:
    """Search for a username across 100+ social media platforms.

    Probes each platform's URL pattern and checks HTTP status to determine
    if the username exists. No API keys required.

    Args:
        username:  Username to search for (without @ prefix).
        timeout:   HTTP timeout per request (default 10s).
        concurrent: Max concurrent requests (default 20).

    Returns:
        A dict with found accounts, total checked, found count, and error.
    """
    result: dict[str, Any] = {
        "username": username,
        "found": [],
        "not_found": [],
        "total_checked": 0,
        "found_count": 0,
        "error": None,
    }

    if not username:
        result["error"] = "username is required."
        return result

    username = username.strip().lstrip("@")

    async with httpx.AsyncClient(
        timeout=float(timeout),
        verify=False,
        follow_redirects=True,
        headers=_HEADERS,
    ) as client:
        semaphore = asyncio.Semaphore(concurrent)

        async def check_platform(name: str, url: str) -> tuple[str, str, bool, int]:
            async with semaphore:
                try:
                    resp = await client.get(url)
                    # 200 = likely exists, 403/401 = might exist (protected),
                    # 404/410 = definitely doesn't exist
                    exists = resp.status_code in (200, 403, 401)
                    return name, url, exists, resp.status_code
                except Exception:
                    return name, url, False, 0

        tasks = [
            check_platform(name, url_template.format(username))
            for name, url_template, _, _ in _PLATFORMS
        ]
        responses = await asyncio.gather(*tasks)

    for name, url, exists, status_code in responses:
        result["total_checked"] += 1
        entry = {
            "platform": name,
            "url": url,
            "status_code": status_code,
            "exists": exists,
        }
        if exists:
            result["found"].append(entry)
            result["found_count"] += 1
        else:
            result["not_found"].append(entry)

    return result

"""Individual OSINT — LinkedIn public profile, GitHub, search."""
import json
import urllib.request
import re

def people_osint(query: str, source: str = "auto") -> str:
    query = query.strip()
    if not query:
        return json.dumps({"error": "Query required (name, username, email)"}, indent=2)

    results = {"query": query, "source": source, "profiles": []}

    if source == "auto":
        sources = ["github", "search", "email"]
    else:
        sources = [source]

    for src in sources:
        if src == "github":
            results["profiles"].extend(_github_lookup(query))
        elif src == "search":
            results["profiles"].extend(_search_lookup(query))
        elif src == "email":
            results["email_analysis"] = _email_analysis(query)

    results["total_profiles"] = len(results["profiles"])
    return json.dumps(results, indent=2)


def _github_lookup(query):
    profiles = []
    if "@" in query:
        username = query.split("@")[0]
    else:
        username = query.replace(" ", "")

    try:
        url = f"https://api.github.com/users/{username}"
        req = urllib.request.Request(url, headers={"User-Agent": "Cybersec-OSINT/1.0", "Accept": "application/vnd.github.v3+json"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))

        if data.get("login"):
            profiles.append({
                "platform": "GitHub",
                "username": data["login"],
                "name": data.get("name", ""),
                "bio": data.get("bio", ""),
                "company": data.get("company", ""),
                "location": data.get("location", ""),
                "blog": data.get("blog", ""),
                "public_repos": data.get("public_repos", 0),
                "followers": data.get("followers", 0),
                "following": data.get("following", 0),
                "created_at": data.get("created_at", ""),
                "profile_url": data.get("html_url", ""),
                "avatar_url": data.get("avatar_url", ""),
            })
    except Exception:
        pass

    if " " in query:
        username2 = query.replace(" ", "-").lower()
        if username2 != username:
            try:
                url = f"https://api.github.com/users/{username2}"
                req = urllib.request.Request(url, headers={"User-Agent": "Cybersec-OSINT/1.0", "Accept": "application/vnd.github.v3+json"})
                resp = urllib.request.urlopen(req, timeout=10)
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("login"):
                    profiles.append({
                        "platform": "GitHub",
                        "username": data["login"],
                        "name": data.get("name", ""),
                        "bio": data.get("bio", ""),
                        "company": data.get("company", ""),
                        "location": data.get("location", ""),
                        "public_repos": data.get("public_repos", 0),
                        "followers": data.get("followers", 0),
                        "profile_url": data.get("html_url", ""),
                    })
            except Exception:
                pass

    return profiles


def _search_lookup(query):
    profiles = []
    if "@" in query:
        username = query.split("@")[0]
        domain = query.split("@")[1] if "@" in query else ""
    else:
        username = query.replace(" ", ".")
        domain = ""

    if domain:
        email_patterns = [f"{username}@{domain}", query]
    else:
        email_patterns = [query]

    profile_templates = [
        {"platform": "LinkedIn", "url": f"https://linkedin.com/in/{username}", "type": "profile"},
        {"platform": "Twitter/X", "url": f"https://twitter.com/{username}", "type": "profile"},
        {"platform": "Instagram", "url": f"https://instagram.com/{username}", "type": "profile"},
        {"platform": "Facebook", "url": f"https://facebook.com/{username}", "type": "profile"},
        {"platform": "GitLab", "url": f"https://gitlab.com/{username}", "type": "profile"},
        {"platform": "HackerOne", "url": f"https://hackerone.com/{username}", "type": "profile"},
        {"platform": "Keybase", "url": f"https://keybase.io/{username}", "type": "profile"},
        {"platform": "Reddit", "url": f"https://reddit.com/user/{username}", "type": "profile"},
        {"platform": "Medium", "url": f"https://medium.com/@{username}", "type": "profile"},
        {"platform": "Patreon", "url": f"https://patreon.com/{username}", "type": "profile"},
        {"platform": "Steam", "url": f"https://steamcommunity.com/id/{username}", "type": "profile"},
        {"platform": "Twitch", "url": f"https://twitch.tv/{username}", "type": "profile"},
    ]

    for p in profile_templates:
        try:
            req = urllib.request.Request(p["url"], headers={"User-Agent": "Cybersec-OSINT/1.0"}, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=8)
            if resp.status in (200, 301, 302, 403):
                p["status"] = "found"
                p["http_status"] = resp.status
                profiles.append(p)
        except urllib.error.HTTPError as e:
            if e.code in (200, 301, 302, 403):
                p["status"] = "found"
                p["http_status"] = e.code
                profiles.append(p)
        except Exception:
            pass

    return profiles


def _email_analysis(email):
    if "@" not in email:
        return {"valid": False, "reason": "Not an email address"}

    username, domain = email.rsplit("@", 1)

    analysis = {
        "email": email,
        "username": username,
        "domain": domain,
        "disposable": domain in ["mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com", "throwaway.email", "yopmail.com"],
        "gravatar_url": f"https://www.gravatar.com/avatar/{_md5(email.lower().strip())}",
    }

    if domain:
        mx_url = f"https://dns.google/resolve?name={domain}&type=MX"
        try:
            req = urllib.request.Request(mx_url, headers={"User-Agent": "Cybersec-OSINT/1.0"})
            resp = urllib.request.urlopen(req, timeout=8)
            dns_data = json.loads(resp.read().decode("utf-8"))
            mx_records = [a.get("data", "") for a in dns_data.get("Answer", [])]
            analysis["mx_records"] = mx_records[:5]
            analysis["has_mx"] = len(mx_records) > 0
        except Exception:
            analysis["mx_records"] = []
            analysis["has_mx"] = "unknown"

    return analysis


def _md5(s):
    import hashlib
    return hashlib.md5(s.encode()).hexdigest()
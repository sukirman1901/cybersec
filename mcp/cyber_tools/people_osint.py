"""Bounded provider observations and username candidates, not identity matches."""
import json
import urllib.request
import urllib.error
import re
from urllib.parse import quote

_MAX_READ = 65536


def _read_json(resp):
    raw = resp.read(_MAX_READ + 1)
    if len(raw) > _MAX_READ:
        raise ValueError("Response too large")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Invalid response")
    return data

def people_osint(query: str, source: str = "auto") -> str:
    if not isinstance(query, str) or len(query) > 254 or any(ord(c) < 32 for c in query):
        return json.dumps({"error": "Invalid query (maximum 254 characters)."})
    query = query.strip()
    if not query:
        return json.dumps({"error": "Query required (name, username, email)"}, indent=2)

    if source not in ("auto", "github", "search", "email"):
        return json.dumps({"error": "Unsupported source."})
    results = {"query": "[redacted]", "source": source, "profiles": [],
               "observations": [], "identity_confirmed": False}

    if source == "auto":
        sources = ["github", "search", "email"]
    else:
        sources = [source]

    for src in sources:
        if src == "github":
            observations = _github_lookup(query)
            results["observations"].extend(observations)
            results["profiles"].extend(row for row in observations if row.get("status") == "candidate")
        elif src == "search":
            results["observations"].extend(_search_lookup(query))
        elif src == "email":
            results["email_analysis"] = _email_analysis(query)

    results["total_profiles"] = len(results["profiles"])
    return json.dumps(results, indent=2)


def _github_lookup(query):
    # Do not infer a GitHub identity from a person's name or email local-part.
    entry = {"platform": "GitHub", "status": "incomplete", "identity_confirmed": False}
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,38}", query):
        entry["reason"] = "An explicit username is required; no identity inference."
        return [entry]
    try:
        req = urllib.request.Request(f"https://api.github.com/users/{query}", headers={"User-Agent": "Cybersec-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            entry["http_status"] = resp.status
            if resp.status == 200:
                data = _read_json(resp)
                login = data.get("login")
                if isinstance(login, str) and login.casefold() == query.casefold():
                    entry.update(status="candidate", observation="provider_username_match", username="[redacted]")
            elif resp.status in (404, 410):
                entry["status"] = "not_found"
    except urllib.error.HTTPError as exc:
        entry["http_status"] = exc.code
        if exc.code in (404, 410):
            entry["status"] = "not_found"
        exc.close()
    except Exception:
        entry["reason"] = "Provider request or response incomplete."
    return [entry]


def _search_lookup(query):
    profiles = []
    if "@" in query:
        username = query.split("@")[0]
        domain = query.split("@")[1] if "@" in query else ""
    else:
        username = query.replace(" ", ".")
        domain = ""

    username = quote(username, safe="")

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
        p.update(status="incomplete", identity_confirmed=False, observation="http_status_only",
                 url_kind="generated_template_redacted")
        try:
            req = urllib.request.Request(p["url"], headers={"User-Agent": "Cybersec-OSINT/1.0"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=8) as resp:
                p["http_status"] = resp.status
                if resp.status in (404, 410):
                    p["status"] = "not_found"
        except urllib.error.HTTPError as e:
            p["http_status"] = e.code
            if e.code in (404, 410):
                p["status"] = "not_found"
            e.close()
        except Exception:
            pass
        p["url"] = p["url"].replace(username, "[redacted]")
        profiles.append(p)

    return profiles


def _email_analysis(email):
    from .email_osint import _validate_email
    if not _validate_email(email):
        return {"valid": False, "reason": "Not an email address"}

    username, domain = email.rsplit("@", 1)

    analysis = {
        "email": "[redacted]",
        "username": "[redacted]",
        "domain": domain,
        "disposable": domain in ["mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com", "throwaway.email", "yopmail.com"],
        "gravatar_url": "https://www.gravatar.com/avatar/[redacted]",
        "gravatar_url_kind": "generated_template_redacted",
        "identity_confirmed": False,
    }

    if domain:
        mx_url = f"https://dns.google/resolve?name={domain}&type=MX"
        try:
            req = urllib.request.Request(mx_url, headers={"User-Agent": "Cybersec-OSINT/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status != 200:
                    raise ValueError("Incomplete provider response")
                dns_data = _read_json(resp)
            if dns_data.get("Status") not in (0, 3):
                raise ValueError("Incomplete DNS response")
            answers = dns_data.get("Answer", [])
            if not isinstance(answers, list) or len(answers) > 100:
                raise ValueError("Invalid DNS answer count")
            mx_records = [a for a in answers if isinstance(a, dict) and a.get("type") == 15
                          and isinstance(a.get("data"), str) and a["data"].split()[-1:] != ["."]]
            analysis["mx_records"] = ["[redacted]" for _ in mx_records[:5]]
            analysis["has_mx"] = bool(mx_records)
        except Exception:
            analysis["mx_records"] = []
            analysis["has_mx"] = None
            analysis["status"] = "incomplete"

    return analysis


def _md5(s):
    import hashlib
    return hashlib.md5(s.encode()).hexdigest()

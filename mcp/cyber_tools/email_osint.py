"""
Email OSINT — email intelligence, validation, MX records, and breach lookup.

Validates email format, checks MX records for the domain, looks up domain
reputation, and generates breach-check URLs (HIBP free, GhostProject, etc.).
No paid APIs required.
"""

import asyncio
import re
import socket
from typing import Any
from urllib.parse import quote

import httpx

_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _validate_email(email: str) -> bool:
    """Basic email format validation."""
    return bool(_EMAIL_REGEX.match(email))


def _check_mx(domain: str) -> dict:
    """Check MX records for a domain using DNS."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        mx_records = []
        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_records.append({"exchange": str(rdata.exchange), "preference": rdata.preference})
        except Exception:
            pass

        a_records = []
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                a_records.append(str(rdata))
        except Exception:
            pass

        return {
            "mx_records": mx_records,
            "a_records": a_records,
            "has_mx": len(mx_records) > 0,
        }
    except ImportError:
        # Fallback: try socket-based check
        try:
            mx_host = f"mail.{domain}"
            socket.getaddrinfo(mx_host, 25, socket.AF_INET, socket.SOCK_STREAM)
            return {"mx_records": [{"exchange": mx_host, "preference": 0}], "a_records": [], "has_mx": True}
        except Exception:
            return {"mx_records": [], "a_records": [], "has_mx": False}


async def _check_gravatar(email: str) -> dict:
    """Check if email has a Gravatar profile."""
    import hashlib
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{email_hash}.json"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                return {
                    "has_gravatar": True,
                    "profile_url": f"https://www.gravatar.com/{email_hash}",
                    "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}",
                    "display_name": entry.get("displayName", ""),
                    "about": entry.get("aboutMe", ""),
                    "accounts": [
                        {"platform": acc.get("shortname", ""), "url": acc.get("url", "")}
                        for acc in entry.get("accounts", [])
                    ],
                }
    except Exception:
        pass
    return {"has_gravatar": False}


async def email_osint(email: str, check_breach_urls: bool = True) -> dict:
    """Gather intelligence about an email address.

    Validates format, checks MX records, domain reputation, Gravatar profile,
    and generates breach lookup URLs. No paid APIs required.

    Args:
        email:            Email address to investigate.
        check_breach_urls: Generate breach check links (default True).

    Returns:
        A dict with validation, domain info, MX records, Gravatar,
        breach URLs, and error.
    """
    result: dict[str, Any] = {
        "email": email,
        "valid_format": False,
        "domain": "",
        "local_part": "",
        "mx_records": [],
        "a_records": [],
        "has_mx": False,
        "gravatar": {},
        "breach_check_urls": [],
        "search_urls": [],
        "error": None,
    }

    if not email:
        result["error"] = "email is required."
        return result

    email = email.strip().lower()

    # Validate format
    result["valid_format"] = _validate_email(email)
    if not result["valid_format"]:
        result["error"] = "Invalid email format."
        return result

    # Split domain and local part
    parts = email.split("@")
    result["local_part"] = parts[0]
    result["domain"] = parts[1]

    # Check MX records
    mx_info = _check_mx(result["domain"])
    result["mx_records"] = mx_info["mx_records"]
    result["a_records"] = mx_info["a_records"]
    result["has_mx"] = mx_info["has_mx"]

    # Check Gravatar
    gravatar = await _check_gravatar(email)
    result["gravatar"] = gravatar

    # Generate breach check URLs
    if check_breach_urls:
        result["breach_check_urls"] = [
            {
                "service": "Have I Been Pwned (free)",
                "url": f"https://haveibeenpwned.com/account/{email}",
                "description": "Check if email appears in known data breaches",
            },
            {
                "service": "GhostProject",
                "url": f"https://ghostproject.fr/search.php?p={quote(email)}",
                "description": "Search leaked credentials databases",
            },
            {
                "service": "IntelligenceX",
                "url": f"https://intelx.io/?s={quote(email)}",
                "description": "Search breach data and leaks",
            },
            {
                "service": "DeHashed (search)",
                "url": f"https://www.dehashed.com/search?query={quote(email)}",
                "description": "Search for leaked credentials",
            },
            {
                "service": "BreachDirectory",
                "url": f"https://breachdirectory.org/search?term={quote(email)}",
                "description": "Free breach database search",
            },
            {
                "service": "LeakCheck",
                "url": f"https://leakcheck.io/search?query={quote(email)}",
                "description": "Check for leaked email credentials",
            },
            {
                "service": "Snusbase",
                "url": f"https://snusbase.com/search?q={quote(email)}",
                "description": "Data breach search engine",
            },
            {
                "service": "Leak-Lookup",
                "url": f"https://leak-lookup.com/search?query={quote(email)}",
                "description": "Breach database lookup",
            },
        ]

    # Generate search URLs
    result["search_urls"] = [
        {
            "service": "Google Search",
            "url": f"https://www.google.com/search?q=%22{quote(email)}%22",
            "description": "Search for this email on Google",
        },
        {
            "service": "Google Search (domain)",
            "url": f"https://www.google.com/search?q=site:{result['domain']}+%22{result['local_part']}%22",
            "description": "Search for email pattern on the same domain",
        },
        {
            "service": "Google Groups",
            "url": f"https://groups.google.com/forum/#!search/{quote(email)}",
            "description": "Search Google Groups for this email",
        },
        {
            "service": "Hunter.io (free)",
            "url": f"https://hunter.io/email-verifier/{email}",
            "description": "Email verifier and domain search",
        },
        {
            "service": "EmailRep (free)",
            "url": f"https://emailrep.io/{email}",
            "description": "Email reputation check",
        },
        {
            "service": "Skype",
            "url": f"skype:{email}?userinfo",
            "description": "Check if email is linked to Skype",
        },
    ]

    # Domain reputation (free check via HTTP)
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Check if domain has a website
            resp = await client.get(f"https://{result['domain']}", follow_redirects=True)
            result["domain_status"] = {
                "alive": resp.status_code < 500,
                "status_code": resp.status_code,
                "final_url": str(resp.url),
            }
    except Exception:
        result["domain_status"] = {"alive": False, "status_code": 0, "final_url": ""}

    return result

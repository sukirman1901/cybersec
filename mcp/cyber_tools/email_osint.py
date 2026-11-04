"""
Email OSINT — bounded format, DNS and HTTP observations.

Generated breach links are redacted templates, not breach observations.
Neither DNS nor HTTP status establishes mailbox ownership or reputation.
"""

import asyncio
import re
from itertools import islice
from typing import Any
from urllib.parse import quote

import httpx
from .http_guard import GuardedAsyncClient

_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_MAX_REQUEST_SECONDS = 10


def _validate_email(email: str) -> bool:
    """Basic email format validation."""
    return (isinstance(email, str) and len(email) <= 254 and
            bool(_EMAIL_REGEX.fullmatch(email)) and len(email.split("@")[0]) <= 64 and
            all(0 < len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
                for label in email.split("@")[-1].split(".")))


def _check_mx(domain: str) -> dict:
    """Check MX records for a domain using DNS."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        mx_records = []
        has_mx = None
        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in islice(answers, 20):
                mx_records.append({"exchange": str(rdata.exchange), "preference": rdata.preference})
            has_mx = any(record["exchange"] != "." for record in mx_records)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            has_mx = False
        except Exception:
            pass

        a_records = []
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in islice(answers, 20):
                a_records.append(str(rdata))
        except Exception:
            pass

        return {
            "mx_records": mx_records,
            "a_records": a_records,
            "has_mx": has_mx,
        }
    except ImportError:
        return {"mx_records": [], "a_records": [], "has_mx": None}


async def _check_gravatar(email: str) -> dict:
    """Check if email has a Gravatar profile."""
    import hashlib
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{email_hash}.json"
    try:
        async with asyncio.timeout(_MAX_REQUEST_SECONDS), httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code == 404:
                    return {"has_gravatar": False, "status": "not_found", "identity_confirmed": False}
                # An HTTP success is not proof of a profile or identity. Do not
                # read or export names, bios, linked accounts or email hashes.
                return {"has_gravatar": None, "status": "incomplete",
                        "status_code": resp.status_code, "identity_confirmed": False}
    except Exception:
        pass
    return {"has_gravatar": None, "status": "incomplete", "identity_confirmed": False}


async def email_osint(email: str, check_breach_urls: bool = True) -> dict:
    """Gather intelligence about an email address.

    Validates format, checks DNS and HTTP status, and generates redacted
    lookup templates. No mailbox ownership or reputation is confirmed.

    Args:
        email:            Email address to investigate.
        check_breach_urls: Generate breach check links (default True).

    Returns:
        A dict with validation, domain info, MX records, Gravatar,
        breach URLs, and error.
    """
    result: dict[str, Any] = {
        "email": "[redacted]",
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

    if not isinstance(email, str) or not email or len(email) > 254:
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
    result["mx_records"] = [{"exchange": "[redacted]"} for _ in mx_info["mx_records"][:20]]
    result["a_records"] = ["[redacted]" for _ in mx_info["a_records"][:20]]
    result["has_mx"] = mx_info["has_mx"]

    # Check Gravatar
    gravatar = await _check_gravatar(email)
    result["gravatar"] = gravatar
    # Returned links are templates, not observations, and must not carry PII.
    email = "[redacted]"
    result["local_part"] = "[redacted]"

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
        async with asyncio.timeout(_MAX_REQUEST_SECONDS), GuardedAsyncClient(timeout=10) as client:
            # Check if domain has a website; redirects still require host scope.
            async with client.stream("HEAD", f"https://{result['domain']}", follow_redirects=False) as resp:
                result["domain_status"] = {
                    "alive": True if 200 <= resp.status_code < 300 else None,
                    "status_code": resp.status_code,
                    "final_url": "[redacted]",
                    "observation": "http_status_only_not_reputation",
                }
    except Exception:
        result["domain_status"] = {"alive": None, "status_code": 0, "final_url": "", "status": "incomplete"}

    for link in result["breach_check_urls"] + result["search_urls"]:
        link.update(observed=False, kind="generated_template_redacted")
    result["identity_confirmed"] = False
    return result

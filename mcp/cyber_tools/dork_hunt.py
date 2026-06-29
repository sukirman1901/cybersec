"""
Dork Hunter — full pipeline: generate dorks → scan engines → probe results → validate.

Combines dork_gen + dork_scan + HTTP probing to find targets ready for attack.
One call does everything: give a category, get back validated vulnerable URLs.
"""

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx

from cyber_tools.dork_gen import _CATEGORIES, _TECH_DORKS, _VULN_DORKS
from cyber_tools.dork_scan import _ENGINE_MAP, _HEADERS


def _build_dorks(
    category: str,
    tech: str,
    vuln_type: str,
    target: str,
    limit: int,
) -> list[str]:
    """Build dork list from category/tech/vuln."""
    dorks: list[str] = []
    site_prefix = f"site:{target} " if target else ""

    if category and category in _CATEGORIES:
        dorks.extend(f"{site_prefix}{d}" for d in _CATEGORIES[category][:limit])
    if tech and tech in _TECH_DORKS:
        dorks.extend(f"{site_prefix}{d}" for d in _TECH_DORKS[tech][:limit])
    if vuln_type and vuln_type in _VULN_DORKS:
        dorks.extend(f"{site_prefix}{d}" for d in _VULN_DORKS[vuln_type][:limit])

    # Deduplicate
    seen = set()
    unique = []
    for d in dorks:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


def _classify_url(url: str, title: str, content: str, dork: str) -> dict[str, Any]:
    """Classify a found URL by vuln indicators in content."""
    findings: list[str] = []
    content_lower = content.lower()
    url_lower = url.lower()

    # SQL injection indicators
    if any(k in content_lower for k in ["sql syntax", "mysql_fetch", "ora-00921", "sql server error", "postgresql query failed"]):
        findings.append("sqli_error")
    if any(k in content_lower for k in ["warning: mysql", "fatal error: call to undefined function"]):
        findings.append("php_error")

    # Config leak indicators
    if any(k in content_lower for k in ["db_password", "database_url", "aws_secret", "secret_key", "api_key"]):
        findings.append("config_leak")
    if ".env" in url_lower and any(k in content_lower for k in ["password", "secret", "key"]):
        findings.append("env_exposure")

    # Backup file indicators
    if any(url_lower.endswith(ext) for ext in [".bak", ".old", ".save", ".swp", ".orig", ".backup", ".sql"]):
        findings.append("backup_file")

    # Git exposed
    if ".git" in url_lower and any(k in content_lower for k in ["repositoryformatversion", "[core]", "ref: refs"]):
        findings.append("git_exposed")
    if ".svn" in url_lower:
        findings.append("svn_exposed")

    # Admin panel
    if any(k in url_lower for k in ["/admin", "/wp-admin", "/administrator", "/admincp", "/login"]):
        findings.append("admin_panel")
    if "login" in title.lower() and any(k in content_lower for k in ["username", "password", "sign in"]):
        findings.append("login_portal")

    # PHP info
    if "phpinfo()" in content_lower or "php version" in content_lower and "configuration file" in content_lower:
        findings.append("phpinfo_exposure")

    # Directory listing
    if "index of" in title.lower() and "parent directory" in content_lower:
        findings.append("directory_listing")

    # API key patterns
    if re.search(r'AKIA[0-9A-Z]{16}', content):
        findings.append("aws_key_exposed")
    if re.search(r'ghp_[A-Za-z0-9]{36}', content):
        findings.append("github_token_exposed")
    if re.search(r'xoxb-[A-Za-z0-9]+', content):
        findings.append("slack_token_exposed")
    if "eyJ" in content and re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ', content):
        findings.append("jwt_token_exposed")

    # Web shell
    if any(k in content_lower for k in ["c99shell", "r57shell", "wso shell", "b374k", "phpspy"]):
        findings.append("webshell_detected")
    if "system(" in content_lower and "$_get" in content_lower:
        findings.append("webshell_cmd")

    # Error messages
    if any(k in content_lower for k in ["warning: include()", "warning: require()", "failed to open stream"]):
        findings.append("lfi_error")
    if "traceback" in content_lower and "django" in content_lower:
        findings.append("django_debug")
    if "whitelabel error page" in content_lower:
        findings.append("spring_debug")

    # IoT devices
    if any(k in title.lower() for k in ["webcam", "camera", "dvr", "network video"]):
        findings.append("iot_device")

    return {
        "findings": findings,
        "risk": "high" if findings else "low",
        "has_findings": bool(findings),
    }


async def dork_hunt(
    category: str = "vuln_sites",
    tech: str = "",
    vuln_type: str = "",
    target: str = "",
    engines: str = "ddg,bing",
    max_dorks: int = 10,
    max_results: int = 15,
    probe: bool = True,
    validate: bool = True,
    delay: float = 1.0,
    timeout: int = 15,
) -> dict:
    """Full dorking pipeline: generate → scan → probe → validate.

    One-call target discovery. Give a category, get back validated URLs
    with vulnerability indicators.

    Args:
        category:  Dork category (see dork_gen for full list).
        tech:      Technology filter (wordpress, laravel, django, etc.).
        vuln_type: Vulnerability type (sqli, lfi, xss, rce).
        target:    Optional target domain to scope dorks.
        engines:   Search engines (default ``"ddg,bing"``).
        max_dorks: Max dorks to generate and execute (default 10).
        max_results: Max results per dork per engine (default 15).
        probe:     HTTP-probe found URLs (default True).
        validate:  Classify results by vuln indicators (default True).
        delay:     Delay between search requests (default 1.0s).
        timeout:   HTTP timeout (default 15s).

    Returns:
        A dict with targets, total_urls, validated_targets, findings_count, error.
    """
    result: dict[str, Any] = {
        "dorks_used": [],
        "targets": [],
        "total_urls": 0,
        "validated_targets": [],
        "findings_count": 0,
        "error": None,
    }

    # Phase 1: Generate dorks
    dorks = _build_dorks(category, tech, vuln_type, target, max_dorks)
    if not dorks:
        result["error"] = f"No dorks generated. Check category/tech/vuln_type parameters."
        return result

    result["dorks_used"] = dorks

    # Phase 2: Scan engines
    engine_list = [e.strip().lower() for e in engines.split(",") if e.strip()]
    for e in engine_list:
        if e not in _ENGINE_MAP:
            result["error"] = f"Unknown engine: '{e}'. Available: {', '.join(sorted(_ENGINE_MAP))}"
            return result

    seen_urls = set()
    raw_results: list[dict] = []

    async with httpx.AsyncClient(timeout=float(timeout), verify=False, follow_redirects=True) as client:
        for dork in dorks:
            for engine in engine_list:
                scan_fn = _ENGINE_MAP[engine]
                try:
                    engine_results = await scan_fn(dork, max_results, client)
                    for r in engine_results:
                        if r["url"] not in seen_urls:
                            seen_urls.add(r["url"])
                            raw_results.append(r)
                except Exception:
                    pass
                if delay > 0:
                    await asyncio.sleep(delay)

        result["total_urls"] = len(raw_results)

        # Phase 3: Probe + Validate
        if probe:
            for item in raw_results:
                url = item["url"]
                entry: dict[str, Any] = {
                    "url": url,
                    "title": item["title"],
                    "engine": item["engine"],
                    "dork": item["dork"],
                    "status_code": 0,
                    "findings": [],
                    "risk": "unknown",
                    "has_findings": False,
                }

                try:
                    resp = await client.get(url, headers=_HEADERS)
                    entry["status_code"] = resp.status_code
                    content = resp.text[:5000]  # First 5KB for classification

                    if validate:
                        classification = _classify_url(url, item["title"], content, item["dork"])
                        entry["findings"] = classification["findings"]
                        entry["risk"] = classification["risk"]
                        entry["has_findings"] = classification["has_findings"]
                        if entry["has_findings"]:
                            result["validated_targets"].append(entry)
                            result["findings_count"] += 1
                except Exception:
                    entry["risk"] = "unreachable"

                result["targets"].append(entry)

                if delay > 0:
                    await asyncio.sleep(delay * 0.5)
        else:
            result["targets"] = raw_results

    return result

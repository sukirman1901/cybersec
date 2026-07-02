"""
Vulnerability scanner via security header checks, path probes, and CVE pattern matching.
Pure Python, no external binaries.

Findings include a ``confidence`` field:
- verified: path/content probe matched real exposure
- probable: version/CVE correlation from response headers only
- info: misconfiguration or informational
"""

import re
from typing import Dict, List, Optional

SECURITY_CHECKS = {
    "missing-x-frame-options": {
        "name": "Missing X-Frame-Options Header",
        "severity": "medium",
        "description": "X-Frame-Options header is not set, may allow clickjacking.",
        "check": lambda h: "x-frame-options" not in {k.lower() for k in h},
    },
    "missing-csp": {
        "name": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "description": "CSP header is not set, may allow XSS attacks.",
        "check": lambda h: "content-security-policy" not in {k.lower() for k in h},
    },
    "missing-hsts": {
        "name": "Missing Strict-Transport-Security Header",
        "severity": "low",
        "description": "HSTS header is not set, may allow downgrade attacks.",
        "check": lambda h: "strict-transport-security" not in {k.lower() for k in h},
    },
    "missing-x-content-type-options": {
        "name": "Missing X-Content-Type-Options Header",
        "severity": "low",
        "description": "X-Content-Type-Options header is not set.",
        "check": lambda h: "x-content-type-options" not in {k.lower() for k in h},
    },
    "missing-x-xss-protection": {
        "name": "Missing X-XSS-Protection Header",
        "severity": "info",
        "description": "X-XSS-Protection header is not set.",
        "check": lambda h: "x-xss-protection" not in {k.lower() for k in h},
    },
    "server-header-disclosure": {
        "name": "Server Header Information Disclosure",
        "severity": "info",
        "description": "Server header reveals software information.",
        "check": lambda h: "server" in {k.lower() for k in h},
    },
    "x-powered-by-disclosure": {
        "name": "X-Powered-By Header Information Disclosure",
        "severity": "info",
        "description": "X-Powered-By header reveals technology information.",
        "check": lambda h: "x-powered-by" in {k.lower() for k in h},
    },
}

PATH_CHECKS = [
    {"path": "/.git/config", "name": "Git Config Exposure", "severity": "high",
     "pattern": r"\[core\]|\[remote"},
    {"path": "/.env", "name": "Environment File Exposure", "severity": "critical",
     "pattern": r"(DB_|API_|SECRET|PASSWORD|KEY)="},
    {"path": "/robots.txt", "name": "Robots.txt Exposure", "severity": "info",
     "pattern": r"^User-agent:|^Disallow:|^Sitemap:", "content_type": "text/plain"},
    {"path": "/.htaccess", "name": "Htaccess File Exposure", "severity": "medium",
     "pattern": r"(RewriteRule|RewriteCond|AuthType)"},
    {"path": "/wp-config.php.bak", "name": "WordPress Config Backup", "severity": "critical",
     "pattern": r"(DB_NAME|DB_USER|DB_PASSWORD)"},
    {"path": "/server-status", "name": "Apache Server Status", "severity": "medium",
     "pattern": r"Apache Server Status"},
    {"path": "/phpinfo.php", "name": "PHP Info Exposure", "severity": "medium",
     "pattern": r"PHP Version|phpinfo\(\)"},
    {"path": "/debug", "name": "Debug Endpoint", "severity": "medium",
     "pattern": r"(debug|stack|trace|error)"},
    {"path": "/admin", "name": "Admin Panel", "severity": "info",
     "pattern": r"(login|admin|dashboard)", "min_length": 200},
    {"path": "/backup.sql", "name": "SQL Backup Exposure", "severity": "critical",
     "pattern": r"(CREATE TABLE|INSERT INTO)"},
    {"path": "/config.json", "name": "Config JSON Exposure", "severity": "high",
     "pattern": r'("password"|"secret"|"api_key")'},
    {"path": "/.DS_Store", "name": "DS_Store File Exposure", "severity": "low",
     "pattern": r"Bud1"},
]

# Match only against Server / X-Powered-By headers (not page body noise)
CVE_PATTERNS = [
    {"pattern": r"Apache/2\.4\.(?:[0-9]|[1-4][0-9]|5[01])\b",
     "cve": "CVE-2021-44790", "name": "Apache HTTP Server Buffer Overflow",
     "severity": "high", "description": "Apache <2.4.52 may be vulnerable to CVE-2021-44790."},
    {"pattern": r"Apache/2\.2\.",
     "cve": "EOL", "name": "Apache 2.2 End-of-Life",
     "severity": "critical", "description": "Apache 2.2.x reached EOL; no security patches."},
    {"pattern": r"nginx/(1\.1[0-8]|1\.19\.[0-9]|1\.20\.0)\b",
     "cve": "CVE-2021-23017", "name": "nginx DNS Resolver Vulnerability",
     "severity": "high", "description": "nginx <1.20.1 may be vulnerable to CVE-2021-23017."},
    {"pattern": r"PHP/5\.",
     "cve": "EOL", "name": "PHP 5.x End-of-Life",
     "severity": "critical", "description": "PHP 5.x reached EOL; no security patches."},
    {"pattern": r"PHP/7\.[0-3]\.",
     "cve": "EOL", "name": "PHP 7.0-7.3 End-of-Life",
     "severity": "high", "description": "PHP 7.0-7.3 reached EOL; upgrade to 8.x."},
    {"pattern": r"PHP/7\.4\.(?:[0-9]|1[0-9]|2[0-9]|30)\b",
     "cve": "EOL", "name": "PHP 7.4 End-of-Life",
     "severity": "high", "description": "PHP 7.4 reached EOL; upgrade to 8.2+."},
    {"pattern": r"PHP/8\.[01]\.",
     "cve": "EOL", "name": "PHP 8.0/8.1 Approaching EOL",
     "severity": "medium", "description": "PHP 8.0/8.1 EOL; plan upgrade to 8.2+."},
]

DEFAULT_CRED_CHECKS = [
    {
        "name": "GeoServer Default Credentials",
        "path": "/geoserver/rest/about/version.xml",
        "username": "admin",
        "password": "geoserver",
        "severity": "critical",
        "pattern": r"<Version>",
    },
]


def _version_banner(headers) -> str:
    parts = []
    for key in ("server", "x-powered-by"):
        val = headers.get(key)
        if val:
            parts.append(val)
    return " ".join(parts)


async def scan_vulnerabilities(target: str) -> Dict:
    """Scan a target for common vulnerabilities (header checks, path probes, CVE patterns)."""
    import httpx

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    vulnerabilities: List[Dict] = []

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
            try:
                response = await client.get(target)
                headers = response.headers

                for check in SECURITY_CHECKS.values():
                    if check["check"](headers):
                        vulnerabilities.append({
                            "name": check["name"],
                            "severity": check["severity"],
                            "description": check["description"],
                            "matched_at": target,
                            "type": "misconfiguration",
                            "confidence": "info",
                        })

                banner = _version_banner(headers)
                for cve in CVE_PATTERNS:
                    if banner and re.search(cve["pattern"], banner, re.IGNORECASE):
                        vulnerabilities.append({
                            "name": cve["name"],
                            "severity": cve["severity"],
                            "description": cve["description"],
                            "matched_at": target,
                            "type": "cve",
                            "cve": cve["cve"],
                            "confidence": "probable",
                            "evidence": banner[:120],
                        })
            except httpx.HTTPError:
                pass

            for pc in PATH_CHECKS:
                try:
                    path_url = target.rstrip("/") + pc["path"]
                    pr = await client.get(path_url)
                    if pr.status_code != 200:
                        continue
                    if not re.search(pc["pattern"], pr.text, re.IGNORECASE | re.MULTILINE):
                        continue
                    min_len = pc.get("min_length", 0)
                    if min_len and len(pr.text) < min_len:
                        continue
                    ct = pr.headers.get("content-type", "").lower()
                    expected_ct = pc.get("content_type")
                    if expected_ct and expected_ct not in ct and "text/html" in ct:
                        continue
                    vulnerabilities.append({
                        "name": pc["name"],
                        "severity": pc["severity"],
                        "description": pc.get("description", pc["name"]),
                        "matched_at": path_url,
                        "type": "exposure",
                        "confidence": "verified",
                    })
                except httpx.HTTPError:
                    continue

            # Default credential probes (read-only GET)
            for dc in DEFAULT_CRED_CHECKS:
                try:
                    cred_url = target.rstrip("/") + dc["path"]
                    auth = httpx.BasicAuth(dc["username"], dc["password"])
                    no_auth = await client.get(cred_url)
                    if no_auth.status_code == 200:
                        continue
                    with_auth = await client.get(cred_url, auth=auth)
                    if with_auth.status_code == 200 and re.search(
                        dc["pattern"], with_auth.text, re.IGNORECASE
                    ):
                        vulnerabilities.append({
                            "name": dc["name"],
                            "severity": dc["severity"],
                            "description": (
                                f"Default credentials {dc['username']}:{dc['password']} "
                                "grant access to protected endpoint."
                            ),
                            "matched_at": cred_url,
                            "type": "default_credential",
                            "confidence": "verified",
                            "evidence": f"HTTP {no_auth.status_code} without auth → "
                            f"HTTP {with_auth.status_code} with default creds",
                        })
                except httpx.HTTPError:
                    continue

    except Exception as e:
        return {"vulnerabilities": [], "error": str(e)}

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_confidence = {"verified": 0, "probable": 0, "info": 0}
    for v in vulnerabilities:
        s = v["severity"]
        if s in by_severity:
            by_severity[s] += 1
        c = v.get("confidence", "info")
        if c in by_confidence:
            by_confidence[c] += 1

    return {
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "verified_count": by_confidence["verified"],
        "note": (
            "Use findings with confidence=verified for reports. "
            "confidence=probable means version/CVE correlation only, not exploited."
        ),
    }

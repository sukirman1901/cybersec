"""Deep vulnerability scanner — security headers, path probes, CVE patterns, tech-specific checks, default creds."""

import re
import httpx
import asyncio
from typing import Dict, List
from .php2shell import assess_headers, cve_records

# --- Security Header Checks ---
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
    "missing-referrer-policy": {
        "name": "Missing Referrer-Policy Header",
        "severity": "low",
        "description": "Referrer-Policy header not set — may leak URLs to third parties.",
        "check": lambda h: "referrer-policy" not in {k.lower() for k in h},
    },
    "missing-permissions-policy": {
        "name": "Missing Permissions-Policy Header",
        "severity": "low",
        "description": "Permissions-Policy header not set — browser features unrestricted.",
        "check": lambda h: "permissions-policy" not in {k.lower() for k in h} and "feature-policy" not in {k.lower() for k in h},
    },
    "missing-x-content-security-policy": {
        "name": "Missing X-Content-Security-Policy Header",
        "severity": "info",
        "description": "Legacy CSP header not set.",
        "check": lambda h: "x-content-security-policy" not in {k.lower() for k in h},
    },
    "missing-x-permitted-cross-domain": {
        "name": "Missing X-Permitted-Cross-Domain-Policies Header",
        "severity": "low",
        "description": "Cross-domain policy header not set.",
        "check": lambda h: "x-permitted-cross-domain-policies" not in {k.lower() for k in h},
    },
    "missing-cross-origin-embedder": {
        "name": "Missing Cross-Origin-Embedder-Policy Header",
        "severity": "info",
        "description": "COEP header not set — cross-origin isolation disabled.",
        "check": lambda h: "cross-origin-embedder-policy" not in {k.lower() for k in h},
    },
    "missing-cross-origin-opener": {
        "name": "Missing Cross-Origin-Opener-Policy Header",
        "severity": "info",
        "description": "COOP header not set.",
        "check": lambda h: "cross-origin-opener-policy" not in {k.lower() for k in h},
    },
    "missing-cross-origin-resource": {
        "name": "Missing Cross-Origin-Resource-Policy Header",
        "severity": "info",
        "description": "CORP header not set.",
        "check": lambda h: "cross-origin-resource-policy" not in {k.lower() for k in h},
    },
    "weak-csp": {
        "name": "Weak Content-Security-Policy",
        "severity": "medium",
        "description": "CSP uses unsafe-inline or unsafe-eval.",
        "check": lambda h: any(
            "unsafe-inline" in h.get("content-security-policy", "").lower() or
            "unsafe-eval" in h.get("content-security-policy", "").lower()
            for _ in [1]
        ),
    },
    "weak-hsts": {
        "name": "Weak HSTS Configuration",
        "severity": "medium",
        "description": "HSTS max-age is too short (< 6 months).",
        "check": lambda h: any(
            int(re.search(r"max-age=(\d+)", h.get("strict-transport-security", "")).group(1) or 0) < 15768000
            for _ in [1] if re.search(r"max-age=(\d+)", h.get("strict-transport-security", ""))
        ),
    },
}

# --- Path Probes ---
PATH_CHECKS = [
    {"path": "/.git/config", "name": "Git Config Exposure", "severity": "high",
     "pattern": r"\[core\]|\[remote"},
    {"path": "/.git/HEAD", "name": "Git HEAD Exposure", "severity": "high",
     "pattern": r"ref:"},
    {"path": "/.env", "name": "Environment File Exposure", "severity": "critical",
     "pattern": r"(DB_|API_|SECRET|PASSWORD|KEY=|APP_|MAIL_|AWS_)"},
    {"path": "/robots.txt", "name": "Robots.txt Exposure", "severity": "info",
     "pattern": r"^User-agent:|^Disallow:|^Sitemap:", "content_type": "text/plain"},
    {"path": "/.htaccess", "name": "Htaccess File Exposure", "severity": "medium",
     "pattern": r"(RewriteRule|RewriteCond|AuthType)", "strong": True},
    {"path": "/wp-config.php.bak", "name": "WordPress Config Backup", "severity": "critical",
     "pattern": r"(DB_NAME|DB_USER|DB_PASSWORD)", "strong": True},
    {"path": "/server-status", "name": "Apache Server Status", "severity": "medium",
     "pattern": r"Apache Server Status"},
    {"path": "/phpinfo.php", "name": "PHP Info Exposure", "severity": "medium",
     "pattern": r"PHP Version|phpinfo\(\)", "strong": True},
    {"path": "/debug", "name": "Debug Endpoint", "severity": "medium",
     "pattern": r"(debug|stack|trace|error)"},
    {"path": "/admin", "name": "Admin Panel", "severity": "info",
     "pattern": r"(login|admin|dashboard)", "min_length": 200},
    {"path": "/backup.sql", "name": "SQL Backup Exposure", "severity": "critical",
     "pattern": r"(CREATE TABLE|INSERT INTO)", "strong": True},
    {"path": "/config.json", "name": "Config JSON Exposure", "severity": "high",
     "pattern": r'("password"|"secret"|"api_key")'},
    {"path": "/.DS_Store", "name": "DS_Store File Exposure", "severity": "low",
     "pattern": r"Bud1", "strong": True},
    {"path": "/.svn/entries", "name": "SVN Entries Exposure", "severity": "high",
     "pattern": r"svn\+|^\d{1,2}$|^(dir|file|log)$", "min_length": 40},
    {"path": "/.hg/store/data", "name": "Mercurial Store Exposure", "severity": "high",
     "pattern": r"(file://\S+|<path\b|node\s*=\s*\w)", "min_length": 40},
    {"path": "/WEB-INF/web.xml", "name": "Java Web Config Exposure", "severity": "high",
     "pattern": r"<web-app|<servlet"},
    {"path": "/crossdomain.xml", "name": "Flash Cross-Domain Policy", "severity": "medium",
     "pattern": r"cross-domain-policy|allow-access-from", "strong": True},
    {"path": "/clientaccesspolicy.xml", "name": "Silverlight Cross-Domain Policy", "severity": "medium",
     "pattern": r"cross-domain-access-policy", "strong": True},
    {"path": "/sitemap.xml", "name": "Sitemap Exposure", "severity": "info",
     "pattern": r"<urlset|<loc>", "content_type": "text/xml", "strong": True},
    {"path": "/.well-known/security.txt", "name": "Security.txt Contact", "severity": "info",
     "pattern": r"Contact:|Expires:", "content_type": "text/plain", "strong": True},
    {"path": "/readme.html", "name": "CMS Readme Exposure", "severity": "info",
     "pattern": r"readme|installation|setup"},
    {"path": "/CHANGELOG.md", "name": "Changelog Exposure", "severity": "info",
     "pattern": r"# Changelog|## \[", "content_type": "text"},
    {"path": "/composer.json", "name": "Composer.json Exposure", "severity": "high",
     "pattern": r'"name"|"require"|"php"'},

    # --- Sensitive Directories ---
    {"path": "/backup/", "name": "Backup Directory Listing", "severity": "high",
     "pattern": r"\.(sql|gz|zip|tar|bak|old|dump)"},
    {"path": "/uploads/", "name": "Uploads Directory Listing", "severity": "medium",
     "pattern": r"\.(jpg|png|gif|pdf|doc|php|jsp)"},
    {"path": "/temp/", "name": "Temp Directory Listing", "severity": "medium",
     "pattern": r"\.(tmp|temp|log)"},
    {"path": "/logs/", "name": "Logs Directory Listing", "severity": "high",
     "pattern": r"\.(log|txt)"},
    {"path": "/debug/", "name": "Debug Directory Listing", "severity": "medium",
     "pattern": r"\.(json|xml|log)"},

    # --- Framework-Specific ---
    {"path": "/.aws/credentials", "name": "AWS Credentials Exposure", "severity": "critical",
     "pattern": r"\[default\]|aws_access_key"},
    {"path": "/.docker/config.json", "name": "Docker Config Exposure", "severity": "critical",
     "pattern": r"auth|email|username"},
    {"path": "/kubeconfig", "name": "Kubernetes Config Exposure", "severity": "critical",
     "pattern": r"apiVersion|clusters|contexts"},
    {"path": "/.ssh/authorized_keys", "name": "SSH Keys Exposure", "severity": "critical",
     "pattern": r"ssh-rsa|ssh-ed25519"},
    {"path": "/etc/passwd", "name": "Path Traversal to /etc/passwd", "severity": "critical",
     "pattern": r"root:x:0:0"},
    {"path": "/proc/self/environ", "name": "Proc Environ Exposure", "severity": "high",
     "pattern": r"PATH=|HOME="},
]

# --- CVE Patterns (Header-Based) ---
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
    {"pattern": r"Microsoft-IIS/[56]\.",
     "cve": "EOL", "name": "IIS 5/6 End-of-Life",
     "severity": "critical", "description": "IIS 5/6 reached EOL; critical vulnerabilities."},
    {"pattern": r"Microsoft-IIS/7\.0",
     "cve": "EOL", "name": "IIS 7.0 End-of-Life",
     "severity": "high", "description": "IIS 7.0 reached EOL; upgrade to latest version."},
    {"pattern": r"Tomcat/[6789]\.",
     "cve": "Multiple", "name": "Apache Tomcat (Older Version)",
     "severity": "high", "description": "Older Tomcat versions have known vulnerabilities."},
    {"pattern": r"Apache-Coyote",
     "cve": "info", "name": "Apache Tomcat Detected",
     "severity": "info", "description": "Tomcat server detected — check for default manager access."},
]

# --- Default Credential Checks ---
DEFAULT_CRED_CHECKS = [
    {
        "name": "GeoServer Default Credentials",
        "path": "/geoserver/rest/about/version.xml",
        "username": "admin", "password": "geoserver",
        "severity": "critical",
        "pattern": r"<Version>",
    },
    {
        "name": "WordPress Default Credentials",
        "path": "/wp-login.php",
        "username": "admin", "password": "admin",
        "severity": "critical",
        "pattern": r"dashboard|Logged in",
    },
    {
        "name": "phpMyAdmin Default Credentials",
        "path": "/phpmyadmin/",
        "username": "root", "password": "",
        "severity": "critical",
        "pattern": r"phpMyAdmin|mysql",
    },
    {
        "name": "Jenkins Default Credentials",
        "path": "/manage",
        "username": "admin", "password": "admin",
        "severity": "critical",
        "pattern": r"Jenkins|Manage Jenkins",
    },
    {
        "name": "Kibana Default Access",
        "path": "/app/kibana",
        "username": "", "password": "",
        "severity": "high",
        "pattern": r"Kibana",
    },
    {
        "name": "Grafana Default Credentials",
        "path": "/api/health",
        "username": "admin", "password": "admin",
        "severity": "critical",
        "pattern": r"ok|database",
    },
    {
        "name": "SonarQube Default Credentials",
        "path": "/api/system/status",
        "username": "admin", "password": "admin",
        "severity": "high",
        "pattern": r"UP|RUNNING",
    },
    {
        "name": "Redis Unauthenticated",
        "path": "",
        "username": "", "password": "",
        "severity": "critical",
        "pattern": r"",
        "port": 6379,
        "protocol": "redis",
    },
]


def _version_banner(headers) -> str:
    """Extract version info from headers."""
    parts = []
    for key in ("server", "x-powered-by"):
        val = headers.get(key)
        if val:
            parts.append(val)
    return " ".join(parts)


async def vuln_scanner(target: str) -> Dict:
    """Deep vulnerability scanner with header checks, path probes, CVE patterns, tech-specific checks, default creds."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    vulnerabilities: List[Dict] = []
    php2shell = assess_headers({})

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
            # --- Security Header Checks ---
            try:
                response = await client.get(target)
                headers = response.headers
                php2shell = assess_headers(headers)
                for record in cve_records(php2shell):
                    grade = record.get("confidence") or "LOW"
                    vulnerabilities.append({
                        "name": record["name"], "severity": record["severity"].lower(),
                        "description": record["description"], "matched_at": str(response.url),
                        "type": "cve", "cve": record["id"], "confidence": grade,
                        "evidence": str(php2shell["evidence"]),
                        "fixed_version": record["fixed_version"], "references": record["references"],
                        "confidence_notes": record.get("confidence_notes", []),
                    })

                for check_id, check in SECURITY_CHECKS.items():
                    try:
                        if check["check"](headers):
                            vulnerabilities.append({
                                "name": check["name"],
                                "severity": check["severity"],
                                "description": check["description"],
                                "matched_at": target,
                                "type": "misconfiguration",
                                "confidence": "info",
                            })
                    except Exception:
                        continue

                # Version/CVE detection
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

            # --- Path Probes ---
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
                        "confidence": "verified" if pc.get("strong") else "probable",
                        "evidence": pr.text[:160],
                    })
                except httpx.HTTPError:
                    continue

            # --- Default Credential Probes ---
            for dc in DEFAULT_CRED_CHECKS:
                if dc.get("protocol") == "redis":
                    continue  # Skip non-HTTP checks here
                try:
                    cred_url = target.rstrip("/") + dc["path"]
                    auth = httpx.BasicAuth(dc["username"], dc["password"]) if dc["username"] else None
                    no_auth = await client.get(cred_url)
                    if no_auth.status_code == 200:
                        continue
                    with_auth = await client.get(cred_url, auth=auth) if auth else no_auth
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

            # --- Technology-Specific Checks ---
            try:
                body = response.text.lower()
                headers_dict = {k.lower(): v.lower() for k, v in response.headers.items()}

                # WordPress checks
                if "wp-content" in body or "wordpress" in body:
                    vuln_paths = ["/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-login.php"]
                    for vp in vuln_paths:
                        try:
                            vr = await client.get(target.rstrip("/") + vp)
                            if vr.status_code == 200:
                                vulnerabilities.append({
                                    "name": f"WordPress {vp} Accessible",
                                    "severity": "medium",
                                    "description": f"WordPress endpoint {vp} is accessible",
                                    "matched_at": target.rstrip("/") + vp,
                                    "type": "exposure",
                                    "confidence": "verified",
                                })
                        except httpx.HTTPError:
                            continue

                # Laravel checks
                if "laravel" in body or "laravel_session" in str(headers_dict):
                    vuln_paths = ["/.env", "/telescope", "/horizon", "/_ignition/health-check"]
                    for vp in vuln_paths:
                        try:
                            vr = await client.get(target.rstrip("/") + vp)
                            if vr.status_code == 200 and len(vr.text) > 100:
                                vulnerabilities.append({
                                    "name": f"Laravel {vp} Accessible",
                                    "severity": "critical" if ".env" in vp else "high",
                                    "description": f"Laravel endpoint {vp} is accessible",
                                    "matched_at": target.rstrip("/") + vp,
                                    "type": "exposure",
                                    "confidence": "verified",
                                })
                        except httpx.HTTPError:
                            continue

                # Spring Boot checks
                if "whitelabel error" in body or "spring" in body:
                    vuln_paths = ["/actuator", "/actuator/env", "/actuator/health", "/env", "/beans", "/mappings"]
                    for vp in vuln_paths:
                        try:
                            vr = await client.get(target.rstrip("/") + vp)
                            if vr.status_code == 200 and ("actuator" in vr.text.lower() or "beans" in vr.text.lower()):
                                vulnerabilities.append({
                                    "name": f"Spring Boot Actuator {vp} Exposed",
                                    "severity": "critical" if "/env" in vp else "high",
                                    "description": f"Spring Boot actuator endpoint {vp} is exposed",
                                    "matched_at": target.rstrip("/") + vp,
                                    "type": "exposure",
                                    "confidence": "verified",
                                })
                        except httpx.HTTPError:
                            continue

                # Django checks
                if "csrfmiddlewaretoken" in body or "django" in body:
                    vuln_paths = ["/admin/", "/static/admin/", "/api/v1/"]
                    for vp in vuln_paths:
                        try:
                            vr = await client.get(target.rstrip("/") + vp)
                            if vr.status_code == 200:
                                vulnerabilities.append({
                                    "name": f"Django {vp} Accessible",
                                    "severity": "info",
                                    "description": f"Django endpoint {vp} is accessible",
                                    "matched_at": target.rstrip("/") + vp,
                                    "type": "exposure",
                                    "confidence": "info",
                                })
                        except httpx.HTTPError:
                            continue

                # Next.js checks
                if "_next/static" in body or "nextjs" in body:
                    vuln_paths = ["/_next/data/", "/api/", "/__nextjs_original-stack-frame"]
                    for vp in vuln_paths:
                        try:
                            vr = await client.get(target.rstrip("/") + vp)
                            if vr.status_code == 200:
                                vulnerabilities.append({
                                    "name": f"Next.js {vp} Accessible",
                                    "severity": "info",
                                    "description": f"Next.js endpoint {vp} is accessible",
                                    "matched_at": target.rstrip("/") + vp,
                                    "type": "exposure",
                                    "confidence": "info",
                                })
                        except httpx.HTTPError:
                            continue

                # Express.js checks
                if "x-powered-by: express" in str(headers_dict):
                    vuln_paths = ["/api/v1/", "/graphql", "/health", "/debug"]
                    for vp in vuln_paths:
                        try:
                            vr = await client.get(target.rstrip("/") + vp)
                            if vr.status_code == 200:
                                vulnerabilities.append({
                                    "name": f"Express.js {vp} Accessible",
                                    "severity": "info",
                                    "description": f"Express.js endpoint {vp} is accessible",
                                    "matched_at": target.rstrip("/") + vp,
                                    "type": "exposure",
                                    "confidence": "info",
                                })
                        except httpx.HTTPError:
                            continue

            except Exception:
                pass

    except Exception as e:
        return {"vulnerabilities": [], "error": str(e), "php2shell": php2shell}

    # Summary
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_confidence = {"verified": 0, "probable": 0, "info": 0,
                     "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulnerabilities:
        s = v["severity"]
        if s in by_severity:
            by_severity[s] += 1
        c = v.get("confidence", "info")
        if c in ("HIGH", "MEDIUM", "LOW"):
            by_confidence[c] += 1
            # Version/CVE correlation remains non-verified for report gating.
            by_confidence["probable"] += 1
        elif c in by_confidence:
            by_confidence[c] += 1

    return {
        "php2shell": php2shell,
        "vulnerabilities": vulnerabilities,
        "count": len(vulnerabilities),
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "verified_count": by_confidence["verified"],
        "note": (
            "Use findings with confidence=verified for reports. "
            "HIGH/MEDIUM/LOW (also counted under probable) are version/CVE "
            "correlation grades only, not verified RCE."
        ),
    }


# Backward-compatible alias
scan_vulnerabilities = vuln_scanner

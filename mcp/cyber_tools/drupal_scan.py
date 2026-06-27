import httpx
import re

CHECKS = [
    ("/user/login", "login|user|password|form", "medium"),
    ("/user/register", "register|signup|create", "medium"),
    ("/user/1", "member|user|profile", "high"),
    ("/admin/", "admin|dashboard|login", "high"),
    ("/admin/config", "config|system", "high"),
    ("/install.php", "install|drupal|configure", "critical"),
    ("/CHANGELOG.txt", "Drupal", "medium"),
    ("/UPGRADE.txt", "UPGRADE|drupal", "info"),
    ("/README.txt", "README|drupal", "info"),
    ("/sites/default/settings.php", r"\$databases|\$db_url", "critical"),
    ("/sites/default/files/", "index|files|test", "high"),
    ("/sites/default/private/", "private|backup", "high"),
    ("/sites/default/settings.local.php", "local|database", "critical"),
    ("/robots.txt", "Disallow|drupal|sites", "info"),
    ("/.htaccess", "Deny|Allow|Rewrite", "high"),
    ("/node/1", "node|content|page", "medium"),
    ("/rest", "rest|endpoint|api", "medium"),
    ("/jsonapi", "data|type|attributes", "high"),
    ("/views/ajax", "view|ajax|render", "medium"),
]

DRUPALGEDDON_PATHS = [
    ("/user/1?q=node&_format=json", "json", "high", "Drupalgeddon CVE-2018-7600"),
    ("/node?q=node&_format=json", "json", "high", "Drupal REST RCE"),
]


async def drupal_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        is_drupal = False
        if "drupal" in resp_root.text.lower() or "Drupal" in resp_root.text:
            is_drupal = True
        if "sites/default" in resp_root.text:
            is_drupal = True
        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 or resp.status_code == 403:
                    exposed = False
                    if resp.status_code == 200 and re.search(indicator, resp.text[:500], re.I):
                        exposed = True
                    elif resp.status_code == 403:
                        exposed = True
                    if exposed:
                        findings.append({"path": path, "status": resp.status_code, "severity": severity})
            except httpx.HTTPError:
                continue
        for path, indicator, severity, note in DRUPALGEDDON_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    findings.append({"path": path, "status": 200, "severity": severity, "note": note})
            except httpx.HTTPError:
                continue
    return {"target": target, "drupal_detected": is_drupal, "findings": findings, "count": len(findings)}

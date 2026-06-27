import httpx
import re

CHECKS = [
    ("/admin", "admin|login|dashboard", "high"),
    ("/admin/", "admin|login|dashboard", "high"),
    ("/index.php/admin", "admin|login", "high"),
    ("/downloader/", "downloader|magento", "critical"),
    ("/install.php", "install|magento", "critical"),
    ("/var/log/system.log", "exception|error|warning", "high"),
    ("/var/log/exception.log", "exception|fatal|error", "high"),
    ("/app/etc/local.xml", "host|username|password|dbname", "critical"),
    ("/app/etc/env.php", "host|username|password|dbname", "critical"),
    ("/app/etc/config.xml", "config|connection", "high"),
    ("/.htaccess", "RewriteEngine|Deny|Allow", "high"),
    ("/pkginfo/MagmiPlugins", "magmi|plugin", "high"),
    ("/errors/default/503.phtml", "503|temporary", "medium"),
    ("/skin/", "skin|css|js", "info"),
]

VERSION_PATHS = [
    "/js/mage/cookies.js",
    "/skin/frontend/base/default/css/styles.css",
    "/RELEASE_NOTES.txt",
]


async def magento_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        is_magento = False
        if "magento" in resp_root.text.lower() or "mage" in resp_root.text.lower():
            is_magento = True
        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 or resp.status_code == 403:
                    exposed = False
                    if resp.status_code == 200:
                        if re.search(indicator, resp.text[:500], re.I):
                            exposed = True
                    elif resp.status_code == 403:
                        exposed = True
                        severity = "medium"
                    if exposed:
                        findings.append({"path": path, "status": resp.status_code, "severity": severity})
            except httpx.HTTPError:
                continue
        for vp in VERSION_PATHS:
            try:
                resp = await client.get(f"{base}{vp}")
                if resp.status_code == 200:
                    findings.append({"path": vp, "status": 200, "severity": "info", "note": "Version info path exposed"})
            except httpx.HTTPError:
                continue
    return {"target": target, "magento_detected": is_magento, "findings": findings, "count": len(findings)}

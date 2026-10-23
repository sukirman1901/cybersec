"""Magento exposure checks — content-confirmed paths + finding contract."""

from __future__ import annotations

import re

import httpx

from .finding_contract import attach_contract_fields, normalize_finding

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

CRED_MARKERS = ("password", "dbname", "username", "crypt_key", "'host'")


async def magento_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        root = resp_root.text.lower()
        is_magento = "magento" in root or "mage/" in root or "varien" in root
        if not is_magento:
            return attach_contract_fields({
                "target": target, "magento_detected": False, "findings": [], "count": 0,
                "confidence": "MEDIUM", "coverage": "magento_markers_absent",
            }, finding_type="magento")

        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code not in (200, 403):
                    continue
                text = resp.text[:4000]
                content_hit = bool(re.search(indicator, text[:800], re.I))
                sensitive = any(k in path for k in ("local.xml", "env.php", "log", "downloader", "install"))
                if resp.status_code == 200 and content_hit:
                    strong = any(m in text.lower() for m in CRED_MARKERS)
                    conf = "HIGH" if severity in ("critical", "high") and (strong or content_hit) else "MEDIUM"
                    if sensitive and not strong and severity == "critical":
                        conf = "MEDIUM"
                    findings.append({
                        "type": "exposed_path", "path": path, "status": 200,
                        "severity": severity, "confidence": conf,
                        "coverage": f"magento_path_probe; content_confirm={content_hit}; cred_markers={strong}",
                        "target": base, "host": base,
                    })
                elif resp.status_code == 403 and sensitive:
                    findings.append({
                        "type": "path_forbidden", "path": path, "status": 403,
                        "severity": "info", "confidence": "LOW",
                        "coverage": "magento_path_probe; content_confirm=False; status_403_only",
                        "target": base, "host": base,
                    })
            except httpx.HTTPError:
                continue

        for vp in VERSION_PATHS:
            try:
                resp = await client.get(f"{base}{vp}")
                if resp.status_code == 200 and (
                    "mage" in resp.text.lower() or "magento" in resp.text.lower() or vp.endswith(".css")
                ):
                    findings.append({
                        "type": "version_path", "path": vp, "status": 200,
                        "severity": "info", "note": "Version/static path exposed",
                        "confidence": "MEDIUM", "coverage": "magento_version_path",
                        "target": base, "host": base,
                    })
            except httpx.HTTPError:
                continue

    structured = [
        normalize_finding(
            {**f, "confidence": f.get("confidence", "LOW"), "coverage": f.get("coverage", "magento_scan")},
            require_quality=False, tool="magento_scan",
        )
        for f in findings
    ]
    result = {
        "target": target,
        "magento_detected": True,
        "findings": structured,
        "count": len(structured),
        "vulnerable": any(f.get("severity") in ("critical", "high") for f in structured),
    }
    return attach_contract_fields(result, finding_type="magento")

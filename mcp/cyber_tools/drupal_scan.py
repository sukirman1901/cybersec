"""Drupal exposure checks — content-confirmed paths + finding contract."""

from __future__ import annotations

import re

import httpx

from .finding_contract import attach_contract_fields, normalize_finding

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
    ("/sites/default/files/", "index|files|Directory listing", "high"),
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
    ("/user/1?q=node&_format=json", "json", "high", "Drupalgeddon CVE-2018-7600 probe"),
    ("/node?q=node&_format=json", "json", "high", "Drupal REST probe"),
]

SENSITIVE_TOKENS = ("$databases", "$db_url", "drupal", "settings.php", "password")


async def drupal_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        root = resp_root.text.lower()
        is_drupal = "drupal" in root or "sites/default" in root or "drupalSettings" in resp_root.text
        if not is_drupal:
            return attach_contract_fields({
                "target": target, "drupal_detected": False, "findings": [], "count": 0,
                "confidence": "MEDIUM", "coverage": "drupal_markers_absent",
            }, finding_type="drupal")

        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code not in (200, 403):
                    continue
                text = resp.text[:4000]
                content_hit = (bool(re.search(indicator, text[:800], re.I))
                               and text.strip() != resp_root.text[:4000].strip())
                if "settings" in path:
                    content_hit = content_hit and bool(re.search(
                        r"\$(?:databases|db_url)\s*(?:\[[^\]]*\]\s*)*=", text))
                sensitive = any(k in path for k in ("settings", "install", "private", ".htaccess", "CHANGELOG"))
                if resp.status_code == 200 and content_hit:
                    conf = "HIGH" if severity in ("critical", "high") and (
                        any(t in text.lower() for t in SENSITIVE_TOKENS) or content_hit
                    ) else "MEDIUM"
                    findings.append({
                        "type": "exposed_path", "path": path, "status": 200,
                        "severity": severity, "confidence": conf,
                        "coverage": f"drupal_path_probe; content_confirm={content_hit}",
                        "target": base, "host": base,
                    })
                elif resp.status_code == 403 and sensitive:
                    # Presence only — do not claim disclosure from 403 alone
                    findings.append({
                        "type": "path_forbidden", "path": path, "status": 403,
                        "severity": "info", "confidence": "LOW",
                        "coverage": "drupal_path_probe; content_confirm=False; status_403_only",
                        "target": base, "host": base,
                    })
            except httpx.HTTPError:
                continue

        for path, indicator, severity, note in DRUPALGEDDON_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and (
                    indicator in resp.headers.get("content-type", "").lower()
                    or resp.text.strip().startswith(("{", "["))
                ):
                    findings.append({
                        "type": "rest_probe", "path": path, "status": 200,
                        "severity": severity, "note": note,
                        "confidence": "MEDIUM",
                        "coverage": "drupal_rest_probe; json_body_confirm",
                        "target": base, "host": base,
                    })
            except httpx.HTTPError:
                continue

    structured = [
        normalize_finding(
            {**f, "confidence": f.get("confidence", "LOW"), "coverage": f.get("coverage", "drupal_scan")},
            require_quality=False, tool="drupal_scan",
        )
        for f in findings
    ]
    result = {
        "target": target,
        "drupal_detected": True,
        "findings": structured,
        "count": len(structured),
        "vulnerable": any(f.get("severity") in ("critical", "high") for f in structured),
    }
    return attach_contract_fields(result, finding_type="drupal")

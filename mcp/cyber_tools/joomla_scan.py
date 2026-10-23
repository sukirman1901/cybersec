"""Joomla exposure checks — content-confirmed paths + finding contract."""

from __future__ import annotations

import re

import httpx

from .finding_contract import attach_contract_fields, normalize_finding

JOOMLA_PATHS = [
    "/administrator/", "/administrator/index.php", "/administrator/templates/",
    "/components/", "/modules/", "/plugins/", "/templates/",
    "/language/", "/cache/", "/logs/", "/tmp/",
    "/configuration.php", "/configuration.php.bak", "/configuration.php.old",
    "/htaccess.txt", "/robots.txt",
    "/index.php?option=com_users",
    "/index.php?option=com_content",
    "/bin/", "/includes/", "/media/",
]

JOOMLA_VULN_PLUGINS = [
    "/components/com_jce/", "/components/com_akeeba/",
    "/components/com_virtuemart/", "/components/com_k2/",
    "/components/com_seblod/", "/components/com_fabrik/",
]

SENSITIVE_MARKERS = (
    "public $host", "public $user", "public $password", "public $db",
    "jconfig", "configuration.php", "joomla", "define(",
)


async def joomla_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.get(base)
        body = resp.text

        is_joomla = any(
            tok in body.lower()
            for tok in ("/media/system/js/", "joomla", "com_content", "option=com_")
        )
        if not is_joomla:
            return attach_contract_fields({
                "target": target, "is_joomla": False, "findings": [], "count": 0,
                "confidence": "MEDIUM", "coverage": "joomla_markers_absent",
            }, finding_type="joomla")

        findings.append({
            "type": "joomla_detected", "severity": "info", "risk": "INFO",
            "confidence": "MEDIUM", "coverage": "joomla_content_markers",
            "target": base, "host": base,
        })

        v = re.search(r'<meta name="generator" content="Joomla! ([^"]+)"', body)
        if v:
            findings.append({
                "type": "version", "version": v.group(1), "severity": "info", "risk": "INFO",
                "confidence": "MEDIUM", "coverage": "generator_meta",
                "target": base, "host": base,
            })

        for path in JOOMLA_PATHS:
            try:
                pr = await client.get(base + path)
                if pr.status_code not in (200, 301, 302, 403):
                    continue
                text = pr.text[:4000].lower()
                sensitive = any(k in path for k in ("configuration", "log", "bak", "cache", "tmp"))
                content_hit = any(tok in text for tok in SENSITIVE_MARKERS)
                if sensitive and pr.status_code == 200 and content_hit:
                    risk, conf = "HIGH", "HIGH"
                elif sensitive and pr.status_code in (200, 403):
                    risk, conf = "MEDIUM", "LOW"
                elif pr.status_code == 200:
                    risk, conf = "MEDIUM", "LOW"
                else:
                    risk, conf = "INFO", "LOW"
                findings.append({
                    "type": "exposed_path", "path": path, "status": pr.status_code,
                    "risk": risk, "severity": risk.lower() if risk != "INFO" else "info",
                    "confidence": conf,
                    "coverage": f"joomla_path_probe; content_confirm={content_hit}",
                    "target": base, "host": base,
                })
            except Exception:
                pass

        for plugin in JOOMLA_VULN_PLUGINS:
            try:
                pr = await client.get(base + plugin)
                if pr.status_code in (200, 301, 302):
                    findings.append({
                        "type": "plugin_detected",
                        "plugin": plugin.rstrip("/").split("/")[-1],
                        "status": pr.status_code,
                        "severity": "info", "risk": "INFO",
                        "confidence": "MEDIUM", "coverage": "joomla_plugin_path",
                        "target": base, "host": base,
                    })
            except Exception:
                pass

        try:
            admin = await client.get(base + "/administrator/")
            admin_body = admin.text[:3000].lower()
            login_markers = ("administrator login", "com_login", "mod-login", "joomla")
            if admin.status_code == 200 and any(m in admin_body for m in login_markers):
                findings.append({
                    "type": "admin_exposed",
                    "note": "Joomla admin login page accessible",
                    "severity": "medium", "risk": "MEDIUM",
                    "confidence": "MEDIUM",
                    "coverage": "admin_login_content_confirm",
                    "target": base, "host": base,
                })
            elif admin.status_code in (200, 403):
                findings.append({
                    "type": "admin_path_present",
                    "note": "Administrator path responds without confirmed login UI",
                    "severity": "info", "risk": "INFO",
                    "confidence": "LOW",
                    "coverage": "admin_status_only",
                    "target": base, "host": base,
                })
        except Exception:
            pass

    structured = []
    for f in findings:
        f.setdefault("severity", (f.get("risk") or "info").lower() if f.get("risk") != "INFO" else "info")
        f.setdefault("confidence", "LOW")
        f.setdefault("coverage", "joomla_scan")
        f.setdefault("target", base)
        structured.append(normalize_finding(f, require_quality=False, tool="joomla_scan"))

    result = {
        "target": target,
        "is_joomla": True,
        "findings": structured,
        "vulnerable": any(
            f.get("risk") in ("HIGH", "CRITICAL") or f.get("severity") in ("high", "critical")
            for f in structured
        ),
        "count": len(structured),
    }
    return attach_contract_fields(result, finding_type="joomla")

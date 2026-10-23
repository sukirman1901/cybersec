import httpx
import re

from .finding_contract import attach_contract_fields, normalize_finding

WP_PATHS = [
    "/wp-admin/", "/wp-login.php", "/wp-json/", "/wp-content/", "/wp-includes/",
    "/xmlrpc.php", "/wp-config.php.bak", "/wp-config.php.save",
    "/wp-content/debug.log", "/wp-content/uploads/", "/wp-content/plugins/",
    "/wp-content/themes/", "/wp-content/backup-", "/wp-admin/admin-ajax.php",
    "/readme.html", "/license.txt", "/wp-cron.php", "/wp-links-opml.php",
]

WP_PLUGINS = [
    "/wp-content/plugins/akismet/", "/wp-content/plugins/woocommerce/",
    "/wp-content/plugins/elementor/", "/wp-content/plugins/wordfence/",
    "/wp-content/plugins/yoast-seo/", "/wp-content/plugins/jetpack/",
    "/wp-content/plugins/contact-form-7/",
]

WP_THEMES = [
    "/wp-content/themes/twentytwentyfour/", "/wp-content/themes/twentytwentythree/",
    "/wp-content/themes/twentytwentytwo/", "/wp-content/themes/astra/",
    "/wp-content/themes/divi/",
]

async def wordpress_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.get(base)
        headers = dict(resp.headers)
        body = resp.text

        # Detect WordPress
        is_wp = False
        if "wp-content" in body or "/wp-json/" in body:
            is_wp = True
            findings.append({"type": "wordpress_detected", "note": "WordPress detected via content markers", "risk": "INFO"})

        if not is_wp:
            return attach_contract_fields({
                "target": target, "is_wordpress": False, "findings": [], "count": 0,
                "confidence": "MEDIUM", "coverage": "wordpress_markers_absent",
            }, finding_type="wordpress")

        # Version detection
        version_m = re.search(r'<meta name="generator" content="WordPress ([^"]+)"', body)
        if version_m:
            findings.append({"type": "version_detected", "version": version_m.group(1), "risk": "INFO"})

        # Check wp-json
        try:
            api = await client.get(base + "/wp-json/")
            if api.status_code == 200:
                findings.append({"type": "rest_api_exposed", "note": "WordPress REST API accessible", "risk": "MEDIUM"})
        except Exception:
            pass

        # Check xmlrpc
        try:
            xml = await client.post(base + "/xmlrpc.php", data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>")
            if xml.status_code == 200 and "methodResponse" in xml.text:
                findings.append({"type": "xmlrpc_enabled", "note": "XML-RPC enabled — risk of brute force amplification", "risk": "HIGH"})
        except Exception:
            pass

        # Check common paths — require body markers for HIGH disclosure claims
        for p in WP_PATHS:
            try:
                pr = await client.get(base + p)
                if pr.status_code not in [200, 301, 302, 403]:
                    continue
                body = pr.text[:4000].lower()
                sensitive = "debug" in p or "config" in p or "backup" in p
                content_hit = any(tok in body for tok in (
                    "db_password", "db_name", "wp_", "define(", "php fatal", "debug.log",
                ))
                if sensitive and pr.status_code == 200 and content_hit:
                    risk, conf = "HIGH", "HIGH"
                elif sensitive and pr.status_code in (200, 403):
                    risk, conf = "MEDIUM", "LOW"
                elif pr.status_code == 200:
                    risk, conf = "MEDIUM", "LOW"
                else:
                    risk, conf = "INFO", "LOW"
                findings.append({
                    "type": "exposed_path", "path": p, "status": pr.status_code,
                    "risk": risk, "severity": risk.lower() if risk != "INFO" else "info",
                    "confidence": conf,
                    "coverage": "wordpress_path_probe; content_confirm=" + str(content_hit),
                    "target": base, "host": base,
                })
            except Exception:
                pass

        # Check plugins
        for p in WP_PLUGINS:
            try:
                pr = await client.get(base + p)
                if pr.status_code in [200, 301, 302]:
                    findings.append({
                        "type": "plugin_detected",
                        "path": p.rstrip("/").split("/")[-1],
                        "status": pr.status_code,
                        "risk": "INFO",
                        "severity": "info",
                        "confidence": "MEDIUM",
                        "coverage": "wordpress_plugin_path",
                        "target": base, "host": base,
                    })
            except Exception:
                pass

    structured = []
    for f in findings:
        f.setdefault("severity", (f.get("risk") or "info").lower() if f.get("risk") != "INFO" else "info")
        f.setdefault("confidence", "LOW")
        f.setdefault("coverage", "wordpress_scan")
        f.setdefault("target", base)
        structured.append(normalize_finding(f, require_quality=False, tool="wordpress_scan"))

    result = {
        "target": target,
        "is_wordpress": True,
        "findings": structured,
        "vulnerable": any(f.get("risk") in ["HIGH", "CRITICAL"] or f.get("severity") == "high" for f in structured),
        "count": len(structured),
    }
    return attach_contract_fields(result, finding_type="wordpress")

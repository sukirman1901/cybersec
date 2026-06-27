import httpx, re

JOOMLA_PATHS = [
    "/administrator/", "/administrator/index.php", "/administrator/templates/",
    "/components/", "/modules/", "/plugins/", "/templates/",
    "/language/", "/cache/", "/logs/", "/tmp/",
    "/configuration.php", "/configuration.php.bak", "/configuration.php.old",
    "/htaccess.txt", "/robots.txt",
    "/index.php?option=com_users",
    "/index.php?option=com_content",
    "/index.php?option=com_admin",
    "/bin/", "/includes/", "/media/",
]

JOOMLA_VULN_PLUGINS = [
    "/components/com_jce/", "/components/com_akeeba/",
    "/components/com_virtuemart/", "/components/com_k2/",
    "/components/com_seblod/", "/components/com_fabrik/",
]

async def joomla_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.get(base)
        body = resp.text
        
        is_joomla = False
        if "/media/system/js/" in body or "joomla" in body.lower() or "com_content" in body:
            is_joomla = True
            findings.append({"type": "joomla_detected", "risk": "INFO"})
        
        if not is_joomla:
            return {"target": target, "is_joomla": False, "findings": []}
        
        # Version
        v = re.search(r'<meta name="generator" content="Joomla! ([^"]+)"', body)
        if v:
            findings.append({"type": "version", "version": v.group(1), "risk": "INFO"})
        
        for path in JOOMLA_PATHS:
            try:
                pr = await client.get(base + path)
                if pr.status_code == 200:
                    risk = "HIGH" if "configuration" in path or "log" in path or "bak" in path else "MEDIUM"
                    findings.append({"type": "exposed_path", "path": path, "status": pr.status_code, "risk": risk})
            except:
                pass
        
        for plugin in JOOMLA_VULN_PLUGINS:
            try:
                pr = await client.get(base + plugin)
                if pr.status_code in [200, 301, 302, 403]:
                    findings.append({"type": "plugin_detected", "plugin": plugin.split("/")[-2], "risk": "INFO"})
            except:
                pass
        
        # Check admin exposure
        try:
            admin = await client.get(base + "/administrator/")
            if admin.status_code == 200:
                findings.append({"type": "admin_exposed", "note": "Joomla admin panel accessible", "risk": "HIGH"})
        except:
            pass
    
    return {"target": target, "is_joomla": is_joomla, "findings": findings, "vulnerable": any(f["risk"] in ["HIGH", "CRITICAL"] for f in findings)}

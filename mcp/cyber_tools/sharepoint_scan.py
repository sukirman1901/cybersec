import httpx, re

SHAREPOINT_PATHS = [
    "/_layouts/", "/_vti_bin/", "/_api/", "/_catalogs/", "/_themes/",
    "/SitePages/", "/Shared%20Documents/", "/_vti_pvt/",
    "/_vti_cnf/", "/_vti_log/", "/_vti_script/",
    "/wpresources/", "/_app_bin/", "/_admin/",
    "/discover/", "/search/", "/sites/", "/teams/",
    "/web.config", "/web.config.bak",
    "/_vti_bin/owssvr.dll",
    "/_vti_bin/lists.asmx",
    "/_vti_bin/search.asmx",
    "/_vti_bin/webs.asmx",
    "/_vti_bin/sitedata.asmx",
    "/_vti_bin/UserGroup.asmx",
    "/_vti_bin/People.asmx",
    "/_vti_bin/Forms.asmx",
]

async def sharepoint_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.get(base)
        body = resp.text
        
        is_sharepoint = False
        if "_layouts" in body or "_vti_bin" in body or "Microsoft SharePoint" in resp.headers.get("microsoftsharepointteamservices", ""):
            is_sharepoint = True
            findings.append({"type": "sharepoint_detected", "risk": "INFO"})
        
        if not is_sharepoint:
            # Check headers
            for h in ["microsoftsharepointteamservices", "x-sharepointhealthscore", "sprequestguid"]:
                if h in resp.headers:
                    is_sharepoint = True
                    findings.append({"type": "sharepoint_detected_via_header", "header": h, "risk": "INFO"})
                    break
        
        if not is_sharepoint:
            return {"target": target, "is_sharepoint": False, "findings": []}
        
        # Check version
        if "microsoftsharepointteamservices" in resp.headers:
            findings.append({"type": "version", "version": resp.headers["microsoftsharepointteamservices"], "risk": "INFO"})
        
        for path in SHAREPOINT_PATHS:
            try:
                pr = await client.get(base + path)
                if pr.status_code in [200, 301, 302, 401, 403]:
                    risk = "HIGH" if "config" in path or "bak" in path or "owssvr" in path else "MEDIUM"
                    size = len(pr.text)
                    findings.append({"type": "exposed_path", "path": path, "status": pr.status_code, "size": size, "risk": risk})
            except:
                pass
    
    return {"target": target, "is_sharepoint": is_sharepoint, "findings": findings, "vulnerable": any(f["risk"] in ["HIGH", "CRITICAL"] for f in findings)}

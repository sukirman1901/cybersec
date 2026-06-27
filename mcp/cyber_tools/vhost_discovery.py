import httpx, re

COMMON_VHOSTS = [
    "admin", "www", "mail", "webmail", "cpanel", "cp", "whm", "support",
    "dev", "api", "stage", "staging", "test", "beta", "alpha",
    "app", "my", "portal", "login", "sso", "auth",
    "blog", "shop", "forum", "wiki", "docs", "help",
    "git", "jenkins", "jira", "confluence", "wiki",
    "monitor", "status", "stats", "analytics",
    "cdn", "static", "assets", "media", "files",
    "backup", "intranet", "internal", "hr", "payroll",
    "vpn", "remote", "cloud", "exchange",
    "wordpress", "wp", "joomla", "drupal",
]

async def vhost_discovery(target: str) -> dict:
    parsed = httpx.URL(target)
    domain = parsed.host
    base = f"{parsed.scheme}://{parsed.netloc}"
    results = []
    
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        # Get baseline response
        try:
            baseline = await client.get(base)
            baseline_size = len(baseline.text)
            baseline_title = ""
            t = re.search(r'<title>([^<]+)</title>', baseline.text, re.I)
            if t:
                baseline_title = t.group(1)
        except:
            baseline_size = 0
        
        for vhost in COMMON_VHOSTS:
            try:
                test_host = f"{vhost}.{domain}"
                resp = await client.get(base, headers={"Host": test_host})
                resp_size = len(resp.text)
                
                # Different response = different vhost
                if resp.status_code != baseline.status_code or abs(resp_size - baseline_size) > 100:
                    title = ""
                    t = re.search(r'<title>([^<]+)</title>', resp.text, re.I)
                    if t:
                        title = t.group(1)
                    results.append({
                        "vhost": test_host,
                        "status": resp.status_code,
                        "size": resp_size,
                        "title": title[:60] if title else "",
                        "different_from_baseline": True,
                    })
            except:
                pass
    
    return {"target": domain, "vhosts_tested": len(COMMON_VHOSTS), "discovered": results, "count": len(results)}

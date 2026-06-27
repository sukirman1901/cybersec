import httpx

PATHS = [
    ("/.env", "APP_KEY|DB_PASSWORD|DB_HOST|APP_URL", "critical"),
    ("/.env.example", "APP_KEY|DB_PASSWORD", "info"),
    ("/storage/logs/laravel.log", "stack trace|production.ERROR", "high"),
    ("/config/app.php", "APP_KEY", "high"),
    ("/config/database.php", "DB_HOST|DB_PASSWORD", "high"),
    ("/api/scheduler", "artisan", "medium"),
    ("/artisan", "Laravel", "medium"),
    ("/debugbar/open", "debugbar", "medium"),
    ("/_debugbar", "DebugBar", "medium"),
    ("/routes/web.php", "Route::", "low"),
    ("/vendor/.composer", "vendor", "low"),
    ("/composer.json", "laravel/framework", "info"),
    ("/phpinfo.php", "PHP Version", "critical"),
]


async def laravel_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        resp_index = await client.get(base)
        x_powered = resp_index.headers.get("x-powered-by", "")
        is_laravel = "laravel" in x_powered.lower() or bool(resp_index.text.count("laravel") > 2)
        for path, indicator, severity in PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                exposed = bool(__import__("re").search(indicator, resp.text, re.I)) and resp.status_code == 200
                if exposed:
                    findings.append({
                        "path": path,
                        "status": resp.status_code,
                        "severity": severity,
                        "indicator_found": True,
                    })
            except httpx.HTTPError:
                continue
    return {
        "target": target,
        "laravel_detected": is_laravel,
        "findings": findings,
        "count": len(findings),
    }

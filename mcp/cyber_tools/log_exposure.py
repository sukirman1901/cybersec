"""Scan for exposed log files — access logs, error logs, debug logs with sensitive data."""

import httpx

LOG_PATHS = [
    "/access.log",
    "/error.log",
    "/debug.log",
    "/app.log",
    "/server.log",
    "/logs/access.log",
    "/logs/error.log",
    "/logs/app.log",
    "/log/access.log",
    "/log/error.log",
    "/var/log/access.log",
    "/var/log/error.log",
    "/storage/logs/laravel.log",
    "/wp-content/debug.log",
    "/logfile.log",
    "/trace.log",
    "/audit.log",
    "/security.log",
]


async def log_exposure(target: str) -> dict:
    results = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in LOG_PATHS:
            try:
                url = target.rstrip("/") + path
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    sensitive = any(
                        kw in resp.text.lower()
                        for kw in [
                            "password", "error", "exception", "stacktrace",
                            "sql", "select", "insert", "delete", "credentials",
                            "token", "session",
                        ]
                    )
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "contains_sensitive": sensitive,
                        "snippet": resp.text[:200] if sensitive else resp.text[:100],
                    })
            except Exception as e:
                results.append({"path": path, "error": str(e)[:60]})

    exposed = [r for r in results if r.get("status") == 200]
    sensitive = [r for r in exposed if r.get("contains_sensitive")]
    return {
        "target": target,
        "paths_checked": len(LOG_PATHS),
        "exposed_logs": len(exposed),
        "sensitive_exposure": len(sensitive),
        "results": results[:10],
        "risk": "CRITICAL" if sensitive else "HIGH" if exposed else "PASS",
    }

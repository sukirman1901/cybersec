"""Laravel exposure checks — bounded concurrent GETs with confidence/coverage."""

from __future__ import annotations

import asyncio
import re
import time

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


async def laravel_scan(target: str, preset: str = "observe-first") -> dict:
    """Scan common Laravel disclosure paths.

    preset observe-first: fewer paths + short deadline.
    staging-deep: full PATHS list within a larger deadline.
    """
    findings = []
    base = target.rstrip("/")
    deep = preset == "staging-deep"
    path_list = PATHS if deep else [p for p in PATHS if p[2] in ("critical", "high", "medium", "info")][:8]
    deadline = time.monotonic() + (20.0 if deep else 10.0)
    timeout = httpx.Timeout(3.0, connect=2.0)
    coverage_notes = [f"preset={preset}", f"paths_planned={len(path_list)}"]
    laravel_detected = False
    errors = 0

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
        try:
            resp_index = await asyncio.wait_for(client.get(base), timeout=3.0)
            x_powered = resp_index.headers.get("x-powered-by", "")
            laravel_detected = "laravel" in x_powered.lower() or resp_index.text.lower().count("laravel") > 2
        except Exception:
            errors += 1
            coverage_notes.append("index_fetch_failed")

        async def probe(path: str, indicator: str, severity: str):
            nonlocal errors
            if time.monotonic() > deadline:
                return None
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                exposed = resp.status_code == 200 and bool(re.search(indicator, resp.text, re.I))
                if exposed:
                    return {
                        "path": path,
                        "status": resp.status_code,
                        "severity": severity,
                        "indicator_found": True,
                        "confidence": "HIGH" if severity in ("critical", "high") else "MEDIUM",
                    }
            except httpx.HTTPError:
                errors += 1
            return None

        # Bound concurrency to avoid connection storms / flaky timeouts.
        sem = asyncio.Semaphore(4)

        async def guarded(item):
            async with sem:
                return await probe(*item)

        remaining = time.monotonic()
        budget = max(0.5, deadline - remaining)
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[guarded(item) for item in path_list], return_exceptions=True),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            results = []
            coverage_notes.append("deadline_reached")

        for item in results:
            if isinstance(item, dict):
                findings.append(item)
            elif isinstance(item, Exception):
                errors += 1

    if findings:
        confidence = "HIGH" if any(f.get("severity") in ("critical", "high") for f in findings) else "MEDIUM"
    elif errors and not laravel_detected:
        confidence = "LOW"
    else:
        confidence = "MEDIUM"

    coverage_notes.append(f"paths_completed≈{len(path_list) - errors}")
    coverage_notes.append(f"findings={len(findings)}")
    if not deep:
        coverage_notes.append("deep path set truncated (use preset=staging-deep)")

    return {
        "target": target,
        "preset": preset,
        "laravel_detected": laravel_detected,
        "findings": findings,
        "count": len(findings),
        "confidence": confidence,
        "coverage": "; ".join(coverage_notes),
    }

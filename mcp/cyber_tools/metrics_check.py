"""Check for exposed metrics endpoints — Prometheus, Actuator, debug, health."""

import httpx

METRICS_PATHS = [
    "/metrics",
    "/actuator/prometheus",
    "/prometheus",
    "/debug/metrics",
    "/metrics.json",
    "/health",
    "/actuator/health",
    "/info",
    "/actuator/info",
]


async def metrics_check(target: str) -> dict:
    results = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for path in METRICS_PATHS:
            try:
                url = target.rstrip("/") + path
                resp = await client.get(url)
                if resp.status_code == 200:
                    has_metrics = any(
                        kw in resp.text.lower()
                        for kw in [
                            "http_requests", "process_cpu", "jvm_", "go_",
                            "python_", "node_", "heap_", "uptime",
                        ]
                    )
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "exposes_metrics": has_metrics,
                        "snippet": resp.text[:200] if has_metrics else "",
                    })
                else:
                    results.append({
                        "path": path,
                        "status": resp.status_code,
                        "exposes_metrics": False,
                    })
            except Exception as e:
                results.append({
                    "path": path,
                    "error": str(e)[:60],
                    "exposes_metrics": False,
                })

    exposed = [r for r in results if r.get("exposes_metrics")]
    return {
        "target": target,
        "paths_checked": len(METRICS_PATHS),
        "exposed_endpoints": exposed,
        "total_exposed": len(exposed),
        "risk": "HIGH" if exposed else "PASS",
    }

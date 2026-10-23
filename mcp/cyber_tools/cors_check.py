"""Test for CORS misconfiguration — origin reflection, credentials, bypass analysis.

Defaults to observe-first (bounded origins + deadline). staging-deep expands
bypass probes. Always returns confidence + coverage notes.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse

import httpx


CORE_ORIGINS = (
    "https://evil.com",
    "http://evil.com",
    "null",
    "https://evil{host}",
    "https://{host}.evil.com",
    "https://evil.com/{host}",
    "{scheme}://{host}",
    "https://sub.{host}.evil.com",
)

DEEP_ORIGINS = CORE_ORIGINS + (
    "https://evil.com%2f@{host}",
    "https://{host}%0d%0aevil.com",
    "https://{host}\\evil.com",
    "https://{host}%5cevil.com",
    "https://evil.{host}",
    "https://{host}-evil.com",
    "https://{host}evil.com",
    "https://evil.com#{host}",
    "https://{host};evil.com",
    "https://{host}@evil.com",
    "https://evil.com/?{host}",
    "{scheme}://evil{host}",
    "https://{host}.evil.com/",
    "https://evil.com:{80}@{host}",
    "https://evil.com:{443}@{host}",
    "https://{host}%20evil.com",
)


def _format_origins(templates: tuple[str, ...], host: str, scheme: str) -> list[str]:
    out = []
    for template in templates:
        try:
            out.append(template.format(host=host, scheme=scheme))
        except (KeyError, ValueError):
            out.append(template)
    # Preserve order, drop empties/dupes
    seen = set()
    unique = []
    for origin in out:
        if origin and origin not in seen:
            seen.add(origin)
            unique.append(origin)
    return unique


def max_risk(current: str, proposed: str) -> str:
    hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return proposed if hierarchy.get(proposed, 0) > hierarchy.get(current, 0) else current


async def cors_check(target: str, preset: str = "observe-first") -> dict:
    """CORS misconfiguration check.

    preset: observe-first (default, bounded) | staging-deep (more origins/methods).
    Schema-compatible: same core keys; adds coverage/confidence/preset.
    """
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    if not host:
        return {
            "target": target, "vulnerable": False, "risk": "info",
            "confidence": "LOW", "coverage": "invalid_target",
            "preset": preset, "total_tests": 0, "vulnerable_count": 0,
            "evidence": [], "findings": [], "all_results": [],
            "error": "hostname required",
        }

    deep = preset == "staging-deep"
    origins = _format_origins(DEEP_ORIGINS if deep else CORE_ORIGINS, host, scheme)
    deadline = time.monotonic() + (25.0 if deep else 12.0)
    per_request_timeout = 4.0 if deep else 3.0

    results = []
    risk = "info"
    evidence_items = []
    timed_out = False

    async with httpx.AsyncClient(timeout=per_request_timeout, verify=False, follow_redirects=True) as client:
        for origin in origins:
            if time.monotonic() > deadline:
                timed_out = True
                break
            try:
                resp = await client.options(
                    target,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization,Content-Type",
                    },
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                acam = resp.headers.get("access-control-allow-methods", "")
                acah = resp.headers.get("access-control-allow-headers", "")

                is_reflected = acao == origin and origin != "null"
                is_wildcard = acao == "*"
                is_null = acao == "null" and origin == "null"
                creds_ok = acac.lower() == "true"

                vulnerable = False
                severity = ""
                if is_wildcard and creds_ok:
                    vulnerable, severity, risk = True, "CRITICAL", "critical"
                elif is_reflected and creds_ok:
                    vulnerable, severity, risk = True, "HIGH", max_risk(risk, "high")
                elif is_reflected:
                    vulnerable, severity, risk = True, "MEDIUM", max_risk(risk, "medium")
                elif is_null and creds_ok:
                    vulnerable, severity, risk = True, "HIGH", max_risk(risk, "high")

                results.append({
                    "origin": origin,
                    "preflight_acao": acao,
                    "preflight_acac": acac,
                    "preflight_acam": acam,
                    "preflight_acah": acah,
                    "is_reflected": is_reflected,
                    "is_wildcard": is_wildcard,
                    "is_null": is_null,
                    "credentials_allowed": creds_ok,
                    "vulnerable": vulnerable,
                    "severity": severity,
                })
                if vulnerable:
                    evidence_items.append(f"Origin '{origin}' → ACAO='{acao}' ACAC='{acac}'")
            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                results.append({"origin": origin, "error": type(e).__name__, "vulnerable": False})

        # Actual GET checks (bounded)
        for origin in [f"https://evil.com", "null", f"{scheme}://{host}"]:
            if time.monotonic() > deadline:
                timed_out = True
                break
            try:
                resp = await client.get(target, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                is_reflected = acao == origin and origin != "null"
                creds_ok = acac.lower() == "true"
                vulnerable = False
                severity = ""
                if is_reflected and creds_ok:
                    vulnerable, severity, risk = True, "HIGH", max_risk(risk, "high")
                elif is_reflected:
                    vulnerable, severity, risk = True, "MEDIUM", max_risk(risk, "medium")
                results.append({
                    "test_type": "actual_request",
                    "origin": origin,
                    "acao": acao,
                    "acac": acac,
                    "status_code": resp.status_code,
                    "credentials_allowed": creds_ok,
                    "vulnerable": vulnerable,
                    "severity": severity,
                })
                if vulnerable:
                    evidence_items.append(f"Actual request origin '{origin}' → ACAO='{acao}' ACAC='{acac}'")
            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                results.append({"test_type": "actual_request", "origin": origin,
                                "error": type(e).__name__, "vulnerable": False})

        if deep and not timed_out:
            for origin in ("https://evil.com", "null"):
                for method in ("GET", "POST", "PUT", "DELETE"):
                    if time.monotonic() > deadline:
                        timed_out = True
                        break
                    try:
                        resp = await client.request(
                            method, target,
                            headers={"Origin": origin, "Content-Type": "application/json"},
                            content=b'{"test":true}' if method in ("POST", "PUT", "DELETE") else None,
                        )
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "")
                        if acao == origin and origin != "null" and acac.lower() == "true":
                            results.append({
                                "test_type": "method_bypass", "origin": origin, "method": method,
                                "acao": acao, "acac": acac, "vulnerable": True, "severity": "HIGH",
                            })
                            risk = max_risk(risk, "high")
                            evidence_items.append(f"Method {method} with origin '{origin}' accepted with creds")
                    except (httpx.HTTPError, asyncio.TimeoutError):
                        continue
                if timed_out:
                    break

    unique_vulns = [r for r in results if r.get("vulnerable")]
    total_tests = len([r for r in results if "error" not in r])
    if unique_vulns:
        confidence = "HIGH" if any(v.get("severity") in ("CRITICAL", "HIGH") for v in unique_vulns) else "MEDIUM"
    elif timed_out:
        confidence = "LOW"
    else:
        confidence = "MEDIUM"

    coverage_parts = [
        f"preset={preset}",
        f"origins_tested={len(origins)}",
        f"tests_completed={total_tests}",
    ]
    if timed_out:
        coverage_parts.append("deadline_reached — remaining probes skipped")
    if not deep:
        coverage_parts.append("method/header deep bypass not run (use preset=staging-deep)")

    return {
        "target": target,
        "preset": preset,
        "total_tests": total_tests,
        "vulnerable_count": len(unique_vulns),
        "vulnerable": len(unique_vulns) > 0,
        "risk": risk,
        "confidence": confidence,
        "coverage": "; ".join(coverage_parts),
        "technique": "CORS misconfiguration — origin reflection, credential leakage, method/header bypass",
        "evidence": evidence_items[:20],
        "findings": unique_vulns[:30],
        "all_results": results[:100],
    }

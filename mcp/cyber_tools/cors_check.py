"""Test for CORS misconfiguration — comprehensive origin reflection, credential, and bypass analysis."""

import httpx
from urllib.parse import urlparse
from typing import Optional


def _build_origin_variations(host: str, scheme: str) -> list[str]:
    base = f"{scheme}://{host}"
    return [
        f"https://evil.com",
        f"http://evil.com",
        f"null",
        f"https://evil{host}",
        f"https://{host}.evil.com",
        f"https://evil.com/{host}",
        f"https://{host}",
        f"{scheme}://{host}.evil.com",
        f"https://evil.com%2f@{host}",
        f"https://{host}%0d%0aevil.com",
        f"https://{host}%0aevil.com",
        f"https://{host}%0d%0d%0a%0aevil.com",
        f"https://{host}\\evil.com",
        f"https://{host}%5cevil.com",
        f"https://{host}%255c%255cevil.com",
        f"https://{host}{'.'*100}evil.com",
        f"https://sub.{host}.evil.com",
        f"https://evil.{host}",
        f"https://{host}-evil.com",
        f"https://{host}evil.com",
        f"https://evil.com#{host}",
        f"https://{host};evil.com",
        f"https://{host},evil.com",
        f"https://evil.com:{scheme == 'https' and 443 or 80}@{host}",
        f"{scheme}://evil.com",
        f"https://{host}.evil.com.{host}",
        f"https://{host}@evil.com",
        f"https://evil.com%60@{host}",
        f"https://{host}%23evil.com",
        f"https://{host}%40evil.com",
        f"https://evil.com&@{host}",
        f"https://{host}%09evil.com",
        f"https://evil.com/?{host}",
        f"https://evil.com#{host}",
        f"{scheme}://evil{host}",
        f"https://evilcom",
        f"https://{host}.evil.com.evil.com",
        f"https://{host}.evil.com/",
        f"https://{host}.evil.com%2f",
        f"https://xn--{host}-o5a.com",
        f"https://\u0435vil.com",
        f"https://evil\u00e7om",
        f"https://evil.com%ff@{host}",
        f"https://{host}%ef%bf%bd%ef%bf%bd",
        f"https://evil.com:{80}@{host}",
        f"https://evil.com:{443}@{host}",
        f"https://{host}..",
        f"https://{host}/.",
        f"https://{host}%20evil.com",
        f"https://{host}%08evil.com",
        f"https://evil.com\\@{host}",
        f"https://{host}%60evil.com",
        f"{scheme}://{host}%00evil.com",
        f"https://evil.com/{host}evil.com",
    ]


def _build_param_variations() -> dict[str, list[str]]:
    return {
        "access-control-allow-methods": [
            "GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD",
            "GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD,TRACE,CONNECT",
            "*",
        ],
        "access-control-allow-headers": [
            "X-Custom-Header,Authorization,Content-Type",
            "X-Requested-With,Authorization,Content-Type,X-API-Key",
            "*",
        ],
    }


async def cors_check(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    host = parsed.hostname
    scheme = parsed.scheme
    results = []
    risk = "info"
    confidence = "high"
    evidence_items = []

    origins = _build_origin_variations(host, scheme)
    acac_methods = _build_param_variations()

    async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
        for origin in origins:
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
                    vulnerable = True
                    severity = "CRITICAL"
                    risk = "critical"
                elif is_reflected and creds_ok:
                    vulnerable = True
                    severity = "HIGH"
                    risk = max_risk(risk, "high")
                elif is_reflected:
                    vulnerable = True
                    severity = "MEDIUM"
                    risk = max_risk(risk, "medium")
                elif is_null and creds_ok:
                    vulnerable = True
                    severity = "HIGH"
                    risk = max_risk(risk, "high")

                test_result = {
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
                }
                results.append(test_result)

                if vulnerable:
                    evidence_items.append(
                        f"Origin '{origin}' → ACAO='{acao}' ACAC='{acac}'"
                    )

            except httpx.HTTPError as e:
                results.append({
                    "origin": origin,
                    "error": str(e),
                    "vulnerable": False,
                })

        for origin in [f"https://evil.com", f"null", f"{scheme}://{host}"]:
            try:
                resp = await client.get(
                    target,
                    headers={
                        "Origin": origin,
                        "Authorization": "Bearer test-token-fake",
                    },
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                server = resp.headers.get("server", "")

                is_reflected = acao == origin and origin != "null"
                creds_ok = acac.lower() == "true"

                vulnerable = False
                severity = ""
                if is_reflected and creds_ok:
                    vulnerable = True
                    severity = "HIGH"
                    risk = max_risk(risk, "high")
                elif is_reflected:
                    vulnerable = True
                    severity = "MEDIUM"
                    risk = max_risk(risk, "medium")

                results.append({
                    "test_type": "actual_request",
                    "origin": origin,
                    "acao": acao,
                    "acac": acac,
                    "status_code": resp.status_code,
                    "server": server,
                    "credentials_allowed": creds_ok,
                    "vulnerable": vulnerable,
                    "severity": severity,
                })

                if vulnerable:
                    evidence_items.append(
                        f"Actual request origin '{origin}' → ACAO='{acao}' ACAC='{acac}'"
                    )

            except httpx.HTTPError as e:
                results.append({
                    "test_type": "actual_request",
                    "origin": origin,
                    "error": str(e),
                    "vulnerable": False,
                })

        for origin in [f"https://evil.com", f"null"]:
            for method in ["GET", "POST", "PUT", "DELETE"]:
                try:
                    resp = await client.request(
                        method,
                        target,
                        headers={
                            "Origin": origin,
                            "Authorization": "Bearer test-token-fake",
                            "Content-Type": "application/json",
                        },
                        content=b'{"test":true}' if method in ("POST", "PUT", "DELETE") else None,
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    is_reflected = acao == origin and origin != "null"
                    creds_ok = acac.lower() == "true"

                    if is_reflected and creds_ok:
                        results.append({
                            "test_type": "method_bypass",
                            "origin": origin,
                            "method": method,
                            "acao": acao,
                            "acac": acac,
                            "vulnerable": True,
                            "severity": "HIGH",
                        })
                        risk = max_risk(risk, "high")
                        evidence_items.append(
                            f"Method {method} with origin '{origin}' accepted with creds"
                        )

                except httpx.HTTPError:
                    continue

        for origin in [f"https://evil.com", f"null"]:
            for header_name in ["X-Custom-Header", "X-Requested-With", "X-API-Key", "Authorization"]:
                try:
                    resp = await client.options(
                        target,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": header_name,
                        },
                    )
                    acah = resp.headers.get("access-control-allow-headers", "")
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if header_name.lower() in acah.lower() or "*" in acah:
                        is_reflected = acao == origin and origin != "null"
                        if is_reflected and acac.lower() == "true":
                            results.append({
                                "test_type": "header_bypass",
                                "origin": origin,
                                "allowed_header": header_name,
                                "acah": acah,
                                "acao": acao,
                                "vulnerable": True,
                                "severity": "HIGH",
                            })
                            risk = max_risk(risk, "high")
                            evidence_items.append(
                                f"Header '{header_name}' allowed with origin reflection and creds"
                            )

                except httpx.HTTPError:
                    continue

        for origin in [f"https://evil.com", f"null"]:
            for method_combo in ["TRACE,CONNECT", "DEBUG", "PATCH"]:
                try:
                    resp = await client.options(
                        target,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": method_combo,
                        },
                    )
                    acam = resp.headers.get("access-control-allow-methods", "")
                    acao = resp.headers.get("access-control-allow-origin", "")

                    if method_combo in acam or "*" in acam:
                        is_reflected = acao == origin and origin != "null"
                        if is_reflected:
                            results.append({
                                "test_type": "dangerous_method",
                                "origin": origin,
                                "allowed_methods": acam,
                                "acao": acao,
                                "vulnerable": True,
                                "severity": "HIGH",
                            })
                            risk = max_risk(risk, "high")
                            evidence_items.append(
                                f"Dangerous method(s) '{method_combo}' allowed with origin reflection"
                            )

                except httpx.HTTPError:
                    continue

    unique_vulns = [r for r in results if r.get("vulnerable")]
    total_tests = len([r for r in results if "error" not in r])

    return {
        "target": target,
        "total_tests": total_tests,
        "vulnerable_count": len(unique_vulns),
        "vulnerable": len(unique_vulns) > 0,
        "risk": risk,
        "confidence": confidence,
        "technique": "CORS misconfiguration — origin reflection, credential leakage, method/header bypass",
        "evidence": evidence_items[:20],
        "findings": unique_vulns[:30],
        "all_results": results[:100],
    }


def max_risk(current: str, proposed: str) -> str:
    hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return proposed if hierarchy.get(proposed, 0) > hierarchy.get(current, 0) else current

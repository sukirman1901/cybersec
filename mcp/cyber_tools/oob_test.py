import httpx


async def oob_test(target: str, payload: str = "") -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    techniques = [
        {"name": "HTTP URL Injection", "payload": payload or "http://oast.fun/test"},
        {"name": "DNS Callback", "payload": "http://oast.fun/dns-test"},
    ]

    results = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        for tech in techniques:
            for param in ["url", "file", "redirect", "src", "load", "dest"]:
                test_url = f"{target.split('?')[0]}?{param}={tech['payload']}"
                try:
                    resp = await client.get(test_url)
                    if resp.elapsed.total_seconds() > 3:
                        results.append({
                            "technique": tech["name"], "parameter": param, "test_url": test_url,
                            "status": resp.status_code, "timing": resp.elapsed.total_seconds(),
                            "note": "Slow response — possible OOB callback",
                        })
                except httpx.TimeoutException:
                    results.append({
                        "technique": tech["name"], "parameter": param, "test_url": test_url,
                        "status": "timeout", "note": "Timeout — possible OOB callback",
                    })
                except httpx.HTTPError as exc:
                    results.append({"technique": tech["name"], "parameter": param,
                                    "error": type(exc).__name__})

    return {
        "target": target,
        "remote_effects_verified": False,
        "coverage_complete": not any(r.get("error") or r.get("status") == "timeout" for r in results),
        "tests": results,
        "recommendation": "Check oast.fun / Burp Collaborator for outbound callbacks. "
        "Timing alone does not verify a callback or vulnerability; independently correlate any callback to the request.",
    }

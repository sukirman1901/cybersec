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
                except httpx.HTTPError:
                    continue

    return {
        "target": target,
        "tests": results,
        "recommendation": "Check oast.fun / Burp Collaborator for outbound callbacks. "
        "A callback confirms blind SSRF, blind RCE, or OOB-based injection.",
    }

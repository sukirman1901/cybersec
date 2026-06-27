import httpx


async def shodan_lookup(query: str, api_key: str = "") -> dict:
    if not api_key:
        return {"query": query, "error": "Shodan API key not provided. Get one at https://account.shodan.io", "results": []}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}")
            if resp.status_code == 200:
                data = resp.json()
                matches = []
                for m in data.get("matches", [])[:20]:
                    matches.append({
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "org": m.get("org"),
                        "hostnames": m.get("hostnames", []),
                        "product": m.get("product"),
                        "version": m.get("version"),
                        "cve": list(m.get("vulns", [])),
                    })
                return {"query": query, "total": data.get("total", 0), "results": matches}
            return {"query": query, "error": f"Shodan API error: {resp.status_code}", "results": []}
    except Exception as e:
        return {"query": query, "error": str(e), "results": []}

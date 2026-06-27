"""Test for GraphQL introspection endpoint."""

import json
import httpx


async def graphql_introspect(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    paths = ["/graphql", "/graphql/", "/api/graphql", "/query"]
    query = {"query": "{ __schema { types { name fields { name } } } }"}

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        for path in paths:
            try:
                url = target.rstrip("/") + path
                resp = await client.post(url, json=query, headers={"Content-Type": "application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and "__schema" in str(data.get("data", {})):
                        types = data["data"]["__schema"]["types"]
                        return {
                            "target": target, "endpoint": url, "introspection_open": True,
                            "types_count": len(types),
                            "types": [t["name"] for t in types if not t["name"].startswith("__")][:50],
                        }
            except (httpx.HTTPError, json.JSONDecodeError):
                continue

    return {"target": target, "introspection_open": False}

"""Fuzz a web target for common API endpoints."""

import httpx


async def api_fuzz(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    paths = [
        "/api", "/api/v1", "/api/v2", "/swagger", "/swagger.json", "/openapi.json",
        "/docs", "/redoc", "/graphql", "/graphiql", "/health", "/readyz",
        "/ping", "/status", "/metrics", "/prometheus",
        "/.well-known", "/.well-known/security.txt",
        "/robots.txt", "/sitemap.xml",
    ]

    found = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in paths:
            try:
                resp = await client.get(target.rstrip("/") + path)
                if resp.status_code != 404:
                    found.append({
                        "path": path, "status": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "size": len(resp.content),
                    })
            except httpx.HTTPError:
                continue

    return {"target": target, "found": found, "count": len(found)}

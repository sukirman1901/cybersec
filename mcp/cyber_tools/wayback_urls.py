import httpx


async def wayback_urls(domain: str, limit: int = 100) -> dict:
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}&fl=timestamp,original,statuscode,contenttype",
            )
            if resp.status_code == 200:
                rows = resp.json()
                urls = []
                for row in rows[1:]:
                    urls.append({"timestamp": row[0], "url": row[1], "status": row[2], "content_type": row[3]})
                return {"domain": domain, "total": len(urls), "urls": urls}
            return {"domain": domain, "error": f"Wayback API error: {resp.status_code}", "urls": []}
    except Exception as e:
        return {"domain": domain, "error": str(e), "urls": []}

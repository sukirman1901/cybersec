import re

PATTERNS = {
    "debug": [r"debug", r"dev", r"test", r"staging", r"internal", r"beta"],
    "sensitive": [r"admin", r"config", r"backup", r"db_", r"password", r"secret", r"token", r"api_key", r"auth"],
    "endpoints": [r"api/", r"v1/", r"v2/", r"graphql", r"swagger", r"openapi", r"rest", r"health", r"metrics"],
    "params": [r"file=", r"url=", r"redirect=", r"path=", r"page=", r"include=", r"load=", r"src=", r"callback="],
    "files": [r"\.php", r"\.asp", r"\.jsp", r"\.xml", r"\.json", r"\.env", r"\.git", r"\.sql", r"\.bak", r"\.old", r"\.config"],
}


async def gf_patterns(urls: str) -> dict:
    url_list = [u.strip() for u in urls.split("\n") if u.strip()]
    results = {cat: [] for cat in PATTERNS}

    for url in url_list:
        for category, patterns in PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    results[category].append(url)
                    break

    matches = {k: {"count": len(v), "urls": v[:20]} for k, v in results.items() if v}
    return {
        "total_urls_analyzed": len(url_list),
        "matches": matches,
        "total_matches": sum(len(v) for v in results.values()),
    }

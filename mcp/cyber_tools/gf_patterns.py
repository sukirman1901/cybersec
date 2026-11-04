import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

PATTERNS = {
    "debug": [r"debug", r"dev", r"test", r"staging", r"internal", r"beta"],
    "sensitive": [r"admin", r"config", r"backup", r"db_", r"password", r"secret", r"token", r"api_key", r"auth"],
    "endpoints": [r"api/", r"v1/", r"v2/", r"graphql", r"swagger", r"openapi", r"rest", r"health", r"metrics"],
    "params": [r"file=", r"url=", r"redirect=", r"path=", r"page=", r"include=", r"load=", r"src=", r"callback="],
    "files": [r"\.php", r"\.asp", r"\.jsp", r"\.xml", r"\.json", r"\.env", r"\.git", r"\.sql", r"\.bak", r"\.old", r"\.config"],
}


async def gf_patterns(urls: str) -> dict:
    coverage = ('Offline path/query-name classification, not vulnerability evidence; '
                '1000 entries, 8192 characters/URL, 1 Mi characters/input; '
                'query values, userinfo and fragments excluded; path text retained')
    if not isinstance(urls, str) or len(urls) > 1048576:
        return {'error': 'Expected a string of at most 1048576 characters',
                'total_urls_analyzed': 0, 'matches': {}, 'total_matches': 0,
                'coverage_complete': False, 'coverage': coverage}
    url_list = [u.strip() for u in urls.split("\n") if u.strip()]
    results = {cat: [] for cat in PATTERNS}
    errors = ['entry_limit'] if len(url_list) > 1000 else []
    analyzed = 0

    for url in url_list[:1000]:
        if len(url) > 8192:
            errors.append('url_size_limit')
            continue
        try:
            parts = urlsplit(url)
            if parts.scheme and (parts.scheme not in ('http', 'https') or not parts.hostname):
                raise ValueError('unsupported URL')
            port = parts.port
            host = parts.hostname or ''
            if ':' in host:
                host = '[' + host + ']'
            if port is not None:
                host += ':' + str(port)
            safe_url = urlunsplit((parts.scheme, host, parts.path, '', ''))
            query_names = '&'.join(key + '=' for key, _ in parse_qsl(parts.query, keep_blank_values=True))
        except ValueError:
            errors.append('invalid_url')
            continue
        analyzed += 1
        for category, patterns in PATTERNS.items():
            surface = parts.path
            if category == 'params':
                surface = query_names
            elif category == 'sensitive':
                surface += '?' + query_names
            for pattern in patterns:
                if re.search(pattern, surface, re.IGNORECASE):
                    results[category].append(safe_url)
                    break

    matches = {k: {"count": len(v), "urls": v[:20]} for k, v in results.items() if v}
    return {
        "total_urls_analyzed": analyzed,
        "matches": matches,
        "total_matches": sum(len(v) for v in results.values()),
        "assessment": "classification_hints_only",
        "confidence": "LOW",
        "coverage": coverage,
        "coverage_complete": not errors,
        "errors": sorted(set(errors)),
    }

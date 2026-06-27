"""
HTTP parameter discovery via response analysis.
Pure Python, no external binaries.
"""

import asyncio
from typing import Dict, List, Optional

COMMON_PARAMS = [
    "id", "user", "username", "login", "email", "password", "pass",
    "user_id", "uid", "token", "auth", "key", "api_key", "access_token",
    "session", "csrf", "name", "title", "content", "body", "text",
    "type", "category", "status", "page", "p", "limit", "offset",
    "size", "count", "start", "end", "sort", "order", "filter",
    "search", "query", "q", "keyword", "file", "filename", "path",
    "url", "uri", "src", "source", "dest", "download", "upload",
    "action", "cmd", "command", "do", "func", "function", "method",
    "mode", "op", "operation", "format", "output", "response", "view",
    "template", "lang", "debug", "redirect", "next", "back",
    "return_url", "goto", "target", "ref", "referer",
    "item_id", "product_id", "post_id", "article_id",
    "admin", "role", "permission", "level", "group", "access",
    "secret", "private", "date", "version", "code", "hash",
    "from", "to", "cc", "bcc",
]

EXTENDED_PARAMS = COMMON_PARAMS + [
    "api", "client_id", "client_secret", "grant_type", "scope",
    "state", "response_type", "table", "column", "field", "db",
    "database", "schema", "host", "port", "ip", "domain",
    "protocol", "proxy", "timeout", "retry", "max", "min",
    "read", "write", "delete", "create", "update", "exec",
    "system", "shell", "bash", "run", "include", "import",
    "cat_id", "parent_id", "menu",
]


async def discover_params(target: str, method: str = "GET", thorough: bool = False) -> Dict:
    """Discover HTTP parameters by testing common names against target."""
    import httpx

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    method = method.upper()
    params_to_test = EXTENDED_PARAMS if thorough else COMMON_PARAMS
    found_params: List[str] = []

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            try:
                if method == "GET":
                    baseline = await client.get(target)
                else:
                    baseline = await client.request(method, target)
                baseline_length = len(baseline.content)
                baseline_status = baseline.status_code
            except httpx.HTTPError as e:
                return {"params": [], "error": f"Failed to get baseline: {e}", "method": method}

            semaphore = asyncio.Semaphore(5)

            async def test_param(param: str) -> Optional[str]:
                async with semaphore:
                    try:
                        test_value = f"xyztest{param[:3]}789"
                        if method == "GET":
                            test_url = f"{target}?{param}={test_value}"
                            response = await client.get(test_url)
                        else:
                            response = await client.request(method, target, data={param: test_value})

                        rlen = len(response.content)
                        rtext = response.text.lower()
                        diff = abs(rlen - baseline_length)
                        reflection = test_value.lower() in rtext
                        error_mention = (
                            f'"{param}"' in rtext or f"'{param}'" in rtext
                        )
                        status_diff = response.status_code != baseline_status
                        significant = diff > max(100, baseline_length * 0.10)

                        if reflection and "args" in rtext:
                            return None

                        if significant or error_mention or (status_diff and response.status_code in [400, 422]):
                            return param
                    except (httpx.HTTPError, asyncio.TimeoutError):
                        pass
                    return None

            tasks = [test_param(p) for p in params_to_test]
            results = await asyncio.gather(*tasks)
            found_params = [p for p in results if p is not None]

    except Exception as e:
        return {"params": [], "error": str(e), "method": method}

    return {
        "params": found_params,
        "method": method,
        "tested_count": len(params_to_test),
        "found_count": len(found_params),
    }

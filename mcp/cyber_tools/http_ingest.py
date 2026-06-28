"""HTTP ingest — parse URL, OpenAPI, HAR, Burp XML, raw HTTP → findings."""
import json
import re
import urllib.parse

def http_ingest(action: str, data: str = "", format: str = "url", target: str = "", output: str = "json") -> str:
    if action == "ingest":
        if format == "url":
            return _ingest_url(data, target)
        elif format == "curl":
            return _ingest_curl(data)
        elif format == "raw":
            return _ingest_raw(data)
        elif format == "har":
            return _ingest_har(data, target)
        elif format == "burp":
            return _ingest_burp(data)
        elif format == "openapi":
            return _ingest_openapi(data)
        elif format == "list":
            return _ingest_list(data)
        else:
            return json.dumps({"error": f"Unknown format: {format}", "formats": ["url", "curl", "raw", "har", "burp", "openapi", "list"]}, indent=2)
    elif action == "batch":
        return _batch_ingest(data, format, target)
    elif action == "deduplicate":
        return _deduplicate(data)
    else:
        return json.dumps({"error": "Unknown action", "actions": ["ingest", "batch", "deduplicate"]}, indent=2)


INGESTED = []


def _ingest_url(data, target):
    entries = []
    urls = [u.strip() for u in data.replace("\n", " ").split() if u.strip().startswith(("http://", "https://"))]
    if not urls:
        urls = [data]
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        entry = {
            "type": "url",
            "original": url,
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "path": parsed.path or "/",
            "query": parsed.query,
            "params": dict(urllib.parse.parse_qsl(parsed.query)),
            "fragment": parsed.fragment,
        }
        entries.append(entry)
        INGESTED.append(entry)
    return json.dumps({"ingested": len(entries), "target": target or entries[0].get("host", ""), "endpoints": entries}, indent=2)


def _ingest_curl(data):
    entries = []
    # Basic curl parse
    url_match = re.search(r"curl\s+['\"]?(https?://[^'\"\s]+)['\"]?", data, re.I)
    method_match = re.search(r"-X\s+(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)", data, re.I)
    header_matches = re.findall(r"-H\s+['\"]([^'\"]+)['\"]", data)
    body_match = re.search(r"--data(?:-raw)?\s+['\"]([^'\"]+)['\"]", data)

    if url_match:
        url = url_match.group(1)
        parsed = urllib.parse.urlparse(url)
        entry = {
            "type": "curl",
            "original": data,
            "method": (method_match.group(1) if method_match else "GET").upper(),
            "url": url,
            "host": parsed.hostname,
            "path": parsed.path or "/",
            "headers": dict(h.split(": ", 1) for h in header_matches if ": " in h) if header_matches else {},
            "body": body_match.group(1) if body_match else "",
        }
        entries.append(entry)
        INGESTED.append(entry)
    return json.dumps({"ingested": len(entries), "format": "curl", "requests": entries}, indent=2)


def _ingest_raw(data):
    entries = []
    lines = data.strip().split("\n")
    if lines and lines[0].startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "HEAD ")):
        first = lines[0].split()
        method = first[0]
        path = first[1]
        http_ver = first[2] if len(first) > 2 else "HTTP/1.1"
        host = ""
        headers = {}
        body_start = -1
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k] = v
                if k.lower() == "host":
                    host = v.strip()
        body = "\n".join(lines[body_start:]) if body_start > 0 else ""
        entry = {
            "type": "raw_http",
            "method": method,
            "path": path,
            "http_version": http_ver,
            "host": host,
            "headers": headers,
            "body": body,
            "url": f"https://{host}{path}" if host else path,
        }
        entries.append(entry)
        INGESTED.append(entry)
    return json.dumps({"ingested": len(entries), "format": "raw_http", "requests": entries}, indent=2)


def _ingest_har(data, target):
    try:
        har = json.loads(data) if isinstance(data, str) else data
        entries = []
        for har_entry in har.get("log", {}).get("entries", []):
            req = har_entry.get("request", {})
            resp = har_entry.get("response", {})
            entry = {
                "type": "har",
                "method": req.get("method"),
                "url": req.get("url"),
                "headers": {h.get("name"): h.get("value") for h in req.get("headers", [])},
                "query": {p.get("name"): p.get("value") for p in req.get("queryString", [])},
                "post_data": req.get("postData", {}).get("text", ""),
                "status": resp.get("status"),
                "mime_type": resp.get("content", {}).get("mimeType", ""),
            }
            entries.append(entry)
            INGESTED.append(entry)
        return json.dumps({"ingested": len(entries), "target": target, "format": "HAR", "requests": entries}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to parse HAR: {str(e)}"}, indent=2)


def _ingest_burp(data):
    entries = []
    # Parse Burp Suite XML
    for item in re.finditer(r"<item>.*?</item>", data, re.DOTALL):
        item_xml = item.group()
        url_m = re.search(r"<url>(.*?)</url>", item_xml)
        host_m = re.search(r"<host>(.*?)</host>", item_xml)
        method_m = re.search(r"<method>(.*?)</method>", item_xml)
        path_m = re.search(r"<path>(.*?)</path>", item_xml)
        req_m = re.search(r"<request>(.*?)</request>", item_xml, re.DOTALL)
        entry = {
            "type": "burp",
            "url": url_m.group(1) if url_m else "",
            "host": host_m.group(1) if host_m else "",
            "method": method_m.group(1) if method_m else "GET",
            "path": path_m.group(1) if path_m else "/",
            "raw_request": req_m.group(1)[:500] if req_m else "",
        }
        entries.append(entry)
        INGESTED.append(entry)
    if not entries:
        # Try URL list format
        urls = re.findall(r"https?://[^\s<>'\"]+", data)
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            entry = {"type": "burp_url", "url": url, "host": parsed.hostname, "path": parsed.path or "/"}
            entries.append(entry)
            INGESTED.append(entry)
    return json.dumps({"ingested": len(entries), "format": "burp", "requests": entries}, indent=2)


def _ingest_openapi(data):
    try:
        spec = json.loads(data) if isinstance(data, str) else data
        endpoints = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ("get", "post", "put", "delete", "patch", "options", "head"):
                    entry = {
                        "type": "openapi",
                        "method": method.upper(),
                        "path": path,
                        "summary": details.get("summary", ""),
                        "parameters": details.get("parameters", []),
                        "request_body": bool(details.get("requestBody")),
                    }
                    endpoints.append(entry)
                    INGESTED.append(entry)
        server_url = ""
        servers = spec.get("servers", [])
        if servers:
            server_url = servers[0].get("url", "")
        return json.dumps({
            "ingested": len(endpoints),
            "total_paths": len(paths),
            "server": server_url,
            "format": "OpenAPI",
            "endpoints": endpoints,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to parse OpenAPI: {str(e)}"}, indent=2)


def _ingest_list(data):
    lines = [l.strip() for l in data.strip().split("\n") if l.strip()]
    entries = []
    for line in lines:
        if line.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(line)
            entry = {
                "type": "url_list",
                "url": line,
                "host": parsed.hostname,
                "path": parsed.path or "/",
            }
            entries.append(entry)
            INGESTED.append(entry)
    return json.dumps({"ingested": len(entries), "total_lines": len(lines), "format": "list", "endpoints": entries}, indent=2)


def _batch_ingest(data, format, target):
    results = []
    if format == "auto":
        for f in ["url", "curl", "raw", "har", "openapi", "list"]:
            try:
                result = json.loads(http_ingest("ingest", data=data, format=f, target=target))
                if result.get("ingested", 0) > 0:
                    results.append({f: result})
                    break
            except Exception:
                continue
    else:
        result = json.loads(http_ingest("ingest", data=data, format=format, target=target))
        results.append({format: result})
    return json.dumps({"batch": True, "formats_tried": len(results), "results": results}, indent=2)


def _deduplicate(data):
    seen = set()
    unique = []
    for entry in INGESTED + (json.loads(data) if isinstance(data, str) and data.startswith("{") else []):
        key = f"{entry.get('method', 'GET')}:{entry.get('url', '')}:{entry.get('path', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return json.dumps({"total": len(unique), "deduplicated": len(INGESTED) - len(unique), "unique_entries": unique}, indent=2)
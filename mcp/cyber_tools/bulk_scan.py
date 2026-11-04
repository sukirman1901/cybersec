"""Bulk scan — scan multiple targets at once."""

import httpx
from .http_guard import guarded_httpx_get
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context


def bulk_scan(targets: str, tool: str = "port_scan") -> str:
    """Run a scan against multiple targets simultaneously.

    targets: comma-separated or newline-separated list of targets
    tool: which scan tool to simulate (port_scan, http_probe, ssl_check, vuln_scan)
    Returns aggregated results.
    """
    target_list = [t.strip() for t in targets.replace("\n", ",").split(",") if t.strip()]
    if not target_list:
        return json.dumps({"error": "No targets provided"}, indent=2)
    if len(target_list) > 50:
        return json.dumps({"error": "Maximum 50 targets per bulk scan"}, indent=2)

    results = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        # Each worker needs the dispatch session's scope, never the process default.
        futures = {pool.submit(copy_context().run, _scan_single, t, tool): t for t in target_list}
        for future in futures:
            target = futures[future]
            try:
                result = future.result(timeout=30)
                entry = {"target": target, "result": result}
                if result.get('error') or result.get('coverage_complete') is False:
                    entry['error'] = result.get('error', 'Scan incomplete')
                results.append(entry)
            except Exception as e:
                results.append({"target": target, "error": str(e)})

    summary = {
        "tool": tool,
        "total_targets": len(target_list),
        "successful": sum(1 for r in results if "error" not in r),
        "failed": sum(1 for r in results if "error" in r),
        "results": results,
    }
    return json.dumps(summary, indent=2)


def _scan_single(target: str, tool: str) -> dict:
    try:
        if tool == "port_scan":
            return _bulk_port_scan(target)
        elif tool == "http_probe":
            return _bulk_http_probe(target)
        elif tool == "ssl_check":
            return _bulk_ssl_check(target)
        elif tool == "vuln_scan":
            return _bulk_vuln_scan(target)
        else:
            return {"error": f"Unknown tool: {tool}. Supported: port_scan, http_probe, ssl_check, vuln_scan"}
    except Exception as e:
        return {"error": str(e)}


def _bulk_port_scan(target: str) -> dict:
    import socket
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append({"port": port, "service": "open"})
            sock.close()
        except socket.error:
            break
    return {"open_ports": open_ports, "count": len(open_ports)}


def _bulk_http_probe(target: str) -> dict:
    results = {}
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{target}"
            resp = guarded_httpx_get(url, timeout=10, follow_redirects=True, verify=False)
            results[scheme] = {
                "status": resp.status_code,
                "title": _extract_title(resp.text),
                "server": resp.headers.get("server", ""),
                "tech": list(resp.headers.keys())[:5],
            }
            break
        except httpx.RequestError:
            continue
    return results if results else {"error": "Connection failed"}


def _bulk_ssl_check(target: str) -> dict:
    import ssl
    import socket
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            return {
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "not_after": cert.get("notAfter", ""),
                "protocol": s.version(),
            }
    except Exception as e:
        return {"error": str(e)}


def _bulk_vuln_scan(target: str) -> dict:
    from .vuln_scanner import scan_vulnerabilities
    return asyncio.run(scan_vulnerabilities(target))


def _extract_title(html):
    import re
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:100] if match else ""

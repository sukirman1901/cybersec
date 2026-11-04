"""Raw replay — faithful raw HTTP request replay with response capture."""
import json
import socket
import ssl
import urllib.parse
import time


def _safe_url(value):
    """Output-only sanitization; never used to construct a transmitted request."""
    try:
        parsed = urllib.parse.urlsplit(value)
        if not parsed.netloc and "@" in parsed.path:
            return "[withheld]"
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            return "[withheld]"
        authority = parsed.netloc.rsplit("@", 1)[-1]
        return urllib.parse.urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
    except (ValueError, TypeError):
        return "[withheld]"

def raw_replay(action: str, raw_request: str = "", target: str = "", url: str = "", method: str = "GET", headers_json: str = "", body: str = "", follow_redirects: bool = False, timeout: int = 15) -> str:
    fields = (action, raw_request, target, url, method, headers_json, body)
    if any(not isinstance(value, str) for value in fields) or not isinstance(follow_redirects, bool):
        return json.dumps({"error": "Invalid argument type"})
    if sum(map(len, fields)) > 1048576:
        return json.dumps({"error": "Request exceeds 1 MiB budget"})
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        return json.dumps({"error": "timeout must be between 0 (exclusive) and 60 seconds"})
    try:
        encoded_size = sum(len(value.encode()) for value in fields)
    except UnicodeError:
        return json.dumps({"error": "Invalid text encoding"})
    if encoded_size > 1048576:
        return json.dumps({"error": "Request exceeds 1 MiB budget"})
    if headers_json:
        try:
            headers = json.loads(headers_json)
            if not isinstance(headers, dict):
                raise ValueError()
        except (ValueError, TypeError, RecursionError):
            return json.dumps({"error": "headers_json must be a JSON object"})
    if action == "replay":
        if raw_request:
            return _replay_raw(raw_request, follow_redirects, timeout)
        else:
            return _replay_constructed(url, method, headers_json, body, follow_redirects, timeout)
    elif action == "send":
        return _send_raw(raw_request, target, timeout)
    elif action == "template":
        return _get_template(method, target or url or "example.com", headers_json, body)
    elif action == "preview":
        return _preview_request(raw_request, target, method, headers_json, body)
    else:
        return json.dumps({"error": "Unknown action", "actions": ["replay", "send", "template", "preview"]}, indent=2)


def _parse_host(raw):
    lines = raw.split("\n")
    for line in lines:
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None


def _replay_raw(raw_request, follow_redirects, timeout):
    host = _parse_host(raw_request)
    if not host:
        return json.dumps({"error": "Could not parse Host header from raw request"}, indent=2)

    port = 80
    use_ssl = False
    if ":" in host:
        hostname, port_str = host.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            pass
        host = hostname
    if port == 443:
        use_ssl = True

    return _do_send(host, port, use_ssl, raw_request.encode(), follow_redirects, timeout)


def _replay_constructed(url, method, headers_json, body, follow_redirects, timeout):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            raise ValueError()
    except ValueError:
        return json.dumps({"error": "Invalid HTTP URL"})
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    try:
        headers = json.loads(headers_json) if headers_json else {}
    except Exception:
        headers = {}

    raw_lines = [f"{method} {path} HTTP/1.1"]
    raw_lines.append(f"Host: {host}")
    for k, v in headers.items():
        raw_lines.append(f"{k}: {v}")
    if body and "Content-Length" not in headers:
        raw_lines.append(f"Content-Length: {len(body)}")
    raw_lines.append("")
    raw_lines.append(body or "")
    raw_request = "\r\n".join(raw_lines)

    return _do_send(host, port, use_ssl, raw_request.encode(), follow_redirects, timeout)


def _do_send(host, port, use_ssl, raw_data, follow_redirects, timeout):
    sock = None
    deadline = time.monotonic() + timeout
    try:
        if not host or not 1 <= port <= 65535:
            return json.dumps({"error": "Invalid host or port"})
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.sendall(raw_data)

        response = b""
        incomplete = False
        for _ in range(256):
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    incomplete = True
                    break
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    if b"\r\n\r\n" in response:
                        head, received_body = response.split(b"\r\n\r\n", 1)
                        for line in head.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                incomplete = len(received_body) < int(line.split(b":", 1)[1])
                    break
                response += chunk
                if time.monotonic() >= deadline:
                    incomplete = True
                    break
                if b"\r\n\r\n" in response:
                    headers_end = response.index(b"\r\n\r\n") + 4
                    header_section = response[:headers_end].decode("utf-8", errors="replace")
                    cl_match = [l for l in header_section.split("\r\n") if "content-length:" in l.lower()]
                    if cl_match:
                        cl = int(cl_match[0].split(":")[1].strip())
                        body_size = len(response) - headers_end
                        if body_size >= cl:
                            break
                    else:
                        break
            except socket.timeout:
                incomplete = True
                break
        else:
            incomplete = True
        sock.close()

        headers_end = response.index(b"\r\n\r\n") + 4 if b"\r\n\r\n" in response else len(response)
        header_raw = response[:headers_end].decode("utf-8", errors="replace")
        body_raw = response[headers_end:]

        status_line = header_raw.split("\r\n")[0] if header_raw else ""
        status_code = 0
        if " " in status_line:
            parts = status_line.split(" ")
            try:
                status_code = int(parts[1])
            except (ValueError, IndexError):
                pass

        resp_headers = {}
        for line in header_raw.split("\r\n")[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                resp_headers[k] = v

        result = {
            "remote_effects_verified": False,
            "coverage_complete": not incomplete and bool(status_code),
            "status_code": status_code,
            "status_line": f"HTTP {status_code}" if status_code else "",
            "headers": {k: _safe_url(v) if k.lower() in ("location", "content-location") else "[withheld]"
                        for k, v in resp_headers.items()},
            "body_size": len(body_raw),
            "body_preview": "",
            "body_b64": "",
            "withheld": {"response_body": True, "header_values": True, "status_reason": True,
                         "url_components": ["userinfo", "query", "fragment"]},
            "timeout_seconds": timeout,
        }
        if incomplete or not status_code:
            result["error"] = "Incomplete or invalid HTTP response"

        if follow_redirects and status_code in (301, 302, 307, 308):
            location = resp_headers.get("Location", "")
            if location:
                if not location.startswith("http"):
                    location = f"{'https' if use_ssl else 'http'}://{host}:{port}{location}"
                result["redirect_followed"] = False
                result["redirect_location"] = _safe_url(location)

        return json.dumps(result, indent=2)

    except socket.timeout:
        return json.dumps({"error": f"Connection timed out after {timeout}s", "host": "[withheld]", "port": port}, indent=2)
    except Exception as e:
        return json.dumps({"error": type(e).__name__, "host": "[withheld]", "port": port}, indent=2)
    finally:
        if sock is not None:
            sock.close()


def _send_raw(raw_request, target, timeout):
    host = target or _parse_host(raw_request)
    if not host:
        return json.dumps({"error": "No target specified and no Host in raw request"}, indent=2)
    port = 80
    use_ssl = False
    if ":" in host:
        h, p = host.rsplit(":", 1)
        try:
            port = int(p)
            host = h
        except ValueError:
            pass
    return _do_send(host, port, use_ssl, raw_request.encode(), False, timeout)


def _get_template(method, target, headers_json, body):
    return json.dumps({"template": "", "withheld": {"request_content": True}}, indent=2)


def _preview_request(raw_request, target, method, headers_json, body):
    if raw_request:
        return json.dumps({"preview": "", "length": len(raw_request), "withheld": {"request_content": True}}, indent=2)
    return json.dumps({"preview": "", "method": "[withheld]", "target": _safe_url(target),
                       "withheld": {"request_content": True, "url_components": ["userinfo", "query", "fragment"]}}, indent=2)


def _to_b64(data):
    import base64
    return base64.b64encode(data).decode()

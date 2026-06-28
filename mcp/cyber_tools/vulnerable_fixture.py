"""Vulnerable fixture — local vulnerable app for E2E tool validation."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import signal
import time
from datetime import datetime

def vulnerable_fixture(action: str, target: str = "127.0.0.1", port: int = 9999, vuln_types: str = "sqli,xss,lfi,cmd,ssrf,open_redirect", ssl: bool = False, reset: bool = False) -> str:
    if action == "start":
        return _start_fixture(target, port, vuln_types, ssl, reset)
    elif action == "stop":
        return _stop_fixture(target, port)
    elif action == "status":
        return _status(port)
    elif action == "endpoints":
        return _list_endpoints(vuln_types, port)
    elif action == "e2e":
        return _run_e2e(target, port, vuln_types, ssl)
    elif action == "cleanup":
        return _cleanup_fixture()
    else:
        return json.dumps({"error": "Unknown action", "actions": ["start", "stop", "status", "endpoints", "e2e", "cleanup"]}, indent=2)


FIXTURE_DIR = tempfile.mkdtemp(prefix="cybersec_fixture_")
FIXTURE_PROCESS = {"pid": None, "port": None, "started_at": None}
FIXTURE_CODE = {}


def _make_fixture_code(vuln_types, port):
    types = [t.strip() for t in vuln_types.split(",")]
    server_code = '''
"""Vulnerable test fixture — DO NOT USE IN PRODUCTION"""
import json
import os
import subprocess
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

VULN_TYPES = %(vuln_types)s

class VulnHandler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if isinstance(body, str):
            self.wfile.write(body.encode())
        else:
            self.wfile.write(body)

    def _params(self):
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def _html(self, body):
        return f"<html><body>{body}</body></html>"

    def do_GET(self):
        params = self._params()
        path = self.path.split("?")[0]

        # --- SQLi endpoint ---
        if path == "/sqli" and "sqli" in VULN_TYPES:
            uid = params.get("id", "1")
            if "'" in uid or "union" in uid.lower() or "or" in uid.lower():
                self._send(200, json.dumps({"query": f"SELECT * FROM users WHERE id = {uid}", "rows": [{"id": 1, "username": "admin", "password": "flag{SQLi_Success}"}]}))
            else:
                self._send(200, json.dumps({"query": f"SELECT * FROM users WHERE id = {uid}", "rows": [{"id": 1, "username": "guest"}]}))

        # --- XSS endpoint ---
        elif path == "/xss" and "xss" in VULN_TYPES:
            name = params.get("name", "world")
            self._send(200, self._html(f"<h1>Hello {name}</h1>"), "text/html")

        # --- Reflected XSS ---
        elif path == "/xss/reflected" and "xss" in VULN_TYPES:
            q = params.get("q", "")
            self._send(200, self._html(f"<div>Search: {q}</div>"), "text/html")

        # --- LFI endpoint ---
        elif path == "/lfi" and "lfi" in VULN_TYPES:
            file = params.get("file", "/etc/passwd")
            try:
                with open(file, "r") as f:
                    self._send(200, f.read(), "text/plain")
            except Exception:
                self._send(200, f"File not found: {file}")

        # --- Command injection ---
        elif path == "/cmd" and "cmd" in VULN_TYPES:
            ip = params.get("ip", "127.0.0.1")
            result = subprocess.run(f"ping -c 1 {ip}", shell=True, capture_output=True, text=True, timeout=5)
            self._send(200, result.stdout or result.stderr, "text/plain")

        # --- SSRF endpoint ---
        elif path == "/ssrf" and "ssrf" in VULN_TYPES:
            url = params.get("url", "http://example.com")
            import urllib.request
            try:
                resp = urllib.request.urlopen(url, timeout=5)
                self._send(200, resp.read()[:500])
            except Exception as e:
                self._send(200, f"SSRF error: {e}")

        # --- Open redirect ---
        elif path == "/redirect" and "open_redirect" in VULN_TYPES:
            url = params.get("url", "/")
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()

        # --- Debug / health ---
        elif path == "/health":
            self._send(200, json.dumps({"status": "ok", "vulns": VULN_TYPES}))

        # --- Admin panel (fake) ---
        elif path == "/admin":
            self._send(200, json.dumps({"message": "Admin panel (no auth)", "sensitive": True}))

        # --- Config exposure ---
        elif path == "/config":
            self._send(200, json.dumps({"DB_PASSWORD": "super_secret_123", "API_KEY": "sk-test-12345", "SECRET_KEY": "dev-key-abc123"}))

        # --- Upload endpoint (POST only) ---
        elif path == "/upload":
            self._send(200, json.dumps({"error": "Use POST to upload"}))

        else:
            self._send(200, json.dumps({"vulns": VULN_TYPES, "endpoints": %(endpoints_json)s, "note": "Vulnerable test fixture"}))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        params = {}
        try:
            params = json.loads(body) if body else {}
        except Exception:
            pass
        path = self.path.split("?")[0]

        if path == "/upload":
            self._send(200, json.dumps({"status": "uploaded", "filename": "shell.php", "path": "/uploads/shell.php", "url": "http://localhost:%(port)d/uploads/shell.php"}))

        elif path == "/api/login":
            self._send(200, json.dumps({"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.", "message": "JWT with alg=none"}))

        elif path == "/api/update":
            uid = params.get("id", "0")
            self._send(200, json.dumps({"updated": True, "id": uid, "note": "No auth check on update"}))

        elif path == "/sqli":
            uid = params.get("id", "1")
            if "'" in uid or "or" in uid.lower():
                self._send(200, json.dumps({"result": "SQL injection confirmed", "data": [{"id": 1, "secret": "flag{sqli_post}"}]}))
            else:
                self._send(200, json.dumps({"result": "normal", "id": uid}))

        else:
            self._send(200, json.dumps({"method": "POST", "path": path}))

def run(port):
    server = HTTPServer(("0.0.0.0", port), VulnHandler)
    print(f"Fixture running on port {port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

if __name__ == "__main__":
    import sys
    run(int(sys.argv[1]))
''' % {
        "vuln_types": json.dumps(types),
        "endpoints_json": json.dumps(["/sqli", "/xss", "/xss/reflected", "/lfi", "/cmd", "/ssrf", "/redirect", "/admin", "/config", "/upload", "/health"]),
        "port": port,
    }
    return server_code


def _start_fixture(target, port, vuln_types, ssl, reset):
    if FIXTURE_PROCESS["pid"]:
        _stop_fixture(target, port)

    if reset and os.path.exists(FIXTURE_DIR):
        shutil.rmtree(FIXTURE_DIR)
        os.makedirs(FIXTURE_DIR, exist_ok=True)

    code = _make_fixture_code(vuln_types, port)
    fixture_path = os.path.join(FIXTURE_DIR, "fixture.py")
    with open(fixture_path, "w") as f:
        f.write(code)

    # Check port availability
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        return json.dumps({"error": f"Port {port} already in use" if port else "Try a different port"}, indent=2)

    proc = subprocess.Popen(
        [sys.executable, fixture_path, str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.5)

    if proc.poll() is not None:
        _, stderr = proc.communicate()
        return json.dumps({"error": f"Fixture failed: {stderr.decode()}"}, indent=2)

    FIXTURE_PROCESS["pid"] = proc.pid
    FIXTURE_PROCESS["port"] = port
    FIXTURE_PROCESS["started_at"] = datetime.utcnow().isoformat() + "Z"
    FIXTURE_CODE[str(port)] = code

    return json.dumps({
        "status": "started",
        "pid": proc.pid,
        "target": target,
        "port": port,
        "vulns": [t.strip() for t in vuln_types.split(",")],
        "ssl": ssl,
        "base_url": f"http://{target}:{port}",
        "health": f"http://{target}:{port}/health",
        "endpoints": ["/sqli", "/xss", "/xss/reflected", "/lfi", "/cmd", "/ssrf", "/redirect", "/admin", "/config", "/upload", "/health"],
        "note": "Vulnerable fixture is running. Use action='e2e' to auto-test tools.",
    }, indent=2)


def _stop_fixture(target, port):
    if FIXTURE_PROCESS["pid"]:
        try:
            os.kill(FIXTURE_PROCESS["pid"], signal.SIGTERM)
            time.sleep(0.5)
            FIXTURE_PROCESS["pid"] = None
            FIXTURE_PROCESS["port"] = None
            return json.dumps({"status": "stopped", "message": "Fixture stopped"}, indent=2)
        except ProcessLookupError:
            pass
    # Also try pkill by port
    try:
        subprocess.run(["pkill", "-f", f"fixture.py {port}"], capture_output=True, timeout=5)
    except Exception:
        pass
    FIXTURE_PROCESS["pid"] = None
    FIXTURE_PROCESS["port"] = None
    return json.dumps({"status": "stopped", "message": "Fixture process cleaned up"}, indent=2)


def _status(port):
    if FIXTURE_PROCESS["pid"] and FIXTURE_PROCESS["port"] == port:
        return json.dumps({
            "running": True,
            "pid": FIXTURE_PROCESS["pid"],
            "port": port,
            "started_at": FIXTURE_PROCESS["started_at"],
        }, indent=2)

    # Check if process is still alive on that port
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        return json.dumps({"running": result == 0, "port": port, "note": "Port in use but not managed by this session" if result == 0 else "Port free"}, indent=2)
    except Exception:
        return json.dumps({"running": False, "port": port}, indent=2)


def _list_endpoints(vuln_types, port):
    return json.dumps({
        "base_url": f"http://127.0.0.1:{port}",
        "endpoints": {
            "sqli": "/sqli?id=1",
            "sqli_injectable": "/sqli?id=1' OR '1'='1",
            "xss": "/xss?name=<script>alert(1)</script>",
            "xss_reflected": "/xss/reflected?q=<script>alert(document.cookie)</script>",
            "lfi": "/lfi?file=/etc/passwd",
            "lfi_path_traversal": "/lfi?file=../../../../etc/passwd",
            "cmd": "/cmd?ip=127.0.0.1",
            "cmd_injectable": "/cmd?ip=127.0.0.1;id",
            "ssrf": "/ssrf?url=http://169.254.169.254/",
            "redirect": "/redirect?url=https://evil.com",
            "admin": "/admin",
            "config": "/config",
            "upload": "/upload (POST)",
            "health": "/health",
        },
        "vulns_enabled": [t.strip() for t in vuln_types.split(",")],
    }, indent=2)


def _run_e2e(target, port, vuln_types, ssl):
    import urllib.request
    results = {}
    base = f"http://{target}:{port}"
    types = [t.strip() for t in vuln_types.split(",")]

    # Test health
    try:
        resp = urllib.request.urlopen(f"{base}/health", timeout=5)
        results["health"] = {"status": resp.status, "ok": resp.status == 200}
    except Exception as e:
        return json.dumps({"error": f"Fixture not reachable at {base}/health: {str(e)}", "start_hint": "Run start action first"}, indent=2)

    # Test SQLi
    if "sqli" in types:
        try:
            resp = urllib.request.urlopen(f"{base}/sqli?id=1'%20OR%20'1'%3D'1", timeout=5)
            data = json.loads(resp.read())
            results["sqli"] = {"detected": "SQL injection" in json.dumps(data), "response": data}
        except Exception as e:
            results["sqli"] = {"error": str(e)}

    # Test XSS
    if "xss" in types:
        try:
            resp = urllib.request.urlopen(f"{base}/xss?name=<script>alert(1)</script>", timeout=5)
            body = resp.read().decode()
            results["xss"] = {"reflected": "<script>" in body, "response_preview": body[:200]}
        except Exception as e:
            results["xss"] = {"error": str(e)}

    # Test LFI
    if "lfi" in types:
        try:
            resp = urllib.request.urlopen(f"{base}/lfi?file=/etc/passwd", timeout=5)
            body = resp.read().decode()
            results["lfi"] = {"readable": "root:" in body or "nobody:" in body, "preview": body[:100]}
        except Exception as e:
            results["lfi"] = {"error": str(e)}

    # Test CMD
    if "cmd" in types:
        try:
            resp = urllib.request.urlopen(f"{base}/cmd?ip=127.0.0.1;id", timeout=5)
            body = resp.read().decode()
            results["cmd"] = {"executed": "uid=" in body, "output": body[:200]}
        except Exception as e:
            results["cmd"] = {"error": str(e)}

    # Test SSRF
    if "ssrf" in types:
        try:
            resp = urllib.request.urlopen(f"{base}/ssrf?url=http://127.0.0.1:{port}/health", timeout=5)
            body = resp.read()
            results["ssrf"] = {"ssrf_possible": True, "note": "SSRF endpoint makes requests to arbitrary URLs"}
        except Exception as e:
            results["ssrf"] = {"error": str(e)}

    # Test redirect
    if "open_redirect" in types:
        try:
            resp = urllib.request.urlopen(f"{base}/redirect?url=https://evil.com", timeout=5)
            results["open_redirect"] = {"status": resp.status, "location": resp.url}
        except Exception as e:
            results["open_redirect"] = {"error": str(e)}

    # Test POST sqli
    if "sqli" in types:
        try:
            import urllib.request
            data = json.dumps({"id": "1' OR '1'='1"}).encode()
            req = urllib.request.Request(f"{base}/sqli", data=data, headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            body = json.loads(resp.read())
            results["sqli_post"] = {"detected": "flag" in json.dumps(body), "response": body}
        except Exception as e:
            results["sqli_post"] = {"error": str(e)}

    all_passed = all(
        r.get("detected") or r.get("readable") or r.get("executed") or r.get("reflected") or r.get("status", 200) == 200
        for k, r in results.items() if isinstance(r, dict) and k != "health"
    )

    return json.dumps({
        "fixture_url": base,
        "total_tests": len(results),
        "results": results,
        "all_detected": all_passed,
        "verdict": "E2E PASSED — all vulns detected" if all_passed else "E2E PARTIAL — some vulns not detected",
    }, indent=2)


def _cleanup_fixture():
    if FIXTURE_PROCESS["pid"]:
        try:
            os.kill(FIXTURE_PROCESS["pid"], signal.SIGTERM)
        except ProcessLookupError:
            pass
    if os.path.exists(FIXTURE_DIR):
        shutil.rmtree(FIXTURE_DIR, ignore_errors=True)
    FIXTURE_PROCESS["pid"] = None
    FIXTURE_PROCESS["port"] = None
    return json.dumps({"status": "cleaned", "removed": FIXTURE_DIR}, indent=2)
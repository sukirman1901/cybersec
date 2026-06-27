import httpx

CHECKS = [
    ("/var/run/docker.sock", "docker socket exposed", "critical"),
    ("/.dockerenv", "docker environment", "info"),
    ("/proc/1/cgroup", "docker", "info"),
    ("/proc/1/environ", "environment variables leaked", "high"),
    ("/proc/self/mounts", "overlay|docker", "info"),
]


async def docker_scan(target: str) -> dict:
    findings = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path, indicator, severity in CHECKS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and resp.text.strip():
                    findings.append({
                        "path": path,
                        "status": resp.status_code,
                        "severity": severity,
                        "indicator": indicator,
                    })
            except (httpx.HTTPError, httpx.ConnectError):
                continue
        try:
            sock = __import__("socket").socket(__import__("socket").AF_UNIX, __import__("socket").SOCK_STREAM)
            sock.settimeout(3)
            sock.connect("/var/run/docker.sock")
            sock.send(b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n")
            resp_sock = sock.recv(4096).decode(errors="replace")
            sock.close()
            if "HTTP/1.1 200" in resp_sock:
                findings.append({"path": "/var/run/docker.sock (local)", "severity": "critical", "indicator": "Docker socket accessible"})
        except (FileNotFoundError, ConnectionRefusedError, OSError):
            pass
    return {"target": target, "findings": findings, "count": len(findings)}

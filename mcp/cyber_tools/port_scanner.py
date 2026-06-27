"""Port scanner using Python sockets. No nmap required."""

import socket
import asyncio

COMMON_SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
}

async def _check_port(ip: str, port: int, timeout: float = 1.0) -> int | None:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

def scan_ports(target: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Scan list of TCP ports, return open ones."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return []

    semaphore = asyncio.Semaphore(100)

    async def limited_check(port: int) -> int | None:
        async with semaphore:
            return await _check_port(ip, port, timeout)

    async def run():
        tasks = [limited_check(p) for p in ports]
        results = await asyncio.gather(*tasks)
        return sorted([p for p in results if p is not None])

    return asyncio.run(run())

async def _grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        if port in [80, 443, 8080, 8443]:
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return banner.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            writer.close()
            await writer.wait_closed()
            return ""
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return ""

def detect_service(target: str, port: int, timeout: float = 1.0) -> dict:
    """Detect service on open port with banner grabbing."""
    service = COMMON_SERVICE_PORTS.get(port, "unknown")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"port": port, "service": service, "banner": "", "protocol": "tcp"}

    banner = asyncio.run(_grab_banner(ip, port, timeout))
    cleaned = banner.strip().split("\n")[0][:100] if banner else ""
    return {"port": port, "service": service, "banner": cleaned, "protocol": "tcp"}

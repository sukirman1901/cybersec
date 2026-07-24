"""Deep port scanner — concurrent scan, service fingerprinting, version detection, vulnerability hints."""

import socket
import asyncio
import re
import time

# --- Extended Port List ---
COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap",
    443: "https", 445: "smb", 464: "kerberos", 465: "smtps",
    514: "syslog", 515: "lpd", 554: "rtsp", 587: "smtp",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1099: "rmiregistry", 1433: "mssql",
    1434: "mssql-m", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2181: "zookeeper", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5672: "rabbitmq",
    5900: "vnc", 5901: "vnc", 6379: "redis", 6443: "kubernetes",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 9418: "git",
    9999: "http-alt", 10000: "webmin", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb", 50000: "sap",
    50070: "hdfs", 60010: "hbase", 60020: "hbase",
}

# --- Service Signatures ---
SERVICE_SIGNATURES = {
    "SSH": {
        "pattern": r"SSH-[\d.]+",
        "ports": [22],
        "risk": "low",
    },
    "FTP": {
        "pattern": r"(220.*FTP|FileZilla|vsftpd|ProFTPD|Pure-FTPd|WU-FTPD)",
        "ports": [21],
        "risk": "medium",
    },
    "SMTP": {
        "pattern": r"(220.*SMTP|ESMTP|Postfix|Exim|Sendmail|Microsoft ESMTP)",
        "ports": [25, 587],
        "risk": "medium",
    },
    "HTTP": {
        "pattern": r"(HTTP/[\d.]+|Server:|X-Powered-By:)",
        "ports": [80, 443, 8080, 8443],
        "risk": "info",
    },
    "MySQL": {
        "pattern": r"(mysql|MariaDB|[\d.]+-mysql)",
        "ports": [3306],
        "risk": "medium",
    },
    "PostgreSQL": {
        "pattern": r"(PostgreSQL|PG)",
        "ports": [5432],
        "risk": "medium",
    },
    "Redis": {
        "pattern": r"(-ERR|redis|REDIS)",
        "ports": [6379],
        "risk": "high",
    },
    "MongoDB": {
        "pattern": r"(MongoDB|ismaster|hello)",
        "ports": [27017, 27018],
        "risk": "medium",
    },
    "MSSQL": {
        "pattern": r"(MSSQL|Microsoft SQL)",
        "ports": [1433, 1434],
        "risk": "medium",
    },
    "SMB": {
        "pattern": r"(SMB|Samba|Microsoft)",
        "ports": [445, 139],
        "risk": "high",
    },
    "LDAP": {
        "pattern": r"(LDAP|Active Directory)",
        "ports": [389, 636],
        "risk": "medium",
    },
    "VNC": {
        "pattern": r"(RFB|VNC)",
        "ports": [5900, 5901],
        "risk": "high",
    },
    "RDP": {
        "pattern": r"(RDP|Remote Desktop)",
        "ports": [3389],
        "risk": "medium",
    },
    "Kubernetes": {
        "pattern": r"(kubernetes|apiserver)",
        "ports": [6443, 8080, 10250],
        "risk": "critical",
    },
    "Docker": {
        "pattern": r"(Docker|docker)",
        "ports": [2375, 2376],
        "risk": "critical",
    },
    "Elasticsearch": {
        "pattern": r"(cluster_name|elasticsearch)",
        "ports": [9200, 9300],
        "risk": "critical",
    },
    "Zookeeper": {
        "pattern": r"(zookeeper|Zookeeper)",
        "ports": [2181],
        "risk": "high",
    },
    "RabbitMQ": {
        "pattern": r"(rabbitmq|RabbitMQ)",
        "ports": [5672, 15672],
        "risk": "medium",
    },
    "Memcached": {
        "pattern": r"(STAT pid|version)",
        "ports": [11211],
        "risk": "high",
    },
    "Prometheus": {
        "pattern": r"(prometheus|# HELP|# TYPE)",
        "ports": [9090],
        "risk": "high",
    },
}

# --- Vulnerability Hints by Service ---
VULN_HINTS = {
    "redis": ["CRITICAL: Redis likely unauthenticated", "Use CONFIG SET to write SSH keys"],
    "mongodb": ["Check for unauthenticated access", "May expose sensitive data"],
    "memcached": ["CRITICAL: Memcached likely unauthenticated", "Use stats to dump data"],
    "elasticsearch": ["CRITICAL: Elasticsearch likely unauthenticated", "May expose all indices"],
    "vnc": ["May have weak/no authentication", "VNC password brute-force possible"],
    "smb": ["Check for anonymous/null session", "SMBv1 may be vulnerable"],
    "ftp": ["Check for anonymous login", "Plain text credentials"],
    "telnet": ["CRITICAL: Telnet transmits credentials in cleartext"],
    "smtp": ["Check for open relay", "User enumeration via VRFY"],
    "snmp": ["Check for default community strings (public/private)", "SNMPv1/v2c transmit community in cleartext"],
    "kubernetes": ["CRITICAL: Kubernetes API may be exposed", "Check for unauthenticated access"],
    "docker": ["CRITICAL: Docker socket exposed", "Container escape possible"],
    "nfs": ["Check for no_root_squash", "Exported shares may be accessible"],
    "jupyter": ["CRITICAL: Jupyter notebook may be unauthenticated", "Remote code execution"],
}


async def _check_port(ip: str, port: int, timeout: float = 1.0) -> int | None:
    """Check if a port is open."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Grab service banner from open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )

        # HTTP ports - send HTTP request
        if port in [80, 443, 8080, 8443, 8888, 9090, 10000, 50000]:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            await writer.drain()
        # SMTP - read greeting
        elif port in [25, 587, 465]:
            pass  # Just read the greeting
        # FTP - read greeting
        elif port in [21]:
            pass  # Just read the greeting
        # SSH - read version
        elif port in [22]:
            pass  # Just read the version
        # Redis - send PING
        elif port in [6379]:
            writer.write(b"PING\r\n")
            await writer.drain()
        # MongoDB - send isMaster
        elif port in [27017, 27018]:
            is_master = b'\x3d\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x0d\x00\x00\x00\x01\x69\x73\x4d\x61\x73\x74\x65\x72\x00\x00\x00\x00\x00\x00\x00\xf0\x3f'
            writer.write(is_master)
            await writer.drain()
        # Memcached - send version
        elif port in [11211]:
            writer.write(b"version\r\n")
            await writer.drain()
        # Elasticsearch
        elif port in [9200]:
            writer.write(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
        # SNMP
        elif port in [161]:
            pass  # SNMP needs specific packets
        # SMB
        elif port in [445, 139]:
            pass  # SMB needs negotiation
        else:
            writer.write(b"\r\n")
            await writer.drain()

        try:
            banner = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return banner.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            writer.close()
            await writer.wait_closed()
            return ""

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return ""


def _fingerprint_service(banner: str, port: int) -> dict:
    """Fingerprint service from banner and port number."""
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": banner[:200] if banner else "",
        "protocol": "tcp",
        "version": "",
        "risk": "info",
        "vuln_hints": [],
    }

    # Match service signatures
    for service_name, sig in SERVICE_SIGNATURES.items():
        if re.search(sig["pattern"], banner, re.IGNORECASE):
            result["detected_service"] = service_name
            result["risk"] = sig["risk"]

            # Extract version
            version_match = re.search(r'([\w]+)[/\s]+([\d.]+)', banner)
            if version_match:
                result["version"] = f"{version_match.group(1)} {version_match.group(2)}"

            break

    # Add vulnerability hints
    for service_key, hints in VULN_HINTS.items():
        if service_key in result["service"].lower() or service_key in result.get("detected_service", "").lower():
            result["vuln_hints"] = hints

    return result


async def _concurrent_scan(ip: str, ports: list[int], timeout: float = 1.0, concurrency: int = 200) -> list[int]:
    """Concurrent port scan with configurable concurrency."""
    semaphore = asyncio.Semaphore(concurrency)

    async def limited_check(port: int) -> int | None:
        async with semaphore:
            return await _check_port(ip, port, timeout)

    tasks = [limited_check(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted([p for p in results if p is not None])


# --- Backward-compatible aliases ---
def scan_ports(target: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Scan list of TCP ports, return open ones. Legacy interface."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return []

    async def run():
        return await _concurrent_scan(ip, ports, timeout, concurrency=100)

    return asyncio.run(run())


def detect_service(target: str, port: int, timeout: float = 1.0) -> dict:
    """Detect service on open port with banner grabbing. Legacy interface."""
    service = COMMON_SERVICE_PORTS.get(port, "unknown")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"port": port, "service": service, "banner": "", "protocol": "tcp"}

    banner = asyncio.run(_grab_banner(ip, port, timeout))
    cleaned = banner.strip().split("\n")[0][:100] if banner else ""
    return {"port": port, "service": service, "banner": cleaned, "protocol": "tcp"}


async def port_scanner(target: str, ports: str = "", timeout: float = 1.0, concurrency: int = 200) -> dict:
    """Deep port scanner with concurrent scan, service fingerprinting, version detection, vulnerability hints."""
    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"target": target, "error": "DNS resolution failed", "open_ports": []}

    # Parse ports
    if ports:
        port_list = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                port_list.extend(range(int(start), int(end) + 1))
            elif part.isdigit():
                port_list.append(int(part))
        port_list = sorted(set(port_list))
    else:
        port_list = sorted(COMMON_PORTS.keys())

    scan_start = time.time()
    open_ports = await _concurrent_scan(ip, port_list, timeout, concurrency)
    scan_time = time.time() - scan_start

    # Fingerprint services
    services = []
    for port in open_ports:
        banner = await _grab_banner(ip, port, timeout=2.0)
        service_info = _fingerprint_service(banner, port)
        services.append(service_info)

    # Summary
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for svc in services:
        risk = svc.get("risk", "info")
        if risk in risk_summary:
            risk_summary[risk] += 1

    return {
        "target": target,
        "ip": ip,
        "scan_time_seconds": round(scan_time, 2),
        "ports_scanned": len(port_list),
        "open_ports": open_ports,
        "services": services,
        "total_open": len(open_ports),
        "risk_summary": risk_summary,
        "critical_services": [s for s in services if s.get("risk") == "critical"],
        "high_risk_services": [s for s in services if s.get("risk") == "high"],
    }

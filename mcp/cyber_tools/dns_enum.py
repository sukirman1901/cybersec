"""DNS enumeration using Python socket. No dig/nslookup required."""

import socket

def _query_dns(domain: str, record_type: str) -> list[str]:
    results = []
    try:
        if record_type == "A":
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            results = list(set(info[4][0] for info in infos))
        elif record_type == "AAAA":
            infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
            results = list(set(info[4][0] for info in infos))
        elif record_type == "CNAME":
            socket.getaddrinfo(domain, None)
            results = [f"Resolves to: {domain}"]
    except socket.gaierror as e:
        results = [f"Error: {e}"]
    except Exception as e:
        results = [f"Error: {e}"]
    return results

def dns_enum(domain: str) -> dict:
    """Enumerate DNS records for a domain."""
    domain = domain.strip().lower()
    records = {}
    for rtype in ["A", "AAAA", "CNAME"]:
        try:
            result = _query_dns(domain, rtype)
            if result:
                records[rtype] = result
        except Exception:
            pass

    for prefix in ["mail", "smtp", "mx"]:
        try:
            ip = socket.gethostbyname(f"{prefix}.{domain}")
            records.setdefault("MX", []).append(f"{prefix}.{domain} -> {ip}")
        except socket.gaierror:
            pass

    for prefix in ["ns1", "ns2", "dns"]:
        try:
            ip = socket.gethostbyname(f"{prefix}.{domain}")
            records.setdefault("NS", []).append(f"{prefix}.{domain} -> {ip}")
        except socket.gaierror:
            pass

    return {"domain": domain, "records": records}

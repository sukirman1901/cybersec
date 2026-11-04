"""Attack surface mapping — aggregate scan results into a graph."""

import json
import re
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime


def _check(value):
    """1 MiB input text, <=1000 items/container, <=10000 nodes, depth <=32."""
    stack, nodes, size = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 10000 or depth > 32:
            raise ValueError('Input structure budget exceeded')
        if isinstance(item, str):
            if len(item) > 1048576:
                raise ValueError('Input exceeds 1 MiB')
            size += len(item.encode('utf-8'))
            if size > 1048576:
                raise ValueError('Input exceeds 1 MiB')
        elif isinstance(item, (dict, list)):
            if len(item) > 1000:
                raise ValueError('Collection exceeds 1000 items')
            children = list(item.keys()) + list(item.values()) if isinstance(item, dict) else item
            stack.extend((v, depth + 1) for v in children)


def _redact(value, key=''):
    """Named credentials/raw payloads and HTTP URL secrets only; not arbitrary prose."""
    if re.search(r'password|passwd|secret|token|authorization|cookie|api[_-]?key', key, re.I) or key.lower() in ('raw', 'body', 'content', 'post_data'):
        return '[REDACTED]'
    if isinstance(value, dict):
        if key.lower() == 'headers':
            return {k: '[REDACTED]' for k in value}
        return {_redact(k): _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if isinstance(value, str):
        def clean(match):
            try:
                p = urlsplit(match.group())
                return urlunsplit((p.scheme, p.netloc.rsplit('@', 1)[-1], p.path,
                                   '[REDACTED]' if p.query else '', '[REDACTED]' if p.fragment else ''))
            except ValueError:
                return '[REDACTED URL]'
        return re.sub(r'https?://[^\s<>"\']+', clean, value, flags=re.I)
    return value


def attack_surface_map(scan_results: str) -> str:
    """Build attack surface map from scan results JSON.

    Accepts JSON string containing results from port_scan, dns_lookup,
    subdomain_enum, http_probe, vuln_scan, etc.
    Returns a structured attack surface graph.
    """
    try:
        _check(scan_results)
        data = json.loads(scan_results)
        _check(data)
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('Expected scan objects')
            if not isinstance(item.get('target', item.get('domain', item.get('host', 'unknown'))), str):
                raise ValueError('Target must be a string')
            for key in ('open_ports', 'vulnerabilities', 'subdomains', 'technologies'):
                if key in item and not isinstance(item[key], list):
                    raise ValueError('Expected result lists')
            for key in ('open_ports', 'vulnerabilities'):
                if any(not isinstance(v, dict) for v in item.get(key, [])):
                    raise ValueError('Expected result objects')
            for key in ('subdomains', 'technologies'):
                if any(not isinstance(v, str) for v in item.get(key, [])):
                    raise ValueError('Expected string list')
            if 'records' in item and (not isinstance(item['records'], dict) or not isinstance(item['records'].get('A', []), list)):
                raise ValueError('Invalid DNS records')
            if any(not isinstance(v.get('severity', 'info'), str) for v in item.get('vulnerabilities', [])):
                raise ValueError('Invalid severity')
        data = _redact(data)
    except (ValueError, TypeError, AttributeError, RecursionError):
        return json.dumps({"error": "Invalid JSON input. Provide scan results as JSON string."})

    surface = {
        "generated": datetime.now().isoformat(),
        "hosts": {},
        "services": {},
        "technologies": [],
        "vulnerabilities": [],
        "exposure_level": "unknown",
        "stats": {
            "total_hosts": 0,
            "total_ports": 0,
            "total_vulns": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    }

    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict):
            continue

        target = item.get("target", item.get("domain", item.get("host", "unknown")))
        if item.get('vulnerabilities') or item.get('technologies'):
            surface['hosts'].setdefault(target, {'ports': [], 'services': [], 'technologies': []})

        if "open_ports" in item:
            ports = item.get("open_ports", [])
            if target not in surface["hosts"]:
                surface["hosts"][target] = {"ports": [], "services": [], "technologies": []}
            for p in ports:
                port_info = {"port": p.get("port"), "service": p.get("service", "unknown")}
                surface["hosts"][target]["ports"].append(port_info)
                svc_key = f"{p.get('service', 'unknown')}"
                if svc_key not in surface["services"]:
                    surface["services"][svc_key] = []
                if target not in surface["services"][svc_key]:
                    surface["services"][svc_key].append(target)
                surface["stats"]["total_ports"] += 1

        if "records" in item:
            records = item.get("records", {})
            if target not in surface["hosts"]:
                surface["hosts"][target] = {"ports": [], "services": [], "technologies": []}
            a_records = records.get("A", [])
            if a_records:
                surface["hosts"][target]["ip"] = a_records[0]
                surface["hosts"][target]["dns_records"] = records

        if "subdomains" in item:
            subs = item.get("subdomains", [])
            for s in subs:
                if s not in surface["hosts"]:
                    surface["hosts"][s] = {"ports": [], "services": [], "technologies": []}

        if "technologies" in item:
            for tech in item.get("technologies", []):
                if tech not in surface["technologies"]:
                    surface["technologies"].append(tech)
                if target in surface["hosts"]:
                    if tech not in surface["hosts"][target]["technologies"]:
                        surface["hosts"][target]["technologies"].append(tech)

        if "vulnerabilities" in item:
            for v in item.get("vulnerabilities", []):
                vuln = {**v, "host": target}
                surface["vulnerabilities"].append(vuln)
                sev = v.get("severity", "info").lower()
                if sev in ('critical', 'high', 'medium', 'low', 'info'):
                    surface["stats"][sev] += 1
                surface["stats"]["total_vulns"] += 1

        if "ssl" in item or "certificate" in item:
            if target not in surface["hosts"]:
                surface["hosts"][target] = {"ports": [], "services": [], "technologies": []}
            surface["hosts"][target]["ssl"] = item.get("ssl", item.get("certificate", {}))

    surface["stats"]["total_hosts"] = len(surface["hosts"])

    crit = surface["stats"]["critical"]
    high = surface["stats"]["high"]
    if crit > 0:
        surface["exposure_level"] = "critical"
    elif high > 0:
        surface["exposure_level"] = "high"
    elif surface["stats"]["medium"] > 0:
        surface["exposure_level"] = "medium"
    elif surface["stats"]["total_ports"] > 0:
        surface["exposure_level"] = "low"
    else:
        surface["exposure_level"] = "unknown"

    surface['limitations'] = 'Aggregation of supplied observations, not proof of assessment coverage or safety. Finding status is not independently verified.'
    result = json.dumps(surface, indent=2)
    if len(result.encode('utf-8')) > 4 * 1024 * 1024:
        return json.dumps({'error': 'Output exceeds 4 MiB; reduce input'})
    return result

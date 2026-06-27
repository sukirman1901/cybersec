"""Attack surface mapping — aggregate scan results into a graph."""

import json
from datetime import datetime


def attack_surface_map(scan_results: str) -> str:
    """Build attack surface map from scan results JSON.

    Accepts JSON string containing results from port_scan, dns_lookup,
    subdomain_enum, http_probe, vuln_scan, etc.
    Returns a structured attack surface graph.
    """
    try:
        data = json.loads(scan_results)
    except json.JSONDecodeError:
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
                if sev in surface["stats"]:
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
        surface["exposure_level"] = "minimal"

    return json.dumps(surface, indent=2)
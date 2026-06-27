"""Vulnerability diff — compare 2 scan results to find new/resolved/changed findings."""

import json
from datetime import datetime


def vuln_diff(scan_before: str, scan_after: str) -> str:
    """Compare 2 scan results to identify new, resolved, and changed vulnerabilities.

    Accepts 2 JSON strings from any scan results.
    Returns diff with new, resolved, and changed findings.
    """
    try:
        before = json.loads(scan_before)
        after = json.loads(scan_after)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"}, indent=2)

    before_vulns = {v.get("id", v.get("description", "")): v for v in before.get("vulnerabilities", [])} if isinstance(before.get("vulnerabilities"), list) else {}
    after_vulns = {v.get("id", v.get("description", "")): v for v in after.get("vulnerabilities", [])} if isinstance(after.get("vulnerabilities"), list) else {}

    before_before = before.get("open_ports", [])
    after_ports = after.get("open_ports", [])
    before_port_set = {p.get("port") for p in before_ports}
    after_port_set = {p.get("port") for p in after_ports}

    new_vulns = []
    resolved_vulns = []
    changed_vulns = []

    for vid, vuln in after_vulns.items():
        if vid not in before_vulns:
            new_vulns.append(vuln)
        else:
            old_v = before_vulns[vid]
            if old_v.get("severity") != vuln.get("severity") or old_v.get("status") != vuln.get("status"):
                changed_vulns.append({
                    "id": vid,
                    "before": {"severity": old_v.get("severity"), "status": old_v.get("status")},
                    "after": {"severity": vuln.get("severity"), "status": vuln.get("status")},
                })

    for vid, vuln in before_vulns.items():
        if vid not in after_vulns:
            resolved_vulns.append(vuln)

    new_ports = after_port_set - before_port_set
    closed_ports = before_port_set - after_port_set

    result = {
        "diff_at": datetime.now().isoformat(),
        "summary": {
            "new_vulnerabilities": len(new_vulns),
            "resolved_vulnerabilities": len(resolved_vulns),
            "changed_vulnerabilities": len(changed_vulns),
            "new_open_ports": list(new_ports),
            "closed_ports": list(closed_ports),
        },
        "new": new_vulns,
        "resolved": resolved_vulns,
        "changed": changed_vulns,
        "port_changes": {
            "new_open": list(new_ports),
            "closed": list(closed_ports),
        },
        "before_stats": {
            "total_vulns": len(before_vulns),
            "open_ports": len(before_port_set),
        },
        "after_stats": {
            "total_vulns": len(after_vulns),
            "open_ports": len(after_port_set),
        },
    }

    if not any([new_vulns, resolved_vulns, changed_vulns, new_ports, closed_ports]):
        result["overall"] = "No changes detected between scans"
    elif len(new_vulns) > len(resolved_vulns):
        result["overall"] = f"WORSE — {len(new_vulns)} new vulnerabilities, {len(resolved_vulns)} resolved"
    elif len(resolved_vulns) > len(new_vulns):
        result["overall"] = f"IMPROVED — {len(resolved_vulns)} resolved, {len(new_vulns)} new"
    else:
        result["overall"] = f"MIXED — {len(new_vulns)} new, {len(resolved_vulns)} resolved"

    return json.dumps(result, indent=2)
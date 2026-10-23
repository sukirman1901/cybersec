"""Vulnerability / exposure diff — novelty-aware compare of two scan snapshots."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .finding_contract import extract_findings_list, finding_fingerprint, normalize_finding


def _vuln_map(payload: dict) -> dict:
    """Map fingerprint -> finding from vulnerabilities or findings lists."""
    items = []
    if isinstance(payload.get("vulnerabilities"), list):
        items.extend([v for v in payload["vulnerabilities"] if isinstance(v, dict)])
    items.extend(extract_findings_list(payload))
    # dedupe while preferring richer records
    out = {}
    for raw in items:
        normalized = normalize_finding(raw, require_quality=False)
        fp = normalized.get("id") or normalized.get("fingerprint") or finding_fingerprint(normalized)
        # Keep explicit id if caller supplied a stable one and no fingerprint clash
        explicit = raw.get("id")
        key = fp
        if explicit and explicit not in out:
            # Prefer fingerprint as canonical novelty key
            key = fp
        out[key] = normalized
    return out


def _port_set(payload: dict) -> set:
    ports = payload.get("open_ports") or payload.get("ports") or []
    result = set()
    for p in ports:
        if isinstance(p, dict):
            port = p.get("port")
        else:
            port = p
        if port is not None:
            result.add(port)
    return result


def vuln_diff(scan_before: str, scan_after: str) -> str:
    """Compare 2 scan results to identify novel, resolved, changed, and regression signals.

    Accepts JSON strings with `vulnerabilities`, `findings`, and/or `open_ports`.
    Identity uses finding_contract fingerprints when ids are absent.
    """
    try:
        before = json.loads(scan_before)
        after = json.loads(scan_after)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"}, indent=2)

    if not isinstance(before, dict):
        before = {"findings": before if isinstance(before, list) else []}
    if not isinstance(after, dict):
        after = {"findings": after if isinstance(after, list) else []}

    before_vulns = _vuln_map(before)
    after_vulns = _vuln_map(after)

    before_ports = before.get("open_ports", [])
    after_ports = after.get("open_ports", [])
    # Keep local names for clarity / backwards-compatible structure
    _ = before_ports, after_ports
    before_port_set = _port_set(before)
    after_port_set = _port_set(after)

    novel = []
    resolved = []
    changed = []
    regressions = []

    for vid, vuln in after_vulns.items():
        if vid not in before_vulns:
            item = dict(vuln)
            item["triage"] = "novel"
            novel.append(item)
        else:
            old_v = before_vulns[vid]
            old_status = (old_v.get("status") or "").lower()
            if old_status in ("fixed", "retested", "wont_fix", "false_positive"):
                item = dict(vuln)
                item["triage"] = "regression"
                item["prior_status"] = old_status
                regressions.append(item)
            elif (
                old_v.get("severity") != vuln.get("severity")
                or old_v.get("status") != vuln.get("status")
                or old_v.get("confidence") != vuln.get("confidence")
            ):
                changed.append({
                    "id": vid,
                    "fingerprint": vid,
                    "triage": "changed",
                    "before": {
                        "severity": old_v.get("severity"),
                        "status": old_v.get("status"),
                        "confidence": old_v.get("confidence"),
                    },
                    "after": {
                        "severity": vuln.get("severity"),
                        "status": vuln.get("status"),
                        "confidence": vuln.get("confidence"),
                    },
                })

    for vid, vuln in before_vulns.items():
        if vid not in after_vulns:
            item = dict(vuln)
            item["triage"] = "resolved"
            resolved.append(item)

    new_ports = sorted(after_port_set - before_port_set, key=lambda x: (str(type(x)), x))
    closed_ports = sorted(before_port_set - after_port_set, key=lambda x: (str(type(x)), x))

    result = {
        "diff_at": datetime.now(timezone.utc).isoformat(),
        "engine": "novelty-v1",
        "summary": {
            "novel": len(novel),
            "new_vulnerabilities": len(novel),  # backwards-compatible alias
            "resolved": len(resolved),
            "resolved_vulnerabilities": len(resolved),
            "changed": len(changed),
            "changed_vulnerabilities": len(changed),
            "regressions": len(regressions),
            "new_open_ports": new_ports,
            "closed_ports": closed_ports,
        },
        "novel": novel,
        "new": novel,  # alias
        "resolved": resolved,
        "changed": changed,
        "regressions": regressions,
        "port_changes": {
            "new_open": new_ports,
            "closed": closed_ports,
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

    if not any([novel, resolved, changed, regressions, new_ports, closed_ports]):
        result["overall"] = "No changes detected between scans"
    elif regressions:
        result["overall"] = (
            f"REGRESSION — {len(regressions)} returned; "
            f"{len(novel)} novel, {len(resolved)} resolved"
        )
    elif len(novel) > len(resolved):
        result["overall"] = f"WORSE — {len(novel)} novel, {len(resolved)} resolved"
    elif len(resolved) > len(novel):
        result["overall"] = f"IMPROVED — {len(resolved)} resolved, {len(novel)} novel"
    else:
        result["overall"] = f"MIXED — {len(novel)} novel, {len(resolved)} resolved"

    return json.dumps(result, indent=2)

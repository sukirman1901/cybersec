"""Auto-generate executive summary from findings."""
import json
import re
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime


def _input_ok(value):
    """Bound each input: 1 MiB UTF-8 text, 1000/container, 10000 nodes, depth 64."""
    stack, size, nodes = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 10000 or depth > 64:
            return False
        if isinstance(item, str):
            if len(item) > 1048576:
                return False
            size += len(item.encode('utf-8', errors='replace'))
            if size > 1048576:
                return False
        elif isinstance(item, (dict, list)):
            if len(item) > 1000:
                return False
            children = list(item.keys()) + list(item.values()) if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return True


def _redact_urls(value):
    """Redact HTTP URL userinfo, query and fragment; not arbitrary prose secrets."""
    if isinstance(value, dict):
        return {_redact_urls(k): _redact_urls(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_urls(v) for v in value]
    if not isinstance(value, str):
        return value
    def clean(match):
        try:
            parsed = urlsplit(match.group())
            return urlunsplit((parsed.scheme, parsed.netloc.rsplit('@', 1)[-1], parsed.path,
                               '[REDACTED]' if parsed.query else '', '[REDACTED]' if parsed.fragment else ''))
        except ValueError:
            return '[REDACTED URL]'
    return re.sub(r'https?://[^\s<>"\']+', clean, value, flags=re.I)

def executive_summary(target: str, findings_json: str) -> str:
    if not all(_input_ok(v) for v in (target, findings_json)):
        return json.dumps({'error': 'Input exceeds 1 MiB/1000-item/10000-node/depth-64 budget'})
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except (ValueError, TypeError, RecursionError):
        return json.dumps({"error": "Invalid findings JSON"})
    if not _input_ok(findings):
        return json.dumps({'error': 'Parsed input exceeds collection/depth budget'})
    target, findings = _redact_urls(target), _redact_urls(findings)

    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))
    if not isinstance(findings, list) or any(not isinstance(f, dict) or any(
        not isinstance(f[k], str) for k in ('severity', 'risk', 'status', 'type', 'vuln_type', 'title') if k in f
    ) for f in findings):
        return json.dumps({"error": "Expected finding objects with string classification fields"})

    total = len(findings)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_type = {}
    by_status = {"new": 0, "candidate": 0, "confirmed": 0, "fixed": 0, "false_positive": 0}

    for f in findings:
        sev = f.get("severity", f.get("risk", "info")).lower()
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity["info"] += 1

        t = f.get("type", f.get("vuln_type", f.get("title", "unknown")))
        by_type[t] = by_type.get(t, 0) + 1

        status = f.get("status", "new").lower()
        by_status[status] = by_status.get(status, 0) + 1

    risk_score = (by_severity["critical"] * 10) + (by_severity["high"] * 7) + (by_severity["medium"] * 4) + (by_severity["low"] * 1)
    max_risk = total * 10 if total > 0 else 1
    risk_pct = round((risk_score / max_risk) * 100, 1) if total > 0 else 0

    if by_severity["critical"] > 0:
        posture = "Critical — immediate action required"
        posture_color = "red"
    elif by_severity["high"] > 0:
        posture = "Poor — urgent remediation needed"
        posture_color = "orange"
    elif by_severity["medium"] > 0:
        posture = "Moderate — schedule remediation"
        posture_color = "yellow"
    elif by_severity["low"] > 0:
        posture = "Fair — minor issues found"
        posture_color = "blue"
    else:
        posture = "Not assessed — supplied findings do not establish safety"
        posture_color = "gray"

    top_findings = sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity", "info").lower(), 5))[:5]

    summary = {
        "metadata": {
            "target": target,
            "generated": datetime.utcnow().isoformat() + "Z",
            "total_findings": total,
        },
        "risk_posture": {
            "rating": posture,
            "color": posture_color,
            "risk_score": risk_score,
            "risk_percentage": risk_pct,
        },
        "severity_breakdown": by_severity,
        "status_breakdown": by_status,
        "vulnerability_types": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
        "top_5_findings": [
            {
                "title": f.get("title", f.get("type", "Unknown")),
                "severity": f.get("severity", "info"),
                "status": f.get("status", "new"),
                "type": f.get("type", ""),
                "target": f.get("target", f.get("host", target)),
                "remediation": f.get("remediation", f.get("fix", "See detailed report")),
            }
            for f in top_findings
        ],
        "recommendations": _gen_recommendations(by_severity, by_type),
    }

    summary["executive_text"] = _exec_text(summary)
    summary["limitations"] = "Severity-based triage of supplied claims; candidate findings require validation. Status labels are supplied, not independently verified."
    return json.dumps(summary, indent=2)


def _gen_recommendations(sev, types):
    recs = []
    if sev["critical"] > 0:
        recs.append(f"CRITICAL: {sev['critical']} critical vulnerability(ies) require immediate patching within 24 hours.")
    if sev["high"] > 0:
        recs.append(f"HIGH: {sev['high']} high severity issue(s) should be remediated within 7 days.")
    if sev["medium"] > 0:
        recs.append(f"MEDIUM: {sev['medium']} medium severity issue(s) should be addressed within 30 days.")
    if "sqli" in types or "xss" in types:
        recs.append("Web application vulnerabilities detected — review input validation and output encoding across all user-facing endpoints.")
    if "ssl" in str(types) or "tls" in str(types):
        recs.append("SSL/TLS configuration weaknesses detected — update cipher suites and certificate configurations.")
    if "auth" in str(types).lower():
        recs.append("Authentication issues detected — review access controls and session management.")
    if not recs:
        recs.append("Validate assessment coverage; absent findings do not establish safety.")
    return recs


def _exec_text(s):
    lines = []
    lines.append(f"EXECUTIVE SUMMARY — Security Assessment of {s['metadata']['target']}")
    lines.append(f"Date: {s['metadata']['generated']}")
    lines.append(f"Total Findings: {s['metadata']['total_findings']}")
    lines.append("")
    lines.append(f"Overall Risk Posture: {s['risk_posture']['rating']}")
    lines.append(f"Risk Score: {s['risk_posture']['risk_score']} / {s['metadata']['total_findings'] * 10} ({s['risk_posture']['risk_percentage']}%)")
    lines.append("")
    lines.append("Severity Breakdown:")
    for sev, count in s["severity_breakdown"].items():
        if count > 0:
            lines.append(f"  {sev.upper()}: {count}")
    lines.append("")
    lines.append("Top Findings:")
    for f in s["top_5_findings"]:
        lines.append(f"  [{f['severity'].upper()} / {f['status']}] {f['title']} — {f['target']}")
    lines.append("")
    lines.append("Recommendations:")
    for r in s["recommendations"]:
        lines.append(f"  - {r}")
    return "\n".join(lines)

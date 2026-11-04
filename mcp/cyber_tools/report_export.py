"""Report exporter — export pentest reports to multiple formats."""

import json
import csv
import io
import re
from urllib.parse import urlsplit, urlunsplit
from html import escape
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


def report_export(target: str, findings_json: str, format: str = "html") -> str:
    """Export pentest report to multiple formats: html, csv, markdown, json.

    format: html, csv, markdown, json
    """
    if not all(_input_ok(v) for v in (target, findings_json, format)):
        return json.dumps({'error': 'Input exceeds 1 MiB/1000-item/10000-node/depth-64 budget'})
    try:
        findings = json.loads(findings_json)
    except (ValueError, TypeError, RecursionError):
        return json.dumps({"error": "Invalid findings JSON"}, indent=2)
    if not _input_ok(findings):
        return json.dumps({'error': 'Parsed input exceeds collection/depth budget'})
    target, findings = _redact_urls(target), _redact_urls(findings)
    if isinstance(findings, list):
        findings = {'vulnerabilities': findings}
    if not isinstance(findings, dict) or any(
        not isinstance(findings.get(k, []), list) or any(not isinstance(v, dict) for v in findings.get(k, []))
        for k in ('vulnerabilities', 'open_ports')
    ):
        return json.dumps({"error": "Expected report object with finding and port lists"})
    if any(any(not isinstance(v[k], str) for k in ('severity', 'type', 'description', 'status') if k in v)
           for v in findings.get('vulnerabilities', [])):
        return json.dumps({"error": "Finding display fields must be strings"})

    if format == "json":
        return json.dumps({"target": target, "generated": datetime.now().isoformat(), "findings": findings}, indent=2)

    elif format == "markdown":
        return _export_markdown(target, findings)

    elif format == "html":
        return _export_html(target, findings)

    elif format == "csv":
        return _export_csv(target, findings)

    else:
        return json.dumps({"error": f"Unknown format: {format}. Supported: html, csv, markdown, json"}, indent=2)


def _export_markdown(target, findings):
    lines = [
        f"# Penetration Test Report: {target}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Tool:** Cybersec Plugin",
        "",
        "## Executive Summary",
        "",
    ]

    vulns = findings.get("vulnerabilities", [])
    ports = findings.get("open_ports", [])
    crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
    med = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")

    lines.extend([
        f"- **Target:** {target}",
        f"- **Open Ports:** {len(ports)}",
        f"- **Total Findings:** {len(vulns)}",
        f"- **Critical:** {crit} | **High:** {high} | **Medium:** {med}",
        "",
        "## Findings",
        "",
    ])

    if vulns:
        lines.append("| # | Severity | Type | Description | Status (supplied) |")
        lines.append("|---|----------|------|-------------|-------------------|")
        for i, v in enumerate(vulns, 1):
            lines.append(f"| {i} | {v.get('severity', 'N/A')} | {v.get('type', 'N/A')} | {v.get('description', '')[:80]} | {v.get('status', 'candidate')} |")
    else:
        lines.append("No findings supplied; assessment coverage and safety are not established.")

    lines.extend(["", "## Open Ports", ""])
    if ports:
        lines.append("| Port | Service |")
        lines.append("|------|---------|")
        for p in ports:
            lines.append(f"| {p.get('port', '?')} | {p.get('service', 'unknown')} |")

    return "\n".join(lines)


def _export_html(target, findings):
    target = escape(str(target))
    vulns = findings.get("vulnerabilities", [])
    ports = findings.get("open_ports", [])

    css = """
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
      h1 { color: #DC2626; border-bottom: 3px solid #DC2626; padding-bottom: 10px; }
      h2 { color: #1F2937; margin-top: 30px; }
      table { border-collapse: collapse; width: 100%; margin: 15px 0; }
      th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
      th { background: #F3F4F6; font-weight: bold; }
      .critical { color: #DC2626; font-weight: bold; }
      .high { color: #F59E0B; font-weight: bold; }
      .medium { color: #3B82F6; }
      .low { color: #10B981; }
      .summary-box { background: #F9FAFB; padding: 20px; border-radius: 8px; margin: 20px 0; }
      .stat { display: inline-block; padding: 10px 20px; margin: 5px; border-radius: 4px; }
    </style>
    """

    vuln_rows = ""
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "info").lower()
        sev_class = sev if sev in ("critical", "high", "medium", "low") else "low"
        vuln_rows += f"<tr><td>{i}</td><td class='{sev_class}'>{escape(v.get('severity', 'N/A'))}</td><td>{escape(v.get('type', 'N/A'))}</td><td>{escape(v.get('description', '')[:100])}</td><td>{escape(v.get('status', 'candidate'))}</td></tr>"

    port_rows = ""
    for p in ports:
        port_rows += f"<tr><td>{escape(str(p.get('port', '?')))}</td><td>{escape(str(p.get('service', 'unknown')))}</td></tr>"

    crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
    high = sum(1 for v in vulns if v.get("severity", "").lower() == "high")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Pentest Report — {target}</title>{css}</head><body>
<h1>Penetration Test Report</h1>
<p><strong>Target:</strong> {target}<br><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}<br><strong>Tool:</strong> Cybersec Plugin</p>

<div class="summary-box">
  <h2>Executive Summary</h2>
  <div class="stat" style="background:#FEE2E2;border-left:4px solid #DC2626;"><strong>{crit}</strong> Critical</div>
  <div class="stat" style="background:#FEF3C7;border-left:4px solid #F59E0B;"><strong>{high}</strong> High</div>
  <div class="stat" style="background:#DBEAFE;border-left:4px solid #3B82F6;"><strong>{len(ports)}</strong> Open Ports</div>
  <div class="stat" style="background:#F3F4F6;border-left:4px solid #6B7280;"><strong>{len(vulns)}</strong> Total Findings</div>
</div>

<h2>Findings</h2>
<p>Supplied findings and status labels; validation and assessment coverage are not independently established.</p>
<table><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Description</th><th>Status (supplied)</th></tr></thead><tbody>{vuln_rows}</tbody></table>

<h2>Open Ports</h2>
<table><thead><tr><th>Port</th><th>Service</th></tr></thead><tbody>{port_rows}</tbody></table>

<p style="margin-top:40px;color:#6B7280;font-size:0.9em;">Generated by Cybersec Plugin on {datetime.now().isoformat()}</p>
</body></html>"""

    return html


def _export_csv(target, findings):
    vulns = findings.get("vulnerabilities", [])
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)

    def row(values):
        cells = [str(v) for v in values]
        writer.writerow(["'" + v if v.lstrip().startswith(('=', '+', '-', '@')) else v for v in cells])

    row(['target', 'severity', 'type', 'description', 'status', 'host', 'port'])
    for v in vulns:
        row([target, v.get('severity', 'N/A'), v.get('type', 'N/A'), v.get('description', ''),
             v.get('status', 'candidate'), v.get('host', ''), v.get('port', '')])

    ports = findings.get("open_ports", [])
    writer.writerow([])
    row(['target', 'port', 'service'])
    for p in ports:
        row([target, p.get('port', ''), p.get('service', '')])

    return stream.getvalue()

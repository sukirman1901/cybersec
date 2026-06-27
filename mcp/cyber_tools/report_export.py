"""Report exporter — export pentest reports to multiple formats."""

import json
from datetime import datetime


def report_export(target: str, findings_json: str, format: str = "html") -> str:
    """Export pentest report to multiple formats: html, csv, markdown, json.

    format: html, csv, markdown, json
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid findings JSON"}, indent=2)

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
        lines.append("| # | Severity | Type | Description |")
        lines.append("|---|----------|------|-------------|")
        for i, v in enumerate(vulns, 1):
            lines.append(f"| {i} | {v.get('severity', 'N/A')} | {v.get('type', 'N/A')} | {v.get('description', '')[:80]} |")
    else:
        lines.append("No vulnerabilities found.")

    lines.extend(["", "## Open Ports", ""])
    if ports:
        lines.append("| Port | Service |")
        lines.append("|------|---------|")
        for p in ports:
            lines.append(f"| {p.get('port', '?')} | {p.get('service', 'unknown')} |")

    return "\n".join(lines)


def _export_html(target, findings):
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
        vuln_rows += f"<tr><td>{i}</td><td class='{sev_class}'>{v.get('severity', 'N/A')}</td><td>{v.get('type', 'N/A')}</td><td>{v.get('description', '')[:100]}</td></tr>"

    port_rows = ""
    for p in ports:
        port_rows += f"<tr><td>{p.get('port', '?')}</td><td>{p.get('service', 'unknown')}</td></tr>"

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
<table><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>{vuln_rows}</tbody></table>

<h2>Open Ports</h2>
<table><thead><tr><th>Port</th><th>Service</th></tr></thead><tbody>{port_rows}</tbody></table>

<p style="margin-top:40px;color:#6B7280;font-size:0.9em;">Generated by Cybersec Plugin on {datetime.now().isoformat()}</p>
</body></html>"""

    return html


def _export_csv(target, findings):
    vulns = findings.get("vulnerabilities", [])
    lines = ["target,severity,type,description,status,host,port"]
    for v in vulns:
        desc = v.get("description", "").replace('"', '""').replace(",", ";")
        lines.append(f'"{target}","{v.get("severity", "N/A")}","{v.get("type", "N/A")}","{desc}","{v.get("status", "new")}","{v.get("host", "")}","{v.get("port", "")}"')

    ports = findings.get("open_ports", [])
    lines.append("")
    lines.append("target,port,service")
    for p in ports:
        lines.append(f'"{target}","{p.get("port", "")}","{p.get("service", "")}"')

    return "\n".join(lines)
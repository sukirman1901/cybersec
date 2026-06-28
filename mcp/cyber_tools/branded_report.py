"""White-label pentest reports — logo, colors, company name, custom footer."""
import json
import base64
import os
from datetime import datetime

def branded_report(target: str, findings_json: str, company_name: str = "Security Assessment", company_logo: str = "", primary_color: str = "#1a1a2e", accent_color: str = "#e94556", report_title: str = "", footer_text: str = "", disclaimer: str = "", contact_info: str = "", format: str = "html") -> str:
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        findings = []
    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))

    if not report_title:
        report_title = f"Penetration Testing Report — {target}"

    if not disclaimer:
        disclaimer = "This document contains confidential security assessment information. Distribution is restricted to authorized personnel only. The findings herein represent a point-in-time assessment and do not guarantee the absence of other vulnerabilities."

    if not footer_text:
        footer_text = f"{company_name} — Confidential Security Report"

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in by_severity:
            by_severity[sev] += 1

    summary = {
        "target": target,
        "company_name": company_name,
        "report_title": report_title,
        "primary_color": primary_color,
        "accent_color": accent_color,
        "total_findings": len(findings),
        "severity_breakdown": by_severity,
        "generated": datetime.utcnow().isoformat() + "Z",
    }

    if format == "json":
        return json.dumps({"summary": summary, "findings": findings}, indent=2)

    if format == "html":
        logo_html = ""
        if company_logo and os.path.exists(company_logo):
            with open(company_logo, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode()
            logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="max-height:60px;margin-right:15px;vertical-align:middle"/>'

        if company_logo and company_logo.startswith("http"):
            logo_html = f'<img src="{company_logo}" style="max-height:60px;margin-right:15px;vertical-align:middle"/>'

        rows = ""
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_colors = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8"}
            badge_color = sev_colors.get(sev, "#6c759d")
            rows += f"""
            <tr>
                <td><span style="background:{badge_color};color:white;padding:2px 8px;border-radius:3px;font-size:11px;text-transform:uppercase">{sev}</span></td>
                <td>{f.get('title', f.get('type', 'Unknown'))}</td>
                <td>{f.get('target', f.get('host', ''))}</td>
                <td>{f.get('remediation', f.get('fix', 'See details'))[:80]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{report_title}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; color:#333; line-height:1.6; }}
  .header {{ background:{primary_color}; color:white; padding:30px 40px; display:flex; align-items:center; }}
  .header h1 {{ font-size:22px; font-weight:300; }}
  .header .subtitle {{ color:{accent_color}; font-size:12px; text-transform:uppercase; letter-spacing:2px; margin-top:5px; }}
  .content {{ padding:40px; }}
  .summary-box {{ display:flex; gap:20px; margin:20px 0 30px; }}
  .summary-card {{ flex:1; background:#f8f9fa; padding:15px 20px; border-radius:6px; border-left:4px solid {accent_color}; }}
  .summary-card .number {{ font-size:28px; font-weight:bold; color:{primary_color}; }}
  .summary-card .label {{ font-size:11px; text-transform:uppercase; color:#666; letter-spacing:1px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
  th {{ background:{primary_color}; color:white; padding:10px; text-align:left; font-size:12px; text-transform:uppercase; }}
  td {{ padding:10px; border-bottom:1px solid #eee; font-size:13px; }}
  tr:nth-child(even) {{ background:#f9f9f9; }}
  .disclaimer {{ margin-top:30px; padding:15px; background:#fff3cd; border:1px solid #ffeaa7; border-radius:4px; font-size:12px; color:#856404; }}
  .footer {{ background:{primary_color}; color:white; padding:15px 40px; font-size:11px; text-align:center; }}
  .contact {{ margin:15px 0; font-size:13px; color:#555; }}
  @media print {{ .header {{ -webkit-print-color-adjust:exact; }} }}
</style>
</head>
<body>
  <div class="header">
    {logo_html}
    <div>
      <h1>{report_title}</h1>
      <div class="subtitle">{company_name} — Confidential</div>
    </div>
  </div>
  <div class="content">
    <div class="contact">{contact_info}</div>
    <h2 style="font-size:18px;color:{primary_color};margin-bottom:10px">Executive Summary</h2>
    <p style="margin-bottom:15px">A security assessment was performed on <strong>{target}</strong>. A total of <strong>{len(findings)}</strong> findings were identified.</p>

    <div class="summary-box">
      <div class="summary-card"><div class="number">{by_severity['critical']}</div><div class="label">Critical</div></div>
      <div class="summary-card"><div class="number">{by_severity['high']}</div><div class="label">High</div></div>
      <div class="summary-card"><div class="number">{by_severity['medium']}</div><div class="label">Medium</div></div>
      <div class="summary-card"><div class="number">{by_severity['low']}</div><div class="label">Low</div></div>
      <div class="summary-card"><div class="number">{by_severity['info']}</div><div class="label">Info</div></div>
    </div>

    <h2 style="font-size:18px;color:{primary_color};margin-bottom:10px">Findings Detail</h2>
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Remediation</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>

    <div class="disclaimer">{disclaimer}</div>
  </div>
  <div class="footer">{footer_text} — Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
</body>
</html>"""
        return html

    elif format == "markdown":
        md = f"# {report_title}\n\n"
        md += f"**{company_name}** — Confidential\n\n"
        md += f"**Target:** {target}\n\n"
        md += f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        md += f"**Total Findings:** {len(findings)}\n\n"
        md += f"| Critical | High | Medium | Low | Info |\n"
        md += f"|----------|------|--------|-----|------|\n"
        md += f"| {by_severity['critical']} | {by_severity['high']} | {by_severity['medium']} | {by_severity['low']} | {by_severity['info']} |\n\n"
        md += "## Findings\n\n"
        for f in findings:
            md += f"### [{f.get('severity', 'info').upper()}] {f.get('title', f.get('type', 'Unknown'))}\n\n"
            md += f"- **Target:** {f.get('target', f.get('host', ''))}\n"
            md += f"- **Type:** {f.get('type', f.get('vuln_type', ''))}\n"
            md += f"- **Remediation:** {f.get('remediation', f.get('fix', 'See details'))}\n\n"
        md += f"---\n\n*{footer_text}*\n\n"
        md += f"> **Disclaimer:** {disclaimer}\n"
        return md

    return json.dumps({"error": f"Unsupported format: {format}"}, indent=2)
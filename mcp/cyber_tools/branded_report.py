"""White-label pentest reports — logo, colors, company name, custom footer."""
import json
import base64
import os
import re
import stat
from html import escape
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

def branded_report(target: str, findings_json: str, company_name: str = "Security Assessment", company_logo: str = "", primary_color: str = "#1a1a2e", accent_color: str = "#e94556", report_title: str = "", footer_text: str = "", disclaimer: str = "", contact_info: str = "", format: str = "html") -> str:
    try:
        fields = [target, company_name, company_logo, primary_color, accent_color, report_title, footer_text, disclaimer, contact_info, format]
        _check(findings_json)
        _check(fields)
        if any(not isinstance(v, str) for v in fields):
            raise ValueError('Brand fields must be strings')
        result = _render(target, findings_json, company_name, company_logo, primary_color, accent_color, report_title, footer_text, disclaimer, contact_info, format)
        if len(result.encode('utf-8')) > 4 * 1024 * 1024:
            raise ValueError('Output exceeds 4 MiB')
        return result
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        return json.dumps({'error': 'Invalid or oversized report input/logo; report not generated'})


def _render(target, findings_json, company_name, company_logo, primary_color, accent_color, report_title, footer_text, disclaimer, contact_info, format):
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except (ValueError, TypeError):
        raise ValueError('Invalid findings JSON')
    _check(findings)
    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))
    if not isinstance(findings, list) or any(not isinstance(f, dict) or any(
        not isinstance(f[k], str) for k in ('severity', 'title', 'type', 'target', 'host', 'remediation', 'fix', 'status') if k in f
    ) for f in findings):
        raise ValueError('Expected finding objects with string display fields')
    findings = _redact(findings)
    target, company_name, company_logo, report_title, footer_text, disclaimer, contact_info = map(
        _redact, (target, company_name, company_logo, report_title, footer_text, disclaimer, contact_info))
    if any(not re.fullmatch(r'#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?', c) for c in (primary_color, accent_color)):
        raise ValueError('Colors must be hex RGB')

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
        target, company_name, report_title, footer_text, disclaimer, contact_info = map(
            escape, (target, company_name, report_title, footer_text, disclaimer, contact_info))
        logo_html = ""
        if company_logo and os.path.exists(company_logo):
            expected = os.lstat(company_logo)
            if not stat.S_ISREG(expected.st_mode) or expected.st_size > 262144:
                raise ValueError('Logo must be a regular PNG of at most 256 KiB')
            fd = os.open(company_logo, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                actual = os.fstat(fd)
                if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino) or actual.st_size > 262144:
                    raise ValueError('Logo changed before open')
                with os.fdopen(fd, 'rb', closefd=False) as f:
                    logo = f.read(262145)
            finally:
                os.close(fd)
            if len(logo) > 262144 or not logo.startswith(b'\x89PNG\r\n\x1a\n') or not logo.endswith(b'IEND\xaeB`\x82'):
                raise ValueError('Logo must be PNG data')
            logo_b64 = base64.b64encode(logo).decode()
            logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="max-height:60px;margin-right:15px;vertical-align:middle"/>'

        if company_logo and company_logo.startswith(("http://", "https://")):
            logo_html = f'<img src="{escape(company_logo, quote=True)}" style="max-height:60px;margin-right:15px;vertical-align:middle"/>'

        rows = ""
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_colors = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8"}
            badge_color = sev_colors.get(sev, "#6c759d")
            rows += f"""
            <tr>
                <td><span style="background:{badge_color};color:white;padding:2px 8px;border-radius:3px;font-size:11px;text-transform:uppercase">{escape(sev)}</span></td>
                <td>{escape(f.get('title', f.get('type', 'Unknown')))}</td>
                <td>{escape(f.get('target', f.get('host', '')))}</td>
                <td>{escape(f.get('remediation', f.get('fix', 'See details'))[:80])}</td>
                <td>{escape(f.get('status', 'candidate'))}</td>
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
    <p style="margin-bottom:15px">Supplied findings for <strong>{target}</strong>: <strong>{len(findings)}</strong>. Assessment coverage and status labels are not independently verified; empty input does not establish safety.</p>

    <div class="summary-box">
      <div class="summary-card"><div class="number">{by_severity['critical']}</div><div class="label">Critical</div></div>
      <div class="summary-card"><div class="number">{by_severity['high']}</div><div class="label">High</div></div>
      <div class="summary-card"><div class="number">{by_severity['medium']}</div><div class="label">Medium</div></div>
      <div class="summary-card"><div class="number">{by_severity['low']}</div><div class="label">Low</div></div>
      <div class="summary-card"><div class="number">{by_severity['info']}</div><div class="label">Info</div></div>
    </div>

    <h2 style="font-size:18px;color:{primary_color};margin-bottom:10px">Findings Detail</h2>
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Remediation</th><th>Status (supplied)</th></tr></thead>
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
            md += f"- **Status (supplied):** {f.get('status', 'candidate')}\n"
            md += f"- **Remediation:** {f.get('remediation', f.get('fix', 'See details'))}\n\n"
        md += f"---\n\n*{footer_text}*\n\n"
        md += f"> **Disclaimer:** {disclaimer}\n"
        return md

    return json.dumps({"error": f"Unsupported format: {format}"}, indent=2)

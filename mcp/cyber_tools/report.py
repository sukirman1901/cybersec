"""Penetration testing report generator with remediation code."""

from datetime import datetime

REMEDIATION_CODE = {
    "lfi": {
        "title": "Local File Inclusion",
        "code": """# Python: Safe file access with allowlist
import os

ALLOWED_DIR = os.path.abspath("/var/www/allowed")
path = os.path.abspath(f"/var/www/allowed/{user_input}")
if not path.startswith(ALLOWED_DIR):
    raise PermissionError("Access denied")
with open(path) as f:
    data = f.read()""",
        "config": r"""# NGINX: Block path traversal
location ~ \.(\.\.|etc|passwd|proc) {
    deny all;
    return 403;
}"""
    },
    "sqli": {
        "title": "SQL Injection",
        "code": """# Python: Parameterized query (safe)
import sqlite3

conn = sqlite3.connect("db.sqlite")
cur = conn.cursor()
# SAFE: parameterized — user input never touches SQL syntax
cur.execute("SELECT * FROM users WHERE id = ?", (user_input,))
row = cur.fetchone()""",
        "config": """# SQLAlchemy ORM (safe by default)
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_input})"""
    },
    "xss": {
        "title": "Cross-Site Scripting",
        "code": """# Python: HTML escape all user output
import html

safe_output = html.escape(user_input, quote=True)
# Also set Content-Security-Policy header

# Flask example
from flask import Flask, render_template_string, escape
app = Flask(__name__)

@app.route("/user/<name>")
def hello(name):
    # escape() auto-escapes HTML
    return f"<h1>Hello {escape(name)}</h1>" """,
        "config": """# NGINX: Add Content-Security-Policy header
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';";
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "DENY";"""
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "code": """# Python: URL validation with allowlist
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = {"api.internal.com", "metadata.cloud"}
BLOCKED_IPS = ["10.", "172.16.", "192.168.", "169.254.", "127."]

def safe_request(url):
    parsed = urlparse(url)
    host = parsed.hostname
    if host in ALLOWED_HOSTS:
        return True
    for prefix in BLOCKED_IPS:
        if host.startswith(prefix):
            raise ValueError(f"Blocked internal IP: {host}")
    raise ValueError(f"Host not in allowlist: {host}")""",
        "config": """# NGINX: Block SSRF to internal networks
if ($host ~* "^(10\\.|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[0-1]\\.|192\\.168\\.|127\\.|0\\.)") {
    return 403;
}"""
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "code": """# Jinja2: Sandbox + autoescape
from jinja2 import Environment, BaseLoader, select_autoescape

# SAFE: autoescape enabled, no access to dangerous globals
env = Environment(
    loader=BaseLoader(),
    autoescape=select_autoescape(["html", "xml"]),
)
# NEVER use env.from_string(user_input) — templates are trusted
template = env.from_string("Hello {{ name }}")
output = template.render(name=user_input)""",
    },
    "xxe": {
        "title": "XML External Entity",
        "code": """# Python: Disable XXE in XML parsers
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,   # XXE protection
    no_network=True,          # No external network access
    dtd_validation=False,     # Don't process DTDs
)
tree = etree.fromstring(xml_input, parser)""",
        "config": """# NGINX: Block XML with external entities
# Use WAF rules or API gateway to block XXE payloads
# See: OWASP XXE Prevention Cheat Sheet"""
    },
    "open_redirect": {
        "title": "Open Redirect",
        "code": """# Python: URL validation with allowlist
from urllib.parse import urlparse

ALLOWED_DOMAINS = {"example.com", "sub.example.com"}

def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError(f"Redirect to {parsed.netloc} not allowed")
    return url""",
        "config": """# NGINX: Validate redirect targets
# Only allow relative redirects or known domains
valid_referers example.com sub.example.com;
if ($invalid_referer) {
    return 403;
}"""
    },
    "cors": {
        "title": "CORS Misconfiguration",
        "code": """# Python: Restrict CORS headers
from flask import Flask, jsonify

app = Flask(__name__)

@app.after_request
def add_cors(resp):
    # Restrict to specific origin, NOT wildcard
    resp.headers["Access-Control-Allow-Origin"] = "https://trusted.example.com"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp""",
        "config": """# NGINX: Restrict CORS
add_header Access-Control-Allow-Origin "https://trusted.example.com";
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
add_header Access-Control-Allow-Credentials "true";
# NEVER use: add_header Access-Control-Allow-Origin "*";"""
    },
    "weak_ssl": {
        "title": "Weak SSL/TLS Configuration",
        "code": """# NGINX: Strong TLS configuration
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    # Modern TLS only
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
}""",
    },
    "missing_headers": {
        "title": "Missing Security Headers",
        "code": """# NGINX: Security headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "0" always;  # Deprecated, use CSP
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self';" always;""",
    },
    "open_port": {
        "title": "Unnecessary Open Ports",
        "code": """# iptables: Restrict access to necessary ports
# Allow SSH, HTTP, HTTPS only
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
# Block all other inbound
iptables -A INPUT -p tcp --syn -j DROP

# macOS: Use pfctl
# /etc/pf.conf:
# block in proto tcp from any to any port 3306
# block in proto tcp from any to any port 5432""",
    },
    "default_cred": {
        "title": "Default Credentials",
        "code": """# Python: Enforce password change on first login
import hashlib, os

def enforce_password_change(user, password):
    common = {"admin", "password", "123456", "root", "test"}
    if password.lower() in common:
        raise ValueError("Password too common. Change immediately.")
    # Hash with salt
    salt = os.urandom(32)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt + hashed""",
    },
}


def gen_report(target: str, findings: dict, format: str = "markdown") -> str:
    """Generate pentest report from findings."""
    if format == "markdown":
        return _gen_markdown(target, findings)
    elif format == "json":
        import json
        return json.dumps({"target": target, **findings, "remediation_code": _get_codes(findings)}, indent=2)
    return str(findings)


def _get_codes(findings: dict) -> list:
    codes = []
    vulns = findings.get("vulnerabilities", [])
    for v in vulns:
        desc = v.get("description", "").lower()
        matched = set()
        for key, rem in REMEDIATION_CODE.items():
            if key in desc and key not in matched:
                codes.append({"vuln": rem["title"], "code": rem["code"], "config": rem.get("config", "")})
                matched.add(key)
    return codes


def _gen_markdown(target: str, findings: dict) -> str:
    lines = []
    lines.append(f"# Penetration Test Report: {target}")
    lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Tool:** Cybersec Plugin for OpenCode")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    open_ports = findings.get("open_ports", [])
    vulns = findings.get("vulnerabilities", [])
    lines.append(f"- **Open Ports Found:** {len(open_ports)}")
    lines.append(f"- **Vulnerabilities Found:** {len(vulns)}")
    if findings.get("technologies"):
        lines.append(f"- **Technologies:** {', '.join(findings['technologies'][:5])}")
    lines.append("")
    if open_ports:
        lines.append("## Open Ports")
        lines.append("")
        lines.append("| Port | Service | Banner |")
        lines.append("|------|---------|--------|")
        for p in open_ports:
            svc = p.get("service", "unknown")
            banner = p.get("banner", "")[:50]
            lines.append(f"| {p.get('port', '?')} | {svc} | {banner} |")
        lines.append("")
    if vulns:
        lines.append("## Vulnerabilities")
        lines.append("")
        lines.append("| ID | Severity | Description |")
        lines.append("|----|----------|-------------|")
        for v in vulns:
            lines.append(f"| {v.get('id', 'N/A')} | {v.get('severity', 'UNKNOWN')} | {v.get('description', '')[:100]} |")
        lines.append("")
        lines.append("## Remediation Code")
        lines.append("")
        codes = _get_codes(findings)
        if codes:
            for c in codes:
                lines.append(f"### {c['vuln']}")
                lines.append("")
                lines.append("**Fix Code:**")
                lines.append("```python")
                lines.append(c["code"])
                lines.append("```")
                lines.append("")
                if c.get("config"):
                    lines.append("**Server Config:**")
                    lines.append("```nginx")
                    lines.append(c["config"])
                    lines.append("```")
                    lines.append("")
        else:
            lines.append("*No specific remediation code available for the identified vulnerabilities.*")
            lines.append("")
    lines.append("## Recommendations")
    lines.append("")
    if vulns:
        for v in vulns:
            lines.append(f"- **{v.get('id', 'N/A')}:** Update/patch to fix {v.get('description', '')[:50]}")
    else:
        lines.append("- No critical issues identified in this assessment.")
    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by Cybersec Plugin on {datetime.now().isoformat()}*")
    return "\n".join(lines)

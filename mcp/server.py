"""
Cybersec MCP Server — provides penetration testing tools for OpenCode AI agent.
"""

import asyncio
import json
from fastmcp import FastMCP
from cyber_tools.port_scanner import scan_ports, detect_service
from cyber_tools.dns_enum import dns_enum
from cyber_tools.http_probe import http_probe
from cyber_tools.web_fuzz import dir_bust
from cyber_tools.ssl_analyzer import ssl_analyze
from cyber_tools.vuln_db import cve_lookup
from cyber_tools.waf_detect import waf_detect
from cyber_tools.google_dork import google_dork
from cyber_tools.report import gen_report
from cyber_tools.subdomain_enum import enumerate_subdomains
from cyber_tools.param_discovery import discover_params
from cyber_tools.tech_detect import detect_technologies
from cyber_tools.vuln_scanner import scan_vulnerabilities
from cyber_tools.cli_tools import (
    nikto_scan as _nikto, sqlmap_check as _sqlmap, amass_enum as _amass,
    wpscan_check as _wpscan, masscan_scan as _masscan, xsstrike_check as _xsstrike,
    gitleaks_check as _gitleaks, cmseek_check as _cmseek, testssl_check as _testssl,
    sslyze_check as _sslyze, gobuster_dir as _gobuster, ffuf_fuzz as _ffuf,
)
from cyber_tools.whois_lookup import whois_lookup as _whois
from cyber_tools.asn_lookup import asn_lookup as _asn
from cyber_tools.reverse_ip import reverse_ip as _revip
from cyber_tools.crt_search import crt_search as _crt
from cyber_tools.cors_check import cors_check as _cors
from cyber_tools.open_redirect import open_redirect as _oredirect
from cyber_tools.graphql_introspect import graphql_introspect as _gql
from cyber_tools.jwt_analyze import jwt_analyze as _jwt
from cyber_tools.api_fuzz import api_fuzz as _apifuzz
from cyber_tools.smtp_enum import smtp_enum as _smtp
from cyber_tools.smb_enum import smb_enum as _smb
from cyber_tools.snmp_enum import snmp_enum as _snmp
from cyber_tools.ssh_audit import ssh_audit as _ssh
from cyber_tools.lfi_detect import lfi_detect as _lfi
from cyber_tools.ssti_detect import ssti_detect as _ssti
from cyber_tools.xxe_detect import xxe_detect as _xxe
from cyber_tools.ssrf_detect import ssrf_detect as _ssrf
from cyber_tools.sub_takeover import sub_takeover as _subto
from cyber_tools.origin_ip_discovery import origin_ip_discovery as _origin
from cyber_tools.service_fingerprint import service_fingerprint as _svcfp

mcp = FastMCP("cybersec")

def _run(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()

# --- Pure Python Tools ---

@mcp.tool()
def port_scan(target: str, ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443") -> str:
    """Scan TCP ports on a target host."""
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    open_ports = scan_ports(target, port_list)
    results = [{"port": p, "service": detect_service(target, p)} for p in open_ports]
    return json.dumps({"target": target, "open_ports": results, "count": len(results)}, indent=2)

@mcp.tool()
def dns_lookup(target: str) -> str:
    """Enumerate DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME)."""
    records = dns_enum(target)
    return json.dumps({"target": target, "records": records}, indent=2)

@mcp.tool()
def http_probe_target(target: str) -> str:
    """Probe HTTP/HTTPS service, detect technology stack and headers."""
    return json.dumps(http_probe(target), indent=2)

@mcp.tool()
def dir_bruteforce(target: str, wordlist: str = "common") -> str:
    """Brute-force directories and files on a web target."""
    common = ["admin", "login", "wp-admin", "backup", ".git", "config", "api", "uploads", "robots.txt", "sitemap.xml"]
    results = dir_bust(target, common)
    return json.dumps({"target": target, "found": results, "count": len(results)}, indent=2)

@mcp.tool()
def ssl_check(target: str, port: int = 443) -> str:
    """Analyze SSL/TLS certificate and protocol security."""
    return json.dumps(ssl_analyze(target, port), indent=2)

@mcp.tool()
def cve_search(service: str, version: str = "") -> str:
    """Look up known CVEs for a given service and optional version."""
    results = cve_lookup(service, version)
    return json.dumps({"query": f"{service} {version}", "results": results, "count": len(results)}, indent=2)

@mcp.tool()
def waf_detection(target: str) -> str:
    """Detect Web Application Firewall (WAF) protecting a target."""
    return json.dumps(waf_detect(target), indent=2)

@mcp.tool()
def dork_search(query: str) -> str:
    """Perform Google dorking to find vulnerable targets or exposed information."""
    results = google_dork(query)
    return json.dumps({"query": query, "results": results, "count": len(results)}, indent=2)

@mcp.tool()
def generate_report(target: str, findings: str, format: str = "markdown") -> str:
    """Generate a penetration testing report from findings JSON."""
    try:
        findings_data = json.loads(findings) if isinstance(findings, str) else findings
    except json.JSONDecodeError:
        findings_data = {"raw": findings}
    return gen_report(target, findings_data, format)

# --- Python Fallback Tools ---

@mcp.tool()
def subdomain_enum(target: str) -> str:
    """Passive subdomain enumeration via crt.sh, DNS brute-force, and APIs."""
    return json.dumps(_run(enumerate_subdomains(target)), indent=2)

@mcp.tool()
def param_discovery(target: str, method: str = "GET", thorough: bool = False) -> str:
    """Discover HTTP parameters by testing common parameter names."""
    return json.dumps(_run(discover_params(target, method=method, thorough=thorough)), indent=2)

@mcp.tool()
def tech_detect(target: str) -> str:
    """Detect web technologies (CMS, JS frameworks, CDN, analytics) from HTTP response."""
    return json.dumps(_run(detect_technologies(target)), indent=2)

@mcp.tool()
def vuln_scan(target: str) -> str:
    """Scan for common vulnerabilities (missing headers, exposed paths, CVE patterns)."""
    return json.dumps(_run(scan_vulnerabilities(target)), indent=2)

# --- CLI Wrapper Tools ---

@mcp.tool()
def nikto_scan(target: str) -> str:
    """Web server vulnerability scanner. Requires nikto CLI."""
    return json.dumps(_run(_nikto(target)), indent=2)

@mcp.tool()
def sqlmap_check(target: str, risk: int = 1, level: int = 1) -> str:
    """SQL injection detection. Requires sqlmap CLI (safe mode default)."""
    return json.dumps(_run(_sqlmap(target, risk=risk, level=level)), indent=2)

@mcp.tool()
def amass_enum(target: str, passive: bool = True) -> str:
    """Attack surface mapping. Requires amass CLI."""
    return json.dumps(_run(_amass(target, passive=passive)), indent=2)

@mcp.tool()
def wpscan_check(target: str) -> str:
    """WordPress vulnerability scanner. Requires wpscan CLI."""
    return json.dumps(_run(_wpscan(target)), indent=2)

@mcp.tool()
def masscan_scan(target: str, ports: str = "80,443", rate: int = 1000) -> str:
    """Ultra-fast TCP port scanner. Requires masscan CLI."""
    return json.dumps(_run(_masscan(target, ports=ports, rate=rate)), indent=2)

@mcp.tool()
def xsstrike_check(target: str) -> str:
    """XSS vulnerability detection. Requires xsstrike CLI."""
    return json.dumps(_run(_xsstrike(target)), indent=2)

@mcp.tool()
def gitleaks_check(path: str) -> str:
    """Git secret scanning in a repository. Requires gitleaks CLI."""
    return json.dumps(_run(_gitleaks(path)), indent=2)

@mcp.tool()
def cmseek_check(target: str) -> str:
    """CMS detection and version identification. Requires cmseek CLI."""
    return json.dumps(_run(_cmseek(target)), indent=2)

@mcp.tool()
def testssl_check(target: str, port: int = 443) -> str:
    """SSL/TLS server testing. Requires testssl CLI."""
    return json.dumps(_run(_testssl(target, port=port)), indent=2)

@mcp.tool()
def sslyze_check(target: str, port: int = 443) -> str:
    """Fast SSL/TLS scanning. Requires sslyze CLI."""
    return json.dumps(_run(_sslyze(target, port=port)), indent=2)

@mcp.tool()
def gobuster_dir(target: str, wordlist: str = "") -> str:
    """Directory/file brute-forcing. Requires gobuster CLI."""
    return json.dumps(_run(_gobuster(target, wordlist=wordlist)), indent=2)

@mcp.tool()
def ffuf_fuzz(target: str, wordlist: str = "") -> str:
    """Fast web fuzzing. Requires ffuf CLI."""
    return json.dumps(_run(_ffuf(target, wordlist=wordlist)), indent=2)

# --- Reconnaissance Tools ---

@mcp.tool()
def whois_lookup(target: str) -> str:
    """Query WHOIS for domain registration information."""
    return json.dumps(_run(_whois(target)), indent=2)

@mcp.tool()
def asn_lookup(target: str) -> str:
    """Look up ASN information for an IP address via Team Cymru."""
    return json.dumps(_run(_asn(target)), indent=2)

@mcp.tool()
def reverse_ip(target: str) -> str:
    """Find domains hosted on the same IP address."""
    return json.dumps(_run(_revip(target)), indent=2)

@mcp.tool()
def crt_search(domain: str) -> str:
    """Search Certificate Transparency logs for certificates."""
    return json.dumps(_run(_crt(domain)), indent=2)

# --- Web Security Testing Tools ---

@mcp.tool()
def cors_check(target: str) -> str:
    """Test for CORS misconfiguration by sending cross-origin requests."""
    return json.dumps(_run(_cors(target)), indent=2)

@mcp.tool()
def open_redirect(target: str) -> str:
    """Test for open redirect vulnerabilities in common parameters."""
    return json.dumps(_run(_oredirect(target)), indent=2)

@mcp.tool()
def graphql_introspect(target: str) -> str:
    """Test for GraphQL introspection endpoint."""
    return json.dumps(_run(_gql(target)), indent=2)

@mcp.tool()
def jwt_analyze(token: str) -> str:
    """Decode and analyze a JWT token for security issues."""
    return json.dumps(_jwt(token), indent=2)

@mcp.tool()
def api_fuzz(target: str) -> str:
    """Fuzz a web target for common API endpoints and swagger docs."""
    return json.dumps(_run(_apifuzz(target)), indent=2)

# --- Network Service Enumeration Tools ---

@mcp.tool()
def smtp_enum(target: str, users: str = "") -> str:
    """Enumerate SMTP users via VRFY, EXPN, and RCPT commands."""
    return json.dumps(_run(_smtp(target, users=users)), indent=2)

@mcp.tool()
def smb_enum(target: str) -> str:
    """Enumerate SMB services — check if port 445 is open."""
    return json.dumps(_run(_smb(target)), indent=2)

@mcp.tool()
def snmp_enum(target: str, community: str = "public") -> str:
    """Check SNMP service availability on port 161."""
    return json.dumps(_run(_snmp(target, community=community)), indent=2)

@mcp.tool()
def ssh_audit(target: str, port: int = 22) -> str:
    """Audit SSH server — grab banner and check algorithm support."""
    return json.dumps(_run(_ssh(target, port=port)), indent=2)

# --- Exploit Detection Tools ---

@mcp.tool()
def lfi_detect(target: str, param: str = "") -> str:
    """Test for Local/Remote File Inclusion vulnerabilities."""
    return json.dumps(_run(_lfi(target, param=param)), indent=2)

@mcp.tool()
def ssti_detect(target: str, param: str = "") -> str:
    """Test for Server-Side Template Injection vulnerabilities."""
    return json.dumps(_run(_ssti(target, param=param)), indent=2)

@mcp.tool()
def xxe_detect(target: str) -> str:
    """Test for XML External Entity injection vulnerabilities."""
    return json.dumps(_run(_xxe(target)), indent=2)

@mcp.tool()
def ssrf_detect(target: str) -> str:
    """Test for Server-Side Request Forgery vulnerabilities."""
    return json.dumps(_run(_ssrf(target)), indent=2)

# --- Infrastructure Testing Tools ---

@mcp.tool()
def sub_takeover(target: str) -> str:
    """Check for subdomain takeover (dangling DNS CNAME)."""
    return json.dumps(_run(_subto(target)), indent=2)

@mcp.tool()
def origin_ip_discovery(target: str) -> str:
    """Discover origin IP behind CDN via historical DNS and records."""
    return json.dumps(_run(_origin(target)), indent=2)

@mcp.tool()
def service_fingerprint(target: str, port: int = 80) -> str:
    """Deep service fingerprinting via banner grabbing."""
    return json.dumps(_run(_svcfp(target, port=port)), indent=2)

if __name__ == "__main__":
    mcp.run(transport="stdio")

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
from cyber_tools.shodan_lookup import shodan_lookup as _shodan
from cyber_tools.wayback_urls import wayback_urls as _wayback
from cyber_tools.bypass_403 import bypass_403 as _bypass
from cyber_tools.smuggling_check import smuggling_check as _smuggling
from cyber_tools.gf_patterns import gf_patterns as _gf
from cyber_tools.oob_test import oob_test as _oob
from cyber_tools.nuclei_scan import nuclei_scan as _nuclei
from cyber_tools.nmap_scan import nmap_scan as _nmap
from cyber_tools.ldap_enum import ldap_enum as _ldap
from cyber_tools.bloodhound_collect import bloodhound_collect as _bloodhound
from cyber_tools.hash_analyze import hash_analyze as _hash
from cyber_tools.hydra_brute import hydra_brute as _hydra
from cyber_tools.cloud_enum import cloud_enum as _cloud
from cyber_tools.s3_scanner import s3_scanner as _s3
from cyber_tools.searchsploit import searchsploit as _searchsploit
from cyber_tools.csrf_detect import csrf_detect as _csrf
from cyber_tools.idor_detect import idor_detect as _idor
from cyber_tools.cmd_injection import cmd_injection as _cmd
from cyber_tools.nosql_inject import nosql_inject as _nosql
from cyber_tools.laravel_scan import laravel_scan as _laravel
from cyber_tools.php_deserialize import php_deserialize as _php
from cyber_tools.java_deserialize import java_deserialize as _java
from cyber_tools.docker_scan import docker_scan as _docker
from cyber_tools.k8s_scan import k8s_scan as _k8s
from cyber_tools.redis_enum import redis_enum as _redis
from cyber_tools.spring_scan import spring_scan as _spring
from cyber_tools.nextjs_scan import nextjs_scan as _nextjs
from cyber_tools.django_scan import django_scan as _django
from cyber_tools.magento_scan import magento_scan as _magento
from cyber_tools.drupal_scan import drupal_scan as _drupal
from cyber_tools.upload_bypass import upload_bypass as _upload
from cyber_tools.host_header import host_header as _hosthdr
from cyber_tools.race_condition import race_condition as _race
from cyber_tools.oauth_scan import oauth_scan as _oauth
from cyber_tools.api_auth import api_auth as _apiauth
from cyber_tools.apk_analyze import apk_analyze as _apk
from cyber_tools.binary_checksec import binary_checksec as _binary
from cyber_tools.ci_cd_scan import ci_cd_scan as _cicd
from cyber_tools.ssl_pinning_check import ssl_pinning_check as _sslpin
from cyber_tools.log4j_scan import log4j_scan as _log4j
from cyber_tools.supply_chain import supply_chain as _supply
from cyber_tools.exposed_git import exposed_git as _exgit
from cyber_tools.exposed_backup import exposed_backup as _exbak
from cyber_tools.csp_analyze import csp_analyze as _csp
from cyber_tools.cookie_audit import cookie_audit as _cookie

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

# --- Bug Bounty Tools ---

@mcp.tool()
def shodan_lookup(query: str, api_key: str = "") -> str:
    """Search Shodan for exposed devices and services."""
    return json.dumps(_run(_shodan(query, api_key=api_key)), indent=2)

@mcp.tool()
def wayback_urls(domain: str, limit: int = 100) -> str:
    """Fetch URL history from Wayback Machine."""
    return json.dumps(_run(_wayback(domain, limit=limit)), indent=2)

@mcp.tool()
def bypass_403(target: str) -> str:
    """Test 403 bypass techniques (headers, path, method)."""
    return json.dumps(_run(_bypass(target)), indent=2)

@mcp.tool()
def smuggling_check(target: str) -> str:
    """Test for HTTP request smuggling (CL.TE, TE.CL)."""
    return json.dumps(_run(_smuggling(target)), indent=2)

@mcp.tool()
def gf_patterns(urls: str) -> str:
    """Find sensitive patterns in URLs (debug, api, files, params)."""
    return json.dumps(_run(_gf(urls)), indent=2)

@mcp.tool()
def oob_test(target: str, payload: str = "") -> str:
    """Test for blind OOB interaction (SSRF, RCE, template injection)."""
    return json.dumps(_run(_oob(target, payload=payload)), indent=2)

@mcp.tool()
def nuclei_scan(target: str, template: str = "", severity: str = "") -> str:
    """Template-based vulnerability scanner. Requires nuclei CLI."""
    return json.dumps(_run(_nuclei(target, template=template, severity=severity)), indent=2)

# --- Enterprise Pentesting Tools (Phase 2) ---

@mcp.tool()
def nmap_scan(target: str, ports: str = "", scripts: str = "") -> str:
    """Full nmap network scan with service detection. Requires nmap CLI."""
    return json.dumps(_run(_nmap(target, ports=ports, scripts=scripts)), indent=2)

@mcp.tool()
def ldap_enum(target: str) -> str:
    """LDAP anonymous bind and server enumeration."""
    return json.dumps(_run(_ldap(target)), indent=2)

@mcp.tool()
def bloodhound_collect(domain: str, username: str = "", password: str = "") -> str:
    """Collect AD data for BloodHound analysis. Requires bloodhound-python CLI."""
    return json.dumps(_run(_bloodhound(domain, username=username, password=password)), indent=2)

@mcp.tool()
def hash_analyze(hash_string: str) -> str:
    """Identify hash type from its format (MD5, SHA1, bcrypt, NTLM, etc)."""
    return json.dumps(_run(_hash(hash_string)), indent=2)

@mcp.tool()
def hydra_brute(target: str, service: str = "ssh", username: str = "root", wordlist: str = "") -> str:
    """Online password brute forcing. Requires hydra CLI."""
    return json.dumps(_run(_hydra(target, service=service, username=username, wordlist=wordlist)), indent=2)

@mcp.tool()
def cloud_enum(company: str) -> str:
    """Enumerate cloud storage resources (AWS S3, Azure, GCP) for a company name."""
    return json.dumps(_run(_cloud(company)), indent=2)

@mcp.tool()
def s3_scanner(bucket_name: str) -> str:
    """Check if an S3 bucket is publicly accessible and list its contents."""
    return json.dumps(_run(_s3(bucket_name)), indent=2)

@mcp.tool()
def searchsploit(search_term: str) -> str:
    """Search exploit-db for exploits. Requires searchsploit CLI."""
    return json.dumps(_run(_searchsploit(search_term)), indent=2)

# --- Mobile, Binary & Supply Chain (Batch 3) ---

@mcp.tool()
def apk_analyze(target: str) -> str:
    """Analyze APK file — permissions, exported activities, package name, suspicious files."""
    return json.dumps(_run(_apk(target)), indent=2)

@mcp.tool()
def binary_checksec(target: str) -> str:
    """Analyze binary security — ELF/Mach-O/PE, PIE, NX, linked libs, interesting strings."""
    return json.dumps(_run(_binary(target)), indent=2)

@mcp.tool()
def ci_cd_scan(target: str) -> str:
    """Scan CI/CD configs — GitHub Actions, GitLab CI, Jenkins, CircleCI, secrets exposure."""
    return json.dumps(_run(_cicd(target)), indent=2)

@mcp.tool()
def ssl_pinning_check(target: str, port: int = 443) -> str:
    """Check SSL certificate details, HSTS, and cert verification behavior."""
    return json.dumps(_run(_sslpin(target, port=port)), indent=2)

@mcp.tool()
def log4j_scan(target: str) -> str:
    """Test for Log4j JNDI injection via headers and params."""
    return json.dumps(_run(_log4j(target)), indent=2)

@mcp.tool()
def supply_chain(target: str) -> str:
    """Check exposed manifest files for known vulnerable package versions."""
    return json.dumps(_run(_supply(target)), indent=2)

@mcp.tool()
def exposed_git(target: str) -> str:
    """Check for exposed .git folder — config, HEAD, logs, objects."""
    return json.dumps(_run(_exgit(target)), indent=2)

@mcp.tool()
def exposed_backup(target: str) -> str:
    """Scan for exposed backup files (.bak, .old, .sql, .dump, ~, etc)."""
    return json.dumps(_run(_exbak(target)), indent=2)

@mcp.tool()
def csp_analyze(target: str) -> str:
    """Analyze Content-Security-Policy header + other security headers."""
    return json.dumps(_run(_csp(target)), indent=2)

@mcp.tool()
def cookie_audit(target: str) -> str:
    """Audit cookie security — HttpOnly, Secure, SameSite, sensitive cookies."""
    return json.dumps(_run(_cookie(target)), indent=2)

# --- Framework & CMS Scanners (Batch 2) ---

@mcp.tool()
def spring_scan(target: str) -> str:
    """Spring Boot actuator scan — env, heapdump, beans, mappings, configprops."""
    return json.dumps(_run(_spring(target)), indent=2)

@mcp.tool()
def nextjs_scan(target: str) -> str:
    """Next.js security scan — source maps, data endpoints, SSR misconfig."""
    return json.dumps(_run(_nextjs(target)), indent=2)

@mcp.tool()
def django_scan(target: str) -> str:
    """Django security scan — debug mode, SECRET_KEY, admin, session flags."""
    return json.dumps(_run(_django(target)), indent=2)

@mcp.tool()
def magento_scan(target: str) -> str:
    """Magento security scan — admin, downloader, local.xml, system.log."""
    return json.dumps(_run(_magento(target)), indent=2)

@mcp.tool()
def drupal_scan(target: str) -> str:
    """Drupal security scan — drupalgeddon, install.php, settings.php, jsonapi."""
    return json.dumps(_run(_drupal(target)), indent=2)

@mcp.tool()
def upload_bypass(target: str) -> str:
    """Test file upload filters — PHP/JSP/ASP shell, double ext, null byte, SVG XSS."""
    return json.dumps(_run(_upload(target)), indent=2)

@mcp.tool()
def host_header_injection(target: str) -> str:
    """Test host header injection — password reset poisoning, cache poison."""
    return json.dumps(_run(_hosthdr(target)), indent=2)

@mcp.tool()
def race_condition(target: str, parallel: int = 5, endpoint: str = "") -> str:
    """Test for race conditions by sending parallel requests to sensitive endpoints."""
    return json.dumps(_run(_race(target, parallel=parallel, endpoint=endpoint)), indent=2)

@mcp.tool()
def oauth_scan(target: str) -> str:
    """Scan OAuth/OIDC endpoints — authorize, token, .well-known, redirect_uri."""
    return json.dumps(_run(_oauth(target)), indent=2)

@mcp.tool()
def api_auth(target: str) -> str:
    """Test API auth bypass — no auth, basic, bearer fake, internal headers."""
    return json.dumps(_run(_apiauth(target)), indent=2)

# --- Advanced Web & Infra Tools (Batch 1) ---

@mcp.tool()
def csrf_detect(target: str) -> str:
    """Check forms for CSRF tokens, SameSite cookies, and Origin/Referer validation."""
    return json.dumps(_run(_csrf(target)), indent=2)

@mcp.tool()
def idor_detect(target: str, ids: str = "1,2,3") -> str:
    """Test for Insecure Direct Object References by accessing sequential IDs."""
    return json.dumps(_run(_idor(target, ids=ids)), indent=2)

@mcp.tool()
def cmd_injection(target: str, param: str = "cmd") -> str:
    """Test for command injection (semicolon, pipe, subshell, etc)."""
    return json.dumps(_run(_cmd(target, param=param)), indent=2)

@mcp.tool()
def nosql_inject(target: str, param: str = "user") -> str:
    """Test for NoSQL injection (MongoDB $ne, $gt, $where payloads)."""
    return json.dumps(_run(_nosql(target, param=param)), indent=2)

@mcp.tool()
def laravel_scan(target: str) -> str:
    """Scan Laravel app for .env leak, debug mode, artisan exposure, etc."""
    return json.dumps(_run(_laravel(target)), indent=2)

@mcp.tool()
def php_deserialize(target: str, param: str = "") -> str:
    """Check for PHP deserialization vulnerabilities via gadget chains."""
    return json.dumps(_run(_php(target, param=param)), indent=2)

@mcp.tool()
def java_deserialize(target: str) -> str:
    """Check for Java deserialization endpoints, RMI, JNDI, and serialized data."""
    return json.dumps(_run(_java(target)), indent=2)

@mcp.tool()
def docker_scan(target: str) -> str:
    """Scan for Docker socket exposure, container escape paths, env leaks."""
    return json.dumps(_run(_docker(target)), indent=2)

@mcp.tool()
def k8s_scan(target: str) -> str:
    """Scan K8s API for unauthorized access, secrets exposure, RBAC issues."""
    return json.dumps(_run(_k8s(target)), indent=2)

@mcp.tool()
def redis_enum(target: str) -> str:
    """Enumerate Redis server — check auth, keyspace, version."""
    return json.dumps(_run(_redis(target)), indent=2)

if __name__ == "__main__":
    mcp.run(transport="stdio")

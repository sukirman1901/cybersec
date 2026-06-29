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
from cyber_tools.prompt_injection import prompt_injection as _prompt_inj
from cyber_tools.llm_guardrails import llm_guardrails as _llm_guard
from cyber_tools.llm_model_dos import llm_model_dos as _llm_dos
from cyber_tools.llm_data_exposure import llm_data_exposure as _llm_data
from cyber_tools.llm_agent_hijack import llm_agent_hijack as _llm_hijack
from cyber_tools.ipa_analyze import ipa_analyze as _ipa
from cyber_tools.ios_data_storage import ios_data_storage as _ios_storage
from cyber_tools.ios_objection import ios_objection as _ios_obj
from cyber_tools.ios_frida import ios_frida as _ios_fr
from cyber_tools.ios_signing import ios_signing as _ios_sign
from cyber_tools.desktop_strings import desktop_strings as _desktop_strings
from cyber_tools.desktop_electron import desktop_electron as _desktop_electron
from cyber_tools.desktop_config import desktop_config as _desktop_config
from cyber_tools.desktop_packages import desktop_packages as _desktop_packages
from cyber_tools.desktop_entitlements import desktop_entitlements as _desktop_ent
from cyber_tools.secret_scanner import secret_scanner as _secret_scanner
from cyber_tools.sast_review import sast_review as _sast_review
from cyber_tools.bandit_scan import bandit_scan as _bandit
from cyber_tools.semgrep_scan import semgrep_scan as _semgrep
from cyber_tools.cloud_iam_audit import cloud_iam_audit as _cloud_iam
from cyber_tools.cloud_infra import cloud_infra as _cloud_infra
from cyber_tools.jwt_forgery import jwt_forgery as _jwt_forgery
from cyber_tools.stego_detect import stego_detect as _stego
from cyber_tools.metrics_check import metrics_check as _metrics
from cyber_tools.log_exposure import log_exposure as _log_exposure
from cyber_tools.captcha_test import captcha_test as _captcha
from cyber_tools.misplaced_files import misplaced_files as _misplaced
from cyber_tools.sqli_detect import sqli_detect as _sqli
from cyber_tools.express_scan import express_scan as _express
from cyber_tools.rails_scan import rails_scan as _rails
from cyber_tools.mcp_abuse_test import mcp_abuse_test as _mcp_abuse
from cyber_tools.browser_agent_hijack import browser_agent_hijack as _browser_hijack
from cyber_tools.cookie_editor import cookie_editor as _cookie_editor
from cyber_tools.xss_detect import xss_detect as _xss_detect
from cyber_tools.wordpress_scan import wordpress_scan as _wordpress_scan
from cyber_tools.graphql_injection import graphql_injection as _graphql_injection
from cyber_tools.websocket_test import websocket_test as _websocket_test
from cyber_tools.hash_detect import hash_detect as _hash_detect
from cyber_tools.prototype_pollution import prototype_pollution as _prototype_pollution
from cyber_tools.vhost_discovery import vhost_discovery as _vhost
from cyber_tools.joomla_scan import joomla_scan as _joomla
from cyber_tools.sharepoint_scan import sharepoint_scan as _sharepoint
from cyber_tools.ghdb_search import ghdb_search as _ghdb
mcp = FastMCP("cybersec")

from cyber_tools.exploit_db import exploit_db_search as _exploit_search
from cyber_tools.exploit_db import exploit_db_detail as _exploit_detail
from cyber_tools.exploit_db import exploit_db_download as _exploit_download
from cyber_tools.attack_surface import attack_surface_map as _attack_surface
from cyber_tools.findings_manager import findings_manager as _findings_mgr
from cyber_tools.vuln_validate import vuln_validate as _vuln_validate
from cyber_tools.pentest_workflow import pentest_workflow as _pentest_workflow
from cyber_tools.continuous_monitor import continuous_monitor as _continuous_monitor
from cyber_tools.retest_vuln import retest_vuln as _retest_vuln
from cyber_tools.bulk_scan import bulk_scan as _bulk_scan
from cyber_tools.vuln_diff import vuln_diff as _vuln_diff
from cyber_tools.authenticated_scan import authenticated_scan as _authenticated_scan
from cyber_tools.report_export import report_export as _report_export
from cyber_tools.risk_score import risk_score as _risk_score
from cyber_tools.auto_exploit import auto_exploit as _auto_exploit
from cyber_tools.scan_template import scan_template as _scan_template
from cyber_tools.executive_summary import executive_summary as _executive_summary
from cyber_tools.compliance_map import compliance_map as _compliance_map
from cyber_tools.notify_webhook import notify_webhook as _notify_webhook
from cyber_tools.jira_create import jira_create as _jira_create
from cyber_tools.people_osint import people_osint as _people_osint
from cyber_tools.password_audit import password_audit as _password_audit
from cyber_tools.cloud_audit import cloud_audit as _cloud_audit
from cyber_tools.sqli_exploit import sqli_exploit as _sqli_exploit
from cyber_tools.xss_exploit import xss_exploit as _xss_exploit
from cyber_tools.http_logger import http_logger as _http_logger
from cyber_tools.branded_report import branded_report as _branded_report
from cyber_tools.vuln_database import vuln_database as _vuln_database
from cyber_tools.github_issue import github_issue as _github_issue
from cyber_tools.custom_wordlist import custom_wordlist as _custom_wordlist
from cyber_tools.auth_macro_runner import auth_macro_runner as _auth_macro_runner
from cyber_tools.csrf_extract import csrf_extract as _csrf_extract
from cyber_tools.idor_access_validation import idor_access_validation as _idor_access_validation
from cyber_tools.injection_validator import injection_validator as _injection_validator
from cyber_tools.oast_callback_server import oast_callback_server as _oast_callback_server
from cyber_tools.upload_exploit_chain import upload_exploit_chain as _upload_exploit_chain
from cyber_tools.cache_poison_check import cache_poison_check as _cache_poison_check
from cyber_tools.cmd_oast_helper import cmd_oast_helper as _cmd_oast_helper
from cyber_tools.report_schema_v2 import report_schema_v2 as _report_schema_v2
from cyber_tools.engagement_gate import engagement_gate as _engagement_gate
from cyber_tools.approval_artifact import approval_artifact as _approval_artifact
from cyber_tools.session_verification import session_verification as _session_verification
from cyber_tools.http_ingest import http_ingest as _http_ingest
from cyber_tools.raw_replay import raw_replay as _raw_replay
from cyber_tools.evidence_manifest import evidence_manifest as _evidence_manifest
from cyber_tools.cleanup_tracking import cleanup_tracking as _cleanup_tracking
from cyber_tools.vulnerable_fixture import vulnerable_fixture as _vulnerable_fixture
from cyber_tools.ad_enum import ad_enum as _ad_enum
from cyber_tools.ad_kerberoast import ad_kerberoast as _ad_kerberoast
from cyber_tools.ad_asrep_roast import ad_asrep_roast as _ad_asrep_roast
from cyber_tools.ad_dcsync import ad_dcsync as _ad_dcsync
from cyber_tools.ad_passthehash import ad_passthehash as _ad_passthehash
from cyber_tools.ad_certipy import ad_certipy as _ad_certipy
from cyber_tools.ad_spray import ad_spray as _ad_spray
from cyber_tools.ad_ntlm_relay import ad_ntlm_relay as _ad_ntlm_relay
from cyber_tools.webshell_gen import webshell_gen as _webshell_gen
from cyber_tools.webshell_upload import webshell_upload as _webshell_upload
from cyber_tools.webshell_connect import webshell_connect as _webshell_connect
from cyber_tools.webshell_detect import webshell_detect as _webshell_detect
from cyber_tools.dork_gen import dork_gen as _dork_gen
from cyber_tools.dork_scan import dork_scan as _dork_scan
from cyber_tools.dork_hunt import dork_hunt as _dork_hunt
from cyber_tools.social_osint import social_osint as _social_osint
from cyber_tools.telegram_osint import telegram_osint as _telegram_osint
from cyber_tools.phone_osint import phone_osint as _phone_osint
from cyber_tools.email_osint import email_osint as _email_osint

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

# --- AI/LLM Security Testing Tools ---

@mcp.tool()
def prompt_injection(target: str, prompt: str = "") -> str:
    """Test LLM endpoint for prompt injection vulnerability."""
    p = prompt if prompt else None
    return json.dumps(_run(_prompt_inj(target, prompt=p)), indent=2)

@mcp.tool()
def llm_guardrails(target: str, prompt: str = "") -> str:
    """Check if LLM output is sanitized against XSS and event handlers."""
    p = prompt if prompt else "Write a webpage with <script>alert(1)</script>"
    return json.dumps(_run(_llm_guard(target, prompt=p)), indent=2)

@mcp.tool()
def llm_model_dos(target: str, iterations: int = 5) -> str:
    """Test LLM for DoS via excessive token generation."""
    return json.dumps(_run(_llm_dos(target, iterations=iterations)), indent=2)

@mcp.tool()
def llm_data_exposure(target: str, extraction_prompt: str = "") -> str:
    """Test for training data leakage (PII exposure) from LLM."""
    p = extraction_prompt if extraction_prompt else None
    return json.dumps(_run(_llm_data(target, extraction_prompt=p)), indent=2)

@mcp.tool()
def llm_agent_hijack(target: str) -> str:
    """Test agent function call/tool injection in LLM."""
    return json.dumps(_run(_llm_hijack(target)), indent=2)

# --- iOS Security Testing Tools ---

@mcp.tool()
def ipa_analyze(path: str) -> str:
    """Analyze iOS IPA file — metadata, entitlements, plist, permissions."""
    return json.dumps(_run(_ipa(path)), indent=2)

@mcp.tool()
def ios_data_storage(path: str) -> str:
    """Check iOS app for insecure local data storage patterns."""
    return json.dumps(_run(_ios_storage(path)), indent=2)

@mcp.tool()
def ios_objection(action: str = "keychain", package: str = "") -> str:
    """Run objection iOS runtime exploration — keychain dump, sqlite, nsuserdefaults."""
    return json.dumps(_run(_ios_obj(action, package or None)), indent=2)

@mcp.tool()
def ios_frida(action: str = "ssl_pinning", process: str = "") -> str:
    """Run frida on iOS device — SSL pinning bypass, method tracing, process list."""
    return json.dumps(_run(_ios_fr(action, process or None)), indent=2)

@mcp.tool()
def ios_signing(path: str) -> str:
    """Check iOS app signing — provisioning profile, team ID, ad-hoc vs distribution."""
    return json.dumps(_run(_ios_sign(path)), indent=2)

# --- Desktop App Security Testing Tools ---

@mcp.tool()
def desktop_strings(path: str, min_length: int = 6) -> str:
    """Extract strings from desktop binaries — find secrets, API keys, URLs, IPs."""
    return json.dumps(_run(_desktop_strings(path, min_length)), indent=2)

@mcp.tool()
def desktop_electron(path: str) -> str:
    """Analyze Electron app — ASAR unpack, preload inspection, IPC safety."""
    return json.dumps(_run(_desktop_electron(path)), indent=2)

@mcp.tool()
def desktop_config(path: str, recursive: bool = True) -> str:
    """Scan for exposed config files and saved credentials in desktop apps."""
    return json.dumps(_run(_desktop_config(path, recursive)), indent=2)

@mcp.tool()
def desktop_packages(path: str) -> str:
    """Check bundled package versions in desktop apps for known CVEs."""
    return json.dumps(_run(_desktop_packages(path)), indent=2)

@mcp.tool()
def desktop_entitlements(path: str) -> str:
    """Check macOS entitlements, Windows manifest, Linux capabilities in desktop apps."""
    return json.dumps(_run(_desktop_ent(path)), indent=2)

# --- Code Security Audit Tools ---

@mcp.tool()
def secret_scanner(path: str, min_entropy: float = 4.5) -> str:
    """Regex + entropy-based secret scanning — API keys, tokens, passwords in code."""
    return json.dumps(_run(_secret_scanner(path, min_entropy)), indent=2)

@mcp.tool()
def sast_review(path: str) -> str:
    """Pattern-based code review — detect eval, deserialization, SQLi, XSS patterns."""
    return json.dumps(_run(_sast_review(path)), indent=2)

@mcp.tool()
def bandit_scan(path: str, severity: str = "medium") -> str:
    """Run bandit SAST scanner on Python codebase."""
    return json.dumps(_run(_bandit(path, severity)), indent=2)

@mcp.tool()
def semgrep_scan(path: str, pattern: str = "") -> str:
    """Run semgrep multi-language SAST — auto or custom pattern."""
    return json.dumps(_run(_semgrep(path, pattern or None)), indent=2)

# --- Cloud Security Testing Tools ---

@mcp.tool()
def cloud_iam_audit(provider: str = "aws") -> str:
    """Audit cloud IAM policies — overly permissive roles, public access, cross-account trust."""
    return json.dumps(_run(_cloud_iam(provider)), indent=2)

@mcp.tool()
def cloud_infra(provider: str = "aws", service: str = "ec2") -> str:
    """Enumerate cloud infra config — open security groups, unencrypted storage, public endpoints."""
    return json.dumps(_run(_cloud_infra(provider, service)), indent=2)

# --- Juice Shop CTF Tools ---

@mcp.tool()
def jwt_forgery(token: str) -> str:
    """Test JWT for known attacks — none algorithm, weak secret, kid injection, algorithm confusion."""
    return json.dumps(_run(_jwt_forgery(token)), indent=2)

@mcp.tool()
def stego_detect(path: str) -> str:
    """Detect hidden data in files — steganography, LSB, metadata anomalies, embedded strings."""
    return json.dumps(_run(_stego(path)), indent=2)

@mcp.tool()
def metrics_check(target: str) -> str:
    """Check for exposed metrics endpoints — Prometheus, Actuator, debug, health."""
    return json.dumps(_run(_metrics(target)), indent=2)

@mcp.tool()
def log_exposure(target: str) -> str:
    """Scan for exposed log files — access logs, error logs, debug logs with sensitive data."""
    return json.dumps(_run(_log_exposure(target)), indent=2)

@mcp.tool()
def captcha_test(target: str, action: str = "all", captcha_url: str = "") -> str:
    """Test CAPTCHA bypass — 10 vectors: token reuse, OCR, math solving, header/cookie bypass, hCaptcha/Turnstile detection. action: all|reuse|ocr|math|header|cookie|recaptcha|detect"""
    return json.dumps(_run(_captcha(target, action, captcha_url)), indent=2)

@mcp.tool()
def misplaced_files(target: str) -> str:
    """Scan for misplaced sensitive files — signatures, certs, configs, backups."""
    return json.dumps(_run(_misplaced(target)), indent=2)

@mcp.tool()
def sqli_detect(target: str, param: str = "") -> str:
    """Test SQL injection via URL parameters — error-based, time-based, UNION, boolean."""
    return json.dumps(_run(_sqli(target, param)), indent=2)

@mcp.tool()
def express_scan(target: str) -> str:
    """Scan Express.js app — header disclosure, error handling, directory listing, exposed paths."""
    return json.dumps(_run(_express(target)), indent=2)

@mcp.tool()
def rails_scan(target: str) -> str:
    """Scan Ruby on Rails app — exposed configs, mass assignment, debug console, routes."""
    return json.dumps(_run(_rails(target)), indent=2)

@mcp.tool()
def mcp_abuse_test(target: str) -> str:
    """Test MCP server for abuse vectors — dangerous tools, JSON-RPC injection, prompt injection in tool descriptions."""
    return json.dumps(_run(_mcp_abuse(target)), indent=2)

@mcp.tool()
def browser_agent_hijack(target: str, page_content: str = "") -> str:
    """Test browser-based AI agents for hijack — prompt injection via web content, hidden forms, autofill, clickjacking."""
    return json.dumps(_run(_browser_hijack(target, page_content)), indent=2)

# --- New Security Testing Tools ---

@mcp.tool()
def cookie_editor(target: str, cookie_str: str = "", action: str = "analyze") -> str:
    """Decode, forge, and test cookie manipulation — base64/JSON decode, privilege escalation."""
    return json.dumps(_run(_cookie_editor(target, cookie_str, action)), indent=2)

@mcp.tool()
def xss_detect(target: str, param: str = "", method: str = "get", use_browser: bool = False) -> str:
    """Active XSS injection testing — reflected, stored, DOM, and browser-based XSS detection with Playwright support."""
    return json.dumps(_run(_xss_detect(target, param, method, use_browser)), indent=2)

@mcp.tool()
def wordpress_scan(target: str) -> str:
    """Scan WordPress site — version, plugins, themes, XML-RPC, REST API, exposed paths."""
    return json.dumps(_run(_wordpress_scan(target)), indent=2)

@mcp.tool()
def graphql_injection(target: str) -> str:
    """Test GraphQL endpoints — SQL injection, deep nesting, alias batching, introspection, auth bypass."""
    return json.dumps(_run(_graphql_injection(target)), indent=2)

@mcp.tool()
def websocket_test(target: str) -> str:
    """Test WebSocket endpoints — origin validation, CSWSH, Socket.IO detection."""
    return json.dumps(_run(_websocket_test(target)), indent=2)

@mcp.tool()
def hash_detect(hash_string: str) -> str:
    """Identify hash type from format — MD5, SHA1/256/512, bcrypt, NTLM, argon2, and 20+ more."""
    return json.dumps(_run(_hash_detect(hash_string)), indent=2)

@mcp.tool()
def prototype_pollution(target: str, param: str = "") -> str:
    """Test for client-side/server-side prototype pollution via query params and JSON body."""
    return json.dumps(_run(_prototype_pollution(target, param)), indent=2)

@mcp.tool()
def vhost_discovery(target: str) -> str:
    """Discover virtual hosts by probing common subdomain vhosts via Host header manipulation."""
    return json.dumps(_run(_vhost(target)), indent=2)

@mcp.tool()
def joomla_scan(target: str) -> str:
    """Scan Joomla CMS — version, admin, components, plugins, exposed configs."""
    return json.dumps(_run(_joomla(target)), indent=2)

@mcp.tool()
def sharepoint_scan(target: str) -> str:
    """Scan Microsoft SharePoint — version, exposed paths, web services, API endpoints."""
    return json.dumps(_run(_sharepoint(target)), indent=2)

@mcp.tool()
def ghdb_search(query: str = "", category: str = "", limit: int = 20) -> str:
    """Search Google Hacking Database (GHDB) for sensitive information dorks — files containing passwords, admin panels, directory listings."""
    return json.dumps(_run(_ghdb(query, category, limit)), indent=2)

@mcp.tool()
def exploit_db_search(query: str = "", cve: str = "", type_: str = "", platform: str = "", port: int = 0, limit: int = 20) -> str:
    """Search Exploit-DB for public exploits by keyword, CVE, type (dos/local/remote/webapps), platform."""
    return json.dumps(_run(_exploit_search(query, cve, type_, platform, port, limit)), indent=2)

@mcp.tool()
def exploit_db_detail(exploit_id: str) -> str:
    """Get Exploit-DB exploit details — title, author, CVE, code, download link."""
    return json.dumps(_run(_exploit_detail(exploit_id)), indent=2)

@mcp.tool()
def exploit_db_download(exploit_id: str) -> str:
    """Download exploit code from Exploit-DB by exploit ID."""
    return json.dumps(_run(_exploit_download(exploit_id)), indent=2)

# --- Enterprise Tools (HackerOne / Pentest-Tools.com inspired) ---

@mcp.tool()
def attack_surface_map(scan_results: str) -> str:
    """Build an attack surface map from aggregated scan results. Accepts JSON string with results from port_scan, dns_lookup, subdomain_enum, http_probe, vuln_scan, etc."""
    return _attack_surface(scan_results)

@mcp.tool()
def findings_manager(action: str, findings_json: str = "", finding_id: str = "", status: str = "", notes: str = "") -> str:
    """Manage penetration testing findings — add, list, update status, stats, export, clear. Deduplicates by hash. Status: new, confirmed, false_positive, fixing, fixed, retested, wont_fix."""
    return _findings_mgr(action, findings_json, finding_id, status, notes)

@mcp.tool()
def vuln_validate(finding_json: str) -> str:
    """Validate a vulnerability finding — confirm exploitability or flag as false positive. Accepts JSON with type, host, evidence, response."""
    return _vuln_validate(finding_json)

@mcp.tool()
def pentest_workflow(target: str, template: str = "web-audit", custom_json: str = "") -> str:
    """Define a chain of pentest tools with conditions. Templates: web-audit, recon-full, network-scan, bugbounty, cloud-audit. Or provide custom JSON."""
    return _pentest_workflow(target, template, custom_json)

@mcp.tool()
def continuous_monitor(target: str, scan_results: str = "", action: str = "record") -> str:
    """Monitor a target for changes over time. Actions: record, history, diff, stats, clear. Stores snapshots and detects changes."""
    return _continuous_monitor(target, scan_results, action)

@mcp.tool()
def retest_vuln(target: str, vuln_type: str, param: str = "", original_payload: str = "") -> str:
    """Retest a previously found vulnerability to confirm if it's fixed. Supports: sqli, xss, lfi, ssrf, open_redirect, ssti, log4j."""
    return _retest_vuln(target, vuln_type, param, original_payload)

@mcp.tool()
def bulk_scan(targets: str, tool: str = "port_scan") -> str:
    """Scan multiple targets at once. Targets: comma or newline separated. Tool: port_scan, http_probe, ssl_check, vuln_scan. Max 50 targets."""
    return _bulk_scan(targets, tool)

@mcp.tool()
def vuln_diff(scan_before: str, scan_after: str) -> str:
    """Compare 2 scan results to identify new, resolved, and changed vulnerabilities. Accepts 2 JSON strings from any scan."""
    return _vuln_diff(scan_before, scan_after)

@mcp.tool()
def authenticated_scan(target: str, login_url: str = "", username: str = "", password: str = "", auth_type: str = "form", cookies: str = "", headers: str = "") -> str:
    """Scan a web target behind authentication. auth_type: form (username/password), cookie (session cookie JSON), header (bearer/api key JSON). Detects IDOR, sensitive data, missing headers."""
    return _authenticated_scan(target, login_url, username, password, auth_type, cookies, headers)

@mcp.tool()
def report_export(target: str, findings_json: str, format: str = "html") -> str:
    """Export pentest report to multiple formats: html, csv, markdown, json. HTML includes styled executive summary with severity color coding."""
    return _report_export(target, findings_json, format)

@mcp.tool()
def risk_score(finding_json: str, target_asset_value: str = "medium") -> str:
    """Calculate risk score for a vulnerability finding. Combines CVSS severity, business impact, and exploitability likelihood. asset_value: low, medium, high, critical."""
    return _risk_score(finding_json, target_asset_value)

# --- Advanced Tools (16 new) ---

@mcp.tool()
def auto_exploit(target: str, vuln_type: str = "auto", param: str = "") -> str:
    """Auto-exploit chain: detect → verify → exploit. vuln_type: auto, sqli, xss, lfi, ssrf, open_redirect."""
    return _auto_exploit(target, vuln_type, param)

@mcp.tool()
def scan_template(target: str, template: str = "quick-recon") -> str:
    """Pre-defined scan template combos. Templates: quick-recon, web-full, network-audit, api-security, cloud-audit, ad-pentest, code-audit, ctf."""
    return _scan_template(target, template)

@mcp.tool()
def executive_summary(target: str, findings_json: str) -> str:
    """Auto-generate executive summary from findings JSON. Risk posture, severity breakdown, top findings, recommendations."""
    return _executive_summary(target, findings_json)

@mcp.tool()
def compliance_map(findings_json: str, framework: str = "auto") -> str:
    """Map findings to compliance frameworks: SOC2, ISO27001, GDPR, PCI-DSS, NIST 800-53."""
    return _compliance_map(findings_json, framework)

@mcp.tool()
def notify_webhook(webhook_url: str, findings_json: str, platform: str = "auto", severity_filter: str = "high") -> str:
    """Send finding notifications to Slack/Discord/Teams webhook. Auto-detects platform from URL."""
    return _notify_webhook(webhook_url, findings_json, platform, severity_filter)

@mcp.tool()
def jira_create(finding_json: str, jira_url: str = "", email: str = "", api_token: str = "", project_key: str = "SEC") -> str:
    """Create a Jira issue from a security finding. Requires Jira URL, email, and API token."""
    return _jira_create(finding_json, jira_url, email, api_token, project_key)

@mcp.tool()
def people_osint(query: str, source: str = "auto") -> str:
    """Individual OSINT — GitHub profile, LinkedIn/Twitter/search, email analysis with Gravatar."""
    return _people_osint(query, source)

@mcp.tool()
def password_audit(target: str, protocol: str = "ssh", port: int = 0, username: str = "admin", password_list: str = "", max_attempts: int = 20) -> str:
    """Multi-protocol password audit — SSH, FTP, SMTP, HTTP form, RDP. Default wordlist included."""
    return _password_audit(target, protocol, port, username, password_list, max_attempts)

@mcp.tool()
def cloud_audit(provider: str = "aws", targets: str = "", company: str = "", buckets: str = "", project: str = "") -> str:
    """Comprehensive cloud security audit — S3 public, K8s API, Docker socket, IAM, infra recommendations."""
    return _cloud_audit(provider, targets, company, buckets, project)

@mcp.tool()
def sqli_exploit(target: str, param: str = "", method: str = "get", technique: str = "auto") -> str:
    """Generate PoC SQL injection exploit payloads. Techniques: error-based, union-based, boolean, time-based, stacked."""
    return _sqli_exploit(target, param, method, technique)

@mcp.tool()
def xss_exploit(target: str, param: str = "", xss_type: str = "auto") -> str:
    """Generate PoC XSS exploit payloads and steal links. Types: reflected, stored, dom_based, bypass_waf, cookie_steal."""
    return _xss_exploit(target, param, xss_type)

@mcp.tool()
def http_logger(action: str, request_data: str = "", response_data: str = "", request_id: str = "") -> str:
    """Persistent HTTP request/response logger. Actions: log, list, search, stats, export, clear."""
    return _http_logger(action, request_data, response_data, request_id)

@mcp.tool()
def branded_report(target: str, findings_json: str, company_name: str = "Security Assessment", company_logo: str = "", primary_color: str = "#1a1a2e", accent_color: str = "#e94556", report_title: str = "", footer_text: str = "", disclaimer: str = "", contact_info: str = "", format: str = "html") -> str:
    """White-label pentest reports — custom logo, colors, company name, footer, disclaimer."""
    return _branded_report(target, findings_json, company_name, company_logo, primary_color, accent_color, report_title, footer_text, disclaimer, contact_info, format)

@mcp.tool()
def vuln_database(action: str, entry_json: str = "", vuln_id: str = "", search_query: str = "", severity_filter: str = "", tag_filter: str = "") -> str:
    """Local vulnerability database. Actions: add, get, search, list, update, delete, stats, export, import, tags, clear."""
    return _vuln_database(action, entry_json, vuln_id, search_query, severity_filter, tag_filter)

@mcp.tool()
def github_issue(finding_json: str, repo: str = "", token: str = "", labels: str = "security,vulnerability") -> str:
    """Create GitHub issue from security finding. Requires repo (owner/repo) and token with repo scope."""
    return _github_issue(finding_json, repo, token, labels)

@mcp.tool()
def custom_wordlist(action: str, name: str = "", words: str = "", wordlist: str = "", source: str = "", ext: str = "") -> str:
    """Custom wordlist manager. Actions: create, list, show, delete, merge, generate, import, builtin, append."""
    return _custom_wordlist(action, name, words, wordlist, source, ext)

# --- Upgraded Tools (10 new/improved) ---

@mcp.tool()
def auth_macro_runner(target: str, auth_type: str = "form", username: str = "", password: str = "", login_url: str = "", username_field: str = "username", password_field: str = "password", extra_fields: str = "", token_extract: str = "", steps_json: str = "") -> str:
    """Multi-step auth macro runner — form login, basic auth, bearer token, custom step chains with cookie persistence."""
    return _auth_macro_runner(target, auth_type, username, password, login_url, username_field, password_field, extra_fields, token_extract, steps_json)

@mcp.tool()
def csrf_extract(target: str, method: str = "get", param_hint: str = "") -> str:
    """Extract and analyze anti-CSRF tokens from meta tags, hidden inputs, JS variables, cookies, headers."""
    return _csrf_extract(target, method, param_hint)

@mcp.tool()
def idor_access_validation(target: str, resource_ids: str = "1,2,3,4,5", user_a_cookie: str = "", user_b_cookie: str = "", param: str = "id", method: str = "get", role_a_header: str = "", role_b_header: str = "") -> str:
    """IDOR/BOLA access validation — sequential enumeration, cross-user access, negative IDs, array bypass."""
    return _idor_access_validation(target, resource_ids, user_a_cookie, user_b_cookie, param, method, role_a_header, role_b_header)

@mcp.tool()
def injection_validator(target: str, types: str = "sqli,xss,nosql,cmd,ldap,ssti,xxe", param: str = "q", method: str = "get", technique: str = "basic") -> str:
    """Unified injection validator — SQLi, XSS, NoSQL, CMD, LDAP, SSTI, XXE with multi-technique payloads."""
    return _injection_validator(target, types, param, method, technique)

@mcp.tool()
def oast_callback_server(action: str, payload: str = "", callback_id: str = "", poll_url: str = "", max_wait: int = 15, platform: str = "auto") -> str:
    """OAST callback server for blind SSRF/XXE/OOB correlation. Actions: generate, poll, status, clear."""
    return _oast_callback_server(action, payload, callback_id, poll_url, max_wait, platform)

@mcp.tool()
def upload_exploit_chain(target: str, upload_url: str = "", file_type: str = "php", param_name: str = "file", content: str = "") -> str:
    """Upload exploit-chain validation — upload (PHP/JSP/ASP/SVG/PY/SH) → verify accessibility → execute payload."""
    return _upload_exploit_chain(target, upload_url, file_type, param_name, content)

@mcp.tool()
def cache_poison_check(target: str, cache_buster: str = "", test_headers: str = "X-Forwarded-Host,X-Forwarded-For,X-Original-URL,X-Rewrite-URL,X-Custom-IP-Authorization,X-Real-IP") -> str:
    """Web cache poisoning detection — header manipulation, cache key injection, cache deception, scheme bypass."""
    return _cache_poison_check(target, cache_buster, test_headers)

@mcp.tool()
def cmd_oast_helper(target: str, param: str = "cmd", method: str = "get", test_type: str = "oob", oob_domain: str = "", callback_server: str = "") -> str:
    """Command injection OAST helper — blind CMD testing with OOB callback correlation and time-based detection."""
    return _cmd_oast_helper(target, param, method, test_type, oob_domain, callback_server)

@mcp.tool()
def report_schema_v2(action: str, findings_json: str = "", report_metadata: str = "", finding_id: str = "", filter_criteria: str = "") -> str:
    """Report schema v2 — validate, convert v1→v2, merge, create standardized reports with evidence chain."""
    return _report_schema_v2(action, findings_json, report_metadata, finding_id, filter_criteria)

# --- 8 Gap Tools ---

@mcp.tool()
def engagement_gate(action: str, target: str = "", scope_json: str = "", rule: str = "", confirmation: str = "") -> str:
    """Engagement gate — scope validation, authorization check, pre-flight approval rules."""
    return _engagement_gate(action, target, scope_json, rule, confirmation)

@mcp.tool()
def approval_artifact(action: str, tool_name: str = "", target: str = "", rationale: str = "", approver: str = "", artifact_id: str = "", method: str = "json") -> str:
    """Approval artifact — digital approval/signature before destructive actions."""
    return _approval_artifact(action, tool_name, target, rationale, approver, artifact_id, method)

@mcp.tool()
def session_verification(action: str, session_data: str = "", session_type: str = "cookie", target: str = "") -> str:
    """Session verification — validate session cookies, tokens, expiry before testing."""
    return _session_verification(action, session_data, session_type, target)

@mcp.tool()
def http_ingest(action: str, data: str = "", format: str = "url", target: str = "", output: str = "json") -> str:
    """HTTP ingest — parse URL, OpenAPI, HAR, Burp XML, raw HTTP, curl → standardized findings."""
    return _http_ingest(action, data, format, target, output)

@mcp.tool()
def raw_replay(action: str, raw_request: str = "", target: str = "", url: str = "", method: str = "GET", headers_json: str = "", body: str = "", follow_redirects: bool = False, timeout: int = 15) -> str:
    """Faithful raw HTTP request replay — send exact bytes, capture full response."""
    return _raw_replay(action, raw_request, target, url, method, headers_json, body, follow_redirects, timeout)

@mcp.tool()
def evidence_manifest(action: str, evidence_json: str = "", manifest_id: str = "", filter_type: str = "", chain_depth: int = 0, verify_hash: str = "") -> str:
    """Evidence manifest — SHA256 hash chain for court-admissible evidence integrity."""
    return _evidence_manifest(action, evidence_json, manifest_id, filter_type, chain_depth, verify_hash)

@mcp.tool()
def cleanup_tracking(action: str, action_type: str = "", target: str = "", tool: str = "", description: str = "", artifact: str = "", cleanup_cmd: str = "", cleanup_status: str = "pending") -> str:
    """Cleanup tracking — log modifications, generate cleanup scripts, track artifact state."""
    return _cleanup_tracking(action, action_type, target, tool, description, artifact, cleanup_cmd, cleanup_status)

@mcp.tool()
def vulnerable_fixture(action: str, target: str = "127.0.0.1", port: int = 9999, vuln_types: str = "sqli,xss,lfi,cmd,ssrf,open_redirect", ssl: bool = False, reset: bool = False) -> str:
    """Vulnerable fixture — local vulnerable app for E2E tool validation. Actions: start, stop, status, endpoints, e2e, cleanup."""
    return _vulnerable_fixture(action, target, port, vuln_types, ssl, reset)

# --- Active Directory Attack Suite ---

@mcp.tool()
def ad_enum(domain: str, dc_ip: str, username: str = "", password: str = "", enum_users: bool = True, enum_groups: bool = True, enum_computers: bool = True, enum_trusts: bool = True) -> str:
    """Comprehensive Active Directory enumeration via LDAP — users, groups, computers, trusts, password policy."""
    return json.dumps(_run(_ad_enum(domain, dc_ip, username, password, enum_users, enum_groups, enum_computers, enum_trusts)), indent=2)

@mcp.tool()
def ad_kerberoast(domain: str, dc_ip: str, username: str = "", password: str = "", output_format: str = "hashcat") -> str:
    """Kerberoasting — request TGS tickets for SPN accounts and return crackable hashes (hashcat format)."""
    return json.dumps(_run(_ad_kerberoast(domain, dc_ip, username, password, output_format)), indent=2)

@mcp.tool()
def ad_asrep_roast(domain: str, dc_ip: str, username: str = "", password: str = "", output_format: str = "hashcat") -> str:
    """ASREP Roasting — request AS-REP tickets for accounts with DONT_REQUIRE_PREAUTH and return crackable hashes."""
    return json.dumps(_run(_ad_asrep_roast(domain, dc_ip, username, password, output_format)), indent=2)

@mcp.tool()
def ad_dcsync(domain: str, dc_ip: str, username: str, password: str = "", target_user: str = "krbtgt", all_users: bool = False) -> str:
    """DCSync — extract password hashes from domain controller via DRSUAPI replication. Requires Domain Admin privileges."""
    return json.dumps(_run(_ad_dcsync(domain, dc_ip, username, password, target_user, all_users)), indent=2)

@mcp.tool()
def ad_passthehash(target: str, username: str, nt_hash: str, domain: str = "", lm_hash: str = "", command: str = "", protocol: str = "smbexec") -> str:
    """Pass-the-Hash — execute commands on remote targets using NTLM hash authentication. Protocols: smbexec, wmiexec, atexec, psexec."""
    return json.dumps(_run(_ad_passthehash(target, username, nt_hash, domain, lm_hash, command, protocol)), indent=2)

@mcp.tool()
def ad_certipy(action: str, target: str, username: str = "", password: str = "", domain: str = "", dc_ip: str = "", ca: str = "", template: str = "", alt_name: str = "", cert_path: str = "", account: str = "") -> str:
    """AD CS abuse via Certipy — enumerate certificate services (ESC1-15), request certificates, PKINIT auth, shadow credentials. Actions: find, req, auth, shadow."""
    return json.dumps(_run(_ad_certipy(action, target, username, password, domain, dc_ip, ca, template, alt_name, cert_path, account)), indent=2)

@mcp.tool()
def ad_spray(domain: str, dc_ip: str, password: str, usernames: str = "", username_file: str = "", delay: int = 0, max_attempts: int = 0) -> str:
    """Password spraying — test a single password against multiple AD accounts while respecting lockout policy."""
    return json.dumps(_run(_ad_spray(domain, dc_ip, password, usernames, username_file, delay, max_attempts)), indent=2)

@mcp.tool()
def ad_ntlm_relay(target: str = "", targets_file: str = "", command: str = "", socks_mode: bool = False, smb_server: bool = True, http_server: bool = True, smb2support: bool = True, loot_dir: str = "/tmp/ntlmrelayx_loot", timeout: int = 60) -> str:
    """NTLM Relay — set up relay server to capture and relay NTLM authentications to target systems via ntlmrelayx."""
    return json.dumps(_run(_ad_ntlm_relay(target, targets_file, command, socks_mode, smb_server, http_server, smb2support, loot_dir, timeout)), indent=2)

# --- Web Shell Suite ---

@mcp.tool()
def webshell_gen(language: str = "php", shell_type: str = "cmd", obfuscate: bool = False, password: str = "", param_name: str = "cmd", reverse_host: str = "", reverse_port: int = 4444) -> str:
    """Generate a web shell payload (PHP/JSP/ASP/ASPX). Types: cmd (command exec), eval (eval code), reverse (reverse shell). Optional obfuscation and password protection."""
    return json.dumps(_run(_webshell_gen(language, shell_type, obfuscate, password, param_name, reverse_host, reverse_port)), indent=2)

@mcp.tool()
def webshell_upload(target_url: str, shell_code: str = "", param_name: str = "file", filename: str = "shell.php", content_type: str = "application/x-php", language: str = "php", auto_gen: bool = True) -> str:
    """Upload a web shell to a target via file upload vulnerability. Auto-discovers upload endpoints and verifies shell accessibility."""
    return json.dumps(_run(_webshell_upload(target_url, shell_code, param_name, filename, content_type, language, auto_gen)), indent=2)

@mcp.tool()
def webshell_connect(shell_url: str, command: str = "", method: str = "get", param_name: str = "cmd", password: str = "", auth_param: str = "auth", extra_params: str = "", timeout: int = 15) -> str:
    """Connect to an uploaded web shell and execute commands. Supports GET/POST, password auth, and extra parameters."""
    return json.dumps(_run(_webshell_connect(shell_url, command, method, param_name, password, auth_param, extra_params, timeout)), indent=2)

@mcp.tool()
def webshell_detect(target_url: str, deep_scan: bool = False, timeout: int = 10) -> str:
    """Detect web shells on a target via signature scanning. Checks common filenames and content patterns (c99, r57, weevely, china chopper, etc.)."""
    return json.dumps(_run(_webshell_detect(target_url, deep_scan, timeout)), indent=2)

# --- Dork Suite ---

@mcp.tool()
def dork_gen(category: str = "", tech: str = "", vuln_type: str = "", target: str = "", limit: int = 50) -> str:
    """Generate Google dorks for target discovery. Categories: vuln_sites, config_leak, admin_panels, db_dumps, backup_files, git_exposed, api_keys, iot_devices, login_portals, phpinfo, error_messages, upload_forms, exposed_cms, shell_upload, deface_target, s3_buckets, exposed_docs. Tech: wordpress, laravel, django, spring, nodejs, jenkins, gitlab, kibana, grafana. Vuln: sqli, lfi, xss, rce."""
    return json.dumps(_run(_dork_gen(category, tech, vuln_type, target, limit)), indent=2)

@mcp.tool()
def dork_scan(dorks: str = "", engines: str = "ddg,bing", max_results: int = 20, delay: float = 1.0, timeout: int = 15) -> str:
    """Execute dork queries via multiple search engines (DuckDuckGo, Bing, Google). Returns URLs found. Avoids CAPTCHA by using DDG HTML version + Bing."""
    return json.dumps(_run(_dork_scan(dorks, engines, max_results, delay, timeout)), indent=2)

@mcp.tool()
def dork_hunt(category: str = "vuln_sites", tech: str = "", vuln_type: str = "", target: str = "", engines: str = "ddg,bing", max_dorks: int = 10, max_results: int = 15, probe: bool = True, validate: bool = True, delay: float = 1.0, timeout: int = 15) -> str:
    """Full dorking pipeline: generate dorks → scan engines → HTTP probe → validate vulnerabilities. One-call target discovery — give a category, get back validated vulnerable URLs."""
    return json.dumps(_run(_dork_hunt(category, tech, vuln_type, target, engines, max_dorks, max_results, probe, validate, delay, timeout)), indent=2)

@mcp.tool()
def social_osint(username: str, timeout: int = 10, concurrent: int = 20) -> str:
    """Search for a username across 100+ social media platforms (Instagram, Twitter, TikTok, GitHub, Telegram, etc.). Sherlock-style — no API keys required. Returns found accounts with URLs and status codes."""
    return json.dumps(_run(_social_osint(username, timeout, concurrent)), indent=2)

@mcp.tool()
def telegram_osint(username: str, timeout: int = 15) -> str:
    """Gather public info about a Telegram user via t.me scraping — user ID, bio, profile photo, username history links (SangMata, TGStat). No Telegram API required."""
    return json.dumps(_run(_telegram_osint(username, timeout)), indent=2)

@mcp.tool()
def phone_osint(phone_number: str, default_region: str = "") -> str:
    """Phone number intelligence — parse carrier, region, line type, timezones (offline via phonenumbers lib). Generates lookup URLs for Truecaller, GetContact, sync.me, and Google search."""
    return json.dumps(_phone_osint(phone_number, default_region), indent=2)

@mcp.tool()
def email_osint(email: str, check_breach_urls: bool = True) -> str:
    """Email intelligence — validate format, check MX records, domain reputation, Gravatar profile, and generate breach lookup URLs (HIBP, GhostProject, IntelligenceX). No paid APIs."""
    return json.dumps(_run(_email_osint(email, check_breach_urls)), indent=2)

if __name__ == "__main__":
    mcp.run(transport="stdio")

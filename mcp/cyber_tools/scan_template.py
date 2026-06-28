"""Pre-defined scan template combos."""
import json

TEMPLATES = {
    "quick-recon": {
        "description": "Fast recon — DNS, subdomains, HTTP probe",
        "steps": [
            {"tool": "dns_lookup", "params": {"target": "{target}"}},
            {"tool": "subdomain_enum", "params": {"target": "{target}"}},
            {"tool": "whois_lookup", "params": {"target": "{target}"}},
        ],
    },
    "web-full": {
        "description": "Full web audit — tech detect, vulns, headers, SQLi, XSS",
        "steps": [
            {"tool": "tech_detect", "params": {"target": "{target}"}},
            {"tool": "vuln_scan", "params": {"target": "{target}"}},
            {"tool": "cors_check", "params": {"target": "{target}"}},
            {"tool": "csp_analyze", "params": {"target": "{target}"}},
            {"tool": "cookie_audit", "params": {"target": "{target}"}},
            {"tool": "sqli_detect", "params": {"target": "{target}"}},
            {"tool": "xss_detect", "params": {"target": "{target}"}},
            {"tool": "lfi_detect", "params": {"target": "{target}"}},
            {"tool": "ssrf_detect", "params": {"target": "{target}"}},
        ],
    },
    "network-audit": {
        "description": "Network security audit — ports, services, SSH, SSL",
        "steps": [
            {"tool": "port_scan", "params": {"target": "{target}", "ports": "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443"}},
            {"tool": "service_fingerprint", "params": {"target": "{target}", "port": 80}},
            {"tool": "ssh_audit", "params": {"target": "{target}"}},
            {"tool": "ssl_check", "params": {"target": "{target}"}},
            {"tool": "smb_enum", "params": {"target": "{target}"}},
            {"tool": "snmp_enum", "params": {"target": "{target}"}},
        ],
    },
    "api-security": {
        "description": "API security testing — fuzz, auth, GraphQL, JWT",
        "steps": [
            {"tool": "api_fuzz", "params": {"target": "{target}"}},
            {"tool": "api_auth", "params": {"target": "{target}"}},
            {"tool": "graphql_introspect", "params": {"target": "{target}"}},
            {"tool": "graphql_injection", "params": {"target": "{target}"}},
            {"tool": "jwt_analyze", "params": {"token": ""}},
            {"tool": "jwt_forgery", "params": {"token": ""}},
        ],
    },
    "cloud-audit": {
        "description": "Cloud security — S3, IAM, infra, K8s, Docker",
        "steps": [
            {"tool": "cloud_enum", "params": {"company": "{target}"}},
            {"tool": "cloud_iam_audit", "params": {"provider": "aws"}},
            {"tool": "cloud_infra", "params": {"provider": "aws"}},
            {"tool": "k8s_scan", "params": {"target": "{target}"}},
            {"tool": "docker_scan", "params": {"target": "{target}"}},
        ],
    },
    "ad-pentest": {
        "description": "Active Directory — LDAP, BloodHound, SMB",
        "steps": [
            {"tool": "ldap_enum", "params": {"target": "{target}"}},
            {"tool": "bloodhound_collect", "params": {"domain": "{target}"}},
            {"tool": "smb_enum", "params": {"target": "{target}"}},
        ],
    },
    "code-audit": {
        "description": "Source code audit — SAST, secrets, deps",
        "steps": [
            {"tool": "bandit_scan", "params": {"path": "{target}"}},
            {"tool": "semgrep_scan", "params": {"path": "{target}"}},
            {"tool": "secret_scanner", "params": {"path": "{target}"}},
            {"tool": "sast_review", "params": {"path": "{target}"}},
            {"tool": "ci_cd_scan", "params": {"target": "{target}"}},
            {"tool": "supply_chain", "params": {"target": "{target}"}},
        ],
    },
    "ctf": {
        "description": "CTF — recon, web, LFI, SQLi, SSTI, XXE",
        "steps": [
            {"tool": "tech_detect", "params": {"target": "{target}"}},
            {"tool": "dir_bruteforce", "params": {"target": "{target}"}},
            {"tool": "sqli_detect", "params": {"target": "{target}"}},
            {"tool": "xss_detect", "params": {"target": "{target}"}},
            {"tool": "lfi_detect", "params": {"target": "{target}"}},
            {"tool": "ssti_detect", "params": {"target": "{target}"}},
            {"tool": "xxe_detect", "params": {"target": "{target}"}},
            {"tool": "cmd_injection", "params": {"target": "{target}"}},
        ],
    },
}

def scan_template(target: str, template: str = "quick-recon") -> str:
    if template not in TEMPLATES:
        available = ", ".join(TEMPLATES.keys())
        return json.dumps({"error": f"Template '{template}' not found", "available": available}, indent=2)
    t = TEMPLATES[template]
    steps = []
    for i, step in enumerate(t["steps"]):
        flat = json.dumps(step["params"])
        flat = flat.replace("{target}", target)
        steps.append({
            "step": i + 1,
            "tool": step["tool"],
            "params": json.loads(flat),
        })
    return json.dumps({
        "template": template,
        "description": t["description"],
        "total_steps": len(steps),
        "steps": steps,
    }, indent=2)
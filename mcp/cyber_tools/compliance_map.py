"""Map findings to SOC2/ISO27001/GDPR compliance controls."""
import json

COMPLIANCE_MAP = {
    "sqli": {
        "soc2": ["CC7.1", "CC7.2"],
        "iso27001": ["A.14.2.5", "A.8.28"],
        "gdpr": ["Art.32", "Art.5"],
        "pci": ["6.5.1"],
        "nist": ["SI-10", "SC-5"],
    },
    "xss": {
        "soc2": ["CC7.1", "CC6.1"],
        "iso27001": ["A.14.2.5", "A.8.28"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.7"],
        "nist": ["SI-10", "SC-5"],
    },
    "lfi": {
        "soc2": ["CC6.1", "CC7.1"],
        "iso27001": ["A.8.9", "A.14.2.5"],
        "gdpr": ["Art.32", "Art.5"],
        "pci": ["6.5.5"],
        "nist": ["SC-7", "SI-3"],
    },
    "ssrf": {
        "soc2": ["CC6.1", "CC7.1"],
        "iso27001": ["A.8.9", "A.14.2.5"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.8"],
        "nist": ["SC-7", "SI-3"],
    },
    "open_redirect": {
        "soc2": ["CC6.1"],
        "iso27001": ["A.14.2.5"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.10"],
        "nist": ["SC-7"],
    },
    "ssti": {
        "soc2": ["CC7.1", "CC6.1"],
        "iso27001": ["A.14.2.5", "A.8.28"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.1"],
        "nist": ["SI-10"],
    },
    "xxe": {
        "soc2": ["CC7.1", "CC6.1"],
        "iso27001": ["A.14.2.5", "A.8.9"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.1"],
        "nist": ["SC-7", "SI-10"],
    },
    "cmd_injection": {
        "soc2": ["CC7.1", "CC6.1"],
        "iso27001": ["A.14.2.5", "A.8.28"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.1"],
        "nist": ["SI-10", "SC-5"],
    },
    "missing_headers": {
        "soc2": ["CC6.1", "CC7.1"],
        "iso27001": ["A.14.1.2", "A.8.20"],
        "gdpr": ["Art.32"],
        "pci": ["6.5.10"],
        "nist": ["SC-3", "SC-7"],
    },
    "ssl_tls_weakness": {
        "soc2": ["CC6.1", "CC6.7"],
        "iso27001": ["A.8.24", "A.10.1.1"],
        "gdpr": ["Art.32"],
        "pci": ["4.1"],
        "nist": ["SC-8", "SC-12", "SC-13"],
    },
    "auth_bypass": {
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.9.2.4", "A.9.4.2"],
        "gdpr": ["Art.5", "Art.32"],
        "pci": ["6.5.10", "8.2"],
        "nist": ["IA-2", "IA-5"],
    },
    "idor": {
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.9.4.5", "A.14.2.5"],
        "gdpr": ["Art.5", "Art.32"],
        "pci": ["6.5.4", "7.2"],
        "nist": ["AC-3", "AC-6"],
    },
    "info_disclosure": {
        "soc2": ["CC6.1", "C1.1"],
        "iso27001": ["A.8.9", "A.5.1.2"],
        "gdpr": ["Art.5", "Art.25"],
        "pci": ["3.1", "3.2"],
        "nist": ["AC-6", "MP-3"],
    },
    "default_creds": {
        "soc2": ["CC6.1", "CC6.3"],
        "iso27001": ["A.9.2.1", "A.9.2.4"],
        "gdpr": ["Art.32"],
        "pci": ["8.2", "2.1"],
        "nist": ["IA-5", "IA-2"],
    },
    "misconfig": {
        "soc2": ["CC6.1", "CC7.1"],
        "iso27001": ["A.12.5.1", "A.14.2.2"],
        "gdpr": ["Art.32"],
        "pci": ["2.2", "6.5.10"],
        "nist": ["CM-2", "CM-6"],
    },
}

FRAMEWORK_DESCRIPTIONS = {
    "soc2": "AICPA SOC 2 Trust Services Criteria",
    "iso27001": "ISO/IEC 27001:2022 Information Security Controls",
    "gdpr": "EU General Data Protection Regulation",
    "pci": "PCI DSS v4.0",
    "nist": "NIST SP 800-53 Rev 5",
}

def compliance_map(findings_json: str, framework: str = "auto") -> str:
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        findings = []
    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))

    frameworks = list(COMPLIANCE_MAP.get("sqli", {}).keys()) if framework == "auto" else [framework]
    mapped_findings = []
    framework_summary = {fw: {"total": 0, "controls": set()} for fw in frameworks}

    for f in findings:
        vtype = f.get("type", f.get("vuln_type", f.get("title", ""))).lower()
        vtype = _normalize_vtype(vtype)
        mappings = COMPLIANCE_MAP.get(vtype, {})

        finding_map = {
            "finding": f.get("title", f.get("type", "Unknown")),
            "severity": f.get("severity", "info"),
            "vuln_type": vtype,
            "compliance": {}
        }

        for fw in frameworks:
            controls = mappings.get(fw, [])
            if controls:
                finding_map["compliance"][fw] = {
                    "controls": controls,
                    "framework": FRAMEWORK_DESCRIPTIONS.get(fw, fw),
                    "status": "non_compliant",
                }
                framework_summary[fw]["total"] += 1
                framework_summary[fw]["controls"].update(controls)
            else:
                finding_map["compliance"][fw] = {
                    "controls": [],
                    "status": "not_applicable",
                }

        mapped_findings.append(finding_map)

    result = {
        "framework": framework,
        "total_findings": len(findings),
        "mapped_findings": len(mapped_findings),
        "frameworks": {
            fw: {
                "description": FRAMEWORK_DESCRIPTIONS.get(fw, fw),
                "affected_findings": framework_summary[fw]["total"],
                "violated_controls": sorted(framework_summary[fw]["controls"]),
                "total_controls_violated": len(framework_summary[fw]["controls"]),
            }
            for fw in frameworks
        },
        "findings": mapped_findings,
    }

    non_compliant = sum(1 for fw in frameworks if framework_summary[fw]["total"] > 0)
    result["compliance_status"] = "non_compliant" if non_compliant > 0 else "compliant"
    result["summary"] = f"{non_compliant}/{len(frameworks)} frameworks have violations from {len(findings)} findings"
    return json.dumps(result, indent=2)


def _normalize_vtype(vtype):
    aliases = {
        "sql_injection": "sqli",
        "sqli": "sqli",
        "cross_site_scripting": "xss",
        "xss": "xss",
        "file_inclusion": "lfi",
        "lfi": "lfi",
        "rfi": "lfi",
        "ssrf": "ssrf",
        "server_side_request_forgery": "ssrf",
        "open_redirect": "open_redirect",
        "redirect": "open_redirect",
        "ssti": "ssti",
        "xxe": "xxe",
        "command_injection": "cmd_injection",
        "cmd_injection": "cmd_injection",
        "missing_security_headers": "missing_headers",
        "weak_ssl": "ssl_tls_weakness",
        "ssl": "ssl_tls_weakness",
        "tls": "ssl_tls_weakness",
        "auth": "auth_bypass",
        "authentication": "auth_bypass",
        "idor": "idor",
        "information_disclosure": "info_disclosure",
        "default_credentials": "default_creds",
        "misconfiguration": "misconfig",
    }
    return aliases.get(vtype, vtype)
"""Vulnerability validation — verify exploitability and filter false positives."""

import json
from datetime import datetime

FP_PATTERNS = {
    "sqli": [
        "syntax error.*mysql",
        "syntax error.*postgresql",
        "warning.*mysqli",
        "pdo.*syntax",
    ],
    "xss": [
        "reflected.*input.*not.*found",
        "payload.*encoded",
        "waf.*blocked",
    ],
    "ssrf": [
        "connection.*refused",
        "timeout.*connect",
        "dns.*not.*found",
    ],
    "lfi": [
        "file.*not.*found",
        "permission.*denied",
        "no such file",
    ],
    "ssti": [
        "template.*not.*found",
        "syntax.*error.*template",
    ],
    "open_redirect": [
        "redirect.*not.*followed",
        "same.*page.*redirect",
    ],
}

CONFIRM_INDICATORS = {
    "sqli": ["union select", "information_schema", "sleep(", "benchmark(", "extractvalue", "updatexml"],
    "xss": ["<script>", "alert(", "onerror=", "onload=", "javascript:"],
    "ssrf": ["169.254.169.254", "metadata", "instance-id", "iam"],
    "lfi": ["root:", "daemon:", "bin:", "/etc/passwd", "/etc/shadow", "[boot loader]"],
    "ssti": ["{{", "}}", "#{", "*{", "pwn", "49", "1337"],
    "open_redirect": ["location:", "redirect:", "302", "301"],
    "log4j": ["${jndi:", "${lower:", "${upper:", "${env:"],
    "xxe": ["system", "entity", "file://", "<!ENTITY"],
    "cmd_injection": ["uid=", "gid=", "root", "whoami", "id", "/bin/"],
}


def vuln_validate(finding_json: str) -> str:
    """Validate a vulnerability finding — confirm exploitability or flag as false positive.

    Accepts JSON string with: type, host, port, description, evidence, response
    Returns validation result with confidence score.
    """
    try:
        finding = json.loads(finding_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"}, indent=2)

    vuln_type = finding.get("type", "").lower()
    evidence = finding.get("evidence", "")
    response = finding.get("response", "")
    description = finding.get("description", "")
    combined = f"{evidence} {response} {description}".lower()

    result = {
        "finding_id": finding.get("id", "unknown"),
        "type": vuln_type,
        "host": finding.get("host", "unknown"),
        "validation": "unverified",
        "confidence": 0,
        "is_false_positive": False,
        "fp_reason": "",
        "confirmed_indicators": [],
        "fp_indicators": [],
        "validated_at": datetime.now().isoformat(),
        "recommendation": "",
    }

    for pattern_set in FP_PATTERNS.values():
        for pattern in pattern_set:
            if pattern in combined:
                result["fp_indicators"].append(pattern)
                result["is_false_positive"] = True
                result["fp_reason"] = f"Matched FP pattern: {pattern}"

    confirm_patterns = CONFIRM_INDICATORS.get(vuln_type, [])
    for pattern in confirm_patterns:
        if pattern.lower() in combined:
            result["confirmed_indicators"].append(pattern)

    fp_count = len(result["fp_indicators"])
    confirm_count = len(result["confirmed_indicators"])

    if confirm_count > 0 and fp_count == 0:
        result["validation"] = "confirmed"
        result["confidence"] = min(90 + confirm_count * 5, 99)
        result["recommendation"] = "Vulnerability confirmed. Proceed with remediation."
    elif confirm_count > 0 and fp_count > 0:
        result["validation"] = "likely_confirmed"
        result["confidence"] = 60 + confirm_count * 10 - fp_count * 15
        result["confidence"] = max(result["confidence"], 30)
        result["recommendation"] = "Likely confirmed but some FP indicators present. Manual review recommended."
    elif fp_count > 0 and confirm_count == 0:
        result["validation"] = "false_positive"
        result["confidence"] = 80 + fp_count * 5
        result["confidence"] = min(result["confidence"], 95)
        result["recommendation"] = "Likely false positive. Review before reporting."
    else:
        result["validation"] = "unverified"
        result["confidence"] = 50
        result["recommendation"] = "No clear indicators. Manual verification required."

    return json.dumps(result, indent=2)
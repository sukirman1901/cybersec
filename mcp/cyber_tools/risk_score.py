"""Risk score calculator — CVSS + business impact + likelihood."""

import json
import re
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime


def _input_ok(value):
    """Bound each input: 1 MiB UTF-8 text, 1000/container, 10000 nodes, depth 64."""
    stack, size, nodes = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 10000 or depth > 64:
            return False
        if isinstance(item, str):
            if len(item) > 1048576:
                return False
            size += len(item.encode('utf-8', errors='replace'))
            if size > 1048576:
                return False
        elif isinstance(item, (dict, list)):
            if len(item) > 1000:
                return False
            children = list(item.keys()) + list(item.values()) if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return True


def _redact_urls(value):
    """Redact HTTP URL userinfo, query and fragment; not arbitrary prose secrets."""
    if isinstance(value, dict):
        return {_redact_urls(k): _redact_urls(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_urls(v) for v in value]
    if not isinstance(value, str):
        return value
    def clean(match):
        try:
            parsed = urlsplit(match.group())
            return urlunsplit((parsed.scheme, parsed.netloc.rsplit('@', 1)[-1], parsed.path,
                               '[REDACTED]' if parsed.query else '', '[REDACTED]' if parsed.fragment else ''))
        except ValueError:
            return '[REDACTED URL]'
    return re.sub(r'https?://[^\s<>"\']+', clean, value, flags=re.I)

CVSS_WEIGHTS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

BUSINESS_IMPACT = {
    "data_breach": 3,
    "service_disruption": 2,
    "privilege_escalation": 3,
    "remote_code_execution": 3,
    "information_disclosure": 2,
    "authentication_bypass": 3,
    "xss": 1,
    "csrf": 1,
    "open_redirect": 1,
    "missing_header": 1,
    "info_disclosure": 1,
}

LIKELIHOOD_FACTORS = {
    "remote_exploitable": 2,
    "has_public_exploit": 2,
    "authenticated_required": -1,
    "internal_only": -1,
    "waf_protected": -1,
    "user_interaction_required": -1,
}


def risk_score(finding_json: str, target_asset_value: str = "medium") -> str:
    """Calculate risk score for a vulnerability finding.

    Combines CVSS severity, business impact, and exploitability likelihood.
    target_asset_value: low, medium, high, critical (business value of the target)
    """
    if not all(_input_ok(v) for v in (finding_json, target_asset_value)):
        return json.dumps({'error': 'Input exceeds 1 MiB/1000-item/10000-node/depth-64 budget'})
    try:
        finding = json.loads(finding_json)
    except (ValueError, TypeError, RecursionError):
        return json.dumps({"error": "Invalid JSON"}, indent=2)
    if not _input_ok(finding):
        return json.dumps({'error': 'Parsed input exceeds collection/depth budget'})
    finding = _redact_urls(finding)
    if not isinstance(finding, dict) or not finding or not isinstance(finding.get('severity'), str) or finding['severity'].lower() not in CVSS_WEIGHTS:
        return json.dumps({"error": "Expected a finding with a recognized severity"})
    if not isinstance(finding.get('type', ''), str) or any(type(finding[k]) is not bool for k in LIKELIHOOD_FACTORS if k in finding):
        return json.dumps({"error": "Type must be a string and likelihood factors must be booleans"})
    if target_asset_value not in ('low', 'medium', 'high', 'critical'):
        return json.dumps({"error": "Unknown asset value"})

    vuln_type = finding.get("type", "").lower()
    severity = finding.get("severity", "info").lower()

    cvss_base = CVSS_WEIGHTS.get(severity, 0.0)

    impact_score = BUSINESS_IMPACT.get(vuln_type, 1)
    if "rce" in vuln_type or "remote_code" in vuln_type:
        impact_score = 3
    elif "sqli" in vuln_type:
        impact_score = 3
    elif "ssrf" in vuln_type:
        impact_score = 2

    likelihood = 1
    factors = []
    for factor, weight in LIKELIHOOD_FACTORS.items():
        if finding.get(factor, False):
            likelihood += weight
            factors.append(f"+{weight} {factor}")

    if finding.get("cve"):
        likelihood += 1
        factors.append("+1 cve_assigned")

    asset_multiplier = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}.get(target_asset_value, 1.0)

    raw_score = (cvss_base * 0.4 + impact_score * 0.3 + likelihood * 0.3) * asset_multiplier
    final_score = min(max(raw_score, 0), 10)

    if final_score >= 9:
        level = "critical"
    elif final_score >= 7:
        level = "high"
    elif final_score >= 4:
        level = "medium"
    elif final_score >= 1:
        level = "low"
    else:
        level = "info"

    result = {
        "finding": {
            "type": vuln_type,
            "severity": severity,
            "host": finding.get("host", "unknown"),
            "status": finding.get("status", "candidate"),
        },
        "scores": {
            "cvss_base": cvss_base,
            "business_impact": impact_score,
            "likelihood": likelihood,
            "asset_multiplier": asset_multiplier,
            "raw_score": round(raw_score, 2),
            "final_score": round(final_score, 2),
            "risk_level": level,
        },
        "factors": {
            "likelihood_factors": factors,
            "asset_value": target_asset_value,
        },
        "recommendation": _get_recommendation(level, vuln_type),
        "calculated_at": datetime.now().isoformat(),
        "limitations": "Heuristic triage, not a calculated CVSS vector or evidence of exploitation. Input status is not independently verified.",
    }

    return json.dumps(result, indent=2)


def _get_recommendation(level, vuln_type):
    recs = {
        "critical": f"CRITICAL — Fix immediately. {vuln_type} poses severe risk. Patch within 24 hours.",
        "high": f"HIGH — Prioritize validation and remediation of {vuln_type}; exploitability remains unverified.",
        "medium": f"MEDIUM — Fix within 30 days. {vuln_type} has moderate risk but should be addressed.",
        "low": f"LOW — Fix when possible. {vuln_type} has minimal impact but still worth addressing.",
        "info": f"INFO — Informational. {vuln_type} noted for awareness. No immediate action required.",
    }
    return recs.get(level, "Review recommended.")

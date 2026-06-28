"""Report schema v2 — standardized finding schema with versioning and validation."""
import json
from datetime import datetime
import hashlib
import uuid

REPORT_SCHEMA_VERSION = "2.0"

def report_schema_v2(action: str, findings_json: str = "", report_metadata: str = "", finding_id: str = "", filter_criteria: str = "") -> str:
    if action == "validate":
        return _validate_findings(findings_json)
    elif action == "convert":
        return _convert_v1_to_v2(findings_json)
    elif action == "schema":
        return _get_schema()
    elif action == "merge":
        return _merge_reports(findings_json, report_metadata)
    elif action == "create":
        return _create_report(findings_json, report_metadata)
    else:
        return json.dumps({"error": "Unknown action", "actions": ["validate", "convert", "schema", "merge", "create"]}, indent=2)


def _validate_findings(findings_json):
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        return json.dumps({"error": "Invalid JSON"}, indent=2)

    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))

    errors = []
    warnings = []
    valid = 0

    for i, f in enumerate(findings):
        f_errors = []
        f_warnings = []

        if not f.get("title") and not f.get("type"):
            f_errors.append("Missing title/type")
        if not f.get("severity"):
            f_warnings.append("Missing severity (defaulting to info)")
        else:
            sev = f["severity"].lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                f_errors.append(f"Invalid severity: {sev}")

        if f.get("cvss") is not None:
            try:
                cvss = float(f["cvss"])
                if cvss < 0 or cvss > 10:
                    f_errors.append(f"CVSS out of range: {cvss}")
            except (ValueError, TypeError):
                f_errors.append("Invalid CVSS format")

        if not f.get("evidence") and not f.get("response"):
            f_warnings.append("No evidence provided")

        if f_errors:
            errors.append({"finding_index": i, "title": f.get("title", "unknown"), "errors": f_errors})
        if f_warnings:
            warnings.append({"finding_index": i, "title": f.get("title", "unknown"), "warnings": f_warnings})
        if not f_errors:
            valid += 1

    return json.dumps({
        "schema_version": REPORT_SCHEMA_VERSION,
        "total_findings": len(findings),
        "valid": valid,
        "errors": len(errors),
        "warnings": len(warnings),
        "error_details": errors,
        "warning_details": warnings,
        "is_valid": len(errors) == 0,
    }, indent=2)


def _convert_v1_to_v2(findings_json):
    """Convert v1 findings (any format) to schema v2."""
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        return json.dumps({"error": "Invalid JSON"}, indent=2)

    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))

    v2_findings = []
    for f in findings:
        v2 = {
            "id": f.get("id", f.get("finding_id", str(uuid.uuid4()))),
            "schema_version": REPORT_SCHEMA_VERSION,
            "title": f.get("title", f.get("type", "Unknown Finding")),
            "type": f.get("type", f.get("vuln_type", "unknown")),
            "severity": f.get("severity", "medium").lower(),
            "cvss": f.get("cvss", f.get("cvss_score", None)),
            "target": f.get("target", f.get("host", f.get("url", ""))),
            "status": f.get("status", "new"),
            "evidence": f.get("evidence", f.get("response", "")),
            "remediation": f.get("remediation", f.get("fix", "")),
            "description": f.get("description", f.get("summary", "")),
            "metadata": {
                "detected_at": f.get("detected_at", f.get("timestamp", f.get("added", datetime.utcnow().isoformat()))),
                "tool": "Cybersec MCP",
                "confidence": f.get("confidence", None),
                "reproducible": f.get("reproducible", f.get("repeatable", False)),
                "poc": f.get("poc_url", f.get("poc_link", "")),
                "tags": f.get("tags", []),
                "references": f.get("references", []),
            }
        }
        # Generate evidence hash for chain of custody
        evidence_hash_input = f"{v2['id']}{v2['evidence'][:500]}{v2['target']}"
        v2["metadata"]["evidence_hash"] = hashlib.sha256(evidence_hash_input.encode()).hexdigest()[:16]
        v2_findings.append(v2)

    return json.dumps({"schema_version": REPORT_SCHEMA_VERSION, "findings": v2_findings, "total": len(v2_findings)}, indent=2)


def _get_schema():
    return json.dumps({
        "schema_version": REPORT_SCHEMA_VERSION,
        "finding_fields": [
            {"name": "id", "type": "string", "required": True, "description": "Unique finding identifier"},
            {"name": "schema_version", "type": "string", "required": True, "description": "Schema version string"},
            {"name": "title", "type": "string", "required": True, "description": "Finding title"},
            {"name": "type", "type": "string", "required": True, "description": "Vulnerability type (sqli, xss, etc)"},
            {"name": "severity", "type": "enum", "values": ["critical", "high", "medium", "low", "info"], "required": True},
            {"name": "cvss", "type": "number", "required": False, "min": 0, "max": 10},
            {"name": "target", "type": "string", "required": True, "description": "Affected host/URL/endpoint"},
            {"name": "status", "type": "enum", "values": ["new", "confirmed", "false_positive", "fixing", "fixed", "retested", "wont_fix"], "required": False, "default": "new"},
            {"name": "evidence", "type": "string", "required": True, "description": "Evidence of the finding"},
            {"name": "remediation", "type": "string", "required": False, "description": "Fix recommendation"},
            {"name": "description", "type": "string", "required": False, "description": "Detailed description"},
            {"name": "metadata", "type": "object", "required": False, "children": [
                {"name": "detected_at", "type": "string (ISO8601)", "required": False},
                {"name": "tool", "type": "string", "required": False},
                {"name": "confidence", "type": "number (0-99)", "required": False},
                {"name": "evidence_hash", "type": "string (SHA256:16)", "required": False},
                {"name": "tags", "type": "array[string]", "required": False},
                {"name": "references", "type": "array[string]", "required": False},
            ]},
        ],
        "validation_rules": [
            "severity must be one of: critical, high, medium, low, info",
            "cvss must be 0-10 if provided",
            "status must be one of: new, confirmed, false_positive, fixing, fixed, retested, wont_fix",
        ]
    }, indent=2)


def _merge_reports(findings_json, report_metadata):
    try:
        primary = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        return json.dumps({"error": "Invalid primary findings"}, indent=2)

    if isinstance(primary, dict):
        primary = primary.get("findings", primary.get("results", [primary]))

    meta = {}
    if report_metadata:
        try:
            meta = json.loads(report_metadata) if isinstance(report_metadata, str) else report_metadata
        except Exception:
            meta = {"error": "Invalid metadata"}

    v2 = []
    for f in primary:
        v2.append({
            "id": f.get("id", str(uuid.uuid4())),
            "schema_version": REPORT_SCHEMA_VERSION,
            "title": f.get("title", f.get("type", "Unknown")),
            "type": f.get("type", f.get("vuln_type", "unknown")),
            "severity": f.get("severity", "medium").lower(),
            "target": f.get("target", f.get("host", "")),
            "status": f.get("status", "new"),
            "evidence": f.get("evidence", f.get("response", "")),
            "remediation": f.get("remediation", f.get("fix", "")),
            "metadata": {
                "detected_at": f.get("detected_at", datetime.utcnow().isoformat()),
                "confidence": f.get("confidence", None),
            }
        })

    return json.dumps({
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_metadata": meta,
        "findings": v2,
        "total": len(v2),
        "merged_at": datetime.utcnow().isoformat() + "Z",
    }, indent=2)


def _create_report(findings_json, report_metadata):
    converted = json.loads(_convert_v1_to_v2(findings_json))
    meta = {}
    if report_metadata:
        try:
            meta = json.loads(report_metadata) if isinstance(report_metadata, str) else report_metadata
        except Exception:
            pass

    by_severity = {}
    for f in converted["findings"]:
        s = f["severity"]
        by_severity[s] = by_severity.get(s, 0) + 1

    return json.dumps({
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_metadata": {
            "title": meta.get("title", "Security Assessment Report"),
            "target": meta.get("target", ""),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "generated_by": "Cybersec MCP",
            "total_findings": converted["total"],
            "severity_summary": by_severity,
            "schema_version": REPORT_SCHEMA_VERSION,
        },
        "findings": converted["findings"],
    }, indent=2)
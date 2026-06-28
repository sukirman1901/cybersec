"""Vulnerability validation v2 — enhanced confidence engine, evidence scoring, reproducibility check."""
import json
from datetime import datetime
import hashlib

SEVERITY_WEIGHTS = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}
MAX_CONFIDENCE = 99

EVIDENCE_TYPES = {
    "response_body": 15, "response_time": 10, "response_header": 12,
    "error_message": 10, "status_code": 8, "callback_received": 20,
    "data_extracted": 18, "command_output": 18, "file_read": 18,
    "poc_generated": 15, "multiple_payloads": 10, "reproducible": 15,
}

FP_SIGNALS = {
    "sqli": ["syntax error.*mysql", "warning.*mysqli", "pdo.*syntax", "no such table", "column.*not found"],
    "xss": ["waf.*blocked", "payload.*rejected", "input.*filtered", "request.*blocked"],
    "ssrf": ["connection refused", "dns resolution failed", "timeout reached", "host unreachable"],
    "lfi": ["no such file", "permission denied", "file not found", "not allowed", "path restricted"],
    "cmd": ["command not found", "not recognized", "permission denied", "access denied"],
    "ssti": ["template not found", "syntax error.*template", "invalid template", "template error"],
    "xxe": ["parser error", "xml parsing failed", "entity not allowed", "doctype not allowed"],
    "log4j": ["invalid jndi", "lookup failed", "not allowed"],
}

def vuln_validate(finding_json: str) -> str:
    try:
        finding = json.loads(finding_json) if isinstance(finding_json, str) else finding_json
    except Exception:
        return json.dumps({"error": "Invalid JSON"}, indent=2)

    vuln_type = finding.get("type", finding.get("vuln_type", "")).lower()
    evidence = finding.get("evidence", finding.get("response", ""))
    description = finding.get("description", "")
    severity = finding.get("severity", "medium").lower()
    combined = f"{evidence} {description}".lower()

    result = {
        "finding_id": finding.get("id", finding.get("finding_id", "unknown")),
        "type": vuln_type,
        "target": finding.get("target", finding.get("host", "")),
        "validation": "unverified",
        "confidence": 0,
        "is_false_positive": False,
        "fp_reason": "",
        "evidence_scored": [],
        "fp_signals_detected": [],
        "reproducible": False,
        "vulnerability_hash": "",
    }

    score = 0
    max_score = 0

    # 1. Score each evidence type
    for etype, weight in EVIDENCE_TYPES.items():
        max_score += weight
        if etype == "response_body" and evidence and len(evidence) > 50:
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "response_time" and finding.get("response_time", 0) > 3:
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "status_code" and finding.get("status", finding.get("status_code", 0)) in (200, 500):
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "error_message" and any(e in evidence.lower() for e in ["error", "warning", "exception", "fatal", "sql", "syntax"]):
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "command_output" and any(e in evidence.lower() for e in ["uid=", "gid=", "www-data", "root:"]):
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "file_read" and any(e in evidence.lower() for e in ["root:", "daemon:", "bin/bash", "/etc/"]):
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "poc_generated" and evidence and finding.get("poc_url", finding.get("poc_link", "")):
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})
        elif etype == "data_extracted" and finding.get("data", finding.get("extracted_data", "")):
            score += weight; result["evidence_scored"].append({"type": etype, "score": weight})

    # 2. Reproducibility check
    if finding.get("reproducible", finding.get("repeatable", False)):
        score += EVIDENCE_TYPES["reproducible"]
        result["reproducible"] = True
        result["evidence_scored"].append({"type": "reproducible", "score": EVIDENCE_TYPES["reproducible"]})

    # 3. Multiple payloads tested
    payloads = finding.get("payloads_tested", finding.get("payloads", []))
    if isinstance(payloads, list) and len(payloads) >= 2:
        score += EVIDENCE_TYPES["multiple_payloads"]
        result["evidence_scored"].append({"type": "multiple_payloads", "score": EVIDENCE_TYPES["multiple_payloads"]})

    # 4. FP signal detection
    fp_score = 0
    for ftype, signals in FP_SIGNALS.items():
        for signal in signals:
            import re
            if re.search(signal, combined):
                result["fp_signals_detected"].append({"type": ftype, "signal": signal})
                fp_score += 15

    # 5. Calculate confidence
    if max_score > 0:
        raw_conf = (score / max_score) * 100
    else:
        raw_conf = 40

    confidence = raw_conf - fp_score
    confidence = max(confidence, 5)
    confidence = min(confidence, MAX_CONFIDENCE)
    result["confidence"] = round(confidence)

    # 6. Determine validation state
    if result["fp_signals_detected"] and confidence < 30:
        result["validation"] = "false_positive"
        result["is_false_positive"] = True
        result["fp_reason"] = f"FP signals: {', '.join(s['signal'] for s in result['fp_signals_detected'][:3])}"
    elif confidence >= 70 and result["reproducible"]:
        result["validation"] = "confirmed"
    elif confidence >= 60:
        result["validation"] = "likely_confirmed"
    elif confidence >= 30:
        result["validation"] = "unverified"
    else:
        result["validation"] = "false_positive"
        result["is_false_positive"] = True

    # 7. Severity-adjusted recommendation
    sev_map = {
        "critical": "Immediate remediation required within 24 hours",
        "high": "Urgent remediation within 7 days",
        "medium": "Schedule remediation within 30 days",
        "low": "Optional — address during next sprint",
        "info": "Informational — no action required"
    }
    result["recommendation"] = sev_map.get(severity, "Manual review required")
    if result["is_false_positive"]:
        result["recommendation"] = "Flagged as false positive — verify manually before discarding"
    elif result["validation"] == "unverified":
        result["recommendation"] = "Manual verification required — insufficient evidence"

    # 8. Vulnerability hash (evidence chain integrity)
    hash_input = f"{result['type']}{result['target']}{evidence[:500]}{datetime.utcnow().isoformat()}"
    result["vulnerability_hash"] = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    result["validated_at"] = datetime.utcnow().isoformat() + "Z"

    return json.dumps(result, indent=2)
"""Approval artifact — digital approval/signature before destructive actions."""
import json
from datetime import datetime

def approval_artifact(action: str, tool_name: str = "", target: str = "", rationale: str = "", approver: str = "", artifact_id: str = "", method: str = "json") -> str:
    if action == "request":
        return _request_approval(tool_name, target, rationale, method)
    elif action == "approve":
        return _grant_approval(artifact_id, approver)
    elif action == "deny":
        return _deny_approval(artifact_id, approver)
    elif action == "list":
        return _list_pending()
    elif action == "audit":
        return _audit_log()
    else:
        return json.dumps({"error": "Unknown action", "actions": ["request", "approve", "deny", "list", "audit"]}, indent=2)


PENDING = []
AUDIT = []
COUNTER = [0]
RISKY_TOOLS = [
    "auto_exploit", "sqli_exploit", "xss_exploit", "upload_exploit_chain",
    "hydra_brute", "sqlmap_check", "masscan_scan", "nmap_scan",
    "cmd_injection", "java_deserialize", "php_deserialize", "log4j_scan",
    "smuggling_check", "xxe_detect", "oast_callback_server",
]


def _request_approval(tool_name, target, rationale, method):
    COUNTER[0] += 1
    aid = f"APR-{COUNTER[0]:04d}"
    entry = {
        "artifact_id": aid,
        "tool": tool_name or "unknown",
        "target": target or "unknown",
        "rationale": rationale or "No rationale provided",
        "status": "pending",
        "method": method,
        "is_risky": tool_name in RISKY_TOOLS if tool_name else True,
    }
    PENDING.append(entry)
    AUDIT.append({**entry, "timestamp": datetime.utcnow().isoformat() + "Z", "action": "requested"})
    return json.dumps({
        "artifact_id": aid,
        "status": "pending",
        "requires_approval": entry["is_risky"],
        "message": "Destructive/risky tool requires explicit approval. Use approve() to grant.",
        "tool": entry["tool"],
        "target": entry["target"],
        "rationale": entry["rationale"],
    }, indent=2)


def _grant_approval(artifact_id, approver):
    for entry in PENDING:
        if entry["artifact_id"] == artifact_id:
            entry["status"] = "approved"
            entry["approved_by"] = approver or "user"
            entry["approved_at"] = datetime.utcnow().isoformat() + "Z"
            AUDIT.append({**entry, "timestamp": entry["approved_at"], "action": "approved"})
            return json.dumps({
                "artifact_id": artifact_id,
                "status": "approved",
                "approved_by": entry["approved_by"],
                "message": f"Approval granted for {entry['tool']} against {entry['target']}",
            }, indent=2)
    return json.dumps({"error": f"No pending request: {artifact_id}"}, indent=2)


def _deny_approval(artifact_id, approver):
    for entry in PENDING:
        if entry["artifact_id"] == artifact_id:
            entry["status"] = "denied"
            entry["denied_by"] = approver or "user"
            entry["denied_at"] = datetime.utcnow().isoformat() + "Z"
            AUDIT.append({**entry, "timestamp": entry["denied_at"], "action": "denied"})
            return json.dumps({
                "artifact_id": artifact_id,
                "status": "denied",
                "denied_by": entry["denied_by"],
                "message": f"Approval denied for {entry['tool']} against {entry['target']}",
            }, indent=2)
    return json.dumps({"error": f"No pending request: {artifact_id}"}, indent=2)


def _list_pending():
    pending = [e for e in PENDING if e["status"] == "pending"]
    return json.dumps({
        "total_pending": len(pending),
        "requests": pending,
    }, indent=2)


def _audit_log():
    return json.dumps({
        "total_entries": len(AUDIT),
        "audit_log": AUDIT[-50:],
    }, indent=2)
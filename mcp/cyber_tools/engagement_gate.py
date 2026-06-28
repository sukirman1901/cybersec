"""Engagement gate — scope validation, authorization check, pre-flight approval rules."""
import json
import re
from datetime import datetime

def engagement_gate(action: str, target: str = "", scope_json: str = "", rule: str = "", confirmation: str = "") -> str:
    if action == "init":
        return _init_engagement(target, scope_json)
    elif action == "validate":
        return _validate_target(target, scope_json)
    elif action == "check":
        return _check_rule(rule, target)
    elif action == "add_rule":
        return _add_rule(rule, target)
    elif action == "authorize":
        return _authorize(confirmation, target, scope_json)
    elif action == "status":
        return _status()
    else:
        return json.dumps({"error": "Unknown action", "actions": ["init", "validate", "check", "add_rule", "authorize", "status"]}, indent=2)


ENGAGEMENT = {
    "active": False,
    "scope": {"domains": [], "ips": [], "networks": [], "authorized": False},
    "rules": [
        {"type": "no_exploit", "description": "No exploitation without explicit approval"},
        {"type": "scope_boundary", "description": "Only test targets within defined scope"},
        {"type": "no_dos", "description": "No denial of service attacks"},
        {"type": "rate_limit", "description": "Respect rate limits — max 50 req/s"},
        {"type": "evidence", "description": "Document all findings with evidence"},
    ],
    "approved_at": "",
    "approved_by": "",
}


def _init_engagement(target, scope_json):
    ENGAGEMENT["active"] = True
    if scope_json:
        try:
            scope = json.loads(scope_json) if isinstance(scope_json, str) else scope_json
            ENGAGEMENT["scope"].update(scope)
        except Exception:
            pass
    if target:
        ENGAGEMENT["scope"]["domains"].append(target)
    return json.dumps({
        "status": "engagement_initialized",
        "scope": ENGAGEMENT["scope"],
        "rules": ENGAGEMENT["rules"],
        "message": "Engagement scope set. All targets must pass validate() before testing.",
    }, indent=2)


def _validate_target(target, scope_json):
    scope = ENGAGEMENT["scope"]
    if scope_json:
        try:
            scope = json.loads(scope_json) if isinstance(scope_json, str) else scope_json
        except Exception:
            pass

    checks = {"in_scope": False, "authorized": False, "violations": []}

    domains = scope.get("domains", [])
    ips = scope.get("ips", [])
    networks = scope.get("networks", [])

    # Domain check
    for d in domains:
        if d in target or target.endswith("." + d.lstrip(".")):
            checks["in_scope"] = True
            break

    # IP check
    for ip in ips:
        if ip in target:
            checks["in_scope"] = True
            break

    # Network check (basic CIDR)
    for net in networks:
        if net in target:
            checks["in_scope"] = True
            break

    if not checks["in_scope"]:
        checks["violations"].append(f"Target {target} not in scope: domains={domains}, ips={ips}")

    checks["authorized"] = ENGAGEMENT["scope"].get("authorized", False) and checks["in_scope"]
    if not checks["authorized"] and checks["in_scope"]:
        checks["violations"].append("Target in scope but not authorized. Run authorize() first.")

    return json.dumps({
        "target": target,
        "validated": checks["in_scope"] and checks["authorized"],
        "checks": checks,
    }, indent=2)


def _check_rule(rule, target):
    for r in ENGAGEMENT["rules"]:
        if r["type"] == rule:
            return json.dumps({"rule": r, "approved": True, "note": f"Rule '{rule}' applies to {target}"}, indent=2)
    return json.dumps({"error": f"Rule not found: {rule}"}, indent=2)


def _add_rule(rule, description):
    ENGAGEMENT["rules"].append({"type": rule, "description": description or rule})
    return json.dumps({"status": "rule_added", "rule": rule, "total_rules": len(ENGAGEMENT["rules"])}, indent=2)


def _authorize(confirmation, target, scope_json):
    valid_words = ["yes", "y", "approve", "authorized", "confirmed", "true"]
    if confirmation.lower() not in valid_words:
        return json.dumps({
            "status": "not_authorized",
            "required": "Explicit confirmation required: authorize(confirmation='yes', ...)",
            "scope": scope_json or "use default scope",
        }, indent=2)

    ENGAGEMENT["scope"]["authorized"] = True
    ENGAGEMENT["approved_at"] = datetime.utcnow().isoformat() + "Z"
    ENGAGEMENT["approved_by"] = "user"
    return json.dumps({
        "status": "authorized",
        "message": "Engagement authorized. Ensure all testing stays within defined scope.",
        "scope": ENGAGEMENT["scope"],
        "approved_at": ENGAGEMENT["approved_at"],
    }, indent=2)


def _status():
    return json.dumps({
        "active": ENGAGEMENT["active"],
        "scope": ENGAGEMENT["scope"],
        "rules_active": len(ENGAGEMENT["rules"]),
        "authorized": ENGAGEMENT["scope"].get("authorized", False),
        "approved_at": ENGAGEMENT["approved_at"] or "not yet approved",
    }, indent=2)
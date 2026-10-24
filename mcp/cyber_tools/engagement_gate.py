"""Engagement scope and intent, isolated by MCP session at dispatch.

Confirmation records client intent; it is not proof of external legal authority.
"""
import copy
import ipaddress
import json
import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from urllib.parse import urlsplit

RESOURCE_KINDS = ("providers", "buckets", "companies", "repositories")


def new_engagement():
    return {
        "active": False,
        "scope": {"domains": [], "ips": [], "networks": [],
                  **{kind: [] for kind in RESOURCE_KINDS}, "authorized": False},
        "rules": [
            {"type": "no_exploit", "description": "No exploitation without explicit approval"},
            {"type": "scope_boundary", "description": "Only test targets within defined scope"},
            {"type": "no_dos", "description": "No denial of service attacks"},
            {"type": "rate_limit", "description": "Respect engagement rate limits"},
            {"type": "evidence", "description": "Document all findings with evidence"},
        ],
        "approved_at": "", "approved_by": "",
    }


# Direct Python callers retain a process-local default; MCP binds a separate state.
ENGAGEMENT = new_engagement()
_CURRENT = ContextVar("cybersec_engagement", default=None)


def current_engagement():
    state = _CURRENT.get()
    return ENGAGEMENT if state is None else state


@contextmanager
def engagement_context(state):
    token = _CURRENT.set(state)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def target_host(target):
    """Canonical hostname/IP only; never match URL paths, userinfo or substrings."""
    if not isinstance(target, str) or not target or any(c.isspace() for c in target):
        raise ValueError("Expected one hostname, IP or URL")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    parsed = urlsplit(target if "://" in target else "//" + target)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Userinfo is not permitted in scoped targets")
    host = parsed.hostname
    _ = parsed.port  # Reject malformed ports rather than accepting a partial host.
    if not host:
        raise ValueError("Missing target hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        if not host or any(not part or not all(c.isalnum() or c == "-" for c in part)
                           for part in host.split(".")):
            raise ValueError("Invalid hostname")
        return host


def _parse_scope(raw):
    raw = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(raw, dict):
        raise ValueError("Scope must be an object")
    scope = new_engagement()["scope"]
    for key in ("domains", "ips", "networks", *RESOURCE_KINDS):
        values = raw.get(key, [])
        if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
            raise ValueError(f"{key} must be a list of nonempty strings")
        for value in values:
            if key == "domains":
                scope[key].append(target_host(value.removeprefix("*.")))
            elif key == "ips":
                scope[key].append(str(ipaddress.ip_address(value)))
            elif key == "networks":
                scope[key].append(str(ipaddress.ip_network(value, strict=False)))
            else:
                scope[key].append(resource_identity(key, value))
    return scope


def resource_identity(kind, value):
    """Normalize non-host resource identifiers without accepting URL injection."""
    if not isinstance(value, str):
        raise ValueError(f"{kind} identifiers must be strings")
    value = value.lower()
    patterns = {
        "providers": r"aws|gcp|azure",
        "buckets": r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",
        "companies": r"[a-z0-9][a-z0-9-]{0,62}",
        "repositories": r"[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+",
    }
    if kind not in patterns or not re.fullmatch(patterns[kind], value) or ".." in value:
        raise ValueError(f"Invalid {kind} resource identifier")
    return value


def validate_resource(kind, value):
    state = current_engagement()
    try:
        value = resource_identity(kind, value)
    except ValueError:
        return False
    return bool(state["active"] and state["scope"]["authorized"] and
                value in state["scope"].get(kind, []))


def _matches(host, scope):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return (host in scope["ips"] or host in scope["domains"] or
                any(ip in ipaddress.ip_network(net) for net in scope["networks"]))
    return any(host == domain or host.endswith("." + domain) for domain in scope["domains"])


def validate_target(target, scope_json=""):
    state = current_engagement()
    checks = {"in_scope": False, "authorized": False, "violations": []}
    try:
        host = target_host(target)
        checks["in_scope"] = state["active"] and _matches(host, state["scope"])
        if scope_json:
            # A per-call scope can narrow, never widen, the authorized engagement.
            checks["in_scope"] = checks["in_scope"] and _matches(host, _parse_scope(scope_json))
    except (ValueError, TypeError, UnicodeError) as error:
        checks["violations"].append(str(error))
    if not checks["in_scope"]:
        checks["violations"].append("Target is not in the active engagement scope")
    checks["authorized"] = bool(state["scope"]["authorized"] and checks["in_scope"])
    if checks["in_scope"] and not checks["authorized"]:
        checks["violations"].append("Explicit engagement authorization is required")
    return {"target": target, "validated": checks["authorized"], "checks": checks}


def engagement_gate(action: str, target: str = "", scope_json: str = "",
                    rule: str = "", confirmation: str = "") -> str:
    state = current_engagement()
    if action == "init":
        # Reinitialization revokes previous authorization even if input is invalid.
        state.clear()
        state.update(new_engagement())
        try:
            scope = _parse_scope(scope_json) if scope_json else state["scope"]
            if target:
                scope["domains"].append(target_host(target))
        except (ValueError, TypeError, UnicodeError) as error:
            return json.dumps({"error": f"Invalid scope: {error}", "authorized": False})
        state["scope"] = scope
        state["active"] = True
        result = {"status": "engagement_initialized", "scope": scope,
                  "rules": state["rules"], "message": "Authorize the new scope before testing."}
    elif action == "validate":
        result = validate_target(target, scope_json)
    elif action == "authorize":
        if confirmation.lower() not in ("yes", "y", "approve", "authorized", "confirmed", "true"):
            result = {"status": "not_authorized", "required": "Explicit confirmation required"}
        elif not state["active"] or not any(state["scope"][k] for k in ("domains", "ips", "networks", *RESOURCE_KINDS)):
            result = {"status": "not_authorized", "error": "Initialize a nonempty scope first"}
        else:
            state["scope"]["authorized"] = True
            state["approved_at"] = datetime.now(timezone.utc).isoformat()
            state["approved_by"] = "client-confirmation"
            result = {"status": "authorized", "scope": state["scope"], "approved_at": state["approved_at"]}
    elif action == "extend":
        if not state["active"] or not state["scope"]["authorized"]:
            result = {"error": "Extend requires an initialized and authorized engagement; "
                               "call init and authorize first"}
        elif confirmation.lower() not in ("yes", "y", "approve", "authorized", "confirmed", "true"):
            result = {"error": "Extending the engagement scope is a new authorization decision; "
                               "resend the extend call with confirmation='yes'"}
        elif not scope_json:
            result = {"error": "extend requires scope_json with the additional resources"}
        else:
            try:
                added_scope = _parse_scope(scope_json)
            except (ValueError, TypeError, UnicodeError) as error:
                result = {"error": f"Invalid scope extension: {error}"}
            else:
                added = []
                for kind in ("domains", "ips", "networks", *RESOURCE_KINDS):
                    values = added_scope.get(kind, [])
                    existing = state["scope"].setdefault(kind, [])
                    for value in values:
                        if value not in existing:
                            existing.append(value)
                            added.append(f"{kind}:{value}")
                state["approved_at"] = datetime.now(timezone.utc).isoformat()
                state["approved_by"] = "client-confirmation"
                result = {"status": "extended", "added": added,
                          "scope": copy.deepcopy(state["scope"]),
                          "approved_at": state["approved_at"]}
    elif action == "check":
        item = next((r for r in state["rules"] if r["type"] == rule), None)
        result = ({"rule": item, "applies": True, "note": "Rule presence does not grant approval"}
                  if item else {"error": f"Rule not found: {rule}"})
    elif action == "add_rule":
        state["rules"].append({"type": rule, "description": target or rule})
        result = {"status": "rule_added", "rule": rule, "total_rules": len(state["rules"])}
    elif action == "status":
        result = {"active": state["active"], "scope": copy.deepcopy(state["scope"]),
                  "rules_active": len(state["rules"]), "authorized": state["scope"]["authorized"],
                  "approved_at": state["approved_at"] or "not yet approved"}
    else:
        result = {"error": "Unknown action", "actions": ["init", "validate", "extend", "check", "add_rule", "authorize", "status"]}
    return json.dumps(result, indent=2)

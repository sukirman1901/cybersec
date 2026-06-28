"""Session verification — validate session cookies, tokens, expiry before testing."""
import json
import re
import time
from datetime import datetime

def session_verification(action: str, session_data: str = "", session_type: str = "cookie", target: str = "") -> str:
    if action == "verify":
        return _verify_session(session_data, session_type, target)
    elif action == "analyze":
        return _analyze_session(session_data, session_type)
    elif action == "refresh":
        return _refresh_session(session_data, session_type, target)
    elif action == "expiry":
        return _check_expiry(session_data, session_type)
    else:
        return json.dumps({"error": "Unknown action", "actions": ["verify", "analyze", "refresh", "expiry"]}, indent=2)


SESSION_STORE = {}


def _verify_session(session_data, session_type, target):
    if not session_data:
        return json.dumps({"valid": False, "error": "No session data provided"}, indent=2)

    issues = []
    score = 100

    if session_type == "cookie":
        # Check basic cookie format
        parts = session_data.split("=")
        if len(parts) < 2:
            issues.append("Invalid cookie format (missing key=value)")
            score -= 50
        else:
            key = parts[0].strip()
            value = "=".join(parts[1:])
            if len(key) == 0:
                issues.append("Empty cookie name")
                score -= 20
            if len(value) == 0:
                issues.append("Empty cookie value")
                score -= 30

        # Check for session-like patterns
        session_patterns = [
            (r'session|token|jwt|sid|auth|identity|credentials?', 'Session-like name found'),
            (r'^[A-Za-z0-9_-]{20,}$', 'Long alphanumeric value (likely session token)'),
            (r'^[A-Fa-f0-9]{32}$', 'MD5-hash cookie (session fixation risk)'),
            (r'^[A-Za-z0-9+/]{20,}={0,2}$', 'Base64-encoded cookie'),
        ]
        for pat, desc in session_patterns:
            if re.search(pat, session_data, re.I):
                pass  # Expected pattern

        # Security flags
        if "httponly" not in session_data.lower() and "HttpOnly" not in session_data:
            issues.append("No HttpOnly flag — JS can access cookie (XSS risk)")
            score -= 15
        if "secure" not in session_data.lower() and "Secure" not in session_data:
            issues.append("No Secure flag — cookie sent over HTTP")
            score -= 15
        if "samesite" not in session_data.lower() and "SameSite" not in session_data:
            issues.append("No SameSite attribute — CSRF risk")
            score -= 10
        if "path=/" not in session_data:
            issues.append("Cookie path not set to '/' — may not apply to all endpoints")
            score -= 5

    elif session_type == "jwt":
        parts = session_data.split(".")
        if len(parts) == 3:
            header, payload, sig = parts
            try:
                hdr = json.loads(_b64decode(header))
                pay = json.loads(_b64decode(payload))
                if hdr.get("alg") == "none":
                    issues.append("JWT alg='none' — authentication bypass risk")
                    score -= 40
                if not sig or len(sig) < 10:
                    issues.append("JWT has no/weak signature")
                    score -= 30
                exp = pay.get("exp", 0)
                if exp and exp < time.time():
                    issues.append("JWT expired")
                    score -= 20
                return json.dumps({
                    "valid": score > 50,
                    "score": max(0, score),
                    "type": "JWT",
                    "header": hdr,
                    "payload": pay,
                    "issues": issues,
                }, indent=2)
            except Exception:
                issues.append("Invalid JWT format")
                score -= 50
        else:
            issues.append("Invalid JWT — expected 3 parts (header.payload.signature)")
            score -= 50

    elif session_type == "bearer":
        if not session_data.startswith("Bearer ") and not session_data.startswith("bearer "):
            issues.append("Missing 'Bearer ' prefix")
            score -= 20
        token = session_data.replace("Bearer ", "").replace("bearer ", "")
        if len(token) < 10:
            issues.append("Bearer token too short")
            score -= 25

    elif session_type == "basic":
        if "Basic " not in session_data and "basic " not in session_data:
            issues.append("Missing 'Basic ' prefix")
            score -= 20

    elif session_type == "api_key":
        if len(session_data) < 10:
            issues.append("API key too short")
            score -= 15

    if target:
        SESSION_STORE[target] = {
            "data": session_data,
            "type": session_type,
            "verified_at": datetime.utcnow().isoformat() + "Z",
            "issues": issues,
            "score": max(0, score),
        }

    return json.dumps({
        "valid": score > 50,
        "score": max(0, score),
        "type": session_type,
        "issues": issues,
        "recommendation": "Session appears valid" if score > 70 else "Review session issues before testing",
    }, indent=2)


def _analyze_session(session_data, session_type):
    analysis = {"type": session_type, "length": len(session_data), "patterns": []}
    if re.search(r'^[A-Za-z0-9_-]{20,}$', session_data):
        analysis["patterns"].append("Random token (likely secure)")
    if re.search(r'user|admin|test|demo', session_data, re.I):
        analysis["patterns"].append("Contains predictable word — may be guessable")
    if re.search(r'^[0-9]+$', session_data):
        analysis["patterns"].append("Numeric only — easily guessable")
    return json.dumps(analysis, indent=2)


def _refresh_session(session_data, session_type, target):
    return json.dumps({
        "status": "refresh_initiated",
        "message": "Session refresh simulation. In real usage, call the auth endpoint to get new credentials.",
        "old_type": session_type,
        "target": target or "unknown",
    }, indent=2)


def _check_expiry(session_data, session_type):
    if session_type == "jwt":
        parts = session_data.split(".")
        if len(parts) == 3:
            try:
                pay = json.loads(_b64decode(parts[1]))
                exp = pay.get("exp", 0)
                iat = pay.get("iat", 0)
                now = time.time()
                return json.dumps({
                    "expires_at": datetime.utcfromtimestamp(exp).isoformat() + "Z" if exp else "unknown",
                    "issued_at": datetime.utcfromtimestamp(iat).isoformat() + "Z" if iat else "unknown",
                    "expired": exp < now if exp else "no_expiry",
                    "time_remaining_seconds": max(0, int(exp - now)) if exp else "unknown",
                }, indent=2)
            except Exception:
                pass
    return json.dumps({
        "note": "Expiry check only supports JWT tokens with 'exp' claim",
        "type": session_type,
    }, indent=2)


def _b64decode(data):
    try:
        padded = data + "=" * (4 - len(data) % 4)
        import base64
        return base64.urlsafe_b64decode(padded).decode()
    except Exception:
        return "{}"
"""Decode and analyze a JWT token for security issues."""

import json
import base64


async def jwt_analyze(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT — expected 3 parts", "token": token[:80]}

    try:
        h = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)))
        p = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4)))
    except Exception as e:
        return {"error": f"Decode failed: {e}", "token": token[:80]}

    issues = []
    if h.get("alg") == "none":
        issues.append({"severity": "critical", "issue": "Algorithm is 'none'"})
    if h.get("alg") == "HS256":
        issues.append({"severity": "high", "issue": "HMAC HS256 — potential confusion attack"})
    if not p.get("exp"):
        issues.append({"severity": "medium", "issue": "No expiration (exp) claim"})
    if not p.get("iat"):
        issues.append({"severity": "low", "issue": "No issued-at (iat) claim"})

    return {"header": h, "payload": p, "signature": parts[2][:20] + "...", "issues": issues, "issues_count": len(issues)}

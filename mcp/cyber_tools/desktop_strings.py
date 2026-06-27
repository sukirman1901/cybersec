import os
import re

SECRET_PATTERNS = [
    (r'api[_-]?key[\s=:]+["\']?([A-Za-z0-9_\-]{16,64})["\']?', 'API Key'),
    (r'token[\s=:]+["\']?([A-Za-z0-9_\-\.]{16,128})["\']?', 'Token'),
    (r'password[\s=:]+["\']?([^"\'\s]{6,})["\']?', 'Password'),
    (r'secret[\s=:]+["\']?([A-Za-z0-9_\-]{8,64})["\']?', 'Secret'),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'https?://[^\s"\']+', 'URL'),
    (r'(?:\d{1,3}\.){3}\d{1,3}', 'IP Address'),
]


async def desktop_strings(path: str, min_length: int = 6) -> dict:
    """Extract printable strings from desktop binaries — find secrets, API keys, URLs, IPs."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    with open(path, 'rb') as f:
        data = f.read()

    # Extract printable ASCII strings
    strings = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_length:
        strings.append(''.join(current))

    # Scan strings for secret patterns
    findings = []
    for s in strings[:5000]:
        for pattern, ptype in SECRET_PATTERNS:
            if re.search(pattern, s):
                findings.append({"type": ptype, "match": s[:120]})
                break

    risk = "HIGH" if len(findings) > 3 else "MEDIUM" if findings else "INFO"

    return {
        "path": path,
        "total_strings": len(strings),
        "findings": findings[:50],
        "total_findings": len(findings),
        "risk": risk,
    }

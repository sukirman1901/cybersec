"""Bounded, offline ASCII-string observations; never disclose matched values."""
import ipaddress
import os
import re
import stat

MAX_BYTES = 8 * 1024 * 1024
MAX_STRINGS = 5000
SECRET_PATTERNS = [
    (r'\bapi[_-]?key\b["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{16,64}', 'API Key'),
    (r'\btoken\b["\']?\s*[:=]\s*["\']?[A-Za-z0-9_.-]{16,128}', 'Token'),
    (r'\bpassword\b["\']?\s*[:=]\s*["\']?[^"\'\s]{6,}', 'Password'),
    (r'\bsecret\b["\']?\s*[:=]\s*["\']?[A-Za-z0-9_-]{8,64}', 'Secret'),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private Key'),
    (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Access Key'),
    (r'https?://[^\s"\']+', 'URL'),
    (r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', 'IP Address'),
]


async def desktop_strings(path: str, min_length: int = 6) -> dict:
    if not isinstance(path, str) or not os.path.isfile(path) or os.path.islink(path):
        return {"error": "Expected an existing regular file, not a symlink", "coverage_complete": False, "execution_status": "not_started"}
    if type(min_length) is not int or not 1 <= min_length <= 4096:
        return {"error": "min_length must be an integer from 1 to 4096", "coverage_complete": False, "execution_status": "not_started"}
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            return {"error": "Non-regular file or 8 MiB analysis limit exceeded", "coverage_complete": False, "execution_status": "not_started"}
        def open_regular(name, flags):
            return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with open(path, 'rb', opener=open_regular) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise OSError('File changed before open')
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return {"error": "File exceeds 8 MiB analysis limit", "coverage_complete": False, "execution_status": "partial"}
    except OSError:
        return {"error": "Unable to safely read artifact", "coverage_complete": False, "execution_status": "not_started"}
    findings = []
    total = 0
    truncated = False
    for match in re.finditer(rb'[ -~]+', data):
        if len(match[0]) < min_length:
            continue
        if total == MAX_STRINGS:
            truncated = True
            break
        total += 1
        if len(match[0]) > 4096:
            truncated = True
        text = match[0][:4096].decode('ascii')
        for pattern, kind in SECRET_PATTERNS:
            hits = list(re.finditer(pattern, text, re.IGNORECASE))
            if kind == 'IP Address':
                valid = []
                for hit in hits:
                    try:
                        ipaddress.IPv4Address(hit[0])
                        valid.append(hit)
                    except ValueError:
                        pass
                hits = valid
            if hits:
                findings.append({"type": kind, "match": "[REDACTED]", "offset": match.start(),
                                 "assessment": "observation" if kind in {'URL', 'IP Address'} else "candidate",
                                 "confidence": "medium", "coverage": "ASCII pattern only; credential validity and use not tested"})
    secret = any(f['assessment'] == 'candidate' for f in findings)
    complete = not truncated and len(findings) <= 50
    return {"path": path, "total_strings": total, "findings": findings[:50],
            "total_findings": len(findings), "risk": "MEDIUM" if secret else "UNKNOWN" if truncated else "INFO",
            "coverage_complete": complete, "execution_status": "completed" if complete else "partial",
            "coverage": {"bytes_read": len(data), "truncated": truncated or len(findings) > 50,
                         "limits": "8 MiB, 5000 ASCII runs, 4096 characters/run, 50 displayed findings; no UTF-16 extraction"}}

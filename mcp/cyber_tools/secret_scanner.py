import os
import re
import math

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'HIGH'),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END.*?KEY-----', 'Private Key', 'CRITICAL'),
    (r'gh[ps]_[0-9a-zA-Z]{36}', 'GitHub Token', 'CRITICAL'),
    (r'sk-[a-zA-Z0-9]{32,}', 'OpenAI API Key', 'HIGH'),
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', 'HIGH'),
    (r'(?i)token[\s:=]+["\']?([0-9a-zA-Z_\-\.]{16,64})["\']?', 'Generic Token', 'MEDIUM'),
    (r'(?i)password[\s:=]+["\']?([^\s"\']{8,})["\']?', 'Password', 'HIGH'),
]

EXTENSIONS = {
    '.py', '.js', '.ts', '.go', '.rs', '.java', '.php', '.rb',
    '.env', '.json', '.yml', '.yaml', '.ini', '.cfg', '.conf',
    '.sh', '.bash', '.txt',
}

SKIP_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.svn', '.hg', '.idea', '.vscode', 'dist', 'build', '.terraform',
}


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string — higher values suggest randomness/ secrets."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        p = data.count(char) / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


async def secret_scanner(path: str, min_entropy: float = 4.5) -> dict:
    """Scan a path for secrets using regex patterns and entropy analysis."""
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    files_scanned = 0
    findings = []
    target_files = []

    if os.path.isfile(path):
        target_files.append(path)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in EXTENSIONS:
                    target_files.append(os.path.join(root, f))
                    if len(target_files) >= 500:
                        break
            if len(target_files) >= 500:
                break

    for fpath in target_files:
        files_scanned += 1
        try:
            with open(fpath, 'r', errors='replace') as f:
                content = f.read()
        except Exception:
            continue

        if os.path.isdir(path):
            rel_path = os.path.relpath(fpath, path)
        else:
            rel_path = os.path.basename(path)

        for pattern, ptype, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                matched_text = match.group(0)
                ent = shannon_entropy(matched_text)
                if ent >= min_entropy:
                    findings.append({
                        "file": rel_path,
                        "type": ptype,
                        "severity": severity,
                        "match": matched_text[:50],
                        "entropy": round(ent, 2),
                    })

    secrets_found = len(findings)
    if secrets_found > 5:
        risk = "CRITICAL"
    elif secrets_found > 0:
        risk = "HIGH"
    else:
        risk = "LOW"

    return {
        "path": path,
        "files_scanned": files_scanned,
        "secrets_found": secrets_found,
        "findings": findings,
        "risk": risk,
    }

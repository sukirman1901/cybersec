import os
import re

# Sensitive config file patterns
SUSPICIOUS_FILENAMES = [
    '.env', '.env.local', '.env.production', '.env.development',
    'config.json', 'credentials.json', 'passwords.txt', 'secrets.txt',
    'secret.json', 'settings.json', 'config.php', 'config.py',
    'database.yml', 'database.json', 'db.config', 'db.conf',
    'wp-config.php', '.ftpconfig', 'id_rsa', 'id_dsa',
    'terraform.tfvars', 'credentials.ini', 'tokens.txt', 'key.pem',
    'cert.pem', 'private.pem', 'appsettings.json',
]

SUSPICIOUS_DIRECTORIES = [
    '.config', '.aws', '.gcp', '.azure', '.ssh',
    'config', 'credentials', 'secrets',
]

SECRET_REGEX = re.compile(
    r'(password|secret|token|api[_-]?key|access[_-]?key|auth[_-]?token'
    r'|private[_-]?key|bearer|jwt|client[_-]?secret)[\s=:]+["\']?'
    r'([^"\'\s]{6,})["\']?',
    re.IGNORECASE
)


def _is_suspicious_filename(name: str) -> bool:
    """Check if a filename matches known sensitive config patterns."""
    for pattern in SUSPICIOUS_FILENAMES:
        if name.lower() == pattern.lower():
            return True
    return False


def _should_skip_dir(name: str) -> bool:
    """Skip common non-target directories."""
    skips = {'.git', '__pycache__', 'node_modules', '.venv', 'venv',
             '.svn', '.hg', '.idea', '.vscode', 'dist', 'build'}
    return name in skips


async def desktop_config(path: str, recursive: bool = True) -> dict:
    """Scan for exposed config files and saved credentials in desktop apps."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    findings = []
    files_scanned = 0

    if os.path.isfile(path):
        files_scanned = 1
        try:
            with open(path, 'r', errors='replace') as f:
                content = f.read()
            secrets = SECRET_REGEX.findall(content)
            if secrets:
                findings.append({
                    "file": os.path.basename(path),
                    "secrets_found": len(secrets),
                    "samples": [s[0] + ': ' + s[1][:40] for s in secrets[:5]],
                })
        except Exception:
            pass
    elif os.path.isdir(path):
        if recursive:
            for root, dirs, files in os.walk(path):
                # Skip non-target directories
                dirs[:] = [d for d in dirs if not _should_skip_dir(d)]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    rel_path = os.path.relpath(fpath, path)
                    files_scanned += 1
                    if _is_suspicious_filename(fname):
                        try:
                            with open(fpath, 'r', errors='replace') as f:
                                content = f.read()
                            secrets = SECRET_REGEX.findall(content)
                            if secrets:
                                findings.append({
                                    "file": rel_path,
                                    "secrets_found": len(secrets),
                                    "samples": [s[0] + ': ' + s[1][:40] for s in secrets[:5]],
                                })
                            else:
                                # File matched by name but no secrets in content
                                findings.append({
                                    "file": rel_path,
                                    "secrets_found": 0,
                                    "note": "Sensitive filename — review manually",
                                })
                        except Exception:
                            findings.append({
                                "file": rel_path,
                                "error": "Could not read file",
                            })
        else:
            for fname in os.listdir(path):
                fpath = os.path.join(path, fname)
                if not os.path.isfile(fpath):
                    continue
                files_scanned += 1
                if _is_suspicious_filename(fname):
                    try:
                        with open(fpath, 'r', errors='replace') as f:
                            content = f.read()
                        secrets = SECRET_REGEX.findall(content)
                        if secrets:
                            findings.append({
                                "file": fname,
                                "secrets_found": len(secrets),
                                "samples": [s[0] + ': ' + s[1][:40] for s in secrets[:5]],
                            })
                        else:
                            findings.append({
                                "file": fname,
                                "secrets_found": 0,
                                "note": "Sensitive filename — review manually",
                            })
                    except Exception:
                        findings.append({
                            "file": fname,
                            "error": "Could not read file",
                        })

    risk = "HIGH" if len(findings) > 0 else "INFO"

    return {
        "path": path,
        "files_scanned": files_scanned,
        "findings": findings,
        "total_findings": len(findings),
        "risk": risk,
    }

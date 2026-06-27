import os
import re

DANGEROUS_PATTERNS = {
    "Python": [
        (r'\beval\s*\(', 'eval() — arbitrary code execution', 'CRITICAL'),
        (r'\bexec\s*\(', 'exec() — arbitrary code execution', 'CRITICAL'),
        (r'\b__import__\s*\(', '__import__() — dynamic import', 'HIGH'),
        (r'\bpickle\.loads?\s*\(', 'pickle deserialization — RCE risk', 'CRITICAL'),
        (r'\bsubprocess\.(call|Popen|run)\s*\(', 'subprocess execution — command injection risk', 'HIGH'),
        (r'\bos\.system\s*\(', 'os.system() — command injection risk', 'HIGH'),
        (r'\binput\s*\(', 'input() — code injection in Python 2', 'MEDIUM'),
        (r'(?i)(execute|cursor\.execute|db\.execute)\s*\(\s*["\']\s*SELECT',
         'Raw SQL construction — SQL injection risk', 'HIGH'),
        (r'(?i)render_template_string\s*\(', 'Template injection — SSTI risk', 'HIGH'),
    ],
    "JavaScript/TypeScript": [
        (r'\beval\s*\(', 'eval() — arbitrary code execution', 'CRITICAL'),
        (r'new\s+Function\s*\(', 'Function() — eval-like code execution', 'CRITICAL'),
        (r'\binnerHTML\s*=', 'innerHTML assignment — XSS risk', 'HIGH'),
        (r'\bdocument\.write\s*\(', 'document.write() — XSS risk', 'HIGH'),
        (r'require\s*\(\s*["\']child_process["\']\s*\)',
         'require(child_process) — shell access', 'CRITICAL'),
        (r'\bexec\s*\(', 'exec() — shell command execution', 'CRITICAL'),
    ],
}

EXTENSIONS_SAST = {'.py', '.js', '.ts', '.jsx', '.tsx'}
SKIP_DIRS_SAST = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.svn', '.hg', '.idea', '.vscode', 'dist', 'build',
}


def _get_language(ext: str) -> str:
    """Map file extension to language group."""
    if ext == '.py':
        return 'Python'
    return 'JavaScript/TypeScript'


async def sast_review(path: str) -> dict:
    """Scan source code for dangerous patterns (eval, exec, deserialization, SQLi, XSS)."""
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    files_scanned = 0
    findings = []

    def _scan_file(fpath: str, rel_path: str) -> None:
        """Scan a single file for dangerous patterns."""
        nonlocal files_scanned
        ext = os.path.splitext(fpath)[1].lower()
        if ext not in EXTENSIONS_SAST:
            return
        files_scanned += 1
        try:
            with open(fpath, 'r', errors='replace') as fh:
                lines = fh.readlines()
        except Exception:
            return

        lang = _get_language(ext)
        patterns = DANGEROUS_PATTERNS.get(lang, [])
        for i, line in enumerate(lines, 1):
            for pattern, issue, severity in patterns:
                if re.search(pattern, line):
                    findings.append({
                        "file": rel_path,
                        "line": i,
                        "language": lang,
                        "issue": issue,
                        "severity": severity,
                        "match": line.strip()[:60],
                    })

    if os.path.isfile(path):
        _scan_file(path, os.path.basename(path))
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS_SAST]
            for f in files:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, path)
                _scan_file(fpath, rel_path)

    total_findings = len(findings)
    if total_findings > 10:
        risk = "CRITICAL"
    elif total_findings > 5:
        risk = "HIGH"
    elif total_findings > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "path": path,
        "files_scanned": files_scanned,
        "findings": findings,
        "total_findings": total_findings,
        "risk": risk,
    }

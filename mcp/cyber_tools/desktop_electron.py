import os
import subprocess
import re

# Insecure Electron patterns
INSECURE_PATTERNS = [
    (r'nodeIntegration\s*=\s*true', 'nodeIntegration enabled — exposes Node APIs to renderer'),
    (r'contextIsolation\s*=\s*false', 'contextIsolation disabled — renderer shares context with main'),
    (r'enableRemoteModule\s*=\s*true', 'enableRemoteModule enabled — dangerous remote module access'),
    (r'openDevTools\b', 'openDevTools in production — exposes debugger'),
    (r'shell\.openExternal\b', 'shell.openExternal used — open redirect / URL handling risk'),
    (r'webContents\.send\b', 'webContents.send in preload — IPC message sniffing possible'),
    (r'preload\s*:\s*[\'"]', 'Custom preload script — review for unsafe bridge APIs'),
]


async def desktop_electron(path: str) -> dict:
    """Analyze Electron app — ASAR unpack, preload inspection, IPC safety."""
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}

    is_asar = path.lower().endswith('.asar')
    content = ""

    if is_asar:
        # Try to extract ASAR using the `asar` CLI tool
        try:
            result = subprocess.run(
                ['asar', 'extract', path, '/tmp/_electron_scan'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return {
                    "path": path,
                    "is_asar": True,
                    "error": "Failed to extract ASAR — is the `asar` npm package installed?",
                    "stderr": result.stderr[:500],
                }
            # Walk extracted files
            insecure_findings = []
            for root, _dirs, files in os.walk('/tmp/_electron_scan'):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', errors='replace') as f:
                            content = f.read()
                        for pattern, desc in INSECURE_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                insecure_findings.append({
                                    "file": fname,
                                    "pattern": pattern,
                                    "description": desc,
                                })
                    except Exception:
                        pass
            # Cleanup
            subprocess.run(['rm', '-rf', '/tmp/_electron_scan'], capture_output=True)
        except FileNotFoundError:
            return {
                "path": path,
                "is_asar": True,
                "error": "`asar` CLI not found. Install with: npm install -g @electron/asar",
            }
    else:
        # Plain JS file
        try:
            with open(path, 'r', errors='replace') as f:
                content = f.read()
        except Exception as e:
            return {"path": path, "is_asar": False, "error": f"Failed to read file: {e}"}

        insecure_findings = []
        for pattern, desc in INSECURE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                insecure_findings.append({
                    "file": os.path.basename(path),
                    "pattern": pattern,
                    "description": desc,
                })

    risk = "HIGH" if len(insecure_findings) > 2 else "MEDIUM" if insecure_findings else "INFO"

    return {
        "path": path,
        "is_asar": is_asar,
        "insecure_findings": insecure_findings,
        "total_findings": len(insecure_findings),
        "risk": risk,
    }

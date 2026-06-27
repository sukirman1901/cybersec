"""
CLI tool wrappers — thin wrappers around external pentesting binaries.
Each function checks if the CLI is installed before running.
"""

import json
import shutil
import asyncio
from typing import Dict, Any


async def _run_cli(cmd: list, timeout: int = 120) -> Dict[str, Any]:
    """Run a CLI command and return structured result."""
    import datetime
    start = datetime.datetime.now()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "exit_code": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "duration": (datetime.datetime.now() - start).total_seconds(),
        }
    except asyncio.TimeoutError:
        return {"exit_code": -1, "stdout": "", "stderr": "timed out", "duration": timeout}


def _check(tool: str) -> bool:
    return shutil.which(tool) is not None


def _err(tool: str) -> Dict:
    return {
        "available": False,
        "error": f"'{tool}' CLI not found in PATH. Install it first.",
        "install_hint": {
            "nmap": "brew install nmap",
            "nikto": "brew install nikto",
            "sqlmap": "brew install sqlmap",
            "amass": "brew install amass",
            "masscan": "brew install masscan",
            "wpscan": "gem install wpscan",
            "gobuster": "brew install gobuster",
            "ffuf": "brew install ffuf",
            "xsstrike": "git clone https://github.com/s0md3v/XSStrike",
            "gitleaks": "brew install gitleaks",
            "cmseek": "git clone https://github.com/Tuhinshubhra/CMSeeK",
            "testssl": "brew install testssl",
            "sslyze": "pip install sslyze",
        }.get(tool, f"Install '{tool}' manually"),
    }


async def nikto_scan(target: str) -> Dict:
    """Web server vulnerability scanner using nikto CLI."""
    if not _check("nikto"):
        return _err("nikto")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["nikto", "-h", target])
    findings = []
    for line in r.get("stdout", "").split("\n"):
        if line.startswith("+") and ":" in line:
            findings.append(line.strip())
    return {"findings": findings, "count": len(findings), "available": True}


async def sqlmap_check(target: str, risk: int = 1, level: int = 1) -> Dict:
    """SQL injection detection using sqlmap CLI (safe mode)."""
    if not _check("sqlmap"):
        return _err("sqlmap")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["sqlmap", "-u", target, "--batch", "--risk", str(risk), "--level", str(level)])
    out = r.get("stdout", "") + r.get("stderr", "")
    vuln = "sqlmap identified the following injection point" in out
    return {
        "vulnerable": vuln,
        "details": out[:2000] if vuln else "No injection detected",
    }


async def amass_enum(target: str, passive: bool = True) -> Dict:
    """Attack surface mapping using amass CLI."""
    if not _check("amass"):
        return _err("amass")
    cmd = ["amass", "enum", "-d", target, "-json", "-"]
    if passive:
        cmd.append("-passive")
    r = await _run_cli(cmd)
    subs = []
    for line in r.get("stdout", "").strip().split("\n"):
        if line:
            try:
                d = json.loads(line)
                subs.append(d.get("name", ""))
            except json.JSONDecodeError:
                pass
    return {"subdomains": subs, "count": len(subs), "available": True}


async def wpscan_check(target: str) -> Dict:
    """WordPress vulnerability scanner using wpscan CLI."""
    if not _check("wpscan"):
        return _err("wpscan")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["wpscan", "--url", target, "--no-banner", "--format", "json"])
    try:
        data = json.loads(r.get("stdout", "{}"))
        return {
            "version": data.get("version", {}),
            "plugins": list(data.get("plugins", {}).keys()),
            "themes": list(data.get("themes", {}).keys()),
            "vulnerabilities": data.get("vulnerabilities", []),
        }
    except json.JSONDecodeError:
        return {"raw": r.get("stdout", "")[:1000]}


async def masscan_scan(target: str, ports: str = "80,443", rate: int = 1000) -> Dict:
    """Ultra-fast TCP port scanner using masscan CLI."""
    if not _check("masscan"):
        return _err("masscan")
    r = await _run_cli(["masscan", target, "-p", ports, "--rate", str(rate)])
    ports_found = []
    for line in r.get("stdout", "").split("\n"):
        if "open" in line and "tcp" in line:
            parts = line.strip().split()
            if len(parts) >= 4:
                ports_found.append({"port": parts[3], "protocol": parts[2], "ip": parts[5] if len(parts) > 5 else target})
    return {"open_ports": ports_found, "count": len(ports_found), "available": True}


async def xsstrike_check(target: str) -> Dict:
    """XSS detection using xsstrike CLI."""
    if not _check("xsstrike"):
        return _err("xsstrike")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["xsstrike", "-u", target, "--silent"])
    out = r.get("stdout", "")
    return {"vulnerable": "XSS" in out or "vulnerable" in out.lower(), "output": out[:1000]}


async def gitleaks_check(path: str) -> Dict:
    """Secret scanning in a git repository using gitleaks CLI."""
    if not _check("gitleaks"):
        return _err("gitleaks")
    r = await _run_cli(["gitleaks", "detect", "--source", path, "--no-git", "--report-format", "json"])
    try:
        leaks = json.loads(r.get("stdout", "[]"))
        if isinstance(leaks, dict):
            leaks = [leaks]
    except json.JSONDecodeError:
        leaks = []
    return {"leaks": leaks, "count": len(leaks), "available": True}


async def cmseek_check(target: str) -> Dict:
    """CMS detection using cmseek CLI."""
    if not _check("cmseek"):
        return _err("cmseek")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["cmseek", "-u", target])
    import re
    cms = None
    version = None
    for line in r.get("stdout", "").split("\n"):
        m = re.search(r"CMS Detected: (.*)", line)
        if m:
            cms = m.group(1).strip()
        m = re.search(r"CMS Version: (.*)", line)
        if m:
            version = m.group(1).strip()
    return {"cms": cms, "version": version, "available": cms is not None}


async def testssl_check(target: str, port: int = 443) -> Dict:
    """SSL/TLS server testing using testssl CLI."""
    if not _check("testssl"):
        return _err("testssl")
    r = await _run_cli(["testssl", "--quiet", "--jsonfile", "/dev/stdout", f"{target}:{port}"])
    findings = []
    for line in r.get("stdout", "").split("\n"):
        if line.strip():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return {"findings": findings, "count": len(findings), "available": True}


async def sslyze_check(target: str, port: int = 443) -> Dict:
    """Fast SSL/TLS scanning using sslyze CLI."""
    if not _check("sslyze"):
        return _err("sslyze")
    r = await _run_cli(["sslyze", "--json_out", "-", f"{target}:{port}"])
    try:
        data = json.loads(r.get("stdout", "{}"))
    except json.JSONDecodeError:
        data = {"raw": r.get("stdout", "")[:1000]}
    return data


async def gobuster_dir(target: str, wordlist: str = "") -> Dict:
    """Directory brute-forcing using gobuster CLI."""
    if not _check("gobuster"):
        return _err("gobuster")
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    r = await _run_cli(["gobuster", "dir", "-u", target, "-w", wordlist, "-q"])
    entries = []
    for line in r.get("stdout", "").split("\n"):
        if "(" in line and ")" in line:
            entries.append(line.strip())
    return {"entries": entries, "count": len(entries), "available": True}


async def ffuf_fuzz(target: str, wordlist: str = "") -> Dict:
    """Fast web fuzzing using ffuf CLI."""
    if not _check("ffuf"):
        return _err("ffuf")
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    r = await _run_cli(["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-o", "json", "-of", "json"])
    try:
        data = json.loads(r.get("stdout", "{}"))
        results = data.get("results", [])
    except json.JSONDecodeError:
        results = []
    return {"results": results, "count": len(results), "available": True}

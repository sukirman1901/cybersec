"""
CLI tool wrappers — thin wrappers around external pentesting binaries.
Each function checks if the CLI is installed before running.
"""

import json
import shutil
import asyncio
from typing import Dict, Any
from .tool_paths import isolated_cli


async def _run_cli(cmd: list, timeout: int = 120) -> Dict[str, Any]:
    """Run a CLI command and return structured result."""
    import datetime
    start = datetime.datetime.now()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        communication = asyncio.create_task(proc.communicate())
        stdout, stderr = await asyncio.wait_for(asyncio.shield(communication), timeout=timeout)
        result = {
            "exit_code": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "duration": (datetime.datetime.now() - start).total_seconds(),
        }
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
        stdout, stderr = await communication
        result = {"exit_code": -1, "stdout": stdout.decode(errors="replace"),
                  "stderr": "timed out; " + stderr.decode(errors="replace"), "duration": timeout}
    except OSError as exc:
        result = {"exit_code": -1, "stdout": "", "stderr": str(exc), "duration": 0}
    except asyncio.CancelledError:
        if proc is not None and proc.returncode is None:
            proc.kill()
        if proc is not None:
            await communication
        raise
    return result


def _check(tool: str) -> bool:
    return _which(tool) is not None


def _which(tool: str) -> str | None:
    for name in {"testssl": ["testssl", "testssl.sh"]}.get(tool, [tool]):
        path = shutil.which(name) or isolated_cli(name)
        if path:
            return path
    return None


def _err(tool: str) -> Dict:
    """Fail closed: missing CLI is not a clean scan."""
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
        "confidence": "LOW",
        "coverage": "cli_missing",
        "findings": [],
        "count": 0,
        "vulnerable": False,
        "ran": False,
        "coverage_complete": False,
        "execution_status": "not_started",
    }


def _stamp_ok(payload: Dict, tool: str, execution: Dict = None) -> Dict:
    out = dict(payload)
    out.setdefault("available", True)
    out.setdefault("ran", True)
    out.setdefault("confidence", "MEDIUM" if out.get("findings") or out.get("count") or out.get("vulnerable") else "LOW")
    out.setdefault("coverage", f"cli_ran={tool}")
    run = execution
    if run is not None:
        out["exit_code"] = run.get("exit_code")
        failed = run.get("exit_code") != 0 or bool(out.get("error"))
        out["coverage_complete"] = not failed
        out["execution_status"] = "error" if failed else "completed"
        if failed:
            out["error"] = run.get("stderr", "")[-1000:] or f"{tool} exited {run.get('exit_code')}"
            out["confidence"] = "LOW"
            out["coverage"] += "; incomplete"
            if out.get("details") == "No injection detected":
                out["details"] = "Scan incomplete; absence of injection not assessed"
    return out


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
    return _stamp_ok({"findings": findings, "count": len(findings)}, "nikto", r)


async def sqlmap_check(target: str, risk: int = 1, level: int = 1) -> Dict:
    """SQL injection detection using sqlmap CLI (safe mode)."""
    if not _check("sqlmap"):
        return _err("sqlmap")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["sqlmap", "-u", target, "--batch", "--risk", str(risk), "--level", str(level)])
    out = r.get("stdout", "") + r.get("stderr", "")
    vuln = "sqlmap identified the following injection point" in out
    return _stamp_ok({
        "vulnerable": vuln,
        "details": out[:2000] if vuln else "No injection detected",
        "confidence": "HIGH" if vuln else "MEDIUM",
        "coverage": "cli_ran=sqlmap; batch_safe_mode",
    }, "sqlmap", r)


async def amass_enum(target: str, passive: bool = True) -> Dict:
    """Attack surface mapping using amass CLI."""
    if not _check("amass"):
        return _err("amass")
    cmd = ["amass", "enum", "-d", target, "-silent"]
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
                import re
                # v5 silent output is text; admit only exact in-scope DNS names.
                for name in re.findall(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", line):
                    if name.lower() == target.lower() or name.lower().endswith('.' + target.lower()):
                        subs.append(name.lower())
    subs = sorted(set(subs))
    return _stamp_ok({"subdomains": subs, "count": len(subs)}, "amass", r)


async def wpscan_check(target: str) -> Dict:
    """WordPress vulnerability scanner using wpscan CLI."""
    if not _check("wpscan"):
        return _err("wpscan")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["wpscan", "--url", target, "--no-banner", "--format", "json"])
    try:
        data = json.loads(r.get("stdout", "{}"))
    except json.JSONDecodeError:
        return _stamp_ok({"error": "Invalid WPScan JSON", "raw": r.get("stdout", "")[:1000], "confidence": "LOW"}, "wpscan", r)
    vulns = list(data.get("vulnerabilities", []) or [])
    components = [("core", "wordpress", data.get("version") or {})]
    for kind in ("plugins", "themes"):
        components.extend((kind, name, value) for name, value in (data.get(kind) or {}).items())
    if isinstance(data.get("main_theme"), dict):
        components.append(("themes", data['main_theme'].get('slug', 'main_theme'), data['main_theme']))
    for kind, name, value in components:
        if isinstance(value, dict):
            for finding in value.get("vulnerabilities", []) or []:
                vulns.append({**finding, "component_type": kind, "component": name})
    if data.get("scan_aborted"):
        r = {**r, "exit_code": -1, "stderr": str(data['scan_aborted'])}
    return _stamp_ok({
        "version": data.get("version", {}),
        "plugins": list(data.get("plugins", {}).keys()),
        "themes": list(data.get("themes", {}).keys()),
        "vulnerabilities": vulns,
        "count": len(vulns),
    }, "wpscan", r)


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
    return _stamp_ok({"open_ports": ports_found, "count": len(ports_found)}, "masscan", r)


async def xsstrike_check(target: str) -> Dict:
    """XSS detection using xsstrike CLI."""
    if not _check("xsstrike"):
        return _err("xsstrike")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli(["xsstrike", "-u", target, "--silent"])
    out = r.get("stdout", "")
    vuln = "XSS" in out or "vulnerable" in out.lower()
    return _stamp_ok({
        "vulnerable": vuln, "output": out[:1000],
        "confidence": "MEDIUM" if vuln else "LOW",
    }, "xsstrike", r)


async def gitleaks_check(path: str) -> Dict:
    """Secret scanning in a git repository using gitleaks CLI."""
    if not _check("gitleaks"):
        return _err("gitleaks")
    r = await _run_cli(["gitleaks", "detect", "--source", path, "--no-git", "--report-format", "json",
                        "--report-path", "-", "--exit-code", "0", "--redact", "--no-banner"])
    try:
        leaks = json.loads(r.get("stdout", "[]"))
        if isinstance(leaks, dict):
            leaks = [leaks]
    except json.JSONDecodeError:
        leaks = []
        r = {**r, 'exit_code': -1, 'stderr': 'Invalid gitleaks JSON; ' + r.get('stderr', '')}
    return _stamp_ok({"leaks": leaks, "count": len(leaks)}, "gitleaks", r)


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
    return _stamp_ok({"cms": cms, "version": version}, "cmseek", r)


async def testssl_check(target: str, port: int = 443) -> Dict:
    """SSL/TLS server testing using testssl CLI."""
    if not _check("testssl"):
        return _err("testssl")
    r = await _run_cli([_which("testssl"), "--quiet", "--jsonfile", "/dev/stdout", f"{target}:{port}"])
    try:
        data = json.loads(r.get('stdout', ''))
        findings = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        findings = []
        r = {**r, 'exit_code': -1, 'stderr': 'Invalid testssl JSON; ' + r.get('stderr', '')}
    return _stamp_ok({"findings": findings, "count": len(findings)}, "testssl", r)


async def sslyze_check(target: str, port: int = 443) -> Dict:
    """Fast SSL/TLS scanning using sslyze CLI."""
    if not _check("sslyze"):
        return _err("sslyze")
    r = await _run_cli([_which("sslyze"), "--json_out", "-", f"{target}:{port}"])
    try:
        data = json.loads(r.get("stdout", "{}"))
    except json.JSONDecodeError:
        data = {"raw": r.get("stdout", "")[:1000]}
    return _stamp_ok(data if isinstance(data, dict) else {"raw": data}, "sslyze", r)


async def gobuster_dir(target: str, wordlist: str = "") -> Dict:
    """Directory brute-forcing using gobuster CLI."""
    if not _check("gobuster"):
        return _err("gobuster")
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    import os
    if not os.path.isfile(wordlist):
        return {'error': 'Wordlist not found; supply an explicit installed wordlist', 'ran': False, 'coverage_complete': False}
    r = await _run_cli(["gobuster", "dir", "-u", target, "-w", wordlist, "-q"])
    entries = []
    for line in r.get("stdout", "").split("\n"):
        if "(" in line and ")" in line:
            entries.append(line.strip())
    return _stamp_ok({"entries": entries, "count": len(entries)}, "gobuster", r)


async def ffuf_fuzz(target: str, wordlist: str = "") -> Dict:
    """Fast web fuzzing using ffuf CLI."""
    if not _check("ffuf"):
        return _err("ffuf")
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    import os
    if not os.path.isfile(wordlist):
        return {'error': 'Wordlist not found; supply an explicit installed wordlist', 'ran': False, 'coverage_complete': False}
    r = await _run_cli(["ffuf", "-u", f"{target.rstrip('/')}/FUZZ", "-w", wordlist, "-json"])
    results = []
    try:
        for line in r.get('stdout', '').splitlines():
            if line.strip():
                results.append(json.loads(line))
    except json.JSONDecodeError:
        r = {**r, 'exit_code': -1, 'stderr': 'Invalid ffuf JSONL; ' + r.get('stderr', '')}
    return _stamp_ok({"results": results, "count": len(results)}, "ffuf", r)

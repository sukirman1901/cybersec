"""
CLI tool wrappers — thin wrappers around external pentesting binaries.
Each function checks if the CLI is installed before running.
"""

import json
import shutil
import asyncio
import ipaddress
import re
import os
import signal
import time
from typing import Dict, Any
from .tool_paths import isolated_cli


MAX_OUTPUT_BYTES = 2 * 1024 * 1024


async def _run_cli(cmd: list, timeout: int = 120) -> Dict[str, Any]:
    """Collect at most 2 MiB across both streams; terminate incomplete children."""
    start = time.monotonic()
    proc = None
    buffers = [bytearray(), bytearray()]
    tasks = []
    error_kind = ''
    cleanup_complete = True
    cancelled = False

    class OutputLimit(Exception):
        pass

    async def collect(stream, index):
        while True:
            chunk = await stream.read(16384)
            if not chunk:
                return
            remaining = MAX_OUTPUT_BYTES - sum(map(len, buffers))
            buffers[index].extend(chunk[:remaining])
            if len(chunk) > remaining:
                raise OutputLimit()

    async def stop():
        nonlocal cleanup_complete
        if proc is None:
            return
        # A child may have exited while descendants still hold its output pipes.
        if os.name == 'posix':
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_complete = False
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        async def discard(stream):
            # Resume paused pipe readers after termination without retaining bytes.
            while await stream.read(16384):
                pass
        try:
            await asyncio.wait_for(asyncio.gather(discard(proc.stdout), discard(proc.stderr), proc.wait()), timeout=2)
        except asyncio.TimeoutError:
            cleanup_complete = False
            # Last-resort pipe release for descendants outside the owned group.
            transport = getattr(proc, '_transport', None)
            if transport is not None:
                transport.close()
            try:
                await asyncio.wait_for(proc.wait(), timeout=.5)
            except asyncio.TimeoutError:
                pass

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=os.name == 'posix',
        )
        tasks = [asyncio.create_task(collect(proc.stdout, 0)),
                 asyncio.create_task(collect(proc.stderr, 1)),
                 asyncio.create_task(proc.wait())]
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
    except OutputLimit:
        error_kind = 'output_limit'
    except asyncio.TimeoutError:
        error_kind = 'timeout'
    except OSError:
        error_kind = 'spawn_error' if proc is None else 'io_error'
    except asyncio.CancelledError:
        cancelled = True
    finally:
        if proc is not None and (error_kind or cancelled):
            # Keep a strong reference and shield cleanup from repeated caller
            # cancellation, then propagate cancellation after bounded cleanup.
            cleanup = asyncio.create_task(stop())
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    cancelled = True
            cleanup.result()
    if cancelled:
        raise asyncio.CancelledError
    stderr = buffers[1].decode('utf-8', errors='replace')
    if error_kind:
        stderr = {'timeout': 'timed out', 'output_limit': 'output limit exceeded',
                  'spawn_error': 'process could not start', 'io_error': 'process output unavailable'}[error_kind]
    return {'exit_code': -1 if error_kind else proc.returncode,
            'stdout': buffers[0].decode('utf-8', errors='replace'), 'stderr': stderr,
            'duration': time.monotonic() - start, 'error_kind': error_kind or None,
            'output_truncated': error_kind == 'output_limit', 'output_byte_limit': MAX_OUTPUT_BYTES,
            'cleanup_complete': cleanup_complete}


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
            out["error"] = out.get("error") or f"{tool} execution incomplete (exit {run.get('exit_code')})"
            if run.get('error_kind'):
                out['error_kind'] = run['error_kind']
            if run.get('output_truncated'):
                out['output_truncated'] = True
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


def _adapter_text(run: Dict) -> str:
    """Text-mode CLIs may write result lines to either output channel."""
    return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '',
                  run.get('stdout', '') + '\n' + run.get('stderr', ''))


def _adapter_result(payload: Dict, tool: str, run: Dict, problem: str = '') -> Dict:
    """Preserve the actual exit code and parser failure independently."""
    if problem:
        payload = {**payload, 'error': problem}
    # stderr often echoes credential-bearing URLs. Keep status and parsed
    # observations, never raw process diagnostics in the public error field.
    result = _stamp_ok(payload, tool, {**run, 'stderr': ''})
    if run.get('exit_code') != 0:
        result['error'] = f'{tool} execution failed or timed out; diagnostics withheld'
        result['error_type'] = 'execution_error'
    elif problem:
        result['error'] = problem
        result['error_type'] = 'invalid_output'
    return result


async def masscan_scan(target: str, ports: str = "80,443", rate: int = 1000) -> Dict:
    """Ultra-fast TCP port scanner using masscan CLI."""
    binary = _which("masscan")
    if not binary:
        return _err("masscan")
    r = await _run_cli([binary, target, "-p", ports, "--rate", str(rate)])
    ports_found = []
    problem = ''
    for line in _adapter_text(r).splitlines():
        match = re.fullmatch(r'\s*Discovered open port (\d+)/(tcp|udp) on (\S+)\s*', line)
        if not match:
            if line.strip().startswith('Discovered open port'):
                problem = 'Malformed masscan port record'
            continue
        port, protocol, host = match.groups()
        try:
            ipaddress.ip_address(host)
            if not 1 <= int(port) <= 65535:
                raise ValueError('port')
        except ValueError:
            problem = 'Malformed masscan port record'
            continue
        record = {'port': port, 'protocol': protocol, 'ip': host}
        if record not in ports_found:
            ports_found.append(record)
    return _adapter_result({"open_ports": ports_found, "count": len(ports_found)}, "masscan", r, problem)


async def xsstrike_check(target: str) -> Dict:
    """XSS detection using xsstrike CLI."""
    binary = _which("xsstrike")
    if not binary:
        return _err("xsstrike")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli([binary, "-u", target, "--silent"])
    out = _adapter_text(r)
    vuln = any(re.fullmatch(r'\s*(?:\[\+\]\s*)?(?:XSS (?:vulnerability )?(?:found|detected)[.!]?|Vulnerable webpage:\s*\S+)\s*',
                           line, re.I) for line in out.splitlines())
    negative = any(re.fullmatch(r'\s*(?:\[-\]\s*)?(?:No reflection found|No XSS found|No vulnerabilities found|Target is not vulnerable)[.!]?\s*',
                               line, re.I) for line in out.splitlines())
    return _adapter_result({
        "vulnerable": vuln,
        "output": ('External tool reported possible XSS; raw output withheld' if vuln else
                   'No XSS reported in supported tool output' if negative else
                   'Unrecognized tool output; raw output withheld'),
        "candidate": vuln, "evidence_type": "external_tool_report", "browser_confirmed": False,
        "confidence": "MEDIUM" if vuln else "LOW",
        "coverage": "XSStrike text report only; browser execution not independently verified",
    }, "xsstrike", r, '' if vuln or negative else 'Unrecognized XSStrike result; absence of XSS not assessed')


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
    binary = _which("cmseek")
    if not binary:
        return _err("cmseek")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    r = await _run_cli([binary, "-u", target])
    cms = None
    version = None
    for line in _adapter_text(r).splitlines():
        m = re.fullmatch(r"\s*(?:\[\+\]\s*)?CMS Detected\s*:\s*(.+?)\s*", line)
        if m:
            cms = m.group(1).strip()
        m = re.fullmatch(r"\s*(?:\[\+\]\s*)?CMS Version\s*:\s*(.+?)\s*", line)
        if m:
            version = m.group(1).strip()
    negative = any(re.fullmatch(r'\s*(?:\[-\]\s*)?(?:CMS not detected|Unable to detect CMS)[.!]?\s*', line, re.I)
                   for line in _adapter_text(r).splitlines())
    return _adapter_result({"cms": cms, "version": version}, "cmseek", r,
                           '' if cms or negative else 'Unrecognized CMSeeK result; CMS identification incomplete')


async def testssl_check(target: str, port: int = 443) -> Dict:
    """SSL/TLS server testing using testssl CLI."""
    binary = _which("testssl")
    if not binary:
        return _err("testssl")
    r = await _run_cli([binary, "--quiet", "--jsonfile", "/dev/stdout", f"{target}:{port}"])
    problem = ''
    findings = []
    try:
        data = json.loads(r.get('stdout', ''))
        if not isinstance(data, list):
            raise ValueError('shape')
        for item in data:
            if not isinstance(item, dict) or not all(isinstance(item.get(key), str) and item[key] for key in ('id', 'severity', 'finding')):
                problem = 'Invalid testssl JSON record'
            else:
                findings.append(item)
                if item['severity'].upper() in ('FATAL', 'ERROR'):
                    problem = 'testssl reported an incomplete scan'
    except ValueError:
        problem = 'Invalid testssl JSON schema'
    return _adapter_result({"findings": findings, "count": len(findings)}, "testssl", r, problem)


async def sslyze_check(target: str, port: int = 443) -> Dict:
    """Fast SSL/TLS scanning using sslyze CLI."""
    binary = _which("sslyze")
    if not binary:
        return _err("sslyze")
    r = await _run_cli([binary, "--json_out", "-", f"{target}:{port}"])
    problem = ''
    try:
        data = json.loads(r.get("stdout", ""))
        if not isinstance(data, dict) or not isinstance(data.get('server_scan_results'), list):
            raise ValueError('shape')
        records = data['server_scan_results']
        if not records or data.get('invalid_server_strings'):
            problem = 'SSLyze did not complete all requested servers'
        for record in records:
            if not isinstance(record, dict) or record.get('scan_status') != 'COMPLETED' or not isinstance(record.get('scan_result'), dict):
                problem = 'SSLyze server scan incomplete'
                continue
            for command in record['scan_result'].values():
                if isinstance(command, dict) and command.get('status') not in (None, 'COMPLETED', 'NOT_SCHEDULED'):
                    problem = 'SSLyze scan command incomplete'
    except ValueError:
        data = {}
        problem = 'Invalid SSLyze JSON schema'
    return _adapter_result(data, "sslyze", r, problem)


async def gobuster_dir(target: str, wordlist: str = "") -> Dict:
    """Directory brute-forcing using gobuster CLI."""
    binary = _which("gobuster")
    if not binary:
        return _err("gobuster")
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    import os
    if not os.path.isfile(wordlist):
        return {'error': 'Wordlist not found; supply an explicit installed wordlist', 'ran': False,
                'coverage_complete': False, 'execution_status': 'not_started', 'available': True,
                'confidence': 'LOW', 'coverage': 'wordlist_missing', 'entries': [], 'count': 0}
    r = await _run_cli([binary, "dir", "-u", target, "-w", wordlist, "-q"])
    entries = []
    problem = ''
    for line in _adapter_text(r).splitlines():
        if re.fullmatch(r'\s*/\S*\s+\(Status:\s*[1-5]\d{2}\)(?:\s+\[Size:\s*\d+\])?(?:\s+\[--> .*\])?\s*', line):
            if line.strip() not in entries:
                entries.append(line.strip())
        elif line.strip():
            problem = 'Unrecognized gobuster quiet output; results may be incomplete'
    return _adapter_result({"entries": entries, "count": len(entries)}, "gobuster", r, problem)


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

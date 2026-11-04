"""Bounded credential adapter; never return CLI output or credential values."""
import asyncio
import os
import re
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from .cli_tools import _run_cli


def _safe_target(target):
    if not isinstance(target, str) or len(target) > 2048:
        return "[REDACTED]"
    try:
        parsed = urlsplit(target if "://" in target else "//" + target)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parsed.port is not None:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", "")) if parsed.scheme else host + parsed.path
    except ValueError:
        return "[REDACTED]"


async def hydra_brute(target: str, service: str = "ssh", username: str = "root", wordlist: str = "") -> dict:
    services = {"ssh", "ftp", "smtp", "http", "https", "rdp", "mysql", "postgres"}
    valid_service = isinstance(service, str) and service in services
    result = {"target": _safe_target(target), "service": service if valid_service else "[INVALID]", "results": [], "count": 0,
              "coverage_complete": False, "attempt_limit": 20,
              "coverage": "At most 20 supplied entries, one worker, stop on first success; actual attempt count unknown.",
              "execution_status": "not_started"}
    if not valid_service:
        result["error"] = "Unsupported service"
        return result
    if (not isinstance(target, str) or not 1 <= len(target) <= 253
            or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in target.rstrip('.').split('.'))
            or not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}", username)):
        result["error"] = "Invalid target or username syntax"
        return result
    if not isinstance(wordlist, str) or not wordlist or len(wordlist) > 4096 or '\x00' in wordlist:
        result["error"] = "An explicit bounded wordlist is required"
        return result
    try:
        info = os.lstat(wordlist)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 81920:
            result["error"] = "Wordlist must be a regular file of at most 81920 bytes"
            return result
        def open_regular(name, flags):
            # Fail closed on platforms without race-safe nonblocking/no-follow open.
            if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_NONBLOCK'):
                raise OSError("Regular-file open unavailable")
            return os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
        # Remove the bounded private input on errors and cancellation as well.
        with tempfile.TemporaryDirectory(prefix="credential-audit-") as directory:
            bounded = Path(directory) / "entries"
            count = 0
            with open(wordlist, 'rb', opener=open_regular) as source, bounded.open("wb") as destination:
                opened = os.fstat(source.fileno())
                if (not stat.S_ISREG(opened.st_mode) or opened.st_size > 81920
                        or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                    result["error"] = "Wordlist changed before open or exceeds size limit"
                    return result
                for _ in range(20):
                    line = source.readline(4097)
                    if not line:
                        break
                    if len(line) > 4096 or b'\x00' in line:
                        result["error"] = "Wordlist entry exceeds size limit"
                        return result
                    destination.write(line.rstrip(b'\r\n') + b'\n')
                    count += 1
            if not count:
                result["error"] = "Empty wordlist"
                return result
            result["attempt_limit"] = count
            cmd = ["hydra", "-l", username, "-P", str(bounded), "-t", "1", "-f", "-I", f"{service}://{target}"]
            run = await _run_cli(cmd, timeout=300)
            # Only full protocol-positive records qualify; diagnostics are not findings.
            pattern = re.compile(r'^\[\d+\]\[' + re.escape(service) + r'\]\s+host:\s+(?P<host>\S+)\s+login:\s+.*?\s+password:\s*.*$')
            for line in run.get("stdout", "").splitlines():
                match = pattern.fullmatch(line)
                if match and match['host'].lower().rstrip('.') == target.lower().rstrip('.'):
                    result["results"].append({"result_index": len(result["results"]) + 1,
                                              "username": "[REDACTED]", "password": "[REDACTED]",
                                              "confidence": "MEDIUM",
                                              "coverage": "CLI protocol-positive record matched requested host and service; authentication not independently verified"})
                    if len(result["results"]) == 20:
                        break
            result["count"] = len(result["results"])
            completion = re.search(r'(?m)^1 of 1 targets? successfully completed, \d+ valid passwords? found\s*$', run.get("stdout", ""))
            complete = (run.get("exit_code") == 0 and not run.get("error_kind")
                        and run.get("cleanup_complete", True) and bool(completion or result["count"]))
            result["coverage_complete"] = bool(complete)
            result["execution_status"] = "completed" if complete else "incomplete"
            result["cleanup_complete"] = run.get("cleanup_complete", True)
            if not complete:
                result["error"] = "Credential test incomplete; CLI execution failed or was interrupted"
    except (OSError, UnicodeError, asyncio.TimeoutError):
        result["error"] = "Credential test incomplete; input or execution unavailable"
        result["execution_status"] = "incomplete"
    return result

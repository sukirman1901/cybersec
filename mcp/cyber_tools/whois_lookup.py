"""WHOIS lookup for domain registration information."""

import asyncio
import os
import re
import signal
import shutil
import subprocess
from typing import Optional
from urllib.parse import urlparse

# TLD-specific WHOIS servers (fallback when IANA referral fails)
_TLD_WHOIS = {
    "go.id": "whois.idnic.net",
    "co.id": "whois.idnic.net",
    "or.id": "whois.idnic.net",
    "ac.id": "whois.idnic.net",
    "sch.id": "whois.idnic.net",
    "web.id": "whois.idnic.net",
    "id": "whois.idnic.net",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
}


def _normalize_domain(target: str) -> str:
    if not isinstance(target, str):
        raise ValueError('Domain must be a string')
    if target.startswith(("http://", "https://")):
        target = urlparse(target).hostname or target
    domain = target.split(":")[0].strip().lower().rstrip(".")
    if len(domain) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', domain):
        raise ValueError('Invalid domain')
    return domain


def _tld_servers(domain: str) -> list[str]:
    parts = domain.split(".")
    servers: list[str] = []
    for i in range(len(parts) - 1):
        tld = ".".join(parts[i:])
        if tld in _TLD_WHOIS:
            servers.append(_TLD_WHOIS[tld])
    return servers


async def _whois_cli(domain: str) -> Optional[dict]:
    if not shutil.which("whois"):
        return None
    process = None
    result = _failure(domain, 'WHOIS CLI incomplete')
    try:
        async with asyncio.timeout(5):
            process = await asyncio.create_subprocess_exec(
                'whois', domain, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                **({'start_new_session': True} if os.name == 'posix' else {}))
            data = bytearray()
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                if len(data) + len(chunk) > 65536:
                    raise ValueError('WHOIS response size limit')
                data.extend(chunk)
            code = await process.wait()
            if code != 0:
                raise ValueError('WHOIS CLI nonzero exit')
        result = _parse_response(domain, 'whois-cli', data.decode(errors='replace'))
    except (OSError, ValueError, asyncio.TimeoutError) as exc:
        result = _failure(domain, type(exc).__name__)
    finally:
        if process is not None:
            # Retain the task: shield alone is insufficient when a caller cancels
            # repeatedly while the killed child's paused stdout is being drained.
            # _cleanup_cli owns its deadlines; cancellation is deferred, not lost.
            cleanup_task = asyncio.create_task(_cleanup_cli(process))
            cancelled = None
            while True:
                try:
                    result['cleanup_complete'] = await asyncio.shield(cleanup_task)
                    break
                except asyncio.CancelledError as exc:
                    if cleanup_task.cancelled():
                        raise
                    cancelled = exc
                    if cleanup_task.done():
                        result['cleanup_complete'] = cleanup_task.result()
                        break
            if not result['cleanup_complete']:
                result.update(cleanup_error='WHOIS CLI cleanup incomplete', coverage_complete=False,
                              assessment='incomplete')
                result.setdefault('error', 'WHOIS CLI cleanup incomplete')
            if cancelled is not None:
                raise cancelled
    return result


async def _cleanup_cli(process) -> bool:
    """Kill owned processes, discard in bounded chunks, and reap within a deadline.

    Waiting without consuming a paused stdout pipe can deadlock even after kill.
    Discarded output is neither retained nor parsed as WHOIS evidence.
    """
    if process.returncode is not None and process.stdout.at_eof():
        return True
    try:
        if os.name == 'posix' and isinstance(process.pid, int):
            # The CLI was launched in a new session; descendants may hold stdout
            # open even after the immediate child has exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass

        async def discard():
            while await process.stdout.read(16384):
                # Ready buffered reads must still yield so the deadline can fire.
                await asyncio.sleep(0)

        async with asyncio.timeout(1):
            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(discard())
                tasks.create_task(process.wait())
        return True
    except (OSError, asyncio.TimeoutError, ExceptionGroup):
        # asyncio.Process has no public close() API. Close its transport only as
        # a last-resort resource release, and keep cleanup explicitly incomplete.
        transport = getattr(process, '_transport', None)
        if transport is not None:
            transport.close()
            try:
                await asyncio.wait_for(process.wait(), timeout=1)
            except (OSError, asyncio.TimeoutError):
                pass
        return False


async def _whois_socket(domain: str, server: str) -> str:
    writer = None
    try:
        async with asyncio.timeout(5):
            reader, writer = await asyncio.open_connection(server, 43)
            writer.write((domain + '\r\n').encode())
            await writer.drain()
            data = bytearray()
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                if len(data) + len(chunk) > 65536:
                    raise ValueError('WHOIS response size limit')
                data.extend(chunk)
        return data.decode(errors='replace')
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except (OSError, asyncio.TimeoutError):
                pass


async def whois_lookup(target: str) -> dict:
    domain = '[invalid domain]'
    try:
        domain = _normalize_domain(target)
        async with asyncio.timeout(15):
            cli_result = await _whois_cli(domain)
            if cli_result is not None:
                return cli_result
            servers = _tld_servers(domain)
            if servers:
                server = servers[0]
            else:
                ref = await _whois_socket(domain, 'whois.iana.org')
                match = re.search(r'(?im)^whois:\s*([a-z0-9.-]+)\s*$', ref)
                server = match.group(1).lower() if match else None
                # Never let provider text choose arbitrary IPs/ports/hosts. This
                # intentionally leaves unsupported TLD referrals incomplete.
                if server not in set(_TLD_WHOIS.values()):
                    return _failure(domain, 'Unsupported or missing IANA referral')
            return _parse_response(domain, server, await _whois_socket(domain, server))
    except (OSError, ValueError, TypeError, asyncio.TimeoutError) as exc:
        return _failure(domain, type(exc).__name__)


def _failure(domain, error):
    return {'target':domain, 'raw':'', 'parsed':{}, 'error':error,
            'coverage_complete':False, 'assessment':'incomplete', 'scope_authorized':False}


def _parse_response(domain, server, text):
    """Allowlisted metadata only; never raw WHOIS/contact records."""
    result = {'target':domain, 'server':server, 'raw':'', 'parsed':{}, 'scope_authorized':False,
              'coverage':'Selected registration metadata only; raw/contact fields omitted; WHOIS provider identity/freshness unverified',
              'coverage_complete':False, 'assessment':'incomplete'}
    if len(text.encode()) > 65536 or re.search(r'(?i)(?:rate limit|limit exceeded|quota exceeded)', text):
        return {**result, 'error':'Provider limit or oversized response'}
    if re.fullmatch(r'\s*No match for\s+[\'"]?' + re.escape(domain) + r'[\'"]?\.?\s*', text, re.I):
        return {**result, 'coverage_complete':True, 'assessment':'provider_no_record'}
    rows = text.splitlines()
    fields = {}
    for line in rows[:200]:
        if ':' not in line or line.lstrip().startswith(('%','#',';')):
            continue
        key, value = (part.strip() for part in line.split(':',1))
        key = key.lower().replace(' ','_')
        if key == 'domain_name':
            if value.lower().rstrip('.') != domain:
                return {**result, 'error':'WHOIS domain identity mismatch'}
            fields[key] = domain
        elif key in ('creation_date','registry_expiry_date','updated_date'):
            if re.fullmatch(r'\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2}))?', value):
                fields[key] = value
        elif key == 'name_server':
            try:
                fields[key] = _normalize_domain(value)
            except ValueError:
                pass
    if fields.get('domain_name') != domain:
        return {**result, 'error':'No recognized domain record'}
    return {**result, 'parsed':fields, 'truncated':len(rows)>200,
            'coverage_complete':len(rows)<=200, 'assessment':'provider_registration_record'}

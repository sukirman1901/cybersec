"""Bounded static inspection of a private artifact snapshot; never execute target."""
import asyncio
import os
import re
import stat
import tempfile
import signal

MAX_FILE = 16 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
MAX_CLEANUP_DISCARD = 1024 * 1024
CLEANUP_TIMEOUT = 1.0


async def _stop(proc):
    """Kill the isolated group, discard bounded stdout and reap before closing pipes."""
    failures = []
    try:
        if os.name == 'posix' and getattr(proc, 'pid', None) is not None:
            # Also stop descendants holding stdout after the direct child exits.
            os.killpg(proc.pid, signal.SIGKILL)
        elif proc.returncode is None:
            proc.kill()
    except ProcessLookupError:
        pass
    except OSError:
        failures.append('unable_to_kill')

    async def discard():
        discarded = 0
        while True:
            chunk = await proc.stdout.read(8192)
            if not chunk:
                return
            discarded += len(chunk)
            if discarded > MAX_CLEANUP_DISCARD:
                raise ValueError('Discard limit')

    tasks = [asyncio.create_task(discard()), asyncio.create_task(proc.wait())]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=CLEANUP_TIMEOUT)
    except (OSError, asyncio.TimeoutError, ValueError):
        failures.append('drain_or_reap_failed')
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Process exposes no public close(); explicitly close its transport so a
        # paused stdout pipe cannot survive a failed bounded drain/reap attempt.
        transport = getattr(proc, '_transport', None)
        if transport is not None:
            transport.close()
    if failures:
        return 'cleanup_failed: ' + ', '.join(failures)
    return None


async def _run_bounded(*args):
    proc = None
    collector = None

    async def cleanup():
        if collector is not None:
            if not collector.done():
                collector.cancel()
            await asyncio.gather(collector, return_exceptions=True)
        return await _stop(proc) if proc is not None else None

    async def protected_cleanup(cancellation=None):
        # Retain the bounded cleanup task: shield alone is insufficient because
        # cancellation still interrupts the caller awaiting the shield. Repeated
        # caller cancellations must not strand a paused pipe or unreaped child.
        worker = asyncio.create_task(cleanup())
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError as exc:
                if cancellation is None:
                    cancellation = exc
            except (OSError, ValueError):
                break
        if worker.cancelled():
            cleanup_error = 'cleanup_failed: cleanup_task_cancelled'
        else:
            try:
                cleanup_error = worker.result()
            except (OSError, ValueError):
                cleanup_error = 'cleanup_failed: cleanup_exception'
        if cancellation is not None:
            if cleanup_error:
                cancellation.add_note(cleanup_error)
            raise cancellation
        return cleanup_error

    try:
        proc = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL,
                                                    limit=MAX_OUTPUT,
                                                    start_new_session=os.name == 'posix')
        async def collect():
            output = bytearray()
            while True:
                chunk = await proc.stdout.read(8192)
                if not chunk:
                    break
                if len(output) + len(chunk) > MAX_OUTPUT:
                    raise ValueError('Output limit')
                output.extend(chunk)
            code = await proc.wait()
            if code != 0:
                raise ValueError('Command failed')
            return bytes(output)
        collector = asyncio.create_task(collect())
        return await asyncio.wait_for(collector, timeout=10), None
    except (OSError, asyncio.TimeoutError, ValueError):
        cleanup_error = await protected_cleanup()
        error = 'Command unavailable, failed, timed out or exceeded 64 KiB output limit'
        return b'', error + ('; ' + cleanup_error if cleanup_error else '')
    except asyncio.CancelledError as exc:
        await protected_cleanup(exc)


def _read_artifact(target):
    if not isinstance(target, str):
        raise ValueError('Invalid target')
    expected = os.lstat(target)
    if not stat.S_ISREG(expected.st_mode) or expected.st_size > MAX_FILE:
        raise ValueError('Non-regular or oversized target')
    def open_regular(name, flags):
        return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with open(target, 'rb', opener=open_regular) as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError('Artifact changed')
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError('Artifact exceeds limit')
    return data


async def binary_checksec(target: str) -> dict:
    try:
        data = _read_artifact(target)
    except (OSError, ValueError):
        return {'error': 'Artifact missing, inaccessible, changed, non-regular or above 16 MiB limit',
                'coverage_complete': False, 'execution_status': 'not_started'}
    findings, errors, checks = [], [], []
    file_type = 'unknown'
    try:
        with tempfile.TemporaryDirectory(prefix='cybersec-checksec-') as directory:
            snapshot = os.path.join(directory, 'artifact.bin')
            with open(snapshot, 'wb') as stream:
                stream.write(data)
            output, error = await _run_bounded('file', '-b', '--', snapshot)
            checks.append('file')
            if error:
                errors.append('file: ' + error)
            else:
                text = output.decode('utf-8', errors='replace')
                # Never echo executable metadata/embedded names from external tools.
                if re.match(r'^ELF\b', text):
                    file_type = 'ELF'
                elif re.match(r'^(?:Mach-O|universal binary.*Mach-O)\b', text):
                    file_type = 'Mach-O'
                elif re.match(r'^PE32\+?\b', text):
                    file_type = 'PE32'
                else:
                    errors.append('Unsupported or unrecognized binary format')
                findings.append({'check': 'file_type', 'value': file_type, 'assessment': 'observation'})
            if file_type != 'unknown':
                output, error = await _run_bounded('strings', '-n', '6', '--', snapshot)
                checks.append('strings')
                if error:
                    errors.append('strings: ' + error)
                else:
                    text = output.decode('utf-8', errors='replace').lower()
                    keywords = [word for word in ('password', 'secret', 'api_key', 'token', 'http://', 'https://', 'admin', 'root', 'debug') if word in text]
                    if keywords:
                        findings.append({'check': 'strings_interesting', 'value': keywords, 'severity': 'info',
                                         'assessment': 'observation', 'coverage': 'Keyword presence only; not proof of credentials or vulnerabilities'})
            if file_type == 'ELF':
                output, error = await _run_bounded('readelf', '-W', '-h', '-l', '-d', '--', snapshot)
                checks.append('readelf')
                if error:
                    errors.append('readelf: ' + error)
                else:
                    text = output.decode('utf-8', errors='replace')
                    kind = re.search(r'^\s*Type:\s+(EXEC|DYN)\b', text, re.MULTILINE)
                    pie = False if kind and kind[1] == 'EXEC' else True if kind and kind[1] == 'DYN' and re.search(r'^\s*INTERP\s|\(FLAGS_1\).*\bPIE\b', text, re.MULTILINE) else 'unknown'
                    stack = re.search(r'^\s*GNU_STACK\s+[^\n]*?\s+(R[WE ]*)\s+0x[0-9a-fA-F]+\s*$', text, re.MULTILINE)
                    nx = 'E' not in stack[1] if stack else 'unknown'
                    for check, enabled in [('PIE/ASLR', pie), ('NX', nx)]:
                        findings.append({'check': check, 'enabled': enabled, 'assessment': 'observation',
                                         'coverage': 'ELF header/program flags only; PIE does not prove runtime ASLR or exploitability'})
                    if pie == 'unknown' or nx == 'unknown':
                        errors.append('ELF headers insufficient for PIE or NX assessment')
            elif file_type == 'Mach-O':
                output, error = await _run_bounded('otool', '-L', snapshot)
                checks.append('otool')
                if error:
                    errors.append('otool: ' + error)
                else:
                    lines = output.decode('utf-8', errors='replace').splitlines()[1:]
                    libraries = [line for line in lines if re.search(r'\(compatibility version [0-9.]+, current version [0-9.]+\)', line)]
                    findings.append({'check': 'linked_libraries', 'libraries': ['[REDACTED]'] * min(len(libraries), 20),
                                     'library_count': len(libraries), 'assessment': 'observation'})
                    if len(libraries) > 20 or not libraries:
                        errors.append('Library listing truncated or unrecognized')
                errors.append('Mach-O hardening flags not assessed')
            elif file_type == 'PE32':
                findings.append({'check': 'binary_type', 'value': 'Windows PE', 'assessment': 'observation'})
                errors.append('PE hardening flags not assessed')
    except OSError:
        errors.append('Unable to create/read private artifact snapshot')
    complete = not errors
    return {'target': target, 'file_type': file_type, 'findings': findings, 'count': len(findings), 'errors': errors,
            'coverage_complete': complete, 'execution_status': 'completed' if complete else 'partial' if checks else 'not_started',
            'checks_attempted': checks,
            'coverage': 'Static private snapshot only; 16 MiB input, 64 KiB stdout/command, stderr discarded, 10s/command with kill/reap on failure. Original binary never executed; no runtime ASLR or vulnerability verification.'}

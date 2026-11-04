import asyncio
import re

from .cli_tools import _run_cli


async def searchsploit(search_term: str) -> dict:
    cmd = ["searchsploit", search_term]
    run = await _run_cli(cmd, timeout=30)
    output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', run.get('stdout', ''))
    exploits = []
    recognized = False
    malformed = False
    for line in output.splitlines():
        line = line.strip()
        if not line or set(line) <= set('-+| '):
            continue
        if re.fullmatch(r'(?:Exploit|Shellcode) Title\s*\|\s*Path', line, re.I):
            recognized = True
            continue
        if re.fullmatch(r'(?:Exploits|Shellcodes):\s*No Results', line, re.I):
            recognized = True
            continue
        if '|' not in line:
            continue
        title, path = (part.strip() for part in line.rsplit('|', 1))
        if not title or not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/\d+\.[A-Za-z0-9]+', path):
            malformed = True
            continue
        recognized = True
        record = {'path': path, 'title': title, 'type': '',
                  'confidence': 'LOW', 'coverage': 'External exploit database match only; target applicability unverified'}
        if record not in exploits:
            exploits.append(record)
    problem = '' if recognized and not malformed else 'Unrecognized or malformed searchsploit output'
    if run.get('exit_code') != 0:
        problem = 'Searchsploit execution failed or timed out; lookup incomplete'
    return {'search': search_term, 'results': exploits[:30], 'count': len(exploits),
            'exit_code': run.get('exit_code'), 'coverage_complete': not problem,
            'execution_status': 'error' if problem else 'completed', 'confidence': 'LOW',
            'coverage': 'External exploit database lookup; no exploitation or applicability verification',
            **({'error': problem} if problem else {})}

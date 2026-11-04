"""Detect recognizable Git metadata, not arbitrary successful paths."""
import re
import struct
import httpx
from .surface_probe import SurfaceProbe

GIT_PATHS = ['/.git/HEAD', '/.git/config', '/.git/index', '/.git/refs/heads/main', '/.git/refs/heads/master']


async def exposed_git(target: str) -> dict:
    findings = []
    base = target.rstrip('/')
    coverage = 'Five Git metadata paths; signatures only, no repository reconstruction or object downloads'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=len(GIT_PATHS))
        for path in GIT_PATHS:
            response = await probe.request('GET', base + path)
            if response is None:
                break
            if response.status_code != 200:
                continue
            text = response.text.strip()
            signature = None
            if path.endswith('/HEAD') and re.fullmatch(r'ref: refs/[A-Za-z0-9_./-]+|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', text):
                signature = 'Git HEAD reference'
            elif '/refs/heads/' in path and re.fullmatch(r'[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', text):
                signature = 'Git object reference'
            elif path.endswith('/config') and re.search(r'(?m)^\[core\]\s*$', text) and re.search(r'(?m)^\s*repositoryformatversion\s*=\s*\d+\s*$', text) and '<html' not in text.lower():
                signature = 'Git core configuration'
            elif path.endswith('/index') and len(response.content) >= 12 and response.content[:4] == b'DIRC' and struct.unpack('>I', response.content[4:8])[0] in (2, 3, 4):
                signature = 'Git index header'
            if signature:
                findings.append({'path': path, 'target':base + path, 'status':200,
                                 'severity':'high' if path.endswith(('/config','/index')) else 'medium',
                                 'evidence':signature, 'confidence':'HIGH', 'coverage':coverage,
                                 'assessment':'observed_metadata_exposure', 'size':len(response.content)})
    return {'target':target, 'findings':findings, 'git_exposed':bool(findings),
            'count':len(findings), 'coverage':coverage, **probe.summary()}

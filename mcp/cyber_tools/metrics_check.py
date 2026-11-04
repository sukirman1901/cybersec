"""Bounded Prometheus text-format recognition without exporting metric labels."""
import re
import secrets
import httpx
from .surface_probe import SurfaceProbe

METRICS_PATHS = ['/metrics', '/actuator/prometheus', '/prometheus', '/debug/metrics',
                 '/metrics.json', '/health', '/actuator/health', '/info', '/actuator/info']
_NAME = r'[a-zA-Z_:][a-zA-Z0-9_:]*'
_LABEL = r'[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\[\\"n])*"'
_LABELS = r'\{\s*(?:' + _LABEL + r'(?:\s*,\s*' + _LABEL + r')*\s*,?)?\s*\}'
_NUMBER = r'(?:[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?|[-+]?Inf|NaN)'
_SAMPLE = re.compile(r'(' + _NAME + r')(?:' + _LABELS + r')?\s+' + _NUMBER + r'(?:\s+\d+)?\s*')


def _sample_count(text):
    if re.search(r'<(?:html|body|!doctype\s+html)\b', text, re.I):
        return 0
    samples, declared = [], set()
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith('#'):
            match = re.fullmatch(r'# TYPE (' + _NAME + r') (?:counter|gauge|histogram|summary|untyped)\s*', line)
            if match:
                declared.add(match.group(1))
            continue
        match = _SAMPLE.fullmatch(line)
        if not match:
            return 0
        samples.append(match.group(1))
    if len(samples) >= 2 or any(name in declared for name in samples):
        return len(samples)
    return 0


async def metrics_check(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    base = target.rstrip('/')
    exposed, checked = [], 0
    coverage = 'Nine paths plus missing-path control; Prometheus text records only; JSON health/info and OpenMetrics exemplars not classified'
    async with httpx.AsyncClient(timeout=5.0) as client:
        probe = SurfaceProbe(client, max_requests=len(METRICS_PATHS)+1)
        control = await probe.request('GET', base + '/.__cybersec_missing_' + secrets.token_hex(8))
        for path in METRICS_PATHS:
            if control is None or probe.stopped:
                break
            response = await probe.request('GET', base+path)
            checked += 1
            if response is None:
                break
            if response.status_code != 200 or response.content == control.content:
                continue
            count = _sample_count(response.text)
            if count:
                exposed.append({'path':path, 'status':200, 'size':len(response.content),
                                'exposes_metrics':True, 'evidence':{'sample_count':count},
                                'confidence':'HIGH', 'coverage':coverage,
                                'assessment':'observed_metrics; sensitivity unverified'})
    return {'target':target, 'paths_checked':checked, 'exposed_endpoints':exposed,
            'total_exposed':len(exposed), 'risk':'MEDIUM' if exposed else 'INCONCLUSIVE' if probe.errors else 'NO_EVIDENCE',
            'coverage':coverage, **probe.summary()}

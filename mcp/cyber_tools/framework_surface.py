"""Shared bounded read-only framework path observations."""
import secrets
from .surface_probe import SurfaceProbe


async def inspect_paths(client, base, paths, classify, fingerprint, coverage):
    probe = SurfaceProbe(client, max_requests=len(paths)+2)
    findings, observations = [], []
    root = await probe.request('GET', base)
    detected = bool(root is not None and fingerprint(root))
    if detected:
        observations.append({'type':'framework_hint', 'severity':'info',
                             'confidence':'MEDIUM', 'coverage':coverage})
    control = await probe.request('GET', base + '/.__cybersec_missing_' + secrets.token_hex(8))
    for path in paths:
        if control is None or probe.stopped:
            break
        response = await probe.request('GET', base+path)
        if response is None:
            break
        if response.status_code != 200 or response.content == control.content:
            continue
        match = classify(path, response)
        if match:
            kind, severity, framework_hint = match
            detected = detected or framework_hint
            item = {'path':path, 'endpoint':path, 'status':200, 'type':kind,
                    'severity':severity, 'risk':severity.upper(), 'confidence':'HIGH',
                    'evidence':kind, 'coverage':coverage,
                    'assessment':'observed_content; sensitivity and runtime unverified'}
            (observations if severity == 'info' else findings).append(item)
    return {'findings':findings, 'observations':observations, 'count':len(findings),
            'vulnerable':bool(findings), 'framework_detected':detected,
            'coverage':coverage, **probe.summary()}

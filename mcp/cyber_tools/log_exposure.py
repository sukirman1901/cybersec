"""Identify structured logs without publishing their raw contents."""
import json
import re
import secrets
import httpx
from .surface_probe import SurfaceProbe

LOG_PATHS = ['/access.log', '/error.log', '/debug.log', '/app.log', '/server.log',
             '/logs/access.log', '/logs/error.log', '/logs/app.log', '/log/access.log',
             '/log/error.log', '/var/log/access.log', '/var/log/error.log',
             '/storage/logs/laravel.log', '/wp-content/debug.log', '/logfile.log',
             '/trace.log', '/audit.log', '/security.log']


async def log_exposure(target: str) -> dict:
    results = []
    if not target.startswith(('http://','https://')):
        target = 'https://' + target
    base = target.rstrip('/')
    checked = 0
    coverage = '18 log paths plus soft-404 control; require structured log records; values/snippets omitted'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=len(LOG_PATHS)+1)
        control = await probe.request('GET', base + '/.__cybersec_missing_' + secrets.token_hex(8))
        for path in LOG_PATHS:
            if control is None or probe.stopped:
                break
            resp = await probe.request('GET', base+path)
            checked += 1
            if resp is None:
                break
            if resp.status_code != 200 or resp.content == control.content or re.search(r'<(?:!doctype\s+html|html|body)\b', resp.text, re.I):
                continue
            records = 0
            for line in resp.text.splitlines()[:100]:
                if re.match(r'^\[?\d{4}-\d{2}-\d{2}[ T][\d:.+Z-]+\]?\s+(?:[\w.-]+\.)?(?:ERROR|INFO|WARN(?:ING)?|DEBUG|CRITICAL|FATAL)\b', line):
                    records += 1
                elif re.match(r'^\S+ \S+ \S+ \[\d{2}/[A-Za-z]{3}/\d{4}:[^]]+\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) [^\"]+" \d{3} ', line):
                    records += 1
                else:
                    try:
                        data = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(data, dict) and isinstance(data.get('message'),str) and {'timestamp','time','@timestamp'} & data.keys() and str(data.get('level','')).lower() in ('info','error','warning','warn','debug','fatal','critical'):
                        records += 1
            if records < 2:
                continue
            sensitive = bool(re.search(r'(?i)\b(?:password|secret|access_token|api_key)[\"\']?\s*[=:]\s*[\"\']?[^\s\"\']+', resp.text))
            results.append({'path':path, 'target':base+path, 'status':200, 'size':len(resp.content),
                            'contains_sensitive':sensitive, 'sensitive_status':'candidate' if sensitive else 'not_observed',
                            'evidence':{'structured_records':records,'credential_assignment_pattern':sensitive},
                            'severity':'medium', 'confidence':'HIGH', 'coverage':coverage,
                            'assessment':'observed_log_structure; data validity and sensitivity unverified'})
    return {'target':target, 'paths_checked':checked, 'exposed_logs':len(results),
            'sensitive_exposure':sum(r['contains_sensitive'] for r in results), 'results':results,
            'risk':'MEDIUM' if results else 'INCONCLUSIVE' if probe.errors else 'NO_EVIDENCE',
            'coverage':coverage, **probe.summary()}

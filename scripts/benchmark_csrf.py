"""CSRF observation benchmark; no fixture establishes exploitable CSRF."""
import argparse
import asyncio
import json
import math
from pathlib import Path
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'mcp/tests'), str(ROOT/'mcp')]
import test_csrf_accuracy as fixture

CASES = {
    'public':{'body':'<html>Welcome</html>'},
    'missing_token':{'body':'<form method=post><input name=email></form>'},
    'protected_form':{'body':'<form method=post><input name=csrf_token value=0123456789abcdef0123456789abcdef></form>'},
    'blocked':{'status':403},
    'rate_limited':{'status':429},
    'offline':{'offline':True},
}


async def benchmark(revision=None):
    original = fixture.module
    if revision:
        source = subprocess.check_output(['git','show',revision+':mcp/cyber_tools/csrf_detect.py'], cwd=ROOT, text=True)
        baseline = types.ModuleType('cyber_tools.csrf_detect')
        baseline.__package__ = 'cyber_tools'
        exec(compile(source, baseline.__name__, 'exec'), baseline.__dict__)
        fixture.module = baseline
    rows = []
    try:
        for _ in range(5):
            for name, kwargs in CASES.items():
                start = time.perf_counter()
                result, seen = await fixture.scan(**kwargs)
                rows.append({'case':name, 'ms':(time.perf_counter()-start)*1000,
                             'requests':len(seen), 'vulnerable':bool(result.get('csrf_vulnerable')),
                             'candidate':bool(result.get('candidate_forms')),
                             'complete':result.get('coverage_complete'),
                             'secret_exported':'private-value' in json.dumps(result)})
    finally:
        fixture.module = original
    scored = [r for r in rows if r['case'] in ('public','missing_token','protected_form')]
    times = sorted(r['ms'] for r in rows)
    return {'revision':revision or 'working_tree', 'runs':5, 'unique_fixtures':len(CASES),
            'unsupported_vulnerability_claims':sum(r['vulnerable'] for r in scored),
            'scored':len(scored), 'excluded':len(rows)-len(scored),
            'missing_token_candidate_recognized':sum(r['candidate'] for r in rows if r['case']=='missing_token'),
            'secret_exports':sum(r['secret_exported'] for r in rows),
            'mock_processing_p95_ms':round(times[math.ceil(.95*len(times))-1],3),
            'requests_by_case':{r['case']:r['requests'] for r in rows},
            'coverage_complete_by_case':{r['case']:r['complete'] for r in rows},
            'limitations':['No true-positive exploitable CSRF fixtures; vulnerability recall unmeasured.',
                           'Missing-token detection is an observation, not proof of CSRF.',
                           'Repetitions are not independent targets; timings exclude network and browser execution.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revision')
    args = parser.parse_args()
    print(json.dumps(asyncio.run(benchmark(args.revision)), indent=2))

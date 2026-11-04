"""Reproducible framework fixtures; optional committed baseline, no network."""
import argparse
import asyncio
import importlib
import json
import math
from pathlib import Path
import subprocess
import sys
import time
import types
import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'mcp/tests'), str(ROOT/'mcp')]
from test_framework_accuracy import TOOLS, run

CASES = ('positive','negative','prose','catchall','blocked','transport')
POSITIVES = {
    'django_scan':('/settings.py', "SECRET_KEY='x'\nDATABASES={}\nINSTALLED_APPS=[]"),
    'express_scan':('/.env','NODE_ENV=production\nDB_PASSWORD=x'),
    'spring_scan':('/actuator/env','{"activeProfiles":[],"propertySources":[{"name":"env","properties":{}}]}'),
    'tech_detect':('/', '<script src="/_next/static/main.js"></script>'),
}


async def benchmark(revision=None, runs=5):
    groups = {}
    for tool in TOOLS:
        name = 'cyber_tools.' + tool
        original = importlib.import_module(name)
        if revision:
            source = subprocess.check_output(['git','show',revision+':mcp/cyber_tools/'+tool+'.py'], cwd=ROOT, text=True)
            baseline = types.ModuleType(name)
            baseline.__package__ = 'cyber_tools'
            exec(compile(source, name, 'exec'), baseline.__dict__)
            sys.modules[name] = baseline
        rows = []
        try:
            for _ in range(runs):
                for case in CASES:
                    def handler(req):
                        if case == 'transport':
                            raise httpx.ConnectError('offline', request=req)
                        if case == 'blocked':
                            return httpx.Response(429)
                        if case == 'catchall':
                            return httpx.Response(200,text='<html>Welcome</html>')
                        if case == 'prose':
                            return httpx.Response(200,text='<html>Learn django spring express WordPress React cloudflare error: at '+req.url.path+'</html>')
                        path, body = POSITIVES[tool]
                        if case == 'positive' and req.url.path == path:
                            return httpx.Response(200,text=body)
                        return httpx.Response(404)
                    start = time.perf_counter()
                    try:
                        result, seen = await run(tool, handler)
                        detected = bool(result.get('javascript_frameworks')) if tool == 'tech_detect' else bool(result.get('findings'))
                        rows.append({'case':case, 'detected':detected, 'requests':len(seen),
                                     'complete':result.get('coverage_complete'), 'exception':None,
                                     'ms':(time.perf_counter()-start)*1000})
                    except Exception as exc:
                        rows.append({'case':case, 'exception':type(exc).__name__,
                                     'ms':(time.perf_counter()-start)*1000})
        finally:
            sys.modules[name] = original
        counts = dict.fromkeys(('tp','tn','fp','fn'), 0)
        for row in rows:
            if row['case'] in ('blocked','transport') or row['exception']:
                continue
            positive = row['case'] == 'positive'
            counts[('t' if row['detected'] == positive else 'f') + ('p' if row['detected'] else 'n')] += 1
        times = sorted(row['ms'] for row in rows)
        groups[tool] = {'counts':counts, 'exceptions':sum(bool(r['exception']) for r in rows),
                        'mock_processing_p95_ms':round(times[math.ceil(.95*len(times))-1],3),
                        'requests_by_case':{r['case']:r.get('requests') for r in rows},
                        'complete_by_case':{r['case']:r.get('complete') for r in rows}}
    return {'revision':revision or 'working_tree', 'runs':runs, 'groups':groups,
            'limitations':['24 unique synthetic cases; repetitions are not independent targets.',
                           'Blocked and transport cases excluded from classification scores.',
                           'Local MockTransport processing only, not network p95 or RSS.',
                           'Signature coverage is limited; no real-world accuracy claim.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revision')
    args = parser.parse_args()
    print(json.dumps(asyncio.run(benchmark(args.revision)), indent=2))

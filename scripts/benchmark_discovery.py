"""Selected synthetic discovery fixtures, with request counts and local p95."""
import asyncio
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'mcp/tests'), str(ROOT/'mcp')]
from test_discovery_accuracy import TOOLS, CASES, run_case


async def benchmark(runs=5):
    groups = {}
    for tool in TOOLS:
        rows = [await run_case(tool, case) for _ in range(runs) for case in CASES]
        # Score fixture recognition separately from overall scan completeness:
        # backup intentionally samples candidates, which is not full coverage.
        scored = [r for r in rows if r['case'] not in ('blocked','transport') and not r['exception']]
        counts = {key:0 for key in ('tp','tn','fp','fn')}
        for row in scored:
            counts[('t' if row['detected']==row['expected_positive'] else 'f') + ('p' if row['detected'] else 'n')] += 1
        times = sorted(r['elapsed_ms'] for r in rows)
        groups[tool] = {'counts':counts, 'scored':len(scored), 'excluded':len(rows)-len(scored),
                        'exceptions':sum(bool(r['exception']) for r in rows),
                        'mock_processing_p95_ms':round(times[math.ceil(.95*len(times))-1],3),
                        'requests_by_case':{case:rows[i]['requests'] for i,case in enumerate(CASES)},
                        'coverage_complete_by_case':{case:rows[i]['result'].get('coverage_complete') for i,case in enumerate(CASES)}}
    return {'environment':'httpx.MockTransport; sequential', 'runs':runs, 'groups':groups,
            'limitations':['Selected fixture recognition, not real-world accuracy or complete scan coverage.',
                           'Repeated cases are not independent targets; p95 is local processing, not network latency.',
                           'Backup deferred candidates remain untested even when a selected positive fixture is recognized.']}


if __name__ == '__main__':
    print(json.dumps(asyncio.run(benchmark()), indent=2))

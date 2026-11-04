"""Offline synthetic benchmark; HTTP latency and real-world recall are not measured."""
import asyncio
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'mcp/tests'), str(ROOT / 'mcp')]
from test_web_surface_accuracy import TOOLS, CASES, run_case


async def benchmark(runs=5):
    groups = {}
    for tool in TOOLS:
        rows = [await run_case(tool, case) for _ in range(runs) for case in CASES]
        scored = [r for r in rows if r['case'] not in ('blocked', 'transport') and not r['exception']]
        counts = {key:0 for key in ('tp','tn','fp','fn')}
        for r in scored:
            counts[('t' if r['detected'] == r['expected_positive'] else 'f') + ('p' if r['detected'] else 'n')] += 1
        times = sorted(r['elapsed_ms'] for r in rows)
        groups[tool] = {'counts': counts, 'scored':len(scored), 'excluded':len(rows)-len(scored),
                        'exceptions':sum(bool(r['exception']) for r in rows),
                        'mock_processing_p95_ms':round(times[math.ceil(.95*len(times))-1],3),
                        'requests_by_case':{case:rows[i]['requests'] for i,case in enumerate(CASES)},
                        'blocked_marked_incomplete':all(r['result'].get('coverage_complete') is False for r in rows if r['case']=='blocked')}
    return {'environment':'httpx.MockTransport; sequential', 'runs':runs, 'groups':groups,
            'limitations':['Selected synthetic fixtures, not production precision/recall.',
                           'p95 measures local Python processing, not network latency.',
                           'Blocked/transport cases excluded from accuracy counts; exceptions reported separately.']}


if __name__ == '__main__':
    print(json.dumps(asyncio.run(benchmark()), indent=2))

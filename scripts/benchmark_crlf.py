#!/usr/bin/env python3
"""Reproduce CRLF before/after results using MockTransport only.

Run: ./mcp/.venv/bin/python scripts/benchmark_crlf.py
No server is started; real HTTP transport is explicitly disabled.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import types
from unittest.mock import patch
from urllib.parse import unquote

import httpx

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'mcp/cyber_tools/crlf_inject.py'
CASES = ('query_header_injection', 'static_script', 'body_reflection',
         'blocked', 'transport_exception')
REAL_CLIENT = httpx.AsyncClient


def load(source, name):
    module = types.ModuleType(name)
    exec(compile(source, name, 'exec'), module.__dict__)
    return module


async def measure(module, case):
    counts = {'requests': 0, 'response_body_bytes_consumed': 0,
              'transport_exceptions': 0, 'blocked_responses': 0}

    class Body(httpx.AsyncByteStream):
        def __init__(self, body):
            self.body = body.encode()

        async def __aiter__(self):
            counts['response_body_bytes_consumed'] += len(self.body)
            yield self.body

    def handler(request):
        counts['requests'] += 1
        if case == 'transport_exception':
            counts['transport_exceptions'] += 1
            raise httpx.ConnectError('offline fixture failure', request=request)
        if case == 'blocked':
            counts['blocked_responses'] += 1
            return httpx.Response(429, stream=Body('Rate limited'))
        headers = {}
        body = 'Ordinary page'
        if case == 'query_header_injection':
            # Model a query-to-header sink which percent-decodes twice and
            # splits CRLF. Only actual extra fields become response headers.
            for value in request.url.params.values():
                decoded = unquote(value)
                for line in decoded.split('\r\n')[1:]:
                    match = re.fullmatch(r'([A-Za-z0-9-]+):\s*([^\r\n]+)', line)
                    if match:
                        headers[match[1]] = match[2]
        elif case == 'static_script':
            body = '<html><script src="/app.js"></script></html>'
        elif case == 'body_reflection':
            # Echoed text is deliberately not parsed into response headers.
            body = unquote(unquote(str(request.url))) + '\n' + str(dict(request.headers))
            body += request.content.decode(errors='replace')
        return httpx.Response(200, headers=headers, stream=Body(body))

    client = REAL_CLIENT(transport=httpx.MockTransport(handler))
    start = time.perf_counter()
    with patch.object(module.httpx, 'AsyncClient', return_value=client), patch.object(
            httpx.AsyncHTTPTransport, 'handle_async_request',
            side_effect=AssertionError('Network disabled in offline benchmark')):
        result = await module.crlf_inject('https://fixture.test/redirect?next=home&tag=a&tag=b')
    coverage = result.get('coverage', {})
    return {
        'expected_vulnerable': case == 'query_header_injection',
        'detected': bool(result['vulnerable']),
        'finding_count': result['total_findings'],
        'false_positive': case != 'query_header_injection' and bool(result['vulnerable']),
        'false_negative': case == 'query_header_injection' and not result['vulnerable'],
        **counts, 'elapsed_seconds': round(time.perf_counter() - start, 6),
        'failure_reported': bool(coverage.get('errors') or result.get('error')),
        'coverage_declared': bool(coverage),
        'per_finding_coverage': all('coverage' in f for f in result['results']) if result['results'] else None,
    }


async def benchmark(baseline):
    revision = subprocess.check_output(['git', 'rev-parse', '--verify', baseline + '^{commit}'], cwd=ROOT, text=True).strip()
    before = subprocess.check_output(['git', 'show', revision + ':' + SOURCE], cwd=ROOT, text=True)
    after = (ROOT / SOURCE).read_text()
    report = {
        'method': 'offline httpx.MockTransport; real HTTP transport disabled',
        'baseline_commit': revision,
        'current_source_sha256': hashlib.sha256(after.encode()).hexdigest(),
        'reproduce': './mcp/.venv/bin/python scripts/benchmark_crlf.py --baseline ' + revision,
        'limitations': [
            'Synthetic cases, not population accuracy or live network performance; elapsed times vary.',
            'Positive fixture models only a query-to-header CRLF sink with up to two percent decodes.',
            'Historical broad loops run unchanged; current scan covers at most four query names and three encodings.',
            'Current tool does not test log forgery, response splitting, paths, request headers, cookies, POST or JSON bodies.',
            'Header detection gains and lower request counts do not demonstrate equivalent breadth of coverage.',
        ],
        'before': {}, 'after': {},
    }
    for label, source in (('before', before), ('after', after)):
        module = load(source, 'crlf_benchmark_' + label)
        for case in CASES:
            report[label][case] = await measure(module, case)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='eeaa568')
    parser.add_argument('--output', type=Path, default=ROOT / 'mcp/crlf-benchmark.json')
    args = parser.parse_args()
    report = asyncio.run(benchmark(args.baseline))
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

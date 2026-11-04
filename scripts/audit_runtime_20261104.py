"""Offline audit reproductions. No external traffic, credentials, or persistent DB writes."""
import asyncio
import importlib
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import httpx


async def main():
    out = {}
    cli = importlib.import_module('cyber_tools.cli_tools')
    with patch.object(cli, '_check', return_value=True), patch.object(
        cli, '_run_cli', new=AsyncMock(return_value={
            'exit_code': -1, 'stdout': '', 'stderr': 'timed out', 'duration': 120
        })
    ):
        out['sqlmap_timeout'] = await cli.sqlmap_check('https://fixture.test/?id=1')
        out['nikto_timeout'] = await cli.nikto_scan('https://fixture.test/')
    wpscan = {'version': {'number': '1.0', 'vulnerabilities': [{'title': 'synthetic core finding'}]},
              'plugins': {'fixture': {'vulnerabilities': [{'title': 'synthetic plugin finding'}]}}}
    with patch.object(cli, '_check', return_value=True), patch.object(
        cli, '_run_cli', new=AsyncMock(return_value={'exit_code': 0, 'stdout': json.dumps(wpscan), 'stderr': ''})
    ):
        out['wpscan_nested_findings'] = await cli.wpscan_check('https://fixture.test/')

    nuclei = importlib.import_module('cyber_tools.nuclei_scan')
    proc = AsyncMock()
    proc.returncode = 1
    proc.communicate.return_value = (b'', b'no templates provided for scan')
    with patch.object(nuclei.asyncio, 'create_subprocess_exec', return_value=proc):
        out['nuclei_failure'] = await nuclei.nuclei_scan('https://fixture.test/')

    auth = importlib.import_module('cyber_tools.authenticated_scan')
    seen = []
    def handler(request):
        seen.append({'url': str(request.url), 'cookie': request.headers.get('cookie')})
        return httpx.Response(200, text='<html>Public documentation</html>' + 'x' * 240)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    with patch.object(auth, 'GuardedClient', return_value=client):
        r = json.loads(auth.authenticated_scan('https://fixture.test', auth_type='cookie', cookies='{"sid":"synthetic"}'))
    out['authenticated_cookie'] = {'authenticated': r['authenticated'], 'requests': seen,
                                  'false_idor_count': sum(f['type'] == 'idor' for f in r['findings'])}

    bulk = importlib.import_module('cyber_tools.bulk_scan')
    good_headers = {h: 'present' for h in ['X-Content-Type-Options', 'X-Frame-Options',
        'Strict-Transport-Security', 'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy']}
    # bulk now delegates to the canonical async scanner. Patch that network seam.
    with patch('cyber_tools.vuln_scanner.scan_vulnerabilities', new=AsyncMock(return_value={
            'vulnerabilities': [], 'count': 0, 'coverage_complete': True})):
        out['bulk_shared_scanner'] = await asyncio.to_thread(bulk._bulk_vuln_scan, 'fixture.test')
    out['bulk_invalid_tool'] = json.loads(bulk.bulk_scan('fixture.test', tool='nonexistent'))

    params = importlib.import_module('cyber_tools.param_discovery')
    urls = []
    def param_handler(request):
        urls.append(str(request.url))
        return httpx.Response(200, text='constant')
    with patch('cyber_tools.http_guard.GuardedAsyncClient', return_value=httpx.AsyncClient(transport=httpx.MockTransport(param_handler))):
        await params.discover_params('https://fixture.test/search?tenant=1')
    out['param_query'] = urls[:3]

    scanner = importlib.import_module('cyber_tools.vuln_scanner')
    def dead(request):
        raise httpx.ConnectError('synthetic offline connection failure', request=request)
    with patch.object(scanner, 'GuardedAsyncClient', return_value=httpx.AsyncClient(transport=httpx.MockTransport(dead))):
        failed = await scanner.vuln_scanner('https://fixture.test')
    out['vuln_scan_all_connections_failed'] = {k: failed.get(k) for k in ('count', 'error', 'coverage', 'verified_count')}
    def catchall(request):
        return httpx.Response(200, headers={'Content-Type': 'text/html'}, text='<html>Laravel public landing</html>' + 'x' * 240)
    with patch.object(scanner, 'GuardedAsyncClient', return_value=httpx.AsyncClient(transport=httpx.MockTransport(catchall))):
        found = await scanner.vuln_scanner('https://fixture.test')
    out['laravel_catchall'] = [f for f in found['vulnerabilities'] if f['name'].startswith('Laravel')]

    converter = importlib.import_module('cyber_tools.report_schema_v2')
    out['vuln_scan_conversion'] = json.loads(converter._convert_v1_to_v2(found))

    retest = importlib.import_module('cyber_tools.retest_vuln')
    with patch.object(retest.httpx, 'get', return_value=httpx.Response(302, headers={'Location': 'https://evil.com'})):
        out['redirect_retest'] = json.loads(retest.retest_vuln('https://fixture.test/redirect', 'open_redirect'))
    with patch.object(retest.httpx, 'get', return_value=httpx.Response(200, text='<script>/* ordinary script */</script>')):
        out['static_script_retest'] = json.loads(retest.retest_vuln('https://fixture.test/', 'xss'))

    oast = importlib.import_module('cyber_tools.oast_callback_server')
    generated = json.loads(oast.oast_callback_server('generate'))
    out['oast'] = generated
    if generated.get('callback_id'):
        out['oast']['poll'] = json.loads(oast.oast_callback_server('poll', callback_id=generated['callback_id'], max_wait=0))
        oast.CALLBACKS.pop(generated['callback_id'])
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    asyncio.run(main())

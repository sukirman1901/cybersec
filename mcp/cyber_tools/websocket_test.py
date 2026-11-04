"""Bounded same-origin HTTP handshake observations; no frames or auth tests."""
import base64
import hashlib
import json
import os
import re
import httpx
from .surface_probe import SurfaceProbe


async def websocket_test(target: str) -> dict:
    result = {'target':'[invalid target]','findings':[],'observations':[],'vulnerable':False,
              'coverage_complete':False,'assessment':'not_auth_tested','scope_authorized':False,
              'coverage':'One page, first 32 URL matches, up to three same-origin HTTP upgrades and one Engine.IO GET; accept hash/header validation only, no WebSocket frames; custom paths redacted',
              'unsupported_detection':['CSWSH/authentication','cross-origin endpoints','query-dependent endpoints','message protocol','Socket.IO application semantics','origin-policy enforcement']}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        if url.scheme not in ('http','https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        url = url.copy_with(query=None,fragment=None)
        result['target'] = str(url)
    except (httpx.InvalidURL,ValueError,TypeError):
        return {**result,'error':'Invalid HTTP target'}
    async with httpx.AsyncClient(timeout=5.0,verify=False,trust_env=False,follow_redirects=False) as client:
        probe = SurfaceProbe(client,max_requests=5)
        root = await probe.request('GET',url)
        if root is not None and root.status_code == 200:
            endpoints = []
            for index, match in enumerate(re.finditer(r'wss?://[^"\'\s<>]+',root.text)):
                if index >= 32:
                    result['links_truncated'] = True
                    break
                value = match.group(0)
                try:
                    ws = httpx.URL(value)
                    endpoint = ws.copy_with(scheme='https' if ws.scheme=='wss' else 'http',query=None,fragment=None)
                except httpx.InvalidURL:
                    continue
                if not ws.userinfo and (endpoint.scheme,endpoint.host,endpoint.port)==(url.scheme,url.host,url.port) and endpoint not in endpoints:
                    endpoints.append(endpoint)
            if not endpoints:
                endpoints = [url.copy_with(path=path) for path in ('/ws','/websocket','/socket.io/')]
            result['endpoints_deferred'] = max(0,len(endpoints)-3)
            for index, endpoint in enumerate(endpoints[:3]):
                key = base64.b64encode(os.urandom(16)).decode()
                headers = {'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':key}
                response = await probe.request('GET',endpoint,headers=headers)
                if response is None:
                    break
                expected = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                if response.status_code==101 and response.headers.get('upgrade','').strip().lower()=='websocket' and 'upgrade' in {x.strip().lower() for x in response.headers.get('connection','').split(',')} and response.headers.get('sec-websocket-accept')==expected:
                    result['observations'].append({'type':'websocket_handshake','endpoint_index':index,
                        'endpoint':endpoint.path if endpoint.path in ('/ws','/websocket','/socket.io/') else '[redacted path]',
                        'assessment':'valid_upgrade_response_not_auth_proof','confidence':'HIGH','coverage':result['coverage']})
                elif response.status_code == 101:
                    probe.errors.append('invalid_websocket_upgrade_headers')
            if not probe.stopped:
                response = await probe.request('GET',url.copy_with(path='/socket.io/',query=b'EIO=4&transport=polling'))
                if response is not None and response.status_code==200 and response.text.startswith('0'):
                    try:
                        data = json.loads(response.text[1:])
                        if isinstance(data,dict) and isinstance(data.get('sid'),str) and data['sid'] and isinstance(data.get('upgrades'),list) and all(isinstance(x,str) for x in data['upgrades']) and all(type(data.get(k)) is int and data[k]>0 for k in ('pingInterval','pingTimeout')):
                            result['observations'].append({'type':'engine_io_open_packet','assessment':'protocol_structure_only','endpoint':'/socket.io/',
                                'confidence':'HIGH','coverage':'Initial Engine.IO v4 polling GET returned a structurally valid open packet; no session continuation, frames or authentication tests'})
                        else:
                            probe.errors.append('malformed_engine_io_packet')
                    except (ValueError,RecursionError):
                        probe.errors.append('malformed_engine_io_packet')
        elif root is not None:
            probe.errors.append('root_not_successful')
    result.update(probe.summary())
    if result.get('endpoints_deferred') or result.get('links_truncated'):
        result.update(coverage_complete=False,execution_status='partial')
    return result

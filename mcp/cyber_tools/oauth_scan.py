"""Read-only OAuth/OIDC metadata and error observations, not bypass detection."""
import uuid
import httpx
from .surface_probe import SurfaceProbe

OAUTH_ENDPOINTS = ['/.well-known/openid-configuration','/.well-known/oauth-authorization-server',
                   '/oauth/authorize','/oauth2/authorize']
_ERRORS = {'invalid_request','invalid_client','unauthorized_client','unsupported_response_type','invalid_scope','access_denied'}


async def oauth_scan(target: str) -> dict:
    result = {'target':'[invalid target]','findings':[],'count':0,'observations':[],
              'coverage_complete':False,'assessment':'not_bypass_tested',
              'paths_not_checked':['/oauth/token','/oauth/revoke','/oauth/authorization','/oauth2/token',
                                   '/api/oauth/authorize','/api/oauth/token','/auth/realms'],
              'coverage':'Four selected GET paths plus catch-all control; metadata/error shape only; no redirects followed',
              'unsupported_detection':['token/revocation requests','login/consent flows','redirect URI validation','state/PKCE enforcement','authorization bypass','other OAuth paths']}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        if url.scheme not in ('http','https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        base = str(url.copy_with(query=None,fragment=None)).rstrip('/')
        result['target'] = base
    except (httpx.InvalidURL, ValueError, TypeError):
        return {**result,'error':'Invalid HTTP target'}
    async with httpx.AsyncClient(timeout=5.0,verify=False,trust_env=False,follow_redirects=False) as client:
        probe = SurfaceProbe(client,max_requests=5)
        control = await probe.request('GET',base+'/.missing-'+uuid.uuid4().hex)
        if control is not None:
            for path in OAUTH_ENDPOINTS:
                response = await probe.request('GET',base+path)
                if response is None:
                    break
                if response.status_code not in (200,400) or (response.status_code == control.status_code and response.content == control.content):
                    continue
                try:
                    data = response.json()
                except (ValueError,RecursionError):
                    if path.startswith('/.well-known/'):
                        probe.errors.append('malformed_discovery_document')
                    continue
                if not isinstance(data,dict):
                    if path.startswith('/.well-known/'):
                        probe.errors.append('malformed_discovery_document')
                    continue
                if path.startswith('/.well-known/') and response.status_code == 200:
                    parsed = []
                    for field in ('issuer','authorization_endpoint'):
                        value = data.get(field)
                        try:
                            endpoint = httpx.URL(value) if isinstance(value,str) else None
                        except httpx.InvalidURL:
                            endpoint = None
                        if endpoint is None or endpoint.scheme not in ('http','https') or not endpoint.host or endpoint.userinfo:
                            break
                        parsed.append(endpoint)
                    if len(parsed) == 2:
                        result['observations'].append({'type':'authorization_server_metadata','endpoint':path,
                            'assessment':'unverified_provider_metadata','confidence':'MEDIUM','issuer_origin_matches_target':(parsed[0].scheme,parsed[0].host,parsed[0].port)==(url.scheme,url.host,url.port),
                            'coverage':result['coverage']})
                    else:
                        probe.errors.append('malformed_discovery_document')
                elif response.status_code == 400 and isinstance(data.get('error'),str) and data['error'] in _ERRORS:
                    result['observations'].append({'type':'oauth_error_response','endpoint':path,
                        'error_code':data['error'],'assessment':'request_rejected_not_bypass',
                        'confidence':'HIGH','coverage':'Recognized OAuth error in HTTP 400 response only; no authorization flow or bypass tested'})
    result.update(probe.summary())
    result['observation_count'] = len(result['observations'])
    return result

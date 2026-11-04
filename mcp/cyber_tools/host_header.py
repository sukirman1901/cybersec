"""Bounded host-header reflection observations; no poisoning/execution claims."""
import uuid
import httpx
from .surface_probe import SurfaceProbe


async def host_header(target: str) -> dict:
    result = {'target':'[invalid target]', 'tests':[], 'observations':[],
              'host_header_vulnerable':False, 'total_findings':0, 'techniques_found':[],
              'risk_summary':{'critical':0,'high':0,'medium':0}, 'cache_analysis':{}, 'header_analysis':{},
              'assessment':'reflection_only', 'coverage_complete':False,
              'coverage':'Baseline plus one GET each with Host/X-Forwarded-Host; reflection is not a demonstrated security effect',
              'unsupported_detection':['password reset poisoning','cache poisoning','SSRF','log poisoning','alternate headers/payloads','write actions']}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        if url.scheme not in ('http','https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        result['target'] = str(url.copy_with(query=None,fragment=None))
    except (httpx.InvalidURL, ValueError, TypeError):
        return {**result,'error':'Invalid HTTP target'}
    async with httpx.AsyncClient(timeout=5.0,verify=False,trust_env=False,follow_redirects=False) as client:
        probe = SurfaceProbe(client,max_requests=3)
        baseline = await probe.request('GET',url)
        if baseline is not None and baseline.status_code == 200:
            cache_names = sorted(k for k in baseline.headers if k in ('cache-control','age','via','x-cache','cf-cache-status'))
            result['cache_analysis'] = {'header_names':cache_names,'cache_headers_present':bool(cache_names),'cache_enabled':None}
            result['header_analysis'] = {k:k in baseline.headers for k in ('x-frame-options','x-content-type-options','strict-transport-security','content-security-policy')}
            for header in ('Host','X-Forwarded-Host'):
                marker = 'probe-' + uuid.uuid4().hex + '.invalid'
                response = await probe.request('GET',url,headers={header:marker})
                if response is None:
                    break
                reflected = response.status_code == 200 and marker not in baseline.text and marker in response.text
                result['tests'].append({'header':header,'status':response.status_code,'body_reflected':reflected})
                if reflected:
                    result['observations'].append({'type':'host_reflection','header':header,
                        'confidence':'HIGH','coverage':'Unique marker reflected in response body; downstream effect not tested'})
        elif baseline is not None:
            probe.errors.append('baseline_not_successful')
    result.update(probe.summary())
    return result

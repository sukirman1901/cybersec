"""Read-only provider-error candidates; no takeover confirmation or claiming."""
import re
import xml.etree.ElementTree as ET

import httpx
from .http_guard import GuardedAsyncClient
from .surface_probe import SurfaceProbe


async def sub_takeover(target: str) -> dict:
    result = {'target':'[invalid target]', 'takeover':False, 'candidates':[], 'signatures':[],
              'scope_authorized':False, 'coverage_complete':False,
              'assessment':'not_takeover_tested',
              'coverage':'One bounded GET; selected provider error signatures only; no DNS chain, resource availability, account ownership or claim validation',
              'unsupported_detection':['CNAME validation','provider resource claimability','takeover confirmation']}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        if url.scheme not in ('http','https') or not url.host or url.userinfo:
            raise ValueError('Invalid HTTP target')
        url = url.copy_with(query=None, fragment=None)
        result['target'] = str(url)
        async with GuardedAsyncClient(timeout=5.0, follow_redirects=False, verify=False, trust_env=False) as client:
            probe = SurfaceProbe(client, max_requests=1)
            response = await probe.request('GET',url)
            result.update(probe.summary())
            result['response_observed'] = result['coverage_complete']
            result['coverage_complete'] = False
            if response is None:
                return result
            result['status'] = response.status_code
            if response.status_code not in (400,404):
                return result
            text = response.text
            provider = None
            if re.search(r'<title>\s*Site not found\s*[·-]\s*GitHub Pages\s*</title>',text,re.I) and re.search(r'<h1>\s*There isn[’\']t a GitHub Pages site here\.?\s*</h1>',text,re.I):
                provider = 'GitHub Pages'
            elif re.search(r'<title>\s*No such app\s*</title>',text,re.I) and re.search(r'https://(?:www\.)?heroku\.com/',text,re.I):
                provider = 'Heroku'
            elif text.lstrip().startswith(('<Error>', '<?xml')) and '<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper():
                try:
                    root = ET.fromstring(text)
                    if root.tag == 'Error' and root.findtext('Code') == 'NoSuchBucket' and root.find('BucketName') is not None:
                        provider = 'S3-compatible storage'
                except ET.ParseError:
                    pass
            if provider:
                result['signatures'] = [provider + ' unavailable-resource response']
                result['candidates'] = [{'provider':provider, 'confidence':'LOW',
                    'assessment':'provider_error_candidate', 'coverage':result['coverage'],
                    'evidence':'Recognized provider-specific error structure; resource claimability unknown'}]
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, TypeError) as exc:
        result.update(error=type(exc).__name__, coverage_complete=False)
    return result

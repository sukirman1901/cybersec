"""Redacted CSRF token-like metadata from one GET; no protection attestation."""
import json
import re
import time
from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError

import httpx
from .http_guard import GuardedClient, guarded_urlopen  # legacy transport import compatibility

_NAMES = {'csrf-token','csrf_token','csrfmiddlewaretoken','_csrf','__requestverificationtoken',
          'authenticity_token','csrftoken','xsrf-token','xsrf_token'}
_HEADERS = ('x-csrf-token','x-csrftoken','csrf-token','x-xsrf-token')


class _TokenParser(HTMLParser):
    def __init__(self, record, hint):
        super().__init__(convert_charrefs=True)
        self.record, self.hint = record, hint

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        name = (values.get('name') or '').lower()
        if name not in _NAMES and (not self.hint or name != self.hint):
            return
        label = name if name in _NAMES else 'custom_hint'
        if tag == 'meta':
            self.record('meta_tag',label,values.get('content'))
        elif tag == 'input' and (values.get('type') or '').lower() == 'hidden':
            self.record('hidden_input',label,values.get('value'))


def csrf_extract(target: str, method: str = "get", param_hint: str = "") -> str:
    result = {'target':'[invalid target]','tokens_found':[],'extraction_methods':[],
              'token_analysis':[],'total_tokens':0,'csrf_protected':None,
              'assessment':'token_metadata_only','coverage_complete':False,'requests_attempted':0,
              'coverage':'One GET; known hidden/meta/header/cookie names or explicit hint; values always redacted; 100 token records, 256 KiB body, 10s processing deadline and 5s per-I/O timeout',
              'unsupported_detection':['server token validation','CSRF exploitability','JS variables/forms','token randomness/strength','non-GET methods']}
    try:
        if not isinstance(method,str) or method.lower() != 'get':
            raise ValueError('Only GET observations supported')
        if not isinstance(param_hint,str) or (param_hint and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',param_hint)):
            raise ValueError('Invalid parameter hint')
        url = httpx.URL(target if '://' in target else 'http://' + target)
        if url.scheme not in ('http','https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        result['target'] = str(url.copy_with(query=None,fragment=None))
        deadline = time.monotonic() + 10
        with GuardedClient(timeout=5.0,trust_env=False,follow_redirects=False) as client:
            result['requests_attempted'] = 1
            with client.stream('GET',url,headers={'User-Agent':'CybersecCSRF/1.0'},follow_redirects=False) as response:
                result['status'] = response.status_code
                if response.status_code != 200:
                    result['error'] = 'Non-success response; extraction incomplete'
                    return json.dumps(result,indent=2)
                if sum(len(k)+len(v) for k,v in response.headers.raw)>16384:
                    raise ValueError('Header limit')
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=16384):
                    if time.monotonic()>deadline:
                        raise TimeoutError('Processing deadline')
                    if len(body)+len(chunk)>262144:
                        raise ValueError('Body limit')
                    body.extend(chunk)
                if time.monotonic()>deadline:
                    raise TimeoutError('Processing deadline')
                result['body_size'] = len(body)
                def record(source, name, value):
                    if not isinstance(value,str) or not value:
                        return
                    if len(result['tokens_found']) >= 100:
                        result['token_limit_reached'] = True
                        return
                    metadata = {'source':source,'name':name,'value_present':True,
                                'value_length':len(value),'value':'[redacted]',
                                'confidence':'MEDIUM','coverage':'Nonempty value under a recognized token-like name or explicit hint; server validation and CSRF protection not tested'}
                    result['tokens_found'].append(metadata)
                    result['token_analysis'].append({'source':source,'value_length':len(value)})
                    if source not in result['extraction_methods']:
                        result['extraction_methods'].append(source)
                content_type = response.headers.get('content-type','').split(';',1)[0].strip().lower()
                is_html = content_type in ('text/html','application/xhtml+xml')
                result['content_type'] = content_type if is_html else 'uninspected_body_format'
                if is_html:
                    parser = _TokenParser(record,param_hint.lower())
                    parser.feed(bytes(body).decode('utf-8',errors='replace'))
                    parser.close()
                for name in _HEADERS:
                    record('response_header',name,response.headers.get(name))
                for header in response.headers.get_list('set-cookie'):
                    cookies = SimpleCookie()
                    try:
                        cookies.load(header)
                    except CookieError:
                        continue
                    for name, morsel in cookies.items():
                        if name.lower() in _NAMES and morsel['max-age'] != '0':
                            record('cookie_set-cookie',name.lower(),morsel.value)
                result['total_tokens'] = len(result['tokens_found'])
                result['coverage_complete'] = is_html and not result.get('token_limit_reached',False)
                result['extraction_summary'] = 'Token-like metadata observed; values redacted' if result['total_tokens'] else 'No supported token metadata observed'
    except (httpx.HTTPError,httpx.InvalidURL,ValueError,TypeError,TimeoutError) as exc:
        result.update(error=type(exc).__name__,coverage_complete=False)
    return json.dumps(result,indent=2)

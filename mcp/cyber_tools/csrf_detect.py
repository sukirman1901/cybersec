"""Read-only CSRF indicators; exploitability requires authenticated state-change proof."""
import re
from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urlsplit, urljoin, parse_qsl, urlencode, urlunsplit
import httpx
from .surface_probe import SurfaceProbe

TOKEN_NAMES = {'csrf_token', 'csrftoken', 'csrf-token', '_token', 'authenticity_token',
               'xsrf_token', 'xsrf-token', '__requestverificationtoken',
               'csrfmiddlewaretoken', 'antiforgerytoken', '_csrf', 'csrf'}
SENSITIVE_ACTIONS = ('password','email','transfer','payment','delete','update','create',
                     'admin','settings','profile','invite','share','grant','revoke','approve')


def _analyze_token(value):
    pattern = 'unknown'
    if re.fullmatch(r'[0-9]+', value):
        pattern = 'numeric_only'
    elif re.fullmatch(r'[a-fA-F0-9]+', value):
        pattern = 'hex'
    elif re.fullmatch(r'[A-Za-z0-9+/]+=*', value):
        pattern = 'base64_like'
    elif re.fullmatch(r'[A-Za-z0-9_-]+', value):
        pattern = 'alphanumeric_safe'
    return {'length':len(value), 'entropy':'unknown', 'pattern':pattern,
            'weaknesses':[], 'assessment':'single_sample_cannot_establish_predictability'}


def _analyze_cookies(headers):
    if isinstance(headers, str):
        headers = [headers] if headers else []
    cookies, values, failures = [], [], 0
    for header in headers:
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except CookieError:
            failures += 1
            continue
        if not parsed:
            failures += 1
        for name, cookie in parsed.items():
            same = cookie['samesite'].lower()
            present = [flag for flag in ('httponly','secure') if cookie[flag]]
            if same in ('lax','strict','none'):
                present.append('samesite')
            cookies.append({'name':name, 'flags_present':present,
                            'flags_missing':[flag for flag in ('httponly','secure','samesite') if flag not in present],
                            'samesite':same if same in ('lax','strict','none') else 'unspecified_or_invalid',
                            'assessment':'attribute_observation_not_csrf_proof'})
            if name.lower() in TOKEN_NAMES and cookie.value:
                values.append(cookie.value)
    return ({'cookies':cookies, 'parse_failures':failures,
             'risk':'NOT_APPLICABLE' if not headers else 'UNKNOWN' if failures else 'OBSERVATION'}, values)


def _safe_target(target):
    parts = urlsplit(target)
    host = parts.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    if parts.port is not None:
        host += ':' + str(parts.port)
    query = urlencode([(key, '[REDACTED]') for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, host, parts.path, query, ''))


class _Forms(HTMLParser):
    def __init__(self, target):
        super().__init__()
        self.target = target
        self.forms, self.tokens = [], []
        self.current = None
        self.meta_token = False
        self.deferred = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'meta' and (attrs.get('name') or '').lower() in ('csrf-token','csrf_token') and attrs.get('content'):
            self.meta_token = True
        if tag == 'form':
            if len(self.forms) >= 100:
                self.deferred += 1
                self.current = None
                return
            method = (attrs.get('method') or 'GET').upper()
            if method not in ('GET','POST','DIALOG'):
                method = 'GET'
            try:
                destination = urlsplit(urljoin(self.target, attrs.get('action') or self.target))
                origin = urlsplit(self.target)
                action = 'same_origin' if (destination.scheme, destination.hostname, destination.port or (443 if destination.scheme == 'https' else 80)) == (origin.scheme, origin.hostname, origin.port or (443 if origin.scheme == 'https' else 80)) else 'external_origin'
            except ValueError:
                action = 'unknown'
            self.current = {'form_index':len(self.forms)+1, 'method':method, 'action':action,
                            'has_csrf_token':False, 'token_details':None,
                            'has_sensitive_fields':False, 'sensitive_fields':[], 'vulnerable':False}
            self.forms.append(self.current)
        if self.current is not None and tag in ('input','textarea','select'):
            name = (attrs.get('name') or '').lower()
            for word in SENSITIVE_ACTIONS:
                if word in name and word not in self.current['sensitive_fields']:
                    self.current['sensitive_fields'].append(word)
            self.current['has_sensitive_fields'] = bool(self.current['sensitive_fields'])
            if tag == 'input' and name in TOKEN_NAMES and attrs.get('value'):
                self.current['has_csrf_token'] = True
                self.current['token_details'] = _analyze_token(attrs['value'])
                self.tokens.append(attrs['value'])

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


async def csrf_detect(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    result = {'target':_safe_target(target), 'forms':[], 'csrf_vulnerable_forms':[],
              'candidate_forms':[], 'security_checks':[], 'cookie_analysis':{}, 'header_analysis':{},
              'csrf_vulnerable':False, 'total_findings':0,
              'risk_summary':{'critical':0,'high':0,'medium':0},
              'assessment':'inconclusive', 'confidence':'LOW',
              'coverage':'One bounded GET; form and cookie observations only; no authenticated cross-site state-change test',
              'checks_not_performed':['token_validation','origin_enforcement_on_state_change',
                                      'browser_samesite_behavior','javascript_forms','external_form_association',
                                      'submit_button_overrides','token_entropy_measurement']}
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=1)
        response = await probe.request('GET', target)
        if response is None:
            return {**result, **probe.summary()}
        if response.status_code != 200:
            probe.errors.append('non_success_response')
            return {**result, **probe.summary()}
        parser = _Forms(target)
        parser.feed(response.text)
        for form in parser.forms:
            form['assessment'] = 'token_observed_not_validated' if form['has_csrf_token'] else 'token_not_observed' if form['method'] == 'POST' else 'not_assessed'
            if form['assessment'] == 'token_not_observed':
                result['candidate_forms'].append(form['form_index'])
        cookie_analysis, cookie_tokens = _analyze_cookies(response.headers.get_list('set-cookie'))
        if cookie_analysis['parse_failures']:
            probe.errors.append('cookie_parse_incomplete')
        if parser.deferred:
            probe.errors.append('form_limit_exceeded')
        result.update({'forms':parser.forms, 'forms_deferred':parser.deferred,
                       'meta_token_observed':parser.meta_token, 'cookie_analysis':cookie_analysis,
                       'assessment':'not_exploit_tested',
                       'header_analysis':{name:bool(response.headers.get(name)) for name in
                                          ('x-frame-options','x-content-type-options','strict-transport-security','content-security-policy')}})
        result['security_checks'] = [
            {'check':'Double-submit cookie pattern', 'observed':bool(set(cookie_tokens) & set(parser.tokens)),
             'vulnerable':False, 'assessment':'matching_value_is_not_a_vulnerability'},
            {'check':'Token-like URL parameter', 'observed':any(key.lower() in TOKEN_NAMES | {'token','xsrf'} for key, _ in parse_qsl(urlsplit(target).query)),
             'vulnerable':False, 'assessment':'token_purpose_and_leakage_not_verified'},
        ]
    return {**result, **probe.summary()}

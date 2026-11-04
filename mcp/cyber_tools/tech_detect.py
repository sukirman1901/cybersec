"""Bounded technology hints from resource attributes and explicit headers."""
import re
from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urlsplit
from .surface_probe import SurfaceProbe


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets, self.generators, self.markers = [], [], set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script','link','img'):
            value = attrs.get('href' if tag == 'link' else 'src')
            if value:
                self.assets.append(value.lower())
        if tag == 'meta' and (attrs.get('name') or '').lower() == 'generator':
            self.generators.append((attrs.get('content') or '').lower())
        if attrs.get('id') in ('__NEXT_DATA__', '___gatsby'):
            self.markers.add(attrs['id'])
        if 'ng-version' in attrs or 'ng-app' in attrs:
            self.markers.add('angular')


CMS_ASSETS = {
    'WordPress':r'/(?:wp-content|wp-includes)/', 'Joomla':r'/components/com_',
    'Drupal':r'/sites/default/files/', 'Shopify':r'^https?://cdn\.shopify\.com/',
    'Wix':r'^https?://[^/]*\.wixstatic\.com/', 'Squarespace':r'^https?://[^/]*\.squarespace\.com/',
    'Webflow':r'/[^/]*webflow[^/]*\.js$', 'Ghost':r'^https?://[^/]*\.ghost\.io/',
    'Magento':r'/mage/',
}
JS_ASSETS = {
    'React':r'/react(?:\.production\.min)?\.js$', 'Vue.js':r'/vue(?:\.runtime)?(?:\.min)?\.js$',
    'Angular':r'/angular(?:\.min)?\.js$', 'jQuery':r'/jquery(?:-[\d.]+)?(?:\.min)?\.js$',
    'Bootstrap':r'/bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)$',
    'Tailwind':r'/tailwind(?:css)?(?:\.min)?\.css$', 'Next.js':r'/_next/static/',
    'Gatsby':r'/gatsby[^/]*\.js$',
}


async def detect_technologies(url: str) -> dict:
    from .http_guard import GuardedAsyncClient
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = {'web_server':None, 'cms':None, 'programming_languages':[],
              'javascript_frameworks':[], 'cdn':[], 'analytics':[],
              'technologies':[], 'headers':{}, 'http_status':None,
              'confidence':'MEDIUM', 'assessment':'fingerprint_hints_not_runtime_proof',
              'coverage':'One bounded response, explicit headers and markup attributes; no script execution or redirects'}
    async with GuardedAsyncClient(timeout=5.0, verify=True) as client:
        probe = SurfaceProbe(client, max_requests=1)
        response = await probe.request('GET', url)
        if response is None:
            return {**result, **probe.summary()}
        result['http_status'] = response.status_code
        if response.status_code != 200:
            probe.errors.append('non_success_response')
            return {**result, **probe.summary()}
        headers = response.headers
        # Publish known product names only, never arbitrary header/cookie values.
        for name in ('nginx','apache','caddy','microsoft-iis','cloudflare'):
            if re.search(r'(?i)(?:^|\s)' + re.escape(name) + r'(?:/|\s|$)', headers.get('server','')):
                result['web_server'] = name
                result['headers']['server'] = name
                result['technologies'].append(name)
                break
        powered = headers.get('x-powered-by','')
        languages = set()
        for pattern, language in ((r'\bPHP(?:/|\b)','PHP'), (r'\bASP\.NET\b','ASP.NET')):
            if re.search(pattern, powered, re.I):
                languages.add(language)
        for value in headers.get_list('set-cookie'):
            cookie = SimpleCookie()
            try:
                cookie.load(value)
            except CookieError:
                continue
            for name in cookie:
                language = {'phpsessid':'PHP', 'asp.net_sessionid':'ASP.NET', 'jsessionid':'Java'}.get(name.lower())
                if language:
                    languages.add(language)
        result['programming_languages'] = sorted(languages)
        markup = _Markup()
        markup.feed(response.text)
        assets = [asset.split('?',1)[0].split('#',1)[0] for asset in markup.assets]
        for cms, pattern in CMS_ASSETS.items():
            if any(re.search(pattern, asset) for asset in assets) or any(re.match(re.escape(cms.lower()) + r'(?:\s|/|$)', gen) for gen in markup.generators):
                result['cms'] = cms
                result['technologies'].append('CMS:' + cms)
                break
        for framework, pattern in JS_ASSETS.items():
            marker = {'Next.js':'__NEXT_DATA__','Gatsby':'___gatsby','Angular':'angular'}.get(framework)
            if any(re.search(pattern, asset) for asset in assets) or marker in markup.markers:
                result['javascript_frameworks'].append(framework)
                result['technologies'].append('JS:' + framework)
        for cdn, header in (('Cloudflare','cf-ray'), ('Akamai','x-akamai-transformed'),
                            ('Fastly','x-fastly-request-id'), ('AWS CloudFront','x-amz-cf-id'),
                            ('Vercel','x-vercel-id'), ('Netlify','x-nf-request-id')):
            if header in headers:
                result['cdn'].append(cdn)
                result['technologies'].append('CDN:' + cdn)
        for asset in assets:
            try:
                host = urlsplit(asset).hostname or ''
            except ValueError:
                continue
            analytics = None
            if host in ('www.google-analytics.com','www.googletagmanager.com'):
                analytics = 'Google Analytics' if host.endswith('google-analytics.com') else 'Google Tag Manager'
            elif host == 'connect.facebook.net' and asset.endswith('/fbevents.js'):
                analytics = 'Facebook Pixel'
            if analytics and analytics not in result['analytics']:
                result['analytics'].append(analytics)
                result['technologies'].append('Analytics:' + analytics)
    return {**result, **probe.summary()}

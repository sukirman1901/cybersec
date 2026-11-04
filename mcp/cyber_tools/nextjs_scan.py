"""Next.js hints and linked source-map inspection; public bundles are expected."""
import re
from urllib.parse import urljoin, urlsplit
import httpx
from .surface_probe import SurfaceProbe


async def nextjs_scan(target: str) -> dict:
    findings = []
    result = {'target':target, 'nextjs_detected':False, 'findings':findings,
              'coverage':'Homepage and at most three explicitly linked same-origin source maps; no dev-server exploit testing'}
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=4)
        root = await probe.request('GET', target)
        if root is not None and root.status_code == 200:
            body = root.text
            result['nextjs_detected'] = bool(re.search(r'<script\b[^>]*\bid=[\"\']__NEXT_DATA__[\"\']', body, re.I)
                                              or re.search(r'(?:src|href)=[\"\'][^\"\']*/_next/static/', body, re.I)
                                              or any(k.startswith('x-nextjs-') for k in root.headers))
            candidates = []
            for ref in re.findall(r'(?:src|href)=[\"\']([^\"\']+\.map)[\"\']', body, re.I):
                url = urljoin(target, ref)
                parsed, origin = urlsplit(url), urlsplit(target)
                if (parsed.scheme, parsed.hostname, parsed.port) != (origin.scheme, origin.hostname, origin.port) or parsed.username or parsed.password:
                    continue
                if '/_next/static/' in parsed.path and url not in candidates:
                    candidates.append(url)
            for url in candidates[:3]:
                response = await probe.request('GET', url)
                if response is None:
                    break
                if response.status_code != 200:
                    continue
                try:
                    data = response.json()
                except ValueError:
                    continue
                if not isinstance(data, dict) or data.get('version') != 3 or not isinstance(data.get('mappings'), str):
                    continue
                sources, contents = data.get('sources'), data.get('sourcesContent')
                if not isinstance(sources, list) or not sources or not all(isinstance(s,str) for s in sources):
                    continue
                embedded = isinstance(contents,list) and len(contents)==len(sources) and any(isinstance(c,str) and c.strip() for c in contents)
                findings.append({'path':urlsplit(url).path, 'target':url, 'status':200,
                                 'severity':'medium' if embedded else 'info',
                                 'desc':'Source map contains embedded source' if embedded else 'Source map metadata observed',
                                 'evidence':{'version':3,'sources_count':len(sources),'embedded_source':bool(embedded)},
                                 'confidence':'HIGH', 'assessment':'observed_source_map; sensitivity not assessed',
                                 'coverage':result['coverage']})
            if len(candidates)>3:
                probe.errors.append('source_map_candidate_limit')
    return {**result, 'count':len(findings), **probe.summary()}

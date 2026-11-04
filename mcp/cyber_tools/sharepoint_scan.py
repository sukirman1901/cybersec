"""Read-only SharePoint hints and selected structured resource observations."""
import re
import uuid
import xml.etree.ElementTree as ET
import httpx
from .surface_probe import SurfaceProbe

SHAREPOINT_PATHS = ['/web.config','/web.config.bak','/_api/','/_vti_bin/lists.asmx']
_UNSUPPORTED_PATHS = ['/_layouts/','/_vti_bin/','/_catalogs/','/_themes/','/SitePages/',
    '/Shared%20Documents/','/_vti_pvt/','/_vti_cnf/','/_vti_log/','/_vti_script/',
    '/wpresources/','/_app_bin/','/_admin/','/discover/','/search/','/sites/','/teams/',
    '/_vti_bin/owssvr.dll','/_vti_bin/search.asmx','/_vti_bin/webs.asmx',
    '/_vti_bin/sitedata.asmx','/_vti_bin/UserGroup.asmx','/_vti_bin/People.asmx','/_vti_bin/Forms.asmx']


async def sharepoint_scan(target: str) -> dict:
    result = {'target':'[invalid target]','is_sharepoint':False,'findings':[],
              'observations':[],'vulnerable':False,'coverage_complete':False,
              'paths_not_checked':list(_UNSUPPORTED_PATHS),'paths_skipped':list(SHAREPOINT_PATHS),
              'assessment':'read_only_observations',
              'coverage':'Root header hints; four selected structured resources only when a product header hint exists, with missing-path control; no permission or credential validation',
              'unsupported_detection':['other SharePoint paths','authentication/authorization','credential validity','version vulnerability correlation','write actions']}
    try:
        url = httpx.URL(target if '://' in target else 'https://' + target)
        if url.scheme not in ('http','https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        base = str(url.copy_with(query=None,fragment=None)).rstrip('/')
        result['target'] = base
    except (httpx.InvalidURL, ValueError, TypeError):
        return {**result,'error':'Invalid HTTP target'}
    async with httpx.AsyncClient(timeout=5.0,verify=False,trust_env=False,follow_redirects=False) as client:
        probe = SurfaceProbe(client,max_requests=6)
        root = await probe.request('GET',base)
        if root is not None and root.status_code == 200:
            hint = any(h in root.headers for h in ('microsoftsharepointteamservices','x-sharepointhealthscore','sprequestguid'))
            result['is_sharepoint'] = hint
            if hint:
                result['observations'].append({'type':'sharepoint_header_hint','assessment':'unverified_product_hint',
                    'confidence':'LOW','coverage':'Product-associated header presence only; product identity not verified'})
                control = await probe.request('GET',base+'/.missing-'+uuid.uuid4().hex)
                if control is not None:
                    for path in SHAREPOINT_PATHS:
                        response = await probe.request('GET',base+path)
                        if response is None:
                            break
                        result['paths_skipped'].remove(path)
                        if response.status_code != 200 or response.content in (control.content,root.content):
                            continue
                        kind = None
                        if path == '/_api/':
                            try:
                                data = response.json()
                                record = data.get('d') if isinstance(data,dict) else None
                                meta = record.get('__metadata') if isinstance(record,dict) else None
                                if isinstance(meta,dict) and meta.get('type') == 'SP.Web':
                                    kind = 'sharepoint_api_structure'
                            except (ValueError,RecursionError):
                                pass
                        elif response.text.lstrip().startswith('<') and not re.search(r'<!DOCTYPE|<!ENTITY',response.text,re.I):
                            try:
                                tree = ET.fromstring(response.text)
                                if path.startswith('/web.config') and tree.tag == 'configuration' and any(tree.find(key) is not None for key in ('system.web','connectionStrings','appSettings')):
                                    kind = 'configuration_source_structure'
                                elif path.endswith('.asmx') and tree.tag == '{http://schemas.xmlsoap.org/wsdl/}definitions' and 'sharepoint' in tree.attrib.get('targetNamespace','').lower():
                                    kind = 'sharepoint_wsdl_structure'
                            except ET.ParseError:
                                pass
                        if kind:
                            result['observations'].append({'type':kind,'path':path,'status':200,
                                'assessment':'recognized_structure','confidence':'MEDIUM','coverage':result['coverage']})
        elif root is not None:
            probe.errors.append('root_not_successful')
    result.update(probe.summary())
    if result['paths_skipped']:
        result.update(coverage_complete=False,execution_status='partial')
    return result

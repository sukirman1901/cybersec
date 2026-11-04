"""Read-only Spring Actuator JSON inspection; heap dumps are not requested."""
import re
import httpx
from .framework_surface import inspect_paths

PATHS = ['/actuator', '/actuator/env', '/actuator/beans', '/actuator/mappings',
         '/actuator/health', '/actuator/info', '/actuator/threaddump',
         '/actuator/loggers', '/actuator/configprops', '/env', '/trace', '/dump']


def _classify(path, response):
    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if path == '/actuator/health' and data.get('status') in ('UP','DOWN','OUT_OF_SERVICE','UNKNOWN'):
        return 'health_status', 'info', False
    if path == '/actuator' and isinstance(data.get('_links'), dict) and isinstance(data['_links'].get('self'), dict) and isinstance(data['_links']['self'].get('href'), str):
        return 'actuator_link_index', 'info', True
    if path in ('/actuator/env', '/env') and isinstance(data.get('activeProfiles'), list) and isinstance(data.get('propertySources'), list) and any(isinstance(p, dict) and isinstance(p.get('name'),str) and isinstance(p.get('properties'),dict) for p in data['propertySources']):
        return 'environment_property_sources', 'medium', True
    if path in ('/actuator/beans','/actuator/mappings','/actuator/configprops'):
        key = {'/actuator/beans':'beans','/actuator/mappings':'mappings','/actuator/configprops':'beans'}[path]
        contexts = data.get('contexts')
        if isinstance(contexts, dict) and any(isinstance(c, dict) and isinstance(c.get(key),dict) and c[key] for c in contexts.values()):
            return 'actuator_' + path.rsplit('/',1)[1], 'medium', True
    if path == '/actuator/threaddump' and isinstance(data.get('threads'),list) and any(isinstance(t,dict) and isinstance(t.get('threadName'),str) and isinstance(t.get('stackTrace'),list) for t in data['threads']):
        return 'thread_metadata', 'medium', True
    if path == '/actuator/loggers' and isinstance(data.get('levels'),list) and isinstance(data.get('loggers'),dict) and any(isinstance(v,dict) and 'effectiveLevel' in v for v in data['loggers'].values()):
        return 'logger_configuration', 'medium', True
    return None


async def spring_scan(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    coverage = '12 GET paths plus root/control; structural Actuator JSON; heap dumps and legacy trace/dump formats not assessed'
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        result = await inspect_paths(client, target.rstrip('/'), PATHS, _classify,
            lambda r: 'x-application-context' in r.headers or bool(re.search(r'\bspring\b',r.headers.get('x-powered-by',''), re.I)), coverage)
    return {'target':target, 'spring_detected':result['framework_detected'],
            'checks_not_performed':['heapdump', 'legacy_trace_dump', 'actuator_write_operations'], **result}

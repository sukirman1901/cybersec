"""Bounded structural check for anonymous GraphQL introspection."""
from urllib.parse import urlsplit
import httpx
from .surface_probe import SurfaceProbe


async def graphql_introspect(target: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    urls = [target] if urlsplit(target).path.strip('/') else [target.rstrip('/') + p for p in ('/graphql','/graphql/','/api/graphql','/query')]
    result = {'target':target, 'introspection_open':False, 'confidence':'LOW',
              'coverage':'Anonymous __schema.types name query; no sensitive-data or authorization assessment'}
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        probe = SurfaceProbe(client, max_requests=len(urls))
        for url in urls:
            response = await probe.request('POST', url, json={'query':'{ __schema { types { name } } }'})
            if response is None:
                break
            if response.status_code != 200:
                continue
            try:
                data = response.json()
            except ValueError:
                continue
            data = data.get('data') if isinstance(data, dict) else None
            schema = data.get('__schema') if isinstance(data, dict) else None
            types = schema.get('types') if isinstance(schema, dict) else None
            if isinstance(types, list) and types and all(isinstance(t, dict) and isinstance(t.get('name'), str) for t in types):
                result.update(endpoint=url, introspection_open=True, types_count=len(types),
                              types=[t['name'] for t in types if not t['name'].startswith('__')][:50],
                              confidence='HIGH', assessment='observed_capability_not_exploit')
                break
    return {**result, **probe.summary()}

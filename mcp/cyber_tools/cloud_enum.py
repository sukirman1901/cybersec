import httpx
import re
import xml.etree.ElementTree as ET

AWS_BUCKET_PATTERNS = ["{name}", "{name}-prod", "{name}-dev", "{name}-staging", "{name}-backup", "{name}-data", "{name}-assets"]
AZURE_STORAGE_PATTERNS = ["{name}", "{name}prod", "{name}dev", "{name}staging", "{name}backup"]
GCP_BUCKET_PATTERNS = ["{name}", "{name}-prod", "{name}-dev", "{name}-staging", "{name}-backup"]


async def cloud_enum(company: str) -> dict:
    found = []
    observations = []
    if not isinstance(company, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', company):
        return {'resources_found': [], 'count': 0, 'error': 'Invalid company identifier', 'coverage_complete': False}
    candidates = []
    for pattern in AWS_BUCKET_PATTERNS:
        bucket = pattern.format(name=company)
        candidates.append(('AWS S3', 'bucket', bucket, f'https://{bucket}.s3.amazonaws.com'))
    for pattern in AZURE_STORAGE_PATTERNS:
        account = pattern.format(name=company)
        candidates.append(('Azure Blob', 'account', account, f'https://{account}.blob.core.windows.net'))
    for pattern in GCP_BUCKET_PATTERNS:
        bucket = pattern.format(name=company)
        candidates.append(('GCP Storage', 'bucket', bucket, f'https://storage.googleapis.com/{bucket}'))
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for provider, key, name, url in candidates:
            try:
                async with client.stream('GET', url) as resp:
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk[:65537 - len(body)])
                        if len(body) > 65536:
                            break
                matched = False
                if resp.status_code == 200 and len(body) <= 65536 and b'<!DOCTYPE' not in body.upper():
                    try:
                        root = ET.fromstring(body)
                        matched = provider in ('AWS S3', 'GCP Storage') and root.tag.rsplit('}', 1)[-1] == 'ListBucketResult' and any(
                            child.tag.rsplit('}', 1)[-1] == 'Name' and child.text == name for child in root)
                    except ET.ParseError:
                        pass
                observations.append({'provider': provider, key: name, 'status': resp.status_code,
                                     'outcome': 'matched' if matched else 'not_found' if resp.status_code == 404 else 'inconclusive'})
                if matched:
                    found.append({'provider': provider, key: name, 'status': resp.status_code, 'evidence': 'Matching bucket listing XML',
                                  'confidence': 'MEDIUM', 'coverage': 'HTTP listing structure candidate only; ownership and object access unverified'})
            except httpx.HTTPError:
                observations.append({'provider': provider, key: name, 'outcome': 'request_failed'})
    return {"company": company, "resources_found": found, "count": len(found), 'observations': observations,
            'coverage_complete': all(o['outcome'] in ('matched', 'not_found') for o in observations),
            'coverage': 'Candidate names only; denied/status-only responses do not confirm resource ownership'}

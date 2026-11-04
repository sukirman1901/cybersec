import asyncio
import re
import xml.etree.ElementTree as ET

import httpx

TOTAL_TIMEOUT = 15.0
MAX_BODY = 262144
MAX_RESULTS = 100


async def s3_scanner(bucket_name: str) -> dict:
    result = {"accessible": None, "public": None, "files": [], "total_files": 0,
              "complete": False, "confidence": "unknown", "requests": 0,
              "coverage": "One listing response only; no objects or pagination fetched."}
    if (not isinstance(bucket_name, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket_name)
            or any(part in bucket_name for part in ("..", ".-", "-."))
            or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", bucket_name)):
        return {**result, "error": "Invalid bucket name"}
    url = f"https://{bucket_name}.s3.amazonaws.com"
    result.update(bucket=bucket_name, url=url)
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, trust_env=False) as client:
                result['requests'] = 1
                async with client.stream('GET', url, headers={'Accept-Encoding': 'identity'}) as resp:
                    result['status'] = resp.status_code
                    if resp.status_code != 200:
                        return {**result, "note": "HTTP status alone does not establish bucket identity or permissions."}
                    if resp.headers.get('content-encoding', 'identity').lower() != 'identity':
                        return {**result, "error": "Encoded response not inspected"}
                    body = bytearray()
                    async for chunk in resp.aiter_bytes():
                        if len(body) + len(chunk) > MAX_BODY:
                            return {**result, "error": "Body budget exceeded"}
                        body.extend(chunk)
                # Reject DTDs/entities, including alternate XML encodings, before parsing.
                text = body.decode('utf-8-sig')
                if '\x00' in text or re.search(r'<!\s*(?:DOCTYPE|ENTITY)', text, re.I):
                    raise ValueError
                root = ET.fromstring(text)
                ns = '{http://s3.amazonaws.com/doc/2006-03-01/}' if root.tag.startswith('{') else ''
                def values(node, tag):
                    return node.findall(ns + tag)
                def one(node, tag):
                    items = values(node, tag)
                    if len(items) != 1 or list(items[0]):
                        raise ValueError
                    return items[0].text or ''
                if root.tag != ns + 'ListBucketResult' or one(root, 'Name') != bucket_name:
                    raise ValueError
                truncated = one(root, 'IsTruncated')
                if truncated not in ('true', 'false'):
                    raise ValueError
                entries = values(root, 'Contents')
                for entry in entries:
                    if not one(entry, 'Key') or not re.fullmatch(r'[0-9]{1,20}', one(entry, 'Size')):
                        raise ValueError
                result.update(accessible=True, public=True, confidence='high',
                              files=['[redacted object key]'] * min(len(entries), MAX_RESULTS),
                              total_files=len(entries), total_files_scope='observed page only',
                              complete=truncated == 'false' and len(entries) <= MAX_RESULTS,
                              note='Structured listing matches bucket identity; object keys withheld.')
    except (ValueError, ET.ParseError, UnicodeError):
        result['error'] = 'Malformed or unverified bucket listing'
    except (httpx.HTTPError, TimeoutError):
        result['error'] = 'Request failed or total time budget exceeded'
    return result

"""Bounded APK inventory and plain-XML manifest observations, not runtime testing."""
import asyncio
import io
import re
import stat
import struct
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
import httpx
from .http_guard import GuardedAsyncClient

MAX_INPUT = 16 * 1024 * 1024
MAX_MEMBER = 1024 * 1024


def _archive(data):
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise ValueError('Missing ZIP directory')
    _, disk, start_disk, count, total, size, offset, comment = struct.unpack('<4s4H2LH', data[end:end + 22])
    if disk or start_disk or count != total or total > 1000 or size > 262144 or offset + size > end or end + 22 + comment != len(data):
        raise ValueError('Unsupported or oversized ZIP directory')
    archive = zipfile.ZipFile(io.BytesIO(data))
    try:
        entries = archive.infolist()
        if len(entries) != total or sum(e.file_size for e in entries) > 32 * 1024 * 1024:
            raise ValueError('Archive budget exceeded')
        seen = set()
        for entry in entries:
            name = entry.filename
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if not name or name.startswith('/') or '\\' in name or ':' in name or '..' in name.split('/') or name != entry.orig_filename or name in seen:
                raise ValueError('Unsafe or duplicate archive member')
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or entry.flag_bits & 1 or entry.file_size > MAX_MEMBER:
                raise ValueError('Unsupported or oversized archive member')
            seen.add(name)
        return archive
    except Exception:
        archive.close()
        raise


async def apk_analyze(target: str) -> dict:
    try:
        if not isinstance(target, str) or len(target) > 4096:
            raise ValueError('Invalid target')
        url = urlsplit(target)
        if url.scheme not in {'https', 'http'} or not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment:
            raise ValueError('Invalid URL')
        url.port
    except ValueError:
        return {'error': 'Expected HTTP(S) artifact URL without credentials/query/fragment', 'findings': [], 'coverage_complete': False, 'execution_status': 'not_started'}
    try:
        async with asyncio.timeout(30), GuardedAsyncClient(timeout=10.0, follow_redirects=False, verify=True) as client:
            async with client.stream('GET', target) as response:
                if response.status_code != 200:
                    return {'target': target, 'error': 'APK download blocked, redirected or unsuccessful', 'findings': [], 'coverage_complete': False, 'execution_status': 'not_started'}
                data = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if len(data) + len(chunk) > MAX_INPUT:
                        raise ValueError('Download budget exceeded')
                    data.extend(chunk)
        with _archive(data) as archive:
            if 'AndroidManifest.xml' not in archive.namelist():
                raise ValueError('Missing manifest')
            with archive.open('AndroidManifest.xml') as stream:
                manifest = stream.read(MAX_MEMBER + 1)
            if len(manifest) > MAX_MEMBER or not manifest.lstrip().startswith(b'<') or b'<!DOCTYPE' in manifest or b'<!ENTITY' in manifest:
                return {'target': target, 'error': 'Binary AXML or unsupported manifest; no binary manifest decoder available', 'findings': [], 'coverage_complete': False, 'execution_status': 'partial'}
            root = ET.fromstring(manifest)
            if root.tag != 'manifest':
                raise ValueError('Not an Android manifest')
            android = '{http://schemas.android.com/apk/res/android}'
            declared = [node.get(android + 'name', '') for node in root.findall('uses-permission')]
            permissions = sorted({name.removeprefix('android.permission.') for name in declared if re.fullmatch(r'android\.permission\.[A-Z_]+', name)})
            exports = [node for app in root.findall('application') for node in app if node.tag in {'activity', 'activity-alias', 'service', 'receiver', 'provider'} and node.get(android + 'exported') == 'true']
            findings = [{'finding': 'APK archive inventory', 'entries': len(archive.infolist()), 'severity': 'info', 'assessment': 'observation'}]
            if permissions:
                sensitive = {'READ_SMS', 'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION', 'READ_EXTERNAL_STORAGE'}
                findings.append({'finding': 'Permissions declared', 'permissions': permissions[:20], 'dangerous': sorted(sensitive.intersection(permissions)),
                                 'severity': 'info', 'assessment': 'observation', 'coverage': 'Declared permissions only; grants and use not tested'})
            if exports:
                findings.append({'finding': 'Explicitly exported components', 'exported_count': len(exports), 'severity': 'medium',
                                 'assessment': 'candidate', 'confidence': 'medium', 'coverage': 'Static exported flag only; intent filters, permission guards, runtime reachability and exploitability not evaluated'})
            names = archive.namelist()
            findings.append({'finding': 'Code inventory', 'dex_present': any(re.fullmatch(r'classes[0-9]*\.dex', n) for n in names),
                             'native_library_count': sum(n.startswith('lib/') and n.endswith('.so') for n in names), 'severity': 'info', 'assessment': 'observation'})
            complete = len(permissions) <= 20 and len(permissions) == len(set(declared))
            return {'target': target, 'package': '[REDACTED]' if root.get('package') else 'unknown',
                    'permissions_count': len(set(declared)), 'findings': findings, 'count': len(findings),
                    'coverage_complete': complete, 'execution_status': 'completed' if complete else 'partial',
                    'truncated': len(permissions) > 20,
                    'coverage': 'Plain XML manifest only; binary AXML explicitly unsupported. No extraction, signature verification or execution. Custom permission names omitted. 30s download, 16 MiB input, 1 MiB/member, 32 MiB declared total, 1000 entries, 256 KiB directory, 20 displayed permissions.'}
    except (httpx.HTTPError, asyncio.TimeoutError, OSError, ValueError, TypeError, OverflowError, RecursionError, zipfile.BadZipFile, RuntimeError, NotImplementedError, ET.ParseError):
        return {'target': target, 'error': 'Request failed or APK is unsafe, oversized, malformed or unsupported', 'findings': [], 'coverage_complete': False, 'execution_status': 'not_started'}

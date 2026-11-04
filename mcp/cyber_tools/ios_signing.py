"""Decode provisioning declarations without claiming CMS or app-signature validity."""
import datetime
import io
import os
import plistlib
import re
import stat
import struct
import zipfile
from xml.parsers.expat import ExpatError

MAX_INPUT = 16 * 1024 * 1024
MAX_MEMBER = 1024 * 1024


def _archive(path):
    if not isinstance(path, str):
        raise ValueError('Expected local path')
    expected = os.lstat(path)
    if not stat.S_ISREG(expected.st_mode) or expected.st_size > MAX_INPUT:
        raise ValueError('Non-regular or oversized input')
    def opener(name, flags):
        return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with open(path, 'rb', opener=opener) as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError('Input changed')
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError('Input limit')
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


def _plist(archive, name, embedded=False):
    with archive.open(name) as stream:
        data = stream.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER or b'<!ENTITY' in data:
        raise ValueError('Unsupported plist')
    if embedded and not data.startswith(b'bplist'):
        start = data.find(b'<?xml')
        if start < 0:
            start = data.find(b'<plist')
        end = data.find(b'</plist>', max(start, 0))
        if start < 0 or end < 0:
            raise ValueError('Missing profile plist')
        data = data[start:end + 8]
    value = plistlib.loads(data)
    if not isinstance(value, dict):
        raise ValueError('Expected plist dictionary')
    return value


async def ios_signing(path: str) -> dict:
    try:
        with _archive(path) as archive:
            paths = [n for n in archive.namelist() if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n)]
            if len(paths) != 1:
                raise ValueError('Expected one main app plist')
            info = _plist(archive, paths[0])
            profile_path = paths[0].rsplit('/', 1)[0] + '/embedded.mobileprovision'
            if profile_path not in archive.namelist():
                return {'path': path, 'app_name': os.path.basename(path), 'provision_error': 'No main-app provisioning profile; signing status unknown',
                        'signature_verified': False, 'coverage_complete': False, 'execution_status': 'partial'}
            profile = _plist(archive, profile_path, embedded=True)
            entitlements = profile.get('Entitlements', {})
            devices = profile.get('ProvisionedDevices', [])
            if not isinstance(entitlements, dict) or not isinstance(devices, list) or not all(isinstance(d, str) for d in devices):
                raise ValueError('Malformed profile fields')
            debug = entitlements.get('get-task-allow')
            enterprise = profile.get('ProvisionsAllDevices', False)
            if (debug is not None and type(debug) is not bool) or type(enterprise) is not bool or (enterprise and devices):
                raise ValueError('Malformed profile flags')
            kind = 'enterprise' if enterprise else 'development' if devices and debug is True else 'ad_hoc' if devices and debug is False else 'app_store_candidate' if not devices and debug is False else 'unknown'
            safe_entitlements = {key: value if type(value) is bool else '[REDACTED]' for key, value in list(entitlements.items())[:20]}
            platform = profile.get('Platform', [])
            if not isinstance(platform, list) or not all(isinstance(p, str) for p in platform):
                raise ValueError('Malformed platform declaration')
            truncated = len(entitlements) > 20 or len(devices) > 20 or len(platform) > 20
            complete = kind != 'unknown' and not truncated
            return {'path': path, 'app_name': os.path.basename(path),
                    'bundle_identifier': '[REDACTED]' if 'CFBundleIdentifier' in info else 'unknown',
                    'app_id_name': '[REDACTED]' if 'AppIDName' in profile else 'N/A',
                    'team_name': '[REDACTED]' if 'TeamName' in profile else 'N/A',
                    'creation_date': profile['CreationDate'].isoformat() if isinstance(profile.get('CreationDate'), datetime.datetime) else None,
                    'expiration_date': profile['ExpirationDate'].isoformat() if isinstance(profile.get('ExpirationDate'), datetime.datetime) else None,
                    'platform': [p for p in platform[:20] if p in {'iOS', 'OSX', 'tvOS', 'watchOS', 'visionOS'}],
                    'entitlements': safe_entitlements, 'provisioned_devices': ['[REDACTED]'] * min(len(devices), 20),
                    'provisioned_devices_count': len(devices), 'is_adhoc': kind == 'ad_hoc', 'profile_type': kind,
                    'signature_verified': False, 'profile_verified': False, 'assessment': 'unverified_declaration',
                    'truncated': truncated, 'coverage_complete': complete, 'execution_status': 'completed' if complete else 'partial',
                    'coverage': 'Decoded main-app profile declarations only; CMS, code signature, certificate chain, expiry validity and device installation NOT verified. Development profiles are not ad-hoc. No extraction/executables. 16 MiB input, 1 MiB/member, 32 MiB declared total, 1000 entries, 256 KiB directory; identifiers redacted, 20 displayed devices/entitlements.'}
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, zipfile.BadZipFile, RuntimeError, NotImplementedError, ExpatError):
        return {'error': 'Missing, unsafe, oversized, malformed or unsupported IPA/profile',
                'signature_verified': False, 'coverage_complete': False, 'execution_status': 'not_started'}

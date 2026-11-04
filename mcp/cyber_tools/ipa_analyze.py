"""Bounded IPA metadata inspection; no extraction or signature verification."""
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


def _main_plist(archive):
    paths = [n for n in archive.namelist() if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n)]
    if len(paths) != 1:
        raise ValueError('Expected one main app Info.plist')
    with archive.open(paths[0]) as stream:
        data = stream.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        raise ValueError('Plist limit')
    result = plistlib.loads(data)
    if not isinstance(result, dict):
        raise ValueError('Plist must be a dictionary')
    return paths[0], result


async def ipa_analyze(path: str) -> dict:
    try:
        with _archive(path) as archive:
            plist_path, plist = _main_plist(archive)
            names = archive.namelist()
            review = [n for n in names if n.lower().endswith(('.dylib', '.sh')) or '.framework/' in n.lower()]
            truncated = len(review) > 20
            return {'path': path, 'app_name': os.path.basename(path), 'file_count': len(names),
                    'plist_found': True, 'plist_path': plist_path, 'entitlements': {},
                    'suspicious_files_count': len(review), 'suspicious_files': review[:20],
                    'assessment': 'observation', 'signature_verified': False,
                    'coverage_complete': not truncated, 'execution_status': 'partial' if truncated else 'completed',
                    'truncated': truncated,
                    'coverage': 'Main Info.plist metadata only; Info.plist is not signing entitlements. Frameworks/scripts are inventory, not maliciousness. No extraction/signature/runtime validation. 16 MiB input, 1 MiB/member, 32 MiB declared total, 1000 entries, 256 KiB directory, 20 displayed review paths.'}
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, zipfile.BadZipFile, RuntimeError, NotImplementedError, ExpatError):
        return {'error': 'Missing, unsafe, oversized, malformed or unsupported IPA/plist',
                'coverage_complete': False, 'execution_status': 'not_started'}

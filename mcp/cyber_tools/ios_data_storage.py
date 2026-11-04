"""Static packaged-storage candidates; not a scan of device data at rest."""
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


async def ios_data_storage(path: str) -> dict:
    try:
        with _archive(path) as archive:
            names = archive.namelist()
            paths = [n for n in names if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n)]
            if len(paths) != 1:
                raise ValueError('Expected one main app plist')
            with archive.open(paths[0]) as stream:
                data = stream.read(MAX_MEMBER + 1)
            if len(data) > MAX_MEMBER:
                raise ValueError('Plist limit')
            plist = plistlib.loads(data)
            if not isinstance(plist, dict):
                raise ValueError('Plist must be a dictionary')
            sensitive = [{'key': key, 'value_preview': '[REDACTED]', 'assessment': 'candidate',
                          'coverage': 'Sensitive-looking Info.plist key only; not proof of NSUserDefaults storage or a usable credential'}
                         for key in plist if re.search(r'password|secret|token|credential|(?:^|[_-])auth(?:$|[_-])', key, re.I)]
            storage = {'coredata': [n for n in names if any(part.endswith(('.xcdatamodel', '.xcdatamodeld', '.momd', '.mom')) for part in n.split('/'))],
                       'sqlite': [n for n in names if n.lower().endswith(('.sqlite', '.db'))],
                       'realm': [n for n in names if n.lower().endswith('.realm')]}
            refs = [n for n in names if n.lower().endswith(('.archive', '.data', '.plist')) and ('archive' in os.path.basename(n).lower())]
            truncated = len(sensitive) > 20 or len(refs) > 20 or any(len(v) > 20 for v in storage.values())
            return {'path': path, 'app_name': os.path.basename(path), 'sensitive_nsuserdefaults_keys': sensitive[:20],
                    'sensitive_keys_count': len(sensitive), 'storage_files': {k: v[:20] for k, v in storage.items()},
                    'storage_files_count': sum(map(len, storage.values())), 'archive_references': refs[:20],
                    'archive_references_count': len(refs), 'assessment': 'candidate', 'truncated': truncated,
                    'coverage_complete': not truncated, 'execution_status': 'partial' if truncated else 'completed',
                    'coverage': 'Packaged filenames and Info.plist keys only, not NSUserDefaults, live app data, encryption or exploit verification. Values redacted; no extraction. 16 MiB input, 1 MiB/member, 32 MiB declared total, 1000 entries, 256 KiB directory, 20 results/category.'}
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, zipfile.BadZipFile, RuntimeError, NotImplementedError, ExpatError):
        return {'error': 'Missing, unsafe, oversized, malformed or unsupported IPA/plist',
                'coverage_complete': False, 'execution_status': 'not_started'}

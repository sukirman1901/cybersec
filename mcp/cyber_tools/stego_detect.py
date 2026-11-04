"""Bounded structural/media and string candidates, not proof of steganography."""
import os
import re
import stat
import struct
import zlib

MAX_INPUT = 16 * 1024 * 1024


def _read(path):
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
    return data


def _png(data):
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Not PNG')
    offset, count = 8, 0
    while offset + 12 <= len(data):
        count += 1
        if count > 10000:
            raise ValueError('Chunk limit')
        size = struct.unpack('>I', data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + size
        if end > len(data) or (count == 1 and (kind != b'IHDR' or size != 13)):
            raise ValueError('Malformed PNG chunk')
        if zlib.crc32(data[offset + 4:end - 4]) != struct.unpack('>I', data[end - 4:end])[0]:
            raise ValueError('PNG CRC mismatch')
        if kind == b'IEND':
            if size:
                raise ValueError('Invalid IEND')
            return len(data) - end
        offset = end
    raise ValueError('Missing PNG IEND')


def _jpeg_exif(data):
    if not data.startswith(b'\xff\xd8'):
        raise ValueError('Not JPEG')
    offset, exif, segments = 2, False, 0
    while offset < len(data):
        segments += 1
        if segments > 10000 or offset + 2 > len(data) or data[offset] != 255:
            raise ValueError('Malformed JPEG marker')
        while offset < len(data) and data[offset] == 255:
            offset += 1
        if offset >= len(data):
            raise ValueError('Truncated JPEG marker')
        marker = data[offset]
        offset += 1
        if marker == 0xD9:
            return exif
        if marker in range(0xD0, 0xD8) or marker == 1:
            continue
        if offset + 2 > len(data):
            raise ValueError('Truncated JPEG length')
        size = struct.unpack('>H', data[offset:offset + 2])[0]
        if size < 2 or offset + size > len(data):
            raise ValueError('Malformed JPEG segment')
        if marker == 0xE1 and data[offset + 2:offset + 8] == b'Exif\0\0':
            exif = True
        offset += size
        if marker == 0xDA:
            # Only header metadata is inspected; no pixel/entropy decoding.
            if b'\xff\xd9' not in data[offset:]:
                raise ValueError('Missing JPEG end marker')
            return exif
    raise ValueError('Missing JPEG end marker')


async def stego_detect(path: str) -> dict:
    try:
        data = _read(path)
    except (OSError, ValueError):
        return {'error': 'Input missing, changed, unsafe or exceeds 16 MiB limit', 'coverage_complete': False, 'execution_status': 'not_started'}
    findings, errors = [], []
    extension = os.path.splitext(path)[1].lower()
    try:
        if extension == '.png' or data.startswith(b'\x89PNG\r\n\x1a\n'):
            trailing = _png(data)
            if trailing:
                findings.append({'type': 'trailing_data', 'size': trailing, 'assessment': 'candidate',
                                 'note': 'Bytes after validated IEND; contents and intent unverified'})
        elif extension in {'.jpg', '.jpeg'} or data.startswith(b'\xff\xd8'):
            if _jpeg_exif(data):
                findings.append({'type': 'exif_found', 'assessment': 'observation', 'note': 'EXIF-marked metadata is normal and not proof of hidden data'})
        elif extension == '.bmp':
            if len(data) < 14 or data[:2] != b'BM':
                raise ValueError('Invalid BMP header')
            size = struct.unpack('<I', data[2:6])[0]
            if size < 14 or size > len(data):
                raise ValueError('Invalid BMP size')
            if len(data) > size:
                findings.append({'type': 'trailing_data', 'size': len(data) - size, 'assessment': 'candidate', 'note': 'Bytes beyond BMP declared file size; intent unverified'})
    except (ValueError, struct.error):
        errors.append('Malformed/unsupported media structure or structural budget exceeded')
    runs = 0
    truncated = False
    for match in re.finditer(rb'[ -~]{8,}', data):
        runs += 1
        if runs > 5000:
            truncated = True
            break
        text = match[0][:4096].decode('ascii')
        if len(match[0]) > 4096:
            truncated = True
        found = re.search(r'\b(flag|ctf|secret|hidden|key|password)\b\s*[:=]\s*[^\s]{4,}', text, re.I)
        if found:
            if len(findings) >= 100:
                truncated = True
                break
            findings.append({'type': 'embedded_secret', 'kind': found[1].lower(), 'match': '[REDACTED]',
                             'offset': match.start() + found.start(), 'assessment': 'candidate',
                             'confidence': 'low', 'coverage': 'ASCII assignment-like bytes; not verified secret material or steganography'})
    if truncated:
        errors.append('String/result budget exceeded')
    complete = not errors
    return {'path': path, 'findings': findings, 'suspicious': any(f['assessment'] == 'candidate' for f in findings),
            'errors': errors, 'truncated': truncated, 'coverage_complete': complete,
            'execution_status': 'completed' if complete else 'partial',
            'coverage': 'Structural PNG/JPEG/BMP observations and ASCII candidates only; no pixel, LSB, cryptographic or steganographic payload validation. 16 MiB input, 10000 chunks/segments, 5000 ASCII runs, 4096 chars/run, 100 findings; matched values redacted.'}

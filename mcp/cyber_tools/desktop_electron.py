"""Bounded static Electron review. ASAR contents are read in memory, never extracted."""
import json
import os
import re
import struct
import stat

MAX_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 1000
INSECURE_PATTERNS = [
    (r'\bnodeIntegration\s*[:=]\s*true\b', 'nodeIntegration enabled'),
    (r'\bcontextIsolation\s*[:=]\s*false\b', 'contextIsolation disabled'),
    (r'\benableRemoteModule\s*[:=]\s*true\b', 'enableRemoteModule enabled'),
    (r'\bopenDevTools\s*\(', 'Debugger invocation; production reachability unknown'),
    (r'\bshell\s*\.\s*openExternal\s*\(', 'External URL handling requires review'),
    (r'\bwebContents\s*\.\s*send\s*\(', 'IPC send requires review'),
    (r'\bpreload\s*:', 'Custom preload requires bridge review'),
]


def _sources(data):
    if len(data) < 16:
        raise ValueError('Invalid ASAR header')
    size_size, header_size, payload_size, json_size = struct.unpack('<IIII', data[:16])
    start = 8 + header_size
    if size_size != 4 or header_size < 8 or payload_size != header_size - 4 or not 0 < json_size <= header_size - 8 or start > len(data):
        raise ValueError('Invalid ASAR header bounds')
    header = json.loads(data[16:16 + json_size])
    stack = [(header['files'], 0)]
    count = 0
    sources = []
    source_bytes = 0
    while stack:
        files, depth = stack.pop()
        if not isinstance(files, dict) or depth > 32:
            raise ValueError('Invalid or excessively nested ASAR directory')
        for name, entry in files.items():
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError('ASAR exceeds 1000 entries')
            if not name or name in {'.', '..'} or '/' in name or '\\' in name or ':' in name or '\0' in name or not isinstance(entry, dict):
                raise ValueError('Unsafe ASAR entry')
            if 'link' in entry or entry.get('unpacked'):
                raise ValueError('Linked or unpacked ASAR entries unsupported')
            if 'files' in entry:
                stack.append((entry['files'], depth + 1))
                continue
            offset, size = entry.get('offset'), entry.get('size')
            if not isinstance(offset, str) or not re.fullmatch(r'[0-9]{1,10}', offset) or type(size) is not int or size < 0:
                raise ValueError('Invalid ASAR file bounds')
            offset = int(offset)
            if offset + size > len(data) - start:
                raise ValueError('ASAR file outside archive bounds')
            if name.lower().endswith(('.js', '.cjs', '.mjs', '.json')):
                source_bytes += size
                if source_bytes > MAX_BYTES:
                    raise ValueError('ASAR expanded scan exceeds 8 MiB')
                sources.append((f'entry-{count}', data[start + offset:start + offset + size]))
    if sum(len(body) for _, body in sources) > MAX_BYTES:
        raise ValueError('ASAR expanded scan exceeds 8 MiB')
    return sources


async def desktop_electron(path: str) -> dict:
    if not isinstance(path, str) or not os.path.isfile(path) or os.path.islink(path):
        return {"error": "Expected an existing regular file, not a symlink", "coverage_complete": False, "execution_status": "not_started"}
    is_asar = path.lower().endswith('.asar')
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError('Artifact exceeds 8 MiB analysis limit')
        def open_regular(name, flags):
            return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with open(path, 'rb', opener=open_regular) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise OSError('File changed before open')
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('Artifact exceeds 8 MiB analysis limit')
        sources = _sources(data) if is_asar else [('input', data)]
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return {"path": path, "is_asar": is_asar, "error": "Unreadable, oversized or unsupported/malformed artifact", "risk": "UNKNOWN", "coverage_complete": False, "execution_status": "not_started"}
    findings = []
    for name, body in sources:
        content = body.decode('utf-8', errors='replace')
        # Lexical filtering, not a JS parser: omit comments and literal bodies.
        def filter_literal(match):
            literal = match[0]
            # Preserve exact quoted option keys, never arbitrary string bodies.
            if literal[0] in {'"', "'"} and literal[1:-1] in {'nodeIntegration', 'contextIsolation', 'enableRemoteModule', 'preload'} and re.compile(r'\s*:').match(content, match.end()):
                return literal[1:-1]
            return ' '
        content = re.sub(r'//[^\n]*|/\*[\s\S]*?(?:\*/|$)|"(?:\\.|[^"\\])*(?:"|$)|\'(?:\\.|[^\'\\])*(?:\'|$)|`(?:\\.|[^`\\])*(?:`|$)', filter_literal, content)
        for pattern, description in INSECURE_PATTERNS:
            if re.search(pattern, content):
                findings.append({"file": name, "pattern": pattern, "description": description,
                                 "assessment": "candidate", "confidence": "medium",
                                 "coverage": "Static lexical match only; runtime configuration, reachability and exploitability not verified"})
    complete = bool(sources) and len(findings) <= 100
    return {"path": path, "is_asar": is_asar, "insecure_findings": findings[:100],
            "coverage_complete": complete, "execution_status": "completed" if complete else "partial",
            "total_findings": len(findings), "risk": "MEDIUM" if findings else "INFO" if sources else "UNKNOWN",
            "coverage": {"sources_scanned": len(sources), "truncated": len(findings) > 100,
                         "limits": "8 MiB input and aggregate source data; 1000 ASAR entries; depth 32; no extraction or runtime evaluation. Lexical filtering is not a JS parser; computed keys, regex literals and dynamic code may be misclassified."}}

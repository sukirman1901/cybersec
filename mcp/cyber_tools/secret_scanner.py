"""Bounded local secret-pattern candidates; matched values are never returned."""
from collections import Counter
import math
import os
import re
import stat

SECRET_PATTERNS = [
    (r'(?<![\w])AKIA[0-9A-Z]{16}(?![\w])', 'AWS Access Key', 'HIGH'),
    (r'-----BEGIN (?P<kind>(?:RSA |EC )?PRIVATE KEY)-----\s+[A-Za-z0-9+/=\s]+-----END (?P=kind)-----', 'Private Key', 'HIGH'),
    (r'(?<![\w])gh[ps]_[0-9a-zA-Z]{36}(?![\w])', 'GitHub Token', 'HIGH'),
    (r'(?<![\w])sk-[a-zA-Z0-9]{32,128}(?![\w])', 'OpenAI API Key', 'MEDIUM'),
    (r'(?<![\w])AIza[0-9A-Za-z_-]{35}(?![\w-])', 'Google API Key', 'MEDIUM'),
    (r'(?i)\btoken\b["\']?\s*[:=]\s*["\']?([0-9a-zA-Z_.-]{16,128})(?![\w.-])', 'Generic Token', 'MEDIUM'),
    (r'(?i)\bpassword\b["\']?\s*[:=]\s*["\']?([^\s"\',;]{8,128})(?![^\s"\',;])', 'Password', 'MEDIUM'),
]
EXTENSIONS = {'.py', '.js', '.ts', '.go', '.rs', '.java', '.php', '.rb', '.env', '.json', '.yml', '.yaml', '.ini', '.cfg', '.conf', '.sh', '.bash', '.txt'}
SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.svn', '.hg', '.idea', '.vscode', 'dist', 'build', '.terraform'}
MAX_FILE = 256 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_FINDINGS = 200


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values())


def _targets(path, errors):
    info = os.lstat(path)
    if stat.S_ISREG(info.st_mode):
        return [(path, info)]
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('Non-regular target')
    pending, files, visited = [(path, info)], [], 0
    while pending:
        directory, expected = pending.pop()
        fd = None
        try:
            fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            opened = os.fstat(fd)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise OSError('Directory changed')
            with os.scandir(fd) as entries:
                for entry in entries:
                    visited += 1
                    if visited > 1000 or len(files) >= 100:
                        errors.append('Traversal budget exhausted')
                        return files
                    child = os.path.join(directory, entry.name)
                    child_info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(child_info.st_mode):
                        if entry.name not in SKIP_DIRS:
                            pending.append((child, child_info))
                    elif stat.S_ISLNK(child_info.st_mode):
                        errors.append('Symlink skipped')
                    elif not stat.S_ISREG(child_info.st_mode):
                        errors.append('Non-regular entry skipped')
                    elif stat.S_ISREG(child_info.st_mode) and (os.path.splitext(entry.name)[1].lower() in EXTENSIONS or entry.name == '.env' or entry.name.startswith('.env.')):
                        files.append((child, child_info))
        except OSError:
            errors.append('Directory unreadable or changed')
        finally:
            if fd is not None:
                os.close(fd)
    return files


def _read_source(path, expected, remaining):
    if expected.st_size > min(MAX_FILE, remaining):
        raise ValueError('Read budget exceeded')
    def open_regular(name, flags):
        return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with open(path, 'rb', opener=open_regular) as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError('File changed')
        data = stream.read(min(MAX_FILE, remaining) + 1)
    if len(data) > min(MAX_FILE, remaining):
        raise ValueError('Read budget exceeded')
    return data


async def secret_scanner(path: str, min_entropy: float = 4.5) -> dict:
    if not isinstance(path, str) or type(min_entropy) not in (int, float) or not 0 <= min_entropy <= 8:
        return {'error': 'Expected a local path and finite entropy threshold from 0 to 8', 'coverage_complete': False, 'execution_status': 'not_started'}
    errors, findings = [], []
    try:
        files = _targets(path, errors)
    except (OSError, ValueError):
        return {'error': 'Target missing, inaccessible or not regular', 'coverage_complete': False, 'execution_status': 'not_started'}
    scanned = total_bytes = 0
    truncated = False
    for file, info in files:
        try:
            data = _read_source(file, info, MAX_TOTAL - total_bytes)
            total_bytes += len(data)
            content = data.decode('utf-8')
        except (OSError, ValueError):
            errors.append('File unreadable, oversized, changed or invalid UTF-8')
            continue
        scanned += 1
        for pattern, kind, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(1) if kind in {'Password', 'Generic Token'} else match[0]
                entropy = shannon_entropy(value)
                if kind in {'Password', 'Generic Token'}:
                    if entropy < min_entropy or any(marker in value.lower() for marker in ('os.getenv', 'os.environ', 'process.env', '${', '{{', 'getenv(', 'example', 'placeholder', 'changeme')):
                        continue
                if len(findings) == MAX_FINDINGS:
                    truncated = True
                    break
                findings.append({'file': os.path.relpath(file, path) if os.path.isdir(path) else os.path.basename(path),
                                 'line': content.count('\n', 0, match.start()) + 1, 'type': kind,
                                 'severity': severity, 'match': '[REDACTED]', 'entropy': round(entropy, 2),
                                 'assessment': 'candidate', 'confidence': 'medium',
                                 'coverage': 'Local pattern only; validity, ownership and use not verified. Entropy filters generic assignments, not provider/private-key structure.'})
            if truncated:
                break
        if truncated:
            break
    if truncated:
        errors.append('Finding budget exhausted')
    complete = not errors and scanned > 0
    return {'path': path, 'files_scanned': scanned, 'secrets_found': len(findings), 'findings': findings,
            'risk': 'MEDIUM' if findings else 'UNKNOWN' if not complete else 'LOW', 'errors': errors,
            'coverage_complete': complete, 'execution_status': 'completed' if complete else 'partial' if scanned else 'not_started',
            'truncated': truncated, 'bytes_read': total_bytes,
            'coverage': 'UTF-8 files only; 256 KiB/file, 8 MiB total, 100 files, 1000 directory entries, 200 findings. Known dependency/build directories excluded; no credential validation.'}

import os
import re
import stat
import time

# Sensitive config file patterns
SUSPICIOUS_FILENAMES = [
    '.env', '.env.local', '.env.production', '.env.development',
    'config.json', 'credentials.json', 'passwords.txt', 'secrets.txt',
    'secret.json', 'settings.json', 'config.php', 'config.py',
    'database.yml', 'database.json', 'db.config', 'db.conf',
    'wp-config.php', '.ftpconfig', 'id_rsa', 'id_dsa',
    'terraform.tfvars', 'credentials.ini', 'tokens.txt', 'key.pem',
    'cert.pem', 'private.pem', 'appsettings.json',
]

SUSPICIOUS_DIRECTORIES = [
    '.config', '.aws', '.gcp', '.azure', '.ssh',
    'config', 'credentials', 'secrets',
]

SECRET_REGEX = re.compile(
    r'(?:^|[,{])\s*["\']?[\w-]*(password|secret|token|api[_-]?key|access[_-]?key'
    r'|private[_-]?key|bearer|jwt)[\w-]*["\']?\s*[:=]\s*["\']?'
    r'([^"\'\s,}]{6,})', re.IGNORECASE | re.MULTILINE
)


def _is_suspicious_filename(name: str) -> bool:
    """Check if a filename matches known sensitive config patterns."""
    for pattern in SUSPICIOUS_FILENAMES:
        if name.lower() == pattern.lower():
            return True
    return False


def _should_skip_dir(name: str) -> bool:
    """Skip common non-target directories."""
    skips = {'.git', '__pycache__', 'node_modules', '.venv', 'venv',
             '.svn', '.hg', '.idea', '.vscode', 'dist', 'build'}
    return name in skips


async def desktop_config(path: str, recursive: bool = True) -> dict:
    """Identify credential-like assignments without exposing values or following links."""
    findings, observations, errors = [], [], []
    scanned = visited = total_bytes = 0
    deadline = time.monotonic() + 15
    coverage = 'Selected config filenames or explicit regular file; 1000 entries, 256 KiB/file, 8 MiB total; 15s cooperative deadline; no credential validity test'

    def inspect(file, label):
        nonlocal scanned, total_bytes
        try:
            info = os.lstat(file)
            if not stat.S_ISREG(info.st_mode):
                errors.append('non_regular_file_skipped')
                return
            if info.st_size > 262144:
                errors.append('file_byte_limit')
                return
            if total_bytes + info.st_size > 8388608:
                errors.append('total_byte_limit')
                return
            def open_regular(name, flags):
                return os.open(name, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with open(file, 'rb', opener=open_regular) as handle:
                opened = os.fstat(handle.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    errors.append('file_changed_before_open')
                    return
                content = handle.read(min(262145, 8388608-total_bytes+1))
            total_bytes += len(content)
            if len(content) > 262144 or total_bytes > 8388608:
                errors.append('file_byte_limit')
                return
            scanned += 1
            text = content.decode('utf-8', errors='replace')
            matches = SECRET_REGEX.findall(text)
            if re.search(r'-----BEGIN ((?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----\s+\S[\s\S]+?-----END \1-----', text):
                matches.append(('private_key_structure', '[REDACTED]'))
            if matches:
                findings.append({'file':label, 'secrets_found':len(matches),
                                 'samples':sorted({kind.lower()+': [REDACTED]' for kind, _ in matches})[:5],
                                 'confidence':'MEDIUM', 'coverage':coverage,
                                 'assessment':'credential_assignment_candidate; validity unverified'})
            else:
                observations.append({'file':label, 'note':'No recognized credential assignment'})
        except OSError as exc:
            errors.append(type(exc).__name__)

    try:
        info = os.lstat(path)
        if stat.S_ISREG(info.st_mode):
            visited = 1
            inspect(path, os.path.basename(path))
        elif stat.S_ISDIR(info.st_mode):
            for root, dirs, files in os.walk(path, followlinks=False, onerror=lambda e: errors.append(type(e).__name__)):
                kept = []
                for name in dirs:
                    if os.path.islink(os.path.join(root,name)):
                        errors.append('symlink_directory_skipped')
                    elif not _should_skip_dir(name) and recursive:
                        kept.append(name)
                visited += len(dirs)
                dirs[:] = sorted(kept)
                for name in sorted(files):
                    if visited >= 1000 or time.monotonic() >= deadline or total_bytes >= 8388608:
                        errors.append('scan_budget_exhausted')
                        break
                    visited += 1
                    if _is_suspicious_filename(name):
                        file = os.path.join(root,name)
                        inspect(file, os.path.relpath(file,path))
                if 'scan_budget_exhausted' in errors or visited >= 1000 or time.monotonic() >= deadline:
                    if 'scan_budget_exhausted' not in errors:
                        errors.append('scan_budget_exhausted')
                    break
        else:
            errors.append('non_regular_target')
    except OSError as exc:
        errors.append(type(exc).__name__)
    return {'path':path, 'files_scanned':scanned, 'entries_visited':visited,
            'bytes_read':total_bytes, 'findings':findings, 'observations':observations,
            'total_findings':len(findings), 'risk':'MEDIUM' if findings else 'INCONCLUSIVE' if errors else 'NO_EVIDENCE',
            'coverage':coverage, 'coverage_complete':not errors,
            'execution_status':'partial' if errors else 'completed',
            **({'error':'Scan incomplete', 'errors':sorted(set(errors))} if errors else {})}

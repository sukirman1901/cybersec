"""Bounded source review. Syntax/pattern observations are never exploit proof."""
import ast
import os
import re
import stat

DANGEROUS_PATTERNS = {
    'JavaScript/TypeScript': [
        (r'\beval\s*\(', 'Dynamic eval call', 'MEDIUM'),
        (r'\bnew\s+Function\s*\(', 'Dynamic Function constructor', 'MEDIUM'),
        (r'\binnerHTML\s*=', 'HTML assignment requires data-flow review', 'MEDIUM'),
        (r'\bdocument\.write\s*\(', 'Document write requires data-flow review', 'MEDIUM'),
        (r'\brequire\s*\(\s*["\']child_process["\']\s*\)', 'Child-process module use', 'MEDIUM'),
        (r'\bexec\s*\(', 'exec-named call requires resolution', 'MEDIUM'),
    ],
}
EXTENSIONS_SAST = {'.py', '.js', '.ts', '.jsx', '.tsx'}
SKIP_DIRS_SAST = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.svn', '.hg', '.idea', '.vscode', 'dist', 'build'}
MAX_FILE = 256 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_FINDINGS = 200


def _get_language(ext: str) -> str:
    return 'Python' if ext == '.py' else 'JavaScript/TypeScript'


def _targets(path, errors):
    info = os.lstat(path)
    if stat.S_ISREG(info.st_mode):
        if os.path.splitext(path)[1].lower() not in EXTENSIONS_SAST:
            raise ValueError('Unsupported source extension')
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
                        if entry.name not in SKIP_DIRS_SAST:
                            pending.append((child, child_info))
                    elif stat.S_ISLNK(child_info.st_mode):
                        errors.append('Symlink skipped')
                    elif not stat.S_ISREG(child_info.st_mode):
                        errors.append('Non-regular entry skipped')
                    elif stat.S_ISREG(child_info.st_mode) and os.path.splitext(entry.name)[1].lower() in EXTENSIONS_SAST:
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


def _python_observations(content):
    tree = ast.parse(content)
    names = {'eval', 'exec', '__import__', 'pickle.load', 'pickle.loads',
             'subprocess.call', 'subprocess.Popen', 'subprocess.run', 'os.system', 'render_template_string'}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name):
            name = function.id
        elif isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            name = function.value.id + '.' + function.attr
        else:
            continue
        if name in names:
            yield node.lineno, 'Review call to ' + name, 'MEDIUM'
        elif isinstance(function, ast.Attribute) and function.attr == 'execute' and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            yield node.lineno, 'Dynamically constructed query requires data-flow review', 'MEDIUM'


def _js_observations(content):
    def mask(match):
        # Preserve only the module literal needed for the require rule.
        if match[0] in {'"child_process"', "'child_process'"}:
            return match[0]
        return re.sub(r'[^\n]', ' ', match[0])
    code = re.sub(r'//[^\n]*|/\*[\s\S]*?(?:\*/|$)|"(?:\\.|[^"\\])*(?:"|$)|\'(?:\\.|[^\'\\])*(?:\'|$)|`(?:\\.|[^`\\])*(?:`|$)', mask, content)
    for pattern, issue, severity in DANGEROUS_PATTERNS['JavaScript/TypeScript']:
        for match in re.finditer(pattern, code):
            yield code.count('\n', 0, match.start()) + 1, issue, severity


async def sast_review(path: str) -> dict:
    if not isinstance(path, str):
        return {'error': 'Expected a local source path', 'coverage_complete': False, 'execution_status': 'not_started'}
    errors, findings = [], []
    try:
        files = _targets(path, errors)
    except (OSError, ValueError):
        return {'error': 'Target missing, inaccessible, non-regular or unsupported', 'coverage_complete': False, 'execution_status': 'not_started'}
    scanned = total_bytes = 0
    truncated = False
    for file, info in files:
        try:
            data = _read_source(file, info, MAX_TOTAL - total_bytes)
            total_bytes += len(data)
            content = data.decode('utf-8')
            lang = _get_language(os.path.splitext(file)[1].lower())
            observations = _python_observations(content) if lang == 'Python' else _js_observations(content)
            file_findings = []
            for line, issue, severity in observations:
                if len(findings) + len(file_findings) == MAX_FINDINGS:
                    truncated = True
                    break
                file_findings.append({'file': os.path.relpath(file, path) if os.path.isdir(path) else os.path.basename(path),
                                      'line': line, 'language': lang, 'issue': issue, 'severity': severity,
                                      'match': '[REDACTED]', 'assessment': 'candidate', 'confidence': 'medium',
                                      'coverage': 'Static source only; no symbol/taint resolution, execution, exploit or reachability verification'})
            findings.extend(file_findings)
            scanned += 1
        except (OSError, ValueError, SyntaxError, RecursionError):
            errors.append('Source unreadable, oversized, changed or malformed')
        if truncated:
            errors.append('Finding budget exhausted')
            break
    complete = not errors and scanned > 0
    return {'path': path, 'files_scanned': scanned, 'findings': findings, 'total_findings': len(findings),
            'risk': 'MEDIUM' if findings else 'UNKNOWN' if not complete else 'LOW', 'errors': errors,
            'coverage_complete': complete, 'execution_status': 'completed' if complete else 'partial' if scanned else 'not_started',
            'truncated': truncated, 'bytes_read': total_bytes,
            'coverage': 'Python AST and JS/TS lexical review, not runtime validation. JS regex literals and template interpolation may be misclassified. 256 KiB/file, 8 MiB total, 100 files, 1000 entries, 200 findings; dependency/build directories excluded.'}

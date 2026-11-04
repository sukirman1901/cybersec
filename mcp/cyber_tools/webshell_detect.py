"""
Web Shell Detector — detect web shells on a target via signature scanning.
"""

import re
from typing import Any
import uuid

import httpx
from .http_guard import GuardedAsyncClient
from .surface_probe import SurfaceProbe

# Common web shell signatures (patterns to look for in file content)
_SIGNATURES = {
    "c99": [
        r"eval\s*\(\s*gzinflate\s*\(",
        r"c99shell",
        r"C99Shell",
        r"Functions\r?\n.*Disnable",
        r"safe_mode\s*=\s*.*off",
    ],
    "r57": [
        r"r57shell",
        r"R57Shell",
        r"wr57shell",
    ],
    "wso": [
        r"WSO\s*Shell",
        r"wso_shell",
        r"\$_\['pass'\]",
    ],
    "china_chopper": [
        r"eval\s*\(\s*\$_POST\[",
        r"chr\s*\(\s*\d+\s*\).*chr\s*\(\s*\d+\s*\).*chr\s*\(\s*\d+\s*\)",
        r"\"one\".*\"two\".*\"three\"",
    ],
    "weevely": [
        r"\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[",
        r"base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[",
        r"eval\s*\(\s*base64_decode\s*\(",
        r"preg_replace\s*\(\s*\"/\.\*/e\"",
    ],
    "b374k": [
        r"b374k",
        r"B374K",
        r"\$b374k",
    ],
    "phpspy": [
        r"PHPSpy",
        r"phpspy",
        r"Spy\.(?:php|jsp|asp)",
    ],
    "generic_cmd": [
        r"system\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"exec\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"passthru\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"popen\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"proc_open\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"Runtime\.getRuntime\(\)\.exec\s*\(.*request\.getParameter",
        r"Runtime\.getRuntime\(\)\.exec\s*\(.*\$_(?:GET|POST)",
    ],
    "generic_eval": [
        r"eval\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"assert\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[",
        r"eval\s*\(\s*base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST)",
        r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode",
        r"eval\s*\(\s*str_rot13\s*\(",
        r"eval\s*\(\s*gzuncompress\s*\(",
        r"preg_replace\s*\(\s*/\.\*/e['\"]?\s*,",
    ],
    "reverse_shell": [
        r"fsockopen\s*\(",
        r"socket_create\s*\(.*AF_INET",
        r"socket_connect\s*\(",
        r"/bin/sh\s+-i",
        r"powershell.*-enc\s+",
        r"nc\s+-e\s+/",
    ],
    "file_manipulation": [
        r"move_uploaded_file\s*\(.*\$_FILES",
        r"copy\s*\(\s*\$_FILES",
        r"file_put_contents\s*\(.*\$_(?:GET|POST|REQUEST)",
        r"fwrite\s*\(.*\$_(?:GET|POST|REQUEST)",
    ],
}

# Common web shell filenames to check
_SHELL_FILENAMES = [
    "shell.php", "cmd.php", "c99.php", "r57.php", "wso.php",
    "b374k.php", "phpspy.php", "eval.php", "test.php", "1.php",
    "0.php", "x.php", "a.php", "cmd.jsp", "shell.jsp", "cmd.asp",
    "shell.asp", "shell.aspx", "cmd.aspx", "webshell.php",
    "backdoor.php", "hack.php", "x.jsp", "test.asp",
    "c100.php", "localhost.php", "wp-config.php.bak",
    "index.php.bak", "config.php.bak", ".htaccess",
    "sh.php", "up.php", "upload.php", "test123.php",
]


async def webshell_detect(
    target_url: str,
    deep_scan: bool = False,
    timeout: int = 10,
) -> dict:
    """Recognize source-code candidates; never execute or confirm a webshell.

    Both modes GET bounded content. deep_scan increases the candidate path budget
    from 24 to 32, not exploit depth. No links or redirects are followed.
    found_shells/count remain confirmed-only; inspect candidates/candidate_count.
    """
    result: dict[str, Any] = {
        "found_shells": [],
        "signatures_matched": [],
        "scanned_urls": 0,
        "count": 0,
        "error": None,
        "candidates": [],
        "candidate_count": 0,
        "assessment": "not_execution_tested",
        "unsupported_detection": ['rendered shell interfaces', 'obfuscated/indirect dataflow', 'heredoc and language parsing',
                                  'command execution', 'linked-path crawling', 'unselected paths'],
    }
    try:
        url = httpx.URL(target_url)
        if url.scheme not in ('http', 'https') or not url.host or url.userinfo:
            raise ValueError('Invalid target')
        base = str(url.copy_with(query=None, fragment=None)).rstrip('/')
        seconds = min(15.0, max(0.1, float(timeout)))
    except (httpx.InvalidURL, ValueError, TypeError):
        return {**result, 'error': 'Invalid HTTP target or timeout', 'requests_attempted': 0,
                'coverage_complete': False}
    paths = ['/' + fn for fn in _SHELL_FILENAMES]
    paths += [f'/{directory}/{fn}' for directory in ('uploads', 'files', 'media', 'images', 'tmp', 'cache', 'static', 'assets')
              for fn in ('shell.php', 'cmd.php', 'test.php', 'c99.php', '1.php')]
    selected = paths[:32 if deep_scan else 24]
    coverage = 'Direct source-code signatures in first source block/16 KiB prefix on selected paths, not family attribution or executable-shell proof; identical catch-all bodies rejected'
    async with GuardedAsyncClient(timeout=min(5.0, seconds), verify=False, trust_env=False, follow_redirects=False) as client:
        probe = SurfaceProbe(client, seconds=seconds, max_requests=len(selected) + 1)
        control = await probe.request('GET', base + '/.missing-' + uuid.uuid4().hex)
        if control is not None:
            for path in selected:
                response = await probe.request('GET', base + path)
                if response is None:
                    break
                result['scanned_urls'] += 1
                if response.status_code != 200 or response.content == control.content:
                    continue
                matched = _scan_content(response.text)
                if matched:
                    result['candidates'].append({'path': path, 'signatures': matched,
                        'status': 200, 'size': len(response.content), 'confidence': 'MEDIUM',
                        'assessment': 'source_code_candidate', 'coverage': coverage})
                    result['signatures_matched'].extend(matched)
    result.update(probe.summary())
    result['selected_paths_complete'] = result['coverage_complete']
    result['coverage_complete'] = False
    result['coverage'] = coverage
    result['candidates_deferred'] = len(paths) - result['scanned_urls']
    result['candidate_count'] = len(result['candidates'])
    result["signatures_matched"] = list(dict.fromkeys(result["signatures_matched"]))
    return result


def _scan_content(content: str) -> list[str]:
    """Apply legacy signatures only to plausible direct-input source candidates.

    A server returning source does not prove it can execute that source. Plain
    brands, normal socket calls and rendered documentation are insufficient.
    """
    content = content.strip()
    if not content.startswith(('<?php', '<%')):
        return []
    # Inspect a bounded prefix; regexes below are heuristics, not a language parser.
    content = content[:16384]
    # Strip common comments and literals before matching code patterns. Preserve
    # quotes as placeholders so direct $_GET["..."] sinks still match. Heredocs
    # need a language parser and are deliberately outside this shallow detector.
    if '<<<' in content:
        return []
    content = re.sub(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|/\*[\s\S]*?\*/|//[^\r\n]*|\#[^\r\n]*''',
                     lambda m: '""' if m.group(0)[0] in ('"', "'") else ' ', content)
    content = content.split('?>' if content.startswith('<?php') else '%>', 1)[0]
    strong = re.search(r'\b(?:system|exec|passthru|shell_exec|popen|proc_open|eval|assert)\s*\(\s*(?:(?:base64_decode|gzinflate)\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[', content, re.I)
    java = re.search(r'Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter\s*\(', content)
    if not (strong or java):
        return []
    matched = []
    for shell_type, patterns in _SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if shell_type not in matched:
                    matched.append(shell_type)
                break
    return matched

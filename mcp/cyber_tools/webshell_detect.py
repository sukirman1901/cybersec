"""
Web Shell Detector — detect web shells on a target via signature scanning.
"""

import re
from typing import Any

import httpx

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
    """Detect web shells on a target via signature and filename scanning.

    Args:
        target_url:  Target URL (e.g. ``"https://example.com"`` or directory URL).
        deep_scan:   Also fetch and scan file content (slower but more accurate).
        timeout:     Request timeout per file (default 10s).

    Returns:
        A dict with found_shells, signatures_matched, scanned_urls, count, error.
    """
    result: dict[str, Any] = {
        "found_shells": [],
        "signatures_matched": [],
        "scanned_urls": 0,
        "count": 0,
        "error": None,
    }

    base = target_url.rstrip("/")

    async with httpx.AsyncClient(timeout=float(timeout), verify=False, follow_redirects=True) as client:
        # Phase 1: Try common shell filenames
        scan_urls = [f"{base}/{fn}" for fn in _SHELL_FILENAMES]

        # If target looks like a directory, also try common upload paths
        upload_dirs = ["/uploads/", "/files/", "/media/", "/images/", "/tmp/", "/cache/", "/static/", "/assets/"]
        for d in upload_dirs:
            for fn in ["shell.php", "cmd.php", "test.php", "c99.php", "1.php"]:
                scan_urls.append(f"{base}{d}{fn}")

        for url in scan_urls:
            result["scanned_urls"] += 1
            try:
                if deep_scan:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        matched = _scan_content(resp.text)
                        if matched:
                            result["found_shells"].append({
                                "url": url,
                                "signatures": matched,
                                "size": len(resp.text),
                                "status": resp.status_code,
                            })
                            result["signatures_matched"].extend(matched)
                else:
                    # Quick scan: HEAD request to check if file exists
                    resp = await client.head(url)
                    if resp.status_code == 200:
                        # Suspicious filename match
                        fn = url.split("/")[-1]
                        suspicious = any(fn.lower() == s.lower() for s in _SHELL_FILENAMES)
                        if suspicious:
                            # Quick GET to check content
                            resp = await client.get(url)
                            matched = _scan_content(resp.text)
                            result["found_shells"].append({
                                "url": url,
                                "signatures": matched or ["suspicious_filename"],
                                "size": len(resp.text),
                                "status": resp.status_code,
                            })
                            result["signatures_matched"].extend(matched or ["suspicious_filename"])

            except Exception:
                continue

        # Phase 2: If deep_scan, also crawl the main page for links to .php/.jsp/.asp files
        if deep_scan:
            try:
                resp = await client.get(base)
                links = re.findall(r'(?:href|src|action)=["\']([^"\']+\.(?:php|jsp|asp|aspx))["\']', resp.text, re.I)
                for link in links:
                    full_url = link if link.startswith("http") else f"{base.rstrip('/')}/{link.lstrip('/')}"
                    if full_url in [s["url"] for s in result["found_shells"]]:
                        continue
                    try:
                        resp2 = await client.get(full_url)
                        result["scanned_urls"] += 1
                        if resp2.status_code == 200:
                            matched = _scan_content(resp2.text)
                            if matched:
                                result["found_shells"].append({
                                    "url": full_url,
                                    "signatures": matched,
                                    "size": len(resp2.text),
                                    "status": resp2.status_code,
                                })
                                result["signatures_matched"].extend(matched)
                    except Exception:
                        continue
            except Exception:
                pass

    result["signatures_matched"] = list(dict.fromkeys(result["signatures_matched"]))
    result["count"] = len(result["found_shells"])
    return result


def _scan_content(content: str) -> list[str]:
    """Scan file content for web shell signatures."""
    matched = []
    for shell_type, patterns in _SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if shell_type not in matched:
                    matched.append(shell_type)
                break
    return matched

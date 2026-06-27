import httpx
import re


async def s3_scanner(bucket_name: str) -> dict:
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                files = re.findall(r"<Key>(.*?)</Key>", resp.text)
                return {
                    "bucket": bucket_name,
                    "accessible": True,
                    "public": True,
                    "files": files[:100],
                    "total_files": len(files),
                    "url": url,
                }
            elif resp.status_code == 403:
                return {"bucket": bucket_name, "accessible": True, "public": False, "url": url, "note": "Bucket exists but not publicly listable."}
            else:
                return {"bucket": bucket_name, "accessible": False, "status": resp.status_code}
    except httpx.HTTPError as e:
        return {"bucket": bucket_name, "accessible": False, "error": str(e)}

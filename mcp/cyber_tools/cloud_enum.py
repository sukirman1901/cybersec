import httpx

AWS_BUCKET_PATTERNS = ["{name}", "{name}-prod", "{name}-dev", "{name}-staging", "{name}-backup", "{name}-data", "{name}-assets"]
AZURE_STORAGE_PATTERNS = ["{name}", "{name}prod", "{name}dev", "{name}staging", "{name}backup"]
GCP_BUCKET_PATTERNS = ["{name}", "{name}-prod", "{name}-dev", "{name}-staging", "{name}-backup"]


async def cloud_enum(company: str) -> dict:
    found = []

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for pattern in AWS_BUCKET_PATTERNS:
            bucket = pattern.format(name=company)
            try:
                resp = await client.get(f"https://{bucket}.s3.amazonaws.com")
                if resp.status_code != 404:
                    found.append({"provider": "AWS S3", "bucket": bucket, "status": resp.status_code})
            except httpx.HTTPError:
                continue

        for pattern in AZURE_STORAGE_PATTERNS:
            account = pattern.format(name=company)
            try:
                resp = await client.get(f"https://{account}.blob.core.windows.net")
                if resp.status_code != 404 and resp.status_code != 400:
                    found.append({"provider": "Azure Blob", "account": account, "status": resp.status_code})
            except httpx.HTTPError:
                continue

        for pattern in GCP_BUCKET_PATTERNS:
            bucket = pattern.format(name=company)
            try:
                resp = await client.get(f"https://storage.googleapis.com/{bucket}")
                if resp.status_code != 404:
                    found.append({"provider": "GCP Storage", "bucket": bucket, "status": resp.status_code})
            except httpx.HTTPError:
                continue

    return {"company": company, "resources_found": found, "count": len(found)}

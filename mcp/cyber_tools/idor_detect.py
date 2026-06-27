import httpx
import re


async def idor_detect(target: str, ids: str = "1,2,3") -> dict:
    base = target.rstrip("/")
    tested = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_base = await client.get(base)
        base_size = len(resp_base.text)
        base_status = resp_base.status_code
        for id_val in ids.split(","):
            tid = id_val.strip()
            paths = [f"{base}/{tid}", f"{base}?id={tid}", f"{base}/{tid}/edit"]
            for path in paths:
                try:
                    r = await client.get(path)
                    same_size = abs(len(r.text) - base_size) < 50
                    different_content = r.status_code != base_status and r.status_code == 200
                    tested.append({
                        "url": path,
                        "status": r.status_code,
                        "size": len(r.text),
                        "different_from_base": different_content,
                        "idor_possible": r.status_code == 200 and r.status_code != 404,
                    })
                except httpx.HTTPError as e:
                    tested.append({"url": path, "error": str(e)})
    idor_findings = [t for t in tested if t.get("idor_possible")]
    return {"target": target, "tests": tested, "idor_candidates": idor_findings, "count": len(idor_findings)}

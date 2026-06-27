import asyncio
import httpx
import re

SENSITIVE_PATHS = [
    "/api/coupon/redeem",
    "/api/voucher/claim",
    "/api/wallet/transfer",
    "/api/withdraw",
    "/api/points/redeem",
    "/api/rewards/claim",
    "/api/signup",
    "/api/register",
    "/api/reset-password",
    "/api/email/verify",
    "/api/vote",
    "/api/like",
    "/api/follow",
    "/api/order/create",
    "/api/checkout",
]


async def race_condition(target: str, parallel: int = 5, endpoint: str = "") -> dict:
    results = []
    base = target.rstrip("/")
    paths = [endpoint] if endpoint else SENSITIVE_PATHS
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in paths:
            url = f"{base}{path}"
            resp_single = await client.get(url)
            single_status = resp_single.status_code
            single_size = len(resp_single.text)
            async def fire():
                try:
                    r = await client.post(url)
                    return {"status": r.status_code, "size": len(r.text)}
                except Exception:
                    return {"error": "failed"}
            tasks = [fire() for _ in range(parallel)]
            responses = await asyncio.gather(*tasks)
            statuses = [r.get("status") for r in responses if "status" in r]
            success_count = sum(1 for s in statuses if s and s < 400)
            first_status = statuses[0] if statuses else 0
            results.append({
                "endpoint": path,
                "single_status": single_status,
                "race_statuses": statuses[:10],
                "parallel_requests": parallel,
                "success_count": success_count,
                "race_possible": success_count > 1 and first_status < 400,
            })
    return {"target": target, "tests": results, "race_condition_possible": any(r.get("race_possible") for r in results)}

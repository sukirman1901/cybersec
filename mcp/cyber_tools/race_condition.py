"""Deep race condition detection — parallel requests, response diff, timing analysis, multi-endpoint."""

import asyncio
import httpx
import re
import time
import json

# --- Sensitive Endpoints ---
SENSITIVE_ENDPOINTS = [
    ("/api/coupon/redeem", "POST", {"code": "TEST123"}),
    ("/api/voucher/claim", "POST", {"voucher": "TEST"}),
    ("/api/wallet/transfer", "POST", {"to": "1", "amount": "100"}),
    ("/api/withdraw", "POST", {"amount": "100"}),
    ("/api/points/redeem", "POST", {"points": "100"}),
    ("/api/rewards/claim", "POST", {"reward": "1"}),
    ("/api/signup", "POST", {"email": "test@test.com", "password": "test123"}),
    ("/api/register", "POST", {"email": "test@test.com", "password": "test123"}),
    ("/api/reset-password", "POST", {"email": "test@test.com"}),
    ("/api/email/verify", "POST", {"token": "test"}),
    ("/api/vote", "POST", {"candidate": "1"}),
    ("/api/like", "POST", {"post_id": "1"}),
    ("/api/follow", "POST", {"user_id": "1"}),
    ("/api/order/create", "POST", {"item": "1", "qty": "1"}),
    ("/api/checkout", "POST", {"cart": "1"}),
    ("/api/payment/process", "POST", {"amount": "100"}),
    ("/api/discount/apply", "POST", {"code": "SAVE10"}),
    ("/api/ticket/purchase", "POST", {"event": "1", "qty": "1"}),
    ("/api/balance/transfer", "POST", {"to": "2", "amount": "50"}),
    ("/api/inventory/reserve", "POST", {"item": "1", "qty": "1"}),
]

# --- Race Condition Indicators ---
SUCCESS_INDICATORS = ["success", "created", "done", "ok", "applied", "redeemed", "transferred", "completed"]
FAILURE_INDICATORS = ["already", "used", "expired", "insufficient", "limit", "duplicate", "conflict", "error", "failed"]
BALANCE_INDICATORS = ["balance", "amount", "credit", "points", "wallet"]


def _analyze_race_responses(responses: list[dict]) -> dict:
    """Analyze parallel responses for race condition evidence."""
    analysis = {
        "total_requests": len(responses),
        "success_count": 0,
        "failure_count": 0,
        "error_count": 0,
        "race_detected": False,
        "evidence": [],
        "unique_bodies": set(),
        "unique_statuses": set(),
        "success_bodies": [],
        "failure_bodies": [],
    }

    for resp in responses:
        status = resp.get("status", 0)
        body = resp.get("body", "").lower()

        analysis["unique_statuses"].add(status)
        analysis["unique_bodies"].add(body[:200])

        if status and 200 <= status < 300:
            analysis["success_count"] += 1
            analysis["success_bodies"].append(body[:200])
        elif status and 400 <= status < 500:
            analysis["failure_count"] += 1
            analysis["failure_bodies"].append(body[:200])
        elif status and status >= 500:
            analysis["error_count"] += 1

    # Race condition detection
    # Multiple successes on a resource that should be single-use
    if analysis["success_count"] > 1:
        analysis["race_detected"] = True
        analysis["evidence"].append(f"Multiple successes: {analysis['success_count']}/{analysis['total_requests']}")

    # Mix of success and failure (partial execution)
    if analysis["success_count"] > 0 and analysis["failure_count"] > 0:
        analysis["race_detected"] = True
        analysis["evidence"].append("Mixed success/failure indicates race window")

    # Different response bodies for same request
    if len(analysis["unique_bodies"]) > 2:
        analysis["race_detected"] = True
        analysis["evidence"].append(f"Multiple different responses: {len(analysis['unique_bodies'])} unique bodies")

    # Status code inconsistency
    if len(analysis["unique_statuses"]) > 2:
        analysis["race_detected"] = True
        analysis["evidence"].append(f"Status code inconsistency: {analysis['unique_statuses']}")

    analysis["unique_bodies"] = len(analysis["unique_bodies"])
    analysis["unique_statuses"] = list(analysis["unique_statuses"])

    return analysis


async def race_condition(target: str, parallel: int = 10, endpoint: str = "", cookies: str = "") -> dict:
    """Deep race condition detection with parallel requests, response diff, timing analysis."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    from urllib.parse import urlparse
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Parse cookies
    cookie_dict = {}
    if cookies:
        for item in cookies.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    # Build endpoint list
    endpoints = []
    if endpoint:
        method = "POST"
        data = {}
        for ep, m, d in SENSITIVE_ENDPOINTS:
            if ep in endpoint:
                method = m
                data = d
                break
        endpoints.append((endpoint, method, data))
    else:
        endpoints = SENSITIVE_ENDPOINTS

    results = []

    async with httpx.AsyncClient(
        timeout=15.0,
        verify=False,
        follow_redirects=False,
        cookies=cookie_dict,
    ) as client:
        # Discover actual endpoints
        discovered_endpoints = []
        try:
            main_resp = await client.get(target)
            api_patterns = re.findall(r'(/api/[a-zA-Z0-9/_-]+)', main_resp.text)
            for pattern in api_patterns:
                if any(kw in pattern.lower() for kw in ["create", "add", "redeem", "claim", "transfer", "withdraw", "apply", "purchase"]):
                    discovered_endpoints.append((pattern, "POST", {}))
        except Exception:
            pass

        all_endpoints = endpoints + discovered_endpoints[:5]

        for path, method, data in all_endpoints:
            url = f"{base}{path}"

            # --- Baseline Request ---
            try:
                baseline_resp = await client.request(method, url, json=data if method == "POST" else None)
                baseline = {
                    "status": baseline_resp.status_code,
                    "size": len(baseline_resp.text),
                    "body": baseline_resp.text,
                    "time": 0,
                }
            except Exception:
                continue

            # --- Parallel Requests ---
            start_time = time.time()
            tasks = []
            for i in range(parallel):
                async def fire(idx):
                    try:
                        req_start = time.time()
                        resp = await client.request(method, url, json=data if method == "POST" else None)
                        req_time = time.time() - req_start
                        return {
                            "index": idx,
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "body": resp.text,
                            "time": round(req_time, 3),
                            "headers": dict(resp.headers),
                        }
                    except httpx.TimeoutException:
                        return {"index": idx, "error": "timeout"}
                    except Exception as e:
                        return {"index": idx, "error": str(e)[:100]}

                tasks.append(fire(i))

            responses = await asyncio.gather(*tasks)
            total_time = time.time() - start_time

            # --- Analysis ---
            valid_responses = [r for r in responses if "status" in r]
            analysis = _analyze_race_responses(valid_responses)

            # --- Timing Analysis ---
            times = [r["time"] for r in valid_responses if "time" in r]
            timing_analysis = {
                "total_time": round(total_time, 3),
                "avg_time": round(sum(times) / len(times), 3) if times else 0,
                "min_time": round(min(times), 3) if times else 0,
                "max_time": round(max(times), 3) if times else 0,
                "timing_consistent": max(times) - min(times) < 2 if len(times) > 1 else True,
            }

            # --- Response Diff ---
            response_diff = {
                "status_changes": len(analysis["unique_statuses"]) > 1,
                "body_changes": analysis["unique_bodies"] > 1,
                "evidence": analysis["evidence"],
            }

            # --- Determine Risk ---
            risk = "NONE"
            confidence = "none"
            if analysis["race_detected"]:
                risk = "CRITICAL"
                confidence = "confirmed"
            elif analysis["success_count"] > 1:
                risk = "HIGH"
                confidence = "probable"
            elif analysis["error_count"] > parallel * 0.5:
                risk = "MEDIUM"
                confidence = "possible"

            results.append({
                "endpoint": path,
                "method": method,
                "parallel_requests": parallel,
                "analysis": analysis,
                "timing": timing_analysis,
                "response_diff": response_diff,
                "race_possible": analysis["race_detected"],
                "risk": risk,
                "confidence": confidence,
                "baseline_status": baseline["status"],
            })

    return {
        "target": target,
        "tests": results,
        "race_condition_possible": any(r.get("race_possible") for r in results),
        "total_endpoints_tested": len(results),
        "vulnerable_endpoints": [r["endpoint"] for r in results if r.get("race_possible")],
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }

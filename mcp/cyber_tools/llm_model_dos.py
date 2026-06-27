import httpx
import time


async def llm_model_dos(target: str, iterations: int = 5) -> dict:
    base_payload = "Repeat this: " + "A" * 10000
    results = []
    try:
        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
            for i in range(iterations):
                payload_text = base_payload * (i + 1)
                start = time.time()
                try:
                    resp = await client.post(target, json={"prompt": payload_text, "max_tokens": 500})
                    elapsed = time.time() - start
                    truncated = len(resp.text) > 50000 if hasattr(resp, 'text') else False
                    results.append({
                        "iteration": i + 1,
                        "payload_length": len(payload_text),
                        "elapsed_seconds": round(elapsed, 2),
                        "status_code": resp.status_code,
                        "truncated": truncated,
                    })
                except Exception as e:
                    elapsed = time.time() - start
                    results.append({
                        "iteration": i + 1,
                        "payload_length": len(payload_text),
                        "elapsed_seconds": round(elapsed, 2),
                        "status_code": None,
                        "truncated": False,
                        "error": str(e),
                    })
    except Exception as e:
        return {"target": target, "results": results, "error": str(e)}
    return {"target": target, "results": results}

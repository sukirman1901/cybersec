import httpx
import time
from .prompt_injection import _validate, _report, _failure, _request, _BoundaryError


async def llm_model_dos(target: str, iterations: int = 5) -> dict:
    base_payload = "Repeat this: " + "A" * 10000
    results = []
    result = _report(target, results=results,
                     note='Timing observations do not establish model resource exhaustion.')
    try:
        _validate(target)
        if type(iterations) is not int or not 1 <= iterations <= 5:
            raise _BoundaryError('iterations must be an integer from 1 to 5')
        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
            for i in range(iterations):
                payload_text = base_payload * (i + 1)
                start = time.monotonic()
                try:
                    resp = await _request(client, 'POST', target, json={"prompt": payload_text, "max_tokens": 500})
                    elapsed = time.monotonic() - start
                    truncated = False
                    results.append({
                        "iteration": i + 1,
                        "payload_length": len(payload_text),
                        "elapsed_seconds": round(elapsed, 2),
                        "status_code": resp.status_code,
                        "truncated": truncated,
                    })
                except Exception as e:
                    elapsed = time.monotonic() - start
                    results.append({
                        "iteration": i + 1,
                        "payload_length": len(payload_text),
                        "elapsed_seconds": round(elapsed, 2),
                        "status_code": None,
                        "truncated": False,
                        "error": type(e).__name__,
                    })
                    return _failure(result, e)
    except Exception as e:
        return _failure(result, e)
    return result

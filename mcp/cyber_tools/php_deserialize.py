import httpx
import re

GADGET_CHAINS = [
    "O:1:\"A\":0:{}",
    "O:10:\"PHPObject\":0:{}",
    "a:1:{i:0;O:7:\"Exploit\":0:{}}",
    "O:14:\"Monolog\\\\Handler\\\\FingersCrossedHandler\":0:{}",
    "O:13:\"PHPUnit\\\\Framework\\\\MockObject\\\\Invocation\":0:{}",
]

SIGNATURES = [
    ("serialized", r'O:\d+:'),
    ("base64_serialized", r'Tzpc'),
    ("url_encoded", r'O%3A\d%2B%3A'),
]


async def php_deserialize(target: str, param: str = "") -> dict:
    results = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        resp = await client.get(target)
        for sig_name, sig_pattern in SIGNATURES:
            if re.search(sig_pattern, resp.text):
                results.append({"finding": f"Serialized data found via {sig_name}", "detail": "PHP serialized input detected", "severity": "high"})
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', resp.text)
        params_to_test = [param] if param else re.findall(r'name=["\']([^"\']*)["\']', resp.text)
        for p in params_to_test[:5]:
            for chain in GADGET_CHAINS[:2]:
                url = f"{target.rstrip('/')}?{p}={__import__('urllib').parse.quote(chain)}"
                try:
                    r = await client.get(url)
                    if r.status_code != 500 and len(r.text) > 100:
                        results.append({"finding": f"Possible deserialization in param {p}", "payload": chain[:30], "status": r.status_code, "severity": "medium"})
                except httpx.HTTPError:
                    continue
    return {"target": target, "findings": results, "count": len(results)}

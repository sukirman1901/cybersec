import httpx
import re

JNDI_PAYLOADS = [
    ("jndi_ldap", "${jndi:ldap://localhost/a}", "ldap"),
    ("jndi_rmi", "${jndi:rmi://localhost/a}", "rmi"),
    ("jndi_dns", "${jndi:dns://localhost/a}", "dns"),
    ("jndi_ldap_lower", "${jndi:ldap://127.0.0.1:1389/a}", "ldap"),
    ("env_defaults", "${${env:FOO:-j}ndi}", "env_bypass"),
    ("upper_lower", "${jndi:LDAP://localhost/a}", "ldap"),
    ("nested", "${${lower:j}ndi:${lower:l}dap://localhost/a}", "ldap"),
]

HEADERS = [
    "User-Agent",
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "Referer",
    "Cookie",
    "Authorization",
]


async def log4j_scan(target: str) -> dict:
    """Bounded observations; JNDI callback verification is unsupported."""
    return await _bounded_detector(target)


async def _bounded_detector(target, *options):
    from functools import partial
    from urllib.parse import urlsplit
    from .surface_probe import SurfaceProbe

    result = {"results": [], "tests": [], "observations": [], "heuristic_signals": [],
              "vulnerable": None, "verification": "unsupported",
              "total_findings": 0, "confirmed_findings": 0,
              "coverage_complete": False, "execution_status": "invalid_input"}
    try:
        if not isinstance(target, str) or not target or len(target) > 4096:
            raise ValueError
        if any(c.isspace() or ord(c) < 32 for c in target):
            raise ValueError
        target = target if "://" in target else "https://" + target
        parsed = urlsplit(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.fragment:
            raise ValueError
        _ = parsed.port
        if any(not isinstance(v, str) or len(v) > 512 or any(ord(c) < 32 for c in v) for v in options):
            raise ValueError
    except (ValueError, TypeError):
        return {**result, "error": "Invalid target or detector arguments"}

    class StopProbe(BaseException):
        """Unwind legacy catch-and-continue handlers without a fake response."""

    class Client(SurfaceProbe):
        async def __aenter__(self):
            self.get = partial(self.request, "GET")
            self.post = partial(self.request, "POST")
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, **kwargs):
            response = await super().request(method, url, **kwargs)
            if response is None:
                raise StopProbe
            result["observations"].append({"method": method, "status": response.status_code,
                                           "response_bytes": len(response.content)})
            return response

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as raw:
        probe = Client(raw, seconds=15, max_requests=32)
        probe.signals = []
        try:
            await _legacy_detector(probe, target, *options)
        except StopProbe:
            pass
        except (ValueError, TypeError, KeyError, AttributeError, IndexError):
            probe.errors.append("malformed_response")
        result.update(probe.summary())
        # No callback receiver exists here: response metadata is the only evidence.
    result["note"] = "HTTP observations and legacy heuristics do not establish exploitation or absence of vulnerability. Raw response data is omitted."
    return result


async def _legacy_detector(_client, target: str) -> dict:
    results = _client.signals
    base = target.rstrip("/")
    async with _client as client:
        for payload_name, payload, _ in JNDI_PAYLOADS:
            url = f"{base}?test={__import__('urllib').parse.quote(payload)}"
            try:
                resp = await client.get(url, headers={"User-Agent": payload})
                response_lower = resp.text.lower()
                jndi_reflected = "${" not in response_lower and "jndi" not in response_lower
                results.append({
                    "payload": payload_name,
                    "param": payload[:40],
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "reflected": False,
                })
            except httpx.HTTPError as e:
                results.append({"payload": payload_name, "error": str(e)})
        for header in HEADERS[:3]:
            for payload_name, payload, _ in JNDI_PAYLOADS[:3]:
                try:
                    resp = await client.get(base, headers={header: payload})
                    results.append({
                        "payload": f"{header}:{payload_name}",
                        "header": header,
                        "status": resp.status_code,
                        "size": len(resp.text),
                        "reflected": False,
                    })
                except httpx.HTTPError:
                    continue
    return {"target": target, "tests": results, "total": len(results), "note": "JNDI injection requires out-of-band callback server to confirm. These tests detect potential reflection/behavior changes."}

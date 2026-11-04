import httpx
import json
import re

GRAPHQL_ABUSE_QUERIES = [
    ("sql_injection", "query { user(id: \"1' OR '1'='1\") { id name email } }"),
    ("deep_nesting", "query { __schema { types { fields { type { fields { type { fields { name } } } } } } } }"),
    ("alias_batching", "query { a: __typename b: __typename c: __typename d: __typename e: __typename f: __typename g: __typename h: __typename i: __typename j: __typename }"),
    ("field_duplication", "query { " + " ".join(f"f{i}: user(id: 1) {{ id name email password }}" for i in range(10)) + " }"),
    ("introspection_auth", "query { __schema { types { name fields { name } } } }"),
]

async def graphql_injection(target: str) -> dict:
    """Bounded observations; injection and authorization verification are unsupported."""
    return await _bounded_detector(target)


async def _bounded_detector(target, *options):
    from functools import partial
    from urllib.parse import urlsplit
    from .surface_probe import SurfaceProbe

    result = {"results": [], "observations": [], "heuristic_signals": [],
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
            if response.status_code == 200:
                try:
                    document = response.json()
                    if not isinstance(document, dict):
                        raise ValueError
                except (ValueError, TypeError, RecursionError):
                    self.errors.append("malformed_response")
                    self.stopped = True
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
        for item in probe.signals:
            technique = item.get("test")
            if isinstance(technique, str) and technique.isascii() and technique.replace("_", "").isalnum():
                result["heuristic_signals"].append({"technique": technique[:80], "verification": "unsupported"})
    result["note"] = "HTTP observations and legacy heuristics do not establish exploitation or absence of vulnerability. Raw response data is omitted."
    return result


async def _legacy_detector(_client, target: str) -> dict:
    results = _client.signals
    base = target.rstrip("/")
    endpoints = [base, base + "/graphql", base + "/v1/graphql", base + "/v2/graphql", base + "/api/graphql", base + "/gql"]

    async with _client as client:
        # Find active GraphQL endpoint
        active_endpoint = None
        for ep in endpoints:
            try:
                r = await client.post(ep, json={"query": "query { __typename }"})
                if r.status_code == 200 and "data" in r.text:
                    active_endpoint = ep
                    results.append({"test": "endpoint_discovery", "endpoint": ep, "status": r.status_code, "risk": "INFO"})
                    break
            except Exception:
                pass

        if not active_endpoint:
            return {"target": target, "error": "No GraphQL endpoint found", "results": []}

        # Test abuse queries
        for name, query in GRAPHQL_ABUSE_QUERIES:
            try:
                r = await client.post(active_endpoint, json={"query": query})
                if r.status_code == 200:
                    data = r.json()
                    has_data = "data" in data and data["data"] is not None
                    has_errors = "errors" in data

                    if "sql_injection" in name and has_data:
                        results.append({"test": name, "vulnerable": True, "note": "SQL injection via GraphQL may be possible", "risk": "CRITICAL"})
                    elif "deep_nesting" in name and has_data:
                        results.append({"test": name, "vulnerable": True, "note": "Deep nesting query succeeded — potential DoS", "risk": "HIGH"})
                    elif "alias_batching" in name and has_data:
                        results.append({"test": name, "vulnerable": True, "note": "Alias batching not restricted — potential abuse", "risk": "MEDIUM"})
                    elif "field_duplication" in name and has_data:
                        results.append({"test": name, "vulnerable": True, "note": "Field duplication allowed — potential resource exhaustion", "risk": "MEDIUM"})
                    elif "introspection" in name and has_data:
                        results.append({"test": name, "vulnerable": True, "note": "Introspection enabled without auth", "risk": "HIGH"})
                else:
                    results.append({"test": name, "vulnerable": False, "status": r.status_code, "note": "Blocked or errored"})
            except Exception:
                results.append({"test": name, "vulnerable": False, "error": "Request failed"})

        # Test auth bypass
        try:
            r = await client.post(active_endpoint, json={"query": "mutation { createUser(input: {role: admin}) { id role } }"})
            if r.status_code == 200 and "errors" not in r.text:
                results.append({"test": "auth_bypass_mutation", "vulnerable": True, "note": "Mutation succeeded without auth", "risk": "CRITICAL"})
        except Exception:
            pass

    return {"target": target, "active_endpoint": active_endpoint, "results": results, "vulnerable": any(r.get("vulnerable") for r in results)}

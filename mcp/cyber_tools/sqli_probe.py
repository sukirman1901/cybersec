"""Controlled GET/query SQLi experiments; no extraction or timing payloads.

Only repeated, control-backed observations become findings. A successful scan is
not proof of absence: the implemented techniques and omissions are always listed.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import time
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from urllib.parse import quote_plus, unquote_plus, urlsplit, urlunsplit

import httpx

from .finding_contract import attach_contract_fields

MAX_BODY_BYTES = 262144
PRESETS = {
    "observe-first": {"seconds": 18, "requests": 80, "params": 2},
    "staging-deep": {"seconds": 55, "requests": 160, "params": 4},
}
SKIPPED = ["time_blind", "union_based", "stacked", "db_enumeration", "post_json_cookie"]
BLOCK_STATUSES = {401, 403, 406, 407, 419, 429, 444, 503}


@dataclass
class QueryContext:
    base: str
    tokens: list[str]
    index: int
    name: str
    original: str
    guessed: bool = False

    def url(self, value: str | None = None) -> str:
        tokens = list(self.tokens)
        if value is not None:
            name = tokens[self.index].partition("=")[0]
            tokens[self.index] = name + "=" + quote_plus(value)
        return self.base + "?" + "&".join(tokens)


def query_contexts(target: str, param: str) -> list[QueryContext]:
    if "://" in target and not target.startswith(("http://", "https://")):
        raise ValueError("unsupported_scheme")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("invalid_target")
    if parts.username is not None or parts.password is not None:
        raise ValueError("userinfo_not_supported")
    base = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
    tokens = parts.query.split("&") if parts.query else []
    contexts = []
    for index, token in enumerate(tokens):
        name, _, value = token.partition("=")
        name = unquote_plus(name)
        if name and (not param or name == param):
            contexts.append(QueryContext(base, tokens, index, name, unquote_plus(value)))
    if contexts:
        return contexts
    for name in ([param] if param else ["id", "q", "search", "page"]):
        synthetic = tokens + [quote_plus(name) + "=1"]
        contexts.append(QueryContext(base, synthetic, len(tokens), name, "1", guessed=True))
    return contexts


def _normalized(body: str, value: str, original: str) -> str:
    # Remove exact probe reflection before comparing content. Never erase arbitrary
    # numbers or learned differing regions: those could be the actual SQL signal.
    if value != original:
        replacements = {
            value: original,
            html.escape(value): html.escape(original),
            html.escape(value, quote=False): html.escape(original, quote=False),
            quote_plus(value): quote_plus(original),
            json.dumps(value)[1:-1]: json.dumps(original)[1:-1],
        }
        for text in sorted(replacements, key=len, reverse=True):
            if text:
                body = body.replace(text, replacements[text])
    return re.sub(r"\s+", " ", body).strip()


def _distance(left: str, right: str) -> float:
    if left == right:
        return 0.0
    # Bound CPU on highly repetitive bodies. Hashes still cover the full body;
    # content comparisons use a documented prefix/suffix window for large pages.
    def window(text):
        return text if len(text) <= 16384 else text[:8192] + text[-8192:]
    def shingles(text):
        text = window(text)
        width = min(4, len(text))
        return Counter(text[i:i + width] for i in range(len(text) - width + 1))
    a, b = shingles(left), shingles(right)
    total = sum(a.values()) + sum(b.values())
    return 1.0 - 2.0 * sum((a & b).values()) / max(total, 1)


def _sensitive(name):
    return bool(re.search(r"password|passwd|pwd|token|api[_-]?key|authorization|cookie|secret|session|csrf",
                          name, re.I))


def _redacted_url(target):
    """Redact known credential query keys and URL userinfo; do not export fragments."""
    try:
        has_scheme = "://" in target
        parts = urlsplit(target if has_scheme else "https://" + target)
        tokens, secrets = [], []
        for token in parts.query.split("&") if parts.query else []:
            name = token.partition("=")[0]
            decoded = unquote_plus(name)
            if _sensitive(decoded):
                tokens.append(name + "=" + quote_plus("<redacted>"))
                secrets.append(decoded)
            else:
                tokens.append(token)
        if "@" in parts.netloc:
            secrets.append("userinfo")
        netloc = parts.netloc.rsplit("@", 1)[-1]
        safe = urlunsplit((parts.scheme, netloc, parts.path, "&".join(tokens), ""))
        return (safe if has_scheme else safe.removeprefix("https://")), sorted(set(secrets))
    except ValueError:
        return "<invalid target>", []


def _blocked(status: int, body: str) -> bool:
    return status in BLOCK_STATUSES or bool(re.search(
        r"request blocked|web application firewall|captcha|too many requests", body, re.I))


class ProbeStop(Exception):
    pass


class ProbeSession:
    def __init__(self, client, config, sql_errors):
        self.client = client
        self.deadline = time.monotonic() + config["seconds"]
        self.budget = config["requests"]
        self.sent = 0
        self.errors = []
        self.sql_errors = [re.compile(pattern, re.I) for pattern in sql_errors]
        self.partial = False
        self.waf = None

    async def sample(self, context, value, role):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.sent >= self.budget:
            raise ProbeStop("deadline_reached" if remaining <= 0 else "request_budget_reached")
        self.sent += 1
        request_id = self.sent
        started = time.monotonic()

        async def read_response():
            async with self.client.stream("GET", context.url(value),
                                          timeout=min(8.0, remaining)) as response:
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(data) + len(chunk) > MAX_BODY_BYTES:
                        raise ProbeStop("response_body_limit")
                    data.extend(chunk)
                body = bytes(data).decode(response.encoding or "utf-8", errors="replace")
                return body, response.status_code, data

        try:
            body, status, data = await asyncio.wait_for(read_response(), timeout=min(8.0, remaining))
        except ProbeStop:
            raise
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            self.partial = True
            self.errors.append({"request_id": request_id, "role": role,
                                "error": type(exc).__name__})
            return None
        normalized = _normalized(body, value if value is not None else context.original,
                                 context.original)
        blocked = _blocked(status, body)
        if blocked:
            self.partial = True
            self.waf = {"detected": True, "name": "blocking_or_challenge_response",
                        "status_code": status}
        signatures = {pattern.pattern for pattern in self.sql_errors if pattern.search(normalized)}
        return {
            "text": normalized,
            "signatures": signatures,
            "blocked": blocked,
            "proof": {
                "request_id": request_id, "role": role, "status": status,
                "body_bytes": len(data), "body_hash": hashlib.sha256(data).hexdigest(),
                "normalized_hash": hashlib.sha256(normalized.encode()).hexdigest(),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "sql_error_signatures": sorted(signatures),
            },
        }


def _proof(samples):
    return [sample["proof"] for sample in samples if sample is not None]


def _finding(context, technique, evidence, preset, payload, probe_values, control_values):
    target, secrets = _redacted_url(context.url())
    hide_value = _sensitive(context.name)
    replay = {"method": "GET", "url": target, "parameter": context.name,
              "query_token_index": context.index,
              "original_value": "<redacted>" if hide_value else context.original,
              "probe_values": ["<redacted>" if hide_value else value for value in probe_values],
              "control_values": ["<redacted>" if hide_value else value for value in control_values],
              "requires_secrets": secrets, "complete": not secrets}
    evidence = {**evidence, "replay": replay}
    # Operational timing, request counters and volatile response bodies must not
    # become the novelty identity of the same causal finding on a later scan.
    identity = {"replay": replay, "technique": technique,
                "signatures": evidence.get("matched_signatures", []),
                "confirmation_rounds": evidence["confirmation_rounds"]}
    evidence_hash = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]
    return {
        "type": "sqli_" + technique, "technique": technique,
        "target": target, "param": context.name,
        "parameter_occurrence": context.index, "payload": payload,
        "severity": "high", "risk": "HIGH", "confidence": "HIGH",
        "evidence": json.dumps(evidence, sort_keys=True),
        "evidence_hash": evidence_hash, "replay": replay,
        "reproducible": not secrets,
        "coverage": f"preset={preset}; GET/query; repeated baselines and controls; {technique}",
    }


async def _experiment(session, context, preset, findings, candidates):
    def candidate(technique, reason, **details):
        candidates.append({"param": context.name, "parameter_occurrence": context.index,
                           "technique": technique, "reason": reason, **details})

    baselines = [await session.sample(context, None, "baseline") for _ in range(3)]
    if any(sample is None for sample in baselines):
        return findings, candidates
    if any(sample["blocked"] or not 200 <= sample["proof"]["status"] < 300
           for sample in baselines):
        session.partial = True
        candidate("baseline", "baseline_not_successful", baseline=_proof(baselines))
        return findings, candidates
    statuses = {sample["proof"]["status"] for sample in baselines}
    noise = max(_distance(a["text"], b["text"]) for a, b in combinations(baselines, 2))
    if noise > 0.03 or len(statuses) != 1:
        session.partial = True
        candidate("baseline", "unstable_baseline", distance=round(noise, 4))
        return findings, candidates
    baseline = baselines[0]
    baseline_errors = set.union(*(sample["signatures"] for sample in baselines))
    if re.fullmatch(r"[+-]?\d+", context.original) and len(context.original) < 18:
        control_values = [str(int(context.original) + 1), str(int(context.original) + 2)]
    else:
        control_values = [context.original + "qa", context.original + "qb"]
    controls = [await session.sample(context, value, "benign_control") for value in control_values]
    if any(sample is None for sample in controls):
        return findings, candidates
    controls_clear = all(not sample["signatures"] and not sample["blocked"]
                         and 200 <= sample["proof"]["status"] < 300 for sample in controls)
    if not controls_clear:
        session.partial = True
        candidate("control", "benign_controls_failed", controls=_proof(controls))
        return findings, candidates
    # New errors need to recur with the same probe and disappear on recovery.
    for quote in ("'", '"'):
        payload = context.original + quote
        first = await session.sample(context, payload, "error_probe")
        if first is None:
            continue
        novel = first["signatures"] - baseline_errors
        if not novel or first["blocked"]:
            continue
        recovery = await session.sample(context, None, "error_recovery")
        repeat = await session.sample(context, payload, "error_repeat")
        confirmed = (controls_clear and recovery is not None and repeat is not None
                     and not recovery["signatures"] and not recovery["blocked"]
                     and recovery["proof"]["status"] == baseline["proof"]["status"]
                     and _distance(baseline["text"], recovery["text"]) <= max(0.02, noise * 2)
                     and not repeat["blocked"] and bool(novel & repeat["signatures"]))
        if confirmed:
            evidence = {"confirmation_rounds": 2, "baseline": _proof(baselines + [recovery]),
                        "controls": _proof(controls), "probes": _proof([first, repeat]),
                        "matched_signatures": sorted(novel & repeat["signatures"])}
            findings.append(_finding(context, "error_based", evidence, preset, "quote_" + quote,
                                     [payload, payload], control_values))
            break
        candidate("error_based", "error_not_causally_confirmed",
                  probes=_proof([first, repeat]), controls=_proof(controls))

    # AND retains a matching row; OR can expand an empty result. The matching
    # branch must reproduce baseline and the opposite branch must be stable and
    # separate. Never infer "empty" from a particular JSON/HTML response format.
    suffixes = ["", "'", '")', "')"] if preset == "staging-deep" else ["", "'"]
    near_limit, far_limit = max(0.02, noise * 2), max(0.06, noise * 3)

    def normal(sample):
        return (sample is not None and not sample["blocked"] and not sample["signatures"]
                and sample["proof"]["status"] == baseline["proof"]["status"])

    def matches_baseline(sample):
        return normal(sample) and max(_distance(b["text"], sample["text"])
                                      for b in baselines) <= near_limit

    for operator, matching_branch, signal_branch in (("AND", "true", "false"),
                                                     ("OR", "false", "true")):
        for suffix in suffixes:
            ending = "-- " if suffix else ""
            keyword_values, keyword_controls = [], []
            if operator == "OR":
                # Same operator token and quoting family, but no boolean
                # predicate. Keyword filters/reflection must not count as SQL.
                keyword_values = [f"{context.original}{suffix} OR qa_probe_{name}{ending}"
                                  for name in ("a", "b")]
                keyword_controls = [await session.sample(context, value, "or_keyword_control")
                                    for value in keyword_values]
                if not all(matches_baseline(sample) for sample in keyword_controls):
                    continue
            pairs = []
            for round_index, (left, right) in enumerate(((17, 18), (29, 30))):
                true_value = f"{context.original}{suffix} {operator} {left}={left}{ending}"
                false_value = f"{context.original}{suffix} {operator} {left}={right}{ending}"
                values = [("true", true_value), ("false", false_value)]
                if round_index:
                    values.reverse()
                samples = {role: await session.sample(context, value, "boolean_" + role)
                           for role, value in values}
                if not all(normal(sample) for sample in samples.values()):
                    break
                near, far = samples[matching_branch], samples[signal_branch]
                if not matches_baseline(near):
                    break
                if min(_distance(b["text"], far["text"]) for b in baselines) < far_limit:
                    break
                if _distance(near["text"], far["text"]) < far_limit:
                    break
                pairs.append({**samples, "probe_values": [value for _, value in values],
                              "true_delta": max(_distance(b["text"], samples["true"]["text"])
                                                for b in baselines),
                              "false_delta": max(_distance(b["text"], samples["false"]["text"])
                                                 for b in baselines)})
            stable_signal = (len(pairs) == 2 and
                             _distance(pairs[0][signal_branch]["text"],
                                       pairs[1][signal_branch]["text"]) <= near_limit)
            if stable_signal:
                recovery = None
                if operator == "OR":
                    recovery = await session.sample(context, None, "or_recovery")
                    if not matches_baseline(recovery):
                        candidate("boolean_blind", "or_baseline_recovery_failed")
                        continue
                evidence = {
                    "operator": operator, "baseline_matches": matching_branch,
                    "confirmation_rounds": 2, "request_order": ["true,false", "false,true"],
                    "baseline": _proof(baselines), "controls": _proof(controls),
                    "keyword_controls": _proof(keyword_controls),
                    "baseline_noise": round(noise, 4),
                    "pairs": [{"true": pair["true"]["proof"], "false": pair["false"]["proof"],
                               "true_distance": round(pair["true_delta"], 4),
                               "false_distance": round(pair["false_delta"], 4)} for pair in pairs],
                }
                if recovery is not None:
                    evidence["recovery"] = recovery["proof"]
                findings.append(_finding(context, "boolean_blind", evidence, preset,
                                         f"paired_{operator}_predicates",
                                         [value for pair in pairs for value in pair["probe_values"]],
                                         control_values + keyword_values))
                return findings, candidates
            if pairs:
                candidate("boolean_blind", "differential_not_reproduced", operator=operator)
    return findings, candidates


async def scan_query(target, param, preset, sql_errors):
    config = PRESETS.get(preset)
    output = {
        "target": _redacted_url(target)[0], "preset": preset, "params_tested": [], "waf_detected": None,
        "db_fingerprint": None, "results": [], "findings": [], "candidates": [],
        "vulnerable": False, "total_findings": 0, "techniques_found": [],
        "techniques_skipped": list(SKIPPED), "techniques_tested": ["error_based", "boolean_blind"],
        "requests_sent": 0, "request_budget": config["requests"] if config else 0,
        "errors": [], "coverage_complete": False, "assessment": "inconclusive",
        "confidence": "LOW", "risk_summary": {"critical": 0, "high": 0, "medium": 0},
    }
    if config is None:
        output["errors"].append("invalid_preset")
        output["coverage"] = "invalid_preset; no requests sent"
        return output
    try:
        contexts = query_contexts(target, param)
    except ValueError as exc:
        output["errors"].append(str(exc))
        output["coverage"] = "invalid_target; no requests sent"
        return output
    selected = contexts[:config["params"]]
    output["parameter_occurrences_skipped"] = max(0, len(contexts) - len(selected))
    async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                 timeout=8.0, trust_env=False) as client:
        session = ProbeSession(client, config, sql_errors)
        for context in selected:
            output["params_tested"].append(context.name)
            try:
                await _experiment(session, context, preset, output["findings"], output["candidates"])
            except ProbeStop as exc:
                session.partial = True
                session.errors.append(str(exc))
                break
    output["results"] = output["findings"]
    output["vulnerable"] = bool(output["findings"])
    output["total_findings"] = len(output["findings"])
    output["techniques_found"] = sorted({f["technique"] for f in output["findings"]})
    output["requests_sent"] = session.sent
    output["errors"] = session.errors
    output["waf_detected"] = session.waf
    output["coverage_complete"] = not session.partial and len(contexts) == len(selected)
    output["assessment"] = ("confirmed" if output["vulnerable"] else
                            "no_evidence" if output["coverage_complete"] and not output["candidates"]
                            else "inconclusive")
    output["confidence"] = "HIGH" if output["vulnerable"] else "LOW"
    output["risk_summary"]["high"] = len(output["findings"])
    guessed = sum(context.guessed for context in selected)
    output["coverage"] = (
        f"preset={preset}; GET/query; error_based+boolean_blind; "
        f"params={len(output['params_tested'])}; guessed_params={guessed}; "
        f"requests={session.sent}/{session.budget}; coverage_complete={output['coverage_complete']}; "
        "response_limit=256KiB; similarity_window=16KiB; "
        "time_blind/union_based/stacked/db_enumeration/POST skipped; "
        "no_evidence does not prove absence of SQLi"
    )
    return attach_contract_fields(output, finding_type="sqli")

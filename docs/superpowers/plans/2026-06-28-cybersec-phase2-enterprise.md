# Cybersec Phase 2: Enterprise Pentesting — Implementation Plan

> **For agentic workers:** Subagent-driven or inline execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 8 new MCP tools + 3 new skills for enterprise AD, cloud, and password testing.

**Architecture:** Pure Python (httpx, socket, regex) + CLI wrappers in `cyber_tools/`, registered via FastMCP in `server.py`.

**Tech Stack:** Python 3.12, httpx, FastMCP, asyncio, ldap3 (optional)

---

### Task 1: `nmap_scan` — Full nmap wrapper

**Files:** Create `mcp/cyber_tools/nmap_scan.py`

- [ ] **Write the tool**

```python
import asyncio


async def nmap_scan(target: str, ports: str = "", scripts: str = "") -> dict:
    cmd = ["nmap", "-oX", "-", target]
    if ports:
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080,8443"])
    if scripts:
        cmd.extend(["--script", scripts])
    cmd.append("-sV")

    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

        import xml.etree.ElementTree as ET
        root = ET.fromstring(stdout)
        hosts = []
        for host in root.findall(".//host"):
            addr = host.find(".//address")
            ip = addr.get("addr") if addr is not None else ""
            ports_found = []
            for p in host.findall(".//port"):
                state = p.find("state")
                svc = p.find("service")
                if state is not None and state.get("state") == "open":
                    ports_found.append({
                        "port": p.get("portid"),
                        "protocol": p.get("protocol"),
                        "service": svc.get("name") if svc is not None else "",
                        "product": svc.get("product") if svc is not None else "",
                        "version": svc.get("version") if svc is not None else "",
                    })
            hosts.append({"ip": ip, "open_ports": ports_found, "count": len(ports_found)})

        return {"target": target, "hosts": hosts, "total_open": sum(h["count"] for h in hosts)}
    except FileNotFoundError:
        return {"target": target, "error": "nmap not found. Install: brew install nmap"}
    except asyncio.TimeoutError:
        return {"target": target, "error": "nmap scan timed out (180s)"}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/nmap_scan.py
git commit -m "feat: add nmap_scan tool"
```

---

### Task 2: `ldap_enum` — LDAP enumeration

**Files:** Create `mcp/cyber_tools/ldap_enum.py`

- [ ] **Write the tool**

```python
import asyncio


async def ldap_enum(target: str, username: str = "", password: str = "") -> dict:
    host = target.split(":")[0]
    port = int(target.split(":")[1]) if ":" in target else 389

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
        # LDAP bind request (anonymous)
        ldap_bind = bytes.fromhex(
            "300c02010160070201030400a000"
        )
        w.write(ldap_bind)
        await w.drain()
        resp = await asyncio.wait_for(r.read(4096), timeout=10)
        w.close()

        info = {
            "target": f"{host}:{port}",
            "ldap_available": len(resp) > 0,
            "anonymous_bind": len(resp) > 10,
            "response_hex": resp.hex()[:200],
            "note": "LDAP server responded. Use ldapsearch for full enumeration."
        }

        # Try to extract server info from response
        try:
            text = resp.decode("utf-8", errors="replace")
            if text:
                info["response_text"] = text[:200]
        except Exception:
            pass

        return info
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
        return {"target": f"{host}:{port}", "ldap_available": False, "error": str(e)}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/ldap_enum.py
git commit -m "feat: add ldap_enum tool"
```

---

### Task 3: `bloodhound_collect` — BloodHound ingestor wrapper

**Files:** Create `mcp/cyber_tools/bloodhound_collect.py`

- [ ] **Write the tool**

```python
import asyncio


async def bloodhound_collect(domain: str, username: str, password: str, collector: str = "sharphound") -> dict:
    if collector == "sharphound":
        cmd = f"SharpHound.exe -c All -d {domain}"
        return {
            "domain": domain,
            "collector": "SharpHound",
            "command": cmd,
            "note": "SharpHound must be run from a Windows domain-joined machine. "
                    "Transfer SharpHound.exe to the target and run the command above.",
        }

    cmd = ["bloodhound-python", "-d", domain, "-u", username, "-p", password, "-c", "All"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        return {"domain": domain, "collector": "bloodhound-python", "output": output[:500], "success": "Done" in output}
    except FileNotFoundError:
        return {"domain": domain, "error": "bloodhound-python not found. Install: pip install bloodhound", "instructions": "Then run: bloodhound-python -d <domain> -u <user> -p <pass> -c All"}
    except asyncio.TimeoutError:
        return {"domain": domain, "error": "BloodHound collection timed out"}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/bloodhound_collect.py
git commit -m "feat: add bloodhound_collect tool"
```

---

### Task 4: `hash_analyze` — Hash type identification

**Files:** Create `mcp/cyber_tools/hash_analyze.py`

- [ ] **Write the tool**

```python
import re

HASH_PATTERNS = [
    (r"^\$2[ayb]\$.{56}", "bcrypt", "BCrypt", 60),
    (r"^\$5\$.{52}", "sha256-crypt", "SHA-256 Crypt", 52),
    (r"^\$6\$.{84}", "sha512-crypt", "SHA-512 Crypt", 84),
    (r"^[a-f0-9]{32}$", "md5", "MD5", 32),
    (r"^[a-f0-9]{40}$", "sha1", "SHA-1", 40),
    (r"^[a-f0-9]{56}$", "sha224", "SHA-224", 56),
    (r"^[a-f0-9]{64}$", "sha256", "SHA-256", 64),
    (r"^[a-f0-9]{96}$", "sha384", "SHA-384", 96),
    (r"^[a-f0-9]{128}$", "sha512", "SHA-512", 128),
    (r"^\$NT\$.{32}", "ntlm", "NTLM", 32 + 4),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "lm-ntlm", "LM:NTLM hash", 65),
    (r"^\$1\$.{34}", "md5-crypt", "MD5 Crypt", 34),
    (r"^[0-9a-f]{16}$", "mysql", "MySQL pre-4.1", 16),
    (r"^\*[0-9a-f]{40}$", "mysql-sha1", "MySQL SHA-1", 41),
    (r"^[0-9a-f]{41}$", "mysql-sha1-alt", "MySQL SHA-1 (alt)", 41),
    (r"^sk-[a-zA-Z0-9]{20,}$", "openai-key", "OpenAI API Key", None),
    (r"^ghp_[a-zA-Z0-9]{36}$", "github-pat", "GitHub Personal Access Token", None),
    (r"^AKIA[0-9A-Z]{16}$", "aws-key", "AWS Access Key ID", 20),
]


async def hash_analyze(hash_string: str) -> dict:
    matches = []
    for pattern, name, display_name, length in HASH_PATTERNS:
        if re.match(pattern, hash_string.strip()):
            matches.append({"type": name, "display_name": display_name, "length": length, "confidence": "high"})

    if not matches:
        # Try to guess by length
        h = hash_string.strip()
        length_guesses = {
            32: "MD5, NTLM, LM",
            40: "SHA-1, MySQL SHA-1",
            56: "SHA-224",
            64: "SHA-256",
            96: "SHA-384",
            128: "SHA-512",
        }
        guess = length_guesses.get(len(h), "Unknown")
        matches.append({"type": "unknown", "display_name": f"Possible: {guess}", "length": len(h), "confidence": "low"})

    hashcat_modes = {m["type"]: m for m in matches}
    mode_map = {
        "bcrypt": 3200, "sha512-crypt": 1800, "sha256-crypt": 7400,
        "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
        "ntlm": 1000, "md5-crypt": 500,
    }

    return {
        "hash": hash_string[:50] + "..." if len(hash_string) > 50 else hash_string,
        "matches": matches,
        "hashcat_mode": [mode_map.get(m["type"]) for m in matches if m["type"] in mode_map],
        "john_format": [m["type"] for m in matches],
        "crack_command": f"hashcat -m {mode_map.get(matches[0]['type'], 0)} hash.txt wordlist.txt" if matches else "",
    }
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/hash_analyze.py
git commit -m "feat: add hash_analyze tool"
```

---

### Task 5: `hydra_brute` — Hydra brute force wrapper

**Files:** Create `mcp/cyber_tools/hydra_brute.py`

- [ ] **Write the tool**

```python
import asyncio


async def hydra_brute(target: str, service: str = "ssh", username: str = "root", wordlist: str = "") -> dict:
    cmd = ["hydra", "-l", username, "-P", wordlist or "/usr/share/wordlists/rockyou.txt", f"{service}://{target}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = stdout.decode(errors="replace")
        lines = output.split("\n")
        results = [l for l in lines if "password:" in l.lower() or "login:" in l.lower() or "host:" in l.lower()]
        return {"target": target, "service": service, "results": results[:20], "count": len(results)}
    except FileNotFoundError:
        return {"target": target, "error": "hydra not found. Install: brew install hydra"}
    except asyncio.TimeoutError:
        return {"target": target, "error": "hydra timed out (300s)"}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/hydra_brute.py
git commit -m "feat: add hydra_brute tool"
```

---

### Task 6: `cloud_enum` — Cloud service enumeration

**Files:** Create `mcp/cyber_tools/cloud_enum.py`

- [ ] **Write the tool**

```python
import httpx

AWS_BUCKET_PATTERNS = ["{name}", "{name}-prod", "{name}-dev", "{name}-staging", "{name}-backup", "{name}-data", "{name}-assets"]
AZURE_STORAGE_PATTERNS = ["{name}", "{name}prod", "{name}dev", "{name}staging", "{name}backup"]
GCP_BUCKET_PATTERNS = ["{name}", "{name}-prod", "{name}-dev", "{name}-staging", "{name}-backup"]


async def cloud_enum(company: str) -> dict:
    found = []

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        # AWS S3
        for pattern in AWS_BUCKET_PATTERNS:
            bucket = pattern.format(name=company)
            try:
                resp = await client.get(f"https://{bucket}.s3.amazonaws.com")
                if resp.status_code != 404:
                    found.append({"provider": "AWS S3", "bucket": bucket, "status": resp.status_code})
            except httpx.HTTPError:
                continue

        # Azure Blob
        for pattern in AZURE_STORAGE_PATTERNS:
            account = pattern.format(name=company)
            try:
                resp = await client.get(f"https://{account}.blob.core.windows.net")
                if resp.status_code != 404 and resp.status_code != 400:
                    found.append({"provider": "Azure Blob", "account": account, "status": resp.status_code})
            except httpx.HTTPError:
                continue

        # GCP Cloud Storage
        for pattern in GCP_BUCKET_PATTERNS:
            bucket = pattern.format(name=company)
            try:
                resp = await client.get(f"https://storage.googleapis.com/{bucket}")
                if resp.status_code != 404:
                    found.append({"provider": "GCP Storage", "bucket": bucket, "status": resp.status_code})
            except httpx.HTTPError:
                continue

    return {"company": company, "resources_found": found, "count": len(found)}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/cloud_enum.py
git commit -m "feat: add cloud_enum tool"
```

---

### Task 7: `s3_scanner` — S3 bucket content scanner

**Files:** Create `mcp/cyber_tools/s3_scanner.py`

- [ ] **Write the tool**

```python
import httpx
import re


async def s3_scanner(bucket_name: str) -> dict:
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                files = re.findall(r"<Key>(.*?)</Key>", resp.text)
                return {
                    "bucket": bucket_name,
                    "accessible": True,
                    "public": True,
                    "files": files[:100],
                    "total_files": len(files),
                    "url": url,
                }
            elif resp.status_code == 403:
                return {"bucket": bucket_name, "accessible": True, "public": False, "url": url, "note": "Bucket exists but not publicly listable. May still be accessible if you know file paths."}
            else:
                return {"bucket": bucket_name, "accessible": False, "status": resp.status_code}
    except httpx.HTTPError as e:
        return {"bucket": bucket_name, "accessible": False, "error": str(e)}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/s3_scanner.py
git commit -m "feat: add s3_scanner tool"
```

---

### Task 8: `searchsploit` — Exploit-db search

**Files:** Create `mcp/cyber_tools/searchsploit.py`

- [ ] **Write the tool**

```python
import asyncio


async def searchsploit(search_term: str) -> dict:
    cmd = ["searchsploit", search_term]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode(errors="replace")
        lines = [l.strip() for l in output.split("\n") if l.strip() and not l.startswith("--")]
        exploits = []
        for line in lines:
            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                exploits.append({
                    "path": parts[0] if len(parts) > 0 else "",
                    "title": parts[1] if len(parts) > 1 else "",
                    "type": parts[2] if len(parts) > 2 else "",
                })
        return {"search": search_term, "results": exploits[:30], "count": len(exploits)}
    except FileNotFoundError:
        return {"search": search_term, "error": "searchsploit not found. Install: git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb && ln -sf /opt/exploitdb/searchsploit /usr/bin/searchsploit"}
    except asyncio.TimeoutError:
        return {"search": search_term, "error": "searchsploit timed out"}
```

- [ ] **Commit**

```bash
git add mcp/cyber_tools/searchsploit.py
git commit -m "feat: add searchsploit tool"
```

---

### Task 9: Register 8 tools in server.py

**Files:** Modify `mcp/server.py`

- [ ] **Add imports** (after existing imports)

```python
from cyber_tools.nmap_scan import nmap_scan as _nmap
from cyber_tools.ldap_enum import ldap_enum as _ldap
from cyber_tools.bloodhound_collect import bloodhound_collect as _bloodhound
from cyber_tools.hash_analyze import hash_analyze as _hash
from cyber_tools.hydra_brute import hydra_brute as _hydra
from cyber_tools.cloud_enum import cloud_enum as _cloud
from cyber_tools.s3_scanner import s3_scanner as _s3
from cyber_tools.searchsploit import searchsploit as _searchsploit
```

- [ ] **Add 8 tool registrations** (before `if __name__`)

```python
@mcp.tool()
def nmap_scan(target: str, ports: str = "", scripts: str = "") -> str:
    """Full nmap network scan with service detection. Requires nmap CLI."""
    return json.dumps(_run(_nmap(target, ports=ports, scripts=scripts)), indent=2)

@mcp.tool()
def ldap_enum(target: str) -> str:
    """LDAP anonymous bind and server enumeration."""
    return json.dumps(_run(_ldap(target)), indent=2)

@mcp.tool()
def bloodhound_collect(domain: str, username: str = "", password: str = "") -> str:
    """Collect AD data for BloodHound analysis. Requires bloodhound-python CLI."""
    return json.dumps(_run(_bloodhound(domain, username=username, password=password)), indent=2)

@mcp.tool()
def hash_analyze(hash_string: str) -> str:
    """Identify hash type from its format (MD5, SHA1, bcrypt, NTLM, etc)."""
    return json.dumps(_run(_hash(hash_string)), indent=2)

@mcp.tool()
def hydra_brute(target: str, service: str = "ssh", username: str = "root", wordlist: str = "") -> str:
    """Online password brute forcing. Requires hydra CLI."""
    return json.dumps(_run(_hydra(target, service=service, username=username, wordlist=wordlist)), indent=2)

@mcp.tool()
def cloud_enum(company: str) -> str:
    """Enumerate cloud storage resources (AWS S3, Azure, GCP) for a company name."""
    return json.dumps(_run(_cloud(company)), indent=2)

@mcp.tool()
def s3_scanner(bucket_name: str) -> str:
    """Check if an S3 bucket is publicly accessible and list its contents."""
    return json.dumps(_run(_s3(bucket_name)), indent=2)

@mcp.tool()
def searchsploit(search_term: str) -> str:
    """Search exploit-db for exploits. Requires searchsploit CLI."""
    return json.dumps(_run(_searchsploit(search_term)), indent=2)
```

- [ ] **Commit**

```bash
git add mcp/server.py
git commit -m "feat: register 8 enterprise tools in MCP server"
```

---

### Task 10: Create `cybersec-ad` skill

**Files:** Create `skills/cybersec-ad/SKILL.md`

- [ ] **Write skill**

```markdown
---
name: cybersec-ad
description: Use when user asks about Active Directory, domain enumeration, Kerberos, or AD attacks
---

<HARD-GATE>
Do NOT run AD attacks without first identifying domain controllers and understanding the domain structure.
AD attacks can disrupt production — always warn user before running kerberos or privesc attacks.
</HARD-GATE>

## Active Directory Security Methodology

### Checklist

1. **Domain Discovery** — Run `ldap_enum(domain_controller)` for LDAP anonymous bind and domain info
2. **Port Scan DC** — Run `nmap_scan(target, ports="88,389,445,464,636,3268,3269", scripts="ldap*")` on domain controllers
3. **BloodHound Collection** — Run `bloodhound_collect(domain, username, password)` to gather AD relationship data
4. **Kerberos Enum** — Check if AS-REP roasting or Kerberoasting is possible via servicePrincipalName
5. **SMB Enum** — Run `smb_enum(target)` on domain controllers for SMB access
6. **Password Policy** — Check domain password policy via SMB or LDAP
7. **Privilege Escalation** — Check for common AD privesc paths (ACL abuse, Group Policy, constrained delegation)
8. **Document Findings** — Compile AD attack paths and recommended mitigations

### Tools Available
`ldap_enum`, `nmap_scan`, `bloodhound_collect`, `smb_enum`, `ssh_audit`, `smb_enum`, `cve_search`

### Next Skill
Load `cybersec-password` if password/hash attacks are relevant, otherwise `cybersec-report`.
```

- [ ] **Commit**

```bash
git add skills/cybersec-ad/SKILL.md
git commit -m "feat: add cybersec-ad skill"
```

---

### Task 11: Create `cybersec-cloud` skill

**Files:** Create `skills/cybersec-cloud/SKILL.md`

- [ ] **Write skill**

```markdown
---
name: cybersec-cloud
description: Use when user asks about cloud security, AWS, Azure, GCP, S3 buckets, or cloud enumeration
---

<HARD-GATE>
Do NOT access cloud resources without explicit authorization.
Cloud enumeration is passive (checking bucket existence, not accessing content) unless user confirms authorization.
</HARD-GATE>

## Cloud Security Testing Methodology

### Checklist

1. **Cloud Resource Enumeration** — Run `cloud_enum(company)` to discover AWS S3, Azure Blob, GCP Storage resources
2. **S3 Bucket Deep Scan** — For each discovered S3 bucket, run `s3_scanner(bucket_name)` to check public access
3. **Metadata API Check** — If inside cloud environment, check http://169.254.169.254/latest/meta-data/ (AWS)
4. **Cloud Config Review** — Check for exposed cloud config files (.aws/config, credentials, .env)
5. **DNS Enum** — Use `dns_lookup(target)` to find cloud services (s3, cloudfront, azurewebsites)
6. **SSL Analysis** — Check SSL certs via `ssl_check(target)` for cloud service info in CN/SAN
7. **Document Findings** — Public buckets, exposed configs, cloud services in use

### Tools Available
`cloud_enum`, `s3_scanner`, `dns_lookup`, `ssl_check`, `crt_search`, `dork_search`

### Next Skill
Load `cybersec-report` for final documentation.
```

- [ ] **Commit**

```bash
git add skills/cybersec-cloud/SKILL.md
git commit -m "feat: add cybersec-cloud skill"
```

---

### Task 12: Create `cybersec-password` skill

**Files:** Create `skills/cybersec-password/SKILL.md`

- [ ] **Write skill**

```markdown
---
name: cybersec-password
description: Use when user asks about password cracking, hash identification, brute force, or credential attacks
---

<HARD-GATE>
Do NOT brute force passwords without explicit authorization.
Hash cracking is offline and safe — but only crack hashes you are authorized to test.
Always identify hash type before attempting to crack.
</HARD-GATE>

## Password Security Testing Methodology

### Checklist

1. **Hash Identification** — Run `hash_analyze(hash)` to identify the hash type (MD5, SHA1, bcrypt, NTLM, etc.)
2. **Crack Command** — Use the hashcat mode from hash_analyze to construct crack command
3. **Online Brute Force** — If authorized, run `hydra_brute(target, service, username)` for online password guessing
4. **Nmap Scan** — If brute forcing services, run `nmap_scan(target, ports)` to discover available login services
5. **Credential Analysis** — Check for default credentials, weak password patterns
6. **Wordlist Suggestion** — Recommend appropriate wordlist based on target (rockyou, SecLists, custom)
7. **Document Results** — Cracked passwords, weak credentials, recommendations

### Tools Available
`hash_analyze`, `hydra_brute`, `nmap_scan`, `ssh_audit`, `smb_enum`, `cve_search`

### Next Skill
Load `cybersec-report` for final documentation.
```

- [ ] **Commit**

```bash
git add skills/cybersec-password/SKILL.md
git commit -m "feat: add cybersec-password skill"
```

---

### Task 13: Update bootstrap with 3 new skills

**Files:** Modify `skills/using-cybersec/SKILL.md`

- [ ] **Update table** (add `cybersec-ad`, `cybersec-cloud`, `cybersec-password`)

```markdown
| **cybersec-recon** | recon, enumerate, find subdomains, DNS, whois, gather info |
| **cybersec-osint** | osint, shodan, url history, wayback, advanced recon, leak |
| **cybersec-scanning** | scan ports, detect services, fingerprint, probe |
| **cybersec-vulns** | vulnerabilities, CVEs, weaknesses, security issues |
| **cybersec-web** | web app test, SQLi, XSS, CMS, WordPress, API |
| **cybersec-bugbounty** | bug bounty, nuclei, 403 bypass, smuggling, dalfox |
| **cybersec-ad** | active directory, domain, kerberos, bloodhound, LDAP |
| **cybersec-cloud** | cloud, AWS, Azure, GCP, S3, bucket |
| **cybersec-password** | password, hash, brute force, hydra, crack |
| **cybersec-exploit** | exploit, PoC, get shell, metasploit, brute force |
| **cybersec-crisis** | incident, breach, emergency, compromised, hacked |
| **cybersec-report** | report, remediation, fix, document, summary |
```

- [ ] **Update count** (52 → 60 tools, 10 → 13 skills)

- [ ] **Commit**

```bash
git add skills/using-cybersec/SKILL.md
git commit -m "feat: update bootstrap with AD, cloud, password skills"
```

---

### Task 14: Verify 60 tools

- [ ] **Count registered tools**

```bash
/Users/aaa/Documents/Developer/cybersec/mcp/.venv/bin/python3 -c "
import ast
with open('/Users/aaa/Documents/Developer/cybersec/mcp/server.py') as f:
    tree = ast.parse(f.read())
tools = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.decorator_list]
print(f'Total tools: {len(tools)}')
"

```

Expected: `Total tools: 60`

- [ ] **Push all**

```bash
git push
```

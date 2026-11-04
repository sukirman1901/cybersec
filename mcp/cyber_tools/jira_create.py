"""Create Jira issue from a security finding."""
import json
import urllib.request
import urllib.parse
import base64
import urllib.error
import re


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _check(value):
    """1 MiB text, 1000 items/container, 10000 nodes, depth 32."""
    stack, nodes, size = [(value, 0)], 0, 0
    while stack:
        v, depth = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 10000:
            raise ValueError('Structure budget exceeded')
        if isinstance(v, str):
            if len(v) > 1048576:
                raise ValueError('Text budget exceeded')
            size += len(v.encode('utf-8'))
            if size > 1048576:
                raise ValueError('Text budget exceeded')
        elif isinstance(v, (list, dict)):
            if len(v) > 1000:
                raise ValueError('Collection budget exceeded')
            stack.extend((x, depth + 1) for x in (list(v.keys()) + list(v.values()) if isinstance(v, dict) else v))


def _redact(value, key=''):
    """Named secrets/raw evidence and HTTP URL credentials/query/fragment, not arbitrary prose."""
    if re.search(r'password|secret|token|authorization|cookie|api[_-]?key', key, re.I) or key.lower() in ('evidence','response','raw','body','headers'):
        return '[REDACTED]'
    if isinstance(value, dict):
        return {_redact(k): _redact(v,k) for k,v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        def clean(m):
            try:
                p=urllib.parse.urlsplit(m.group())
                return urllib.parse.urlunsplit((p.scheme,p.netloc.rsplit('@',1)[-1],p.path,'[REDACTED]' if p.query else '', '[REDACTED]' if p.fragment else ''))
            except ValueError:
                return '[REDACTED URL]'
        return re.sub(r'https?://[^\s<>"\']+',clean,value,flags=re.I)
    return value

def jira_create(finding_json: str, jira_url: str = "", email: str = "", api_token: str = "", project_key: str = "SEC") -> str:
    try:
        for value in (finding_json,jira_url,email,api_token,project_key):
            _check(value)
        finding = json.loads(finding_json) if isinstance(finding_json, str) else finding_json
        _check(finding)
        if not isinstance(finding,dict) or not finding or not any(finding.get(k) for k in ('title','type')):
            raise ValueError('Finding required')
        if any(not isinstance(finding[k],str) for k in ('title','type','severity','status','target','host','remediation','fix') if k in finding):
            raise ValueError('Invalid field type')
        parsed=urllib.parse.urlsplit(jira_url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('HTTPS Jira base URL required')
        parsed.port
        if not isinstance(project_key,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,49}',project_key):
            raise ValueError('Invalid project key')
        if not isinstance(email,str) or not isinstance(api_token,str):
            raise ValueError('Invalid credentials')
        finding=_redact(finding)
    except (ValueError,TypeError,AttributeError,RecursionError):
        return json.dumps({"error": "Invalid finding JSON"}, indent=2)

    if not jira_url or not email or not api_token:
        return json.dumps({
            "error": "Missing Jira credentials",
            "required": ["jira_url (e.g. https://yourorg.atlassian.net)", "email", "api_token"],
            "hint": "Create API token at https://id.atlassian.com/manage-profile/security/api-tokens"
        }, indent=2)

    sev = finding.get("severity", "Medium")
    sev_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
    priority = sev_map.get(sev.lower(), "Medium")

    title = finding.get("title", finding.get("type", "Security Finding"))
    target = finding.get("target", finding.get("host", ""))
    evidence = finding.get("evidence", finding.get("response", ""))
    remediation = finding.get("remediation", finding.get("fix", "See vulnerability details"))

    description = f"""
h2. Security Finding: {title}

||Field||Value||
|Severity|{sev.upper()}|
|Target|{target}|
|Type|{finding.get('type', finding.get('vuln_type', 'Unknown'))}|
|Status|{finding.get('status', 'new')}|

h3. Evidence
{{code}}
{evidence[:2000]}
{{code}}

h3. Remediation
{remediation}

h3. Metadata
* Detected by: Cybersec MCP
* Finding ID: {finding.get('id', finding.get('finding_id', 'N/A'))}
"""

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[{sev.upper()}] {title} — {target}",
            "description": {"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":description}]}]},
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": ["security", "cybersec", sev.lower()],
        }
    }

    api_url = f"{jira_url.rstrip('/')}/rest/api/3/issue"
    credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(api_url, data=data, headers=headers, method="POST")
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=15) as resp:
            if resp.status != 201:
                raise ValueError('Creation not acknowledged')
            raw=resp.read(65537)
        if len(raw)>65536:
            raise ValueError('Receipt exceeds 64 KiB')
        body=json.loads(raw.decode('utf-8'))
        if not isinstance(body,dict) or not isinstance(body.get('key'),str) or not re.fullmatch(re.escape(project_key)+r'-[1-9][0-9]*',body['key']) or not isinstance(body.get('id'),str) or not body['id'].isdigit():
            raise ValueError('Invalid creation receipt')
        return json.dumps({
            "status": "created",
            "issue_key": body.get("key", ""),
            "issue_url": f"{jira_url.rstrip('/')}/browse/{body.get('key', '')}",
            "project": project_key,
            "priority": priority,
        }, indent=2)
    except urllib.error.HTTPError as e:
        e.close()
        return json.dumps({
            "error": f"Jira API returned {e.code}",
            "status":"incomplete", "creation_confirmed":False,
        }, indent=2)
    except (OSError,ValueError,TypeError,RecursionError):
        return json.dumps({"error": "Jira creation not confirmed; response invalid or request failed", "status":"incomplete", "creation_confirmed":False}, indent=2)

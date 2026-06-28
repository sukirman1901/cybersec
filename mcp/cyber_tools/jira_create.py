"""Create Jira issue from a security finding."""
import json
import urllib.request
import urllib.parse
import base64

def jira_create(finding_json: str, jira_url: str = "", email: str = "", api_token: str = "", project_key: str = "SEC") -> str:
    try:
        finding = json.loads(finding_json) if isinstance(finding_json, str) else finding_json
    except Exception:
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
            "description": description,
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
        resp = urllib.request.urlopen(req, timeout=15)
        body = json.loads(resp.read().decode("utf-8"))
        return json.dumps({
            "status": "created",
            "issue_key": body.get("key", ""),
            "issue_url": f"{jira_url.rstrip('/')}/browse/{body.get('key', '')}",
            "project": project_key,
            "priority": priority,
        }, indent=2)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return json.dumps({
            "error": f"Jira API returned {e.code}",
            "response": body[:500],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
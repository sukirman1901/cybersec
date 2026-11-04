"""Send finding notifications to Slack/Discord/Teams via webhook."""
import json
import urllib.request
import urllib.error
import re
from urllib.parse import urlsplit, urlunsplit


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
    """Named secrets/raw evidence and HTTP URL secrets, not arbitrary prose."""
    if re.search(r'password|secret|token|authorization|cookie|api[_-]?key', key, re.I) or key.lower() in ('evidence','response','raw','body','headers'):
        return '[REDACTED]'
    if isinstance(value, dict):
        return {_redact(k): _redact(v,k) for k,v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        def clean(m):
            try:
                p=urlsplit(m.group())
                return urlunsplit((p.scheme,p.netloc.rsplit('@',1)[-1],p.path,'[REDACTED]' if p.query else '', '[REDACTED]' if p.fragment else ''))
            except ValueError:
                return '[REDACTED URL]'
        return re.sub(r'https?://[^\s<>"\']+',clean,value,flags=re.I)
    return value

def notify_webhook(webhook_url: str, findings_json: str, platform: str = "auto", severity_filter: str = "high") -> str:
    try:
        for value in (webhook_url,findings_json,platform,severity_filter):
            _check(value)
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
        _check(findings)
        parsed=urlsplit(webhook_url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('HTTPS webhook URL required')
        parsed.port
        if not isinstance(platform,str) or not isinstance(severity_filter,str):
            raise ValueError('Invalid platform/filter')
    except (ValueError,TypeError,AttributeError,RecursionError):
        return json.dumps({"error": "Invalid findings JSON"}, indent=2)

    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))

    severities = ["critical", "high", "medium", "low", "info"]
    severity_filter=severity_filter.lower()
    if severity_filter not in severities+['all'] or not isinstance(findings,list) or any(not isinstance(f,dict) or any(not isinstance(f[k],str) for k in ('title','type','severity','status','target','host') if k in f) or f.get('severity','info').lower() not in severities for f in findings):
        return json.dumps({'error':'Invalid findings or severity filter','status':'incomplete','sent':False})
    findings=_redact(findings)
    min_sev = severities.index(severity_filter) if severity_filter in severities else 1
    filtered = [f for f in findings if severities.index(f.get("severity", "info").lower()) <= min_sev] if severity_filter != "all" else findings

    if not filtered:
        return json.dumps({"status": "no_findings_match_filter", "sent": False}, indent=2)

    if platform == "auto":
        if parsed.hostname == "hooks.slack.com":
            platform = "slack"
        elif parsed.hostname in ('discord.com','discordapp.com') and parsed.path.startswith('/api/webhooks/'):
            platform = "discord"
        elif parsed.hostname.endswith('.webhook.office.com') or parsed.hostname in ('webhook.office.com','outlook.office.com'):
            platform = "teams"
        else:
            platform = "slack"

    matched=len(filtered)
    filtered=filtered[:10]
    if platform == "slack":
        payload = _slack_payload(filtered)
    elif platform == "discord":
        payload = _discord_payload(filtered)
    elif platform == "teams":
        payload = _teams_payload(filtered)
    else:
        return json.dumps({"error": f"Unknown platform: {platform}"}, indent=2)

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(webhook_url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        if len(data)>65536:
            raise ValueError('Notification payload exceeds 64 KiB')
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=10) as resp:
            status=resp.status
            raw=resp.read(65537)
        if len(raw)>65536:
            raise ValueError('Receipt exceeds 64 KiB')
        acknowledged = (platform=='slack' and status==200 and raw.strip()==b'ok') or (platform=='discord' and status==204 and not raw.strip()) or (platform=='teams' and status==200 and raw.strip()==b'1')
        if platform=='discord' and status==200:
            receipt=json.loads(raw)
            acknowledged=isinstance(receipt,dict) and isinstance(receipt.get('id'),str) and receipt['id'].isdigit()
        if not acknowledged:
            return json.dumps({'error':'Provider did not return a supported acknowledgement','status':'incomplete','sent':False,'http_status':status})
        return json.dumps({
            "status": "sent",
            "sent": True,
            "platform": platform,
            "findings_sent": len(filtered),
            "findings_omitted": matched-len(filtered),
            "http_status": status,
        }, indent=2)
    except urllib.error.HTTPError as e:
        e.close()
        return json.dumps({'error':'Webhook provider rejected request','http_status':e.code,'status':'incomplete','sent':False})
    except (OSError,ValueError,TypeError,RecursionError):
        return json.dumps({"error": "Webhook delivery not confirmed", "status": "incomplete", "sent":False}, indent=2)


def _slack_payload(findings):
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "Cybersec Security Alert"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{len(findings)} security finding(s) detected*"}},
        {"type": "divider"},
    ]
    for f in findings[:10]:
        sev = f.get("severity", "info").upper()
        emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":fire:", "MEDIUM": ":warning:", "LOW": ":large_blue_circle:", "INFO": ":information_source:"}.get(sev, ":question:")
        title = f.get("title", f.get("type", "Unknown"))
        target = f.get("target", f.get("host", ""))
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{emoji} *[{sev}]* {title}\nTarget: {target}\nStatus (supplied): {f.get('status','candidate')}"}
        })
    if len(findings) > 10:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"_...and {len(findings) - 10} more findings_"}]})
    return {"blocks": blocks}


def _discord_payload(findings):
    embeds = []
    for f in findings[:10]:
        sev = f.get("severity", "info").lower()
        color = {"critical": 16711680, "high": 16744448, "medium": 16776960, "low": 65280, "info": 3447003}.get(sev, 3447003)
        embeds.append({
            "title": f.get("title", f.get("type", "Unknown")),
            "description": f"Severity: **{sev.upper()}**\nTarget: {f.get('target', f.get('host', ''))}\nStatus (supplied): {f.get('status','candidate')}",
            "color": color,
        })
    return {
        "content": f"**{len(findings)} Security Findings Detected**",
        "embeds": embeds,
    }


def _teams_payload(findings):
    cards = []
    for f in findings:
        sev = f.get("severity", "info").upper()
        title = f.get("title", f.get("type", "Unknown"))
        target = f.get("target", f.get("host", ""))
        cards.append({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": f"{sev}: {title}",
            "themeColor": "FF0000" if sev == "CRITICAL" else "FF8C00" if sev == "HIGH" else "FFD700" if sev == "MEDIUM" else "4CAF50",
            "sections": [{
                "activityTitle": f"**[{sev}]** {title}",
                "facts": [{"name": "Target", "value": target}, {"name": "Type", "value": f.get("type", "")}, {"name":"Status (supplied)","value":f.get('status','candidate')}],
            }],
        })
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Security Alert: {len(findings)} findings",
        "themeColor": "FF0000",
        "title": f"Cybersec Security Alert — {len(findings)} Findings",
        "sections": [section for card in cards[:10] for section in card['sections']],
    }

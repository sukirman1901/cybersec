"""Send finding notifications to Slack/Discord/Teams via webhook."""
import json
import urllib.request

def notify_webhook(webhook_url: str, findings_json: str, platform: str = "auto", severity_filter: str = "high") -> str:
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        return json.dumps({"error": "Invalid findings JSON"}, indent=2)

    if isinstance(findings, dict):
        findings = findings.get("findings", findings.get("results", [findings]))

    severities = ["critical", "high", "medium", "low", "info"]
    min_sev = severities.index(severity_filter) if severity_filter.lower() in severities else 1
    filtered = [f for f in findings if severities.index(f.get("severity", "info").lower()) <= min_sev] if severity_filter != "all" else findings

    if not filtered:
        return json.dumps({"status": "no_findings_match_filter", "sent": False}, indent=2)

    if platform == "auto":
        if "hooks.slack.com" in webhook_url:
            platform = "slack"
        elif "discord.com/api/webhooks" in webhook_url:
            platform = "discord"
        elif "webhook.office.com" in webhook_url or "outlook.office.com" in webhook_url:
            platform = "teams"
        else:
            platform = "slack"

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
        resp = urllib.request.urlopen(req, timeout=10)
        return json.dumps({
            "status": "sent",
            "platform": platform,
            "findings_sent": len(filtered),
            "http_status": resp.status,
            "response": resp.read().decode("utf-8", errors="ignore")[:200],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "status": "failed"}, indent=2)


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
            "text": {"type": "mrkdwn", "text": f"{emoji} *[{sev}]* {title}\nTarget: {target}"}
        })
    if len(findings) > 10:
        blocks.append({"type": "context", "text": {"type": "mrkdwn", "text": f"_...and {len(findings) - 10} more findings_"}})
    return {"blocks": blocks}


def _discord_payload(findings):
    embeds = []
    for f in findings[:10]:
        sev = f.get("severity", "info").lower()
        color = {"critical": 16711680, "high": 16744448, "medium": 16776960, "low": 65280, "info": 3447003}.get(sev, 3447003)
        embeds.append({
            "title": f.get("title", f.get("type", "Unknown")),
            "description": f"Severity: **{sev.upper()}**\nTarget: {f.get('target', f.get('host', ''))}",
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
                "facts": [{"name": "Target", "value": target}, {"name": "Type", "value": f.get("type", "")}],
            }],
        })
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Security Alert: {len(findings)} findings",
        "themeColor": "FF0000",
        "title": f"Cybersec Security Alert — {len(findings)} Findings",
        "potentialAction": cards[:10] if cards else [],
    }
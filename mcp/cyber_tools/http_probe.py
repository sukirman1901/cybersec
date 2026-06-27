"""HTTP service probing using Python http.client."""

import http.client
import ssl
import re

TECH_PATTERNS = {
    "Apache": [r"Apache", r"mod_"],
    "nginx": [r"nginx"],
    "IIS": [r"Microsoft-IIS", r"IIS"],
    "PHP": [r"PHP", r"X-Powered-By: PHP"],
    "WordPress": [r"wp-content", r"wp-json", r"WordPress"],
    "Joomla": [r"joomla", r"com_content"],
    "Drupal": [r"Drupal", r"sites/default"],
    "Node.js": [r"Node\.js", r"express"],
    "Python": [r"Python", r"gunicorn", r"uwsgi", r"Django"],
    "Ruby": [r"Ruby", r"Rails", r"rack"],
    "Java": [r"Java", r"Tomcat", r"JBoss", r"Jetty"],
    "Cloudflare": [r"cloudflare"],
}

def _probe(host: str, port: int, use_ssl: bool) -> dict:
    result = {"port": port, "ssl": use_ssl, "status": 0, "headers": {}, "server": "", "technologies": [], "error": None}
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=5)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0", "Host": host})
        resp = conn.getresponse()
        result["status"] = resp.status
        headers_text = str(resp.headers)
        result["server"] = resp.getheader("Server", "")
        for key, val in resp.headers.items():
            result["headers"][key] = val
        for tech, patterns in TECH_PATTERNS.items():
            for p in patterns:
                if re.search(p, headers_text, re.IGNORECASE) or re.search(p, result.get("server", ""), re.IGNORECASE):
                    result["technologies"].append(tech)
                    break
        conn.close()
    except Exception as e:
        result["error"] = str(e)
    return result

def http_probe(target: str) -> dict:
    """Probe HTTP/HTTPS service."""
    target = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    results = {"target": target, "probes": []}
    for port, use_ssl in [(443, True), (80, False), (8080, False), (8443, True)]:
        probe = _probe(target, port, use_ssl)
        if probe["status"] > 0 or (probe["error"] and "refused" not in probe["error"].lower()):
            results["probes"].append(probe)
    return results

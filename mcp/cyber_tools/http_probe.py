"""HTTP service probing using Python http.client."""

import http.client
import ssl
import re
from urllib.parse import urlparse

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
        headers = {key.lower(): val for key, val in resp.headers.items()}
        # Arbitrary policy/cookie values are not framework evidence (e.g.
        # "xr-spatial-tracking" contains "rack", but does not indicate Ruby).
        headers_text = ' '.join(headers.get(key, '') for key in ('server', 'x-powered-by', 'x-generator', 'x-runtime-framework'))
        result["server"] = resp.getheader("Server", "")
        for key, val in resp.headers.items():
            result["headers"][key] = val
        for tech, patterns in TECH_PATTERNS.items():
            for p in patterns:
                if re.search(r'\b(?:' + p + r')\b', headers_text, re.IGNORECASE):
                    result["technologies"].append(tech)
                    break
        if any(key.startswith('x-nextjs-') for key in headers):
            result['technologies'].append('Next.js')
        result['coverage'] = 'HTTP response header hints only; versions and origin runtime not verified'
        conn.close()
    except Exception as e:
        result["error"] = str(e)
    return result

def http_probe(target: str) -> dict:
    """Probe HTTP/HTTPS service, honoring an explicit port in the target."""
    try:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or ""
        explicit_port = parsed.port
    except ValueError:
        explicit_port = None
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    results = {"target": host, "probes": []}
    if explicit_port:
        # User gave a specific port — probe exactly that (scheme decides SSL).
        ports = [(explicit_port, parsed.scheme == "https")]
    else:
        ports = [(443, True), (80, False), (8080, False), (8443, True)]
    for port, use_ssl in ports:
        probe = _probe(host, port, use_ssl)
        if probe["status"] > 0 or (probe["error"] and "refused" not in probe["error"].lower()):
            results["probes"].append(probe)
    return results

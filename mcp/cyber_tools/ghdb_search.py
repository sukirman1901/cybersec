"""Search Google Hacking Database (GHDB) from exploit-db.com — dork categories, sensitive files, login portals."""

import httpx, re
from html import unescape
from urllib.parse import quote, urlencode

GHDB_BASE = "https://www.exploit-db.com/google-hacking-database"
GHDB_CATEGORIES = [
    "Footholds",
    "Files Containing Usernames",
    "Sensitive Directories",
    "Web Server Detection",
    "Vulnerable Files",
    "Vulnerable Servers",
    "Error Messages",
    "Files Containing Juicy Info",
    "Files Containing Passwords",
    "Sensitive Online Shopping Info",
    "Network or Vulnerability Data",
    "Pages Containing Login Portals",
    "Various Online Devices",
    "Advisories and Vulnerabilities",
]

DORK_TEMPLATES = {
    "admin_panel": 'inurl:admin intitle:"index of"',
    "login_page": 'intitle:"login" inurl:login',
    "config_files": 'filetype:env inurl:".env"',
    "database_dump": 'filetype:sql "INSERT INTO"',
    "backup_files": 'filetype:bak inurl:bak',
    "php_info": 'filetype:php intitle:phpinfo',
    "directory_listing": 'intitle:"index of" "parent directory"',
    "log_files": 'filetype:log inurl:log',
    "password_files": 'filetype:passwd',
    "htaccess": 'filetype:htaccess',
    "xml_files": 'filetype:xml inurl:config',
    "git_exposed": 'inurl:.git',
    "env_files": 'filetype:env',
    "docker_files": 'filetype:dockerfile',
    "s3_buckets": 'site:s3.amazonaws.com',
    "pastebin": 'site:pastebin.com',
    "github_secrets": 'site:github.com password',
    "stackoverflow_leaks": 'site:stackoverflow.com api key',
    "open_database": 'intitle:"index of" "database"',
    "phpmyadmin": 'intitle:phpmyadmin',
    "wordpress_config": 'wp-config.php',
    "tomcat_manager": 'intitle:"Tomcat Manager"',
    "weblogic_console": 'intitle:"WebLogic"',
    "jboss_console": 'intitle:"JBoss"',
    "grafana": 'intitle:"Grafana"',
    "kibana": 'intitle:"Kibana"',
    "jenkins": 'intitle:"Dashboard [Jenkins]"',
    "gitlab": 'intitle:"GitLab"',
    "jira": 'intitle:"JIRA"',
    "confluence": 'intitle:"Confluence"',
    "sonarqube": 'intitle:"SonarQube"',
    "nexus": 'intitle:"Nexus Repository"',
    "portainer": 'intitle:"Portainer"',
    "kubernetes": 'intitle:"Kubernetes Dashboard"',
    "zabbix": 'intitle:"Zabbix"',
    "nagios": 'intitle:"Nagios"',
    "cacti": 'intitle:"Cacti"',
    "munin": 'intitle:"Munin"',
    "phpinfo": 'filetype:php "phpinfo()"',
    "ws_ftp": 'filetype:log "WS_FTP"',
    "mysql_dump": 'filetype:sql "mysql"',
    "error_messages": 'intext:"SQL syntax" | intext:"mysql_fetch"',
    "directory_listing_sensitive": 'intitle:"index of" (passwd | shadow | etc)',
    "open_s3_bucket": 'site:s3.amazonaws.com "listObjects"',
    "exposed_api_keys": 'filetype:json "api_key"',
    "jwt_tokens": 'intext:"eyJ"',
    "swagger_docs": 'inurl:swagger',
    "graphql": 'inurl:graphql',
    "firebase": 'firebaseio.com',
}


async def ghdb_search(query: str = "", category: str = "", limit: int = 20) -> dict:
    """Search Google Hacking Database (GHDB) for sensitive information dorks.

    - query:  search term (e.g., "phpmyadmin", "password", "admin panel")
    - category: filter by category (e.g., "Files Containing Passwords")
    - Returns dorks with descriptions, categories, and Google search links.
    """
    result = {
        "source": "exploit-db.com", "count": 0, "results": [],
        "categories": GHDB_CATEGORIES, "coverage_complete": False,
        "assessment": "incomplete", "execution_status": "partial", "truncated": False,
        "coverage": "One provider response, at most 1 MiB and 100 rows; corpus completeness "
                    "and freshness unverified. Search matches do not establish target "
                    "vulnerability or authorization. Builtin templates are suggestions, not provider matches.",
    }
    if (type(limit) is not int or not 1 <= limit <= 100
            or not isinstance(query, str) or len(query) > 2048
            or any(ord(c) < 32 or ord(c) == 127 for c in query)
            or not isinstance(category, str) or category not in ["", *GHDB_CATEGORIES]):
        result.update(error="Invalid query, category or limit", execution_status="invalid_input")
        return result

    params = {k: v for k, v in (("search", query), ("category", category)) if v}
    url = GHDB_BASE + ("?" + urlencode(params) if params else "")
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            async with client.stream("GET", url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                if resp.status_code != 200:
                    raise ValueError(f"HTTP {resp.status_code}")
                body = bytearray()
                async for chunk in resp.aiter_bytes(chunk_size=65536):
                    if len(body) + len(chunk) > 1048576:
                        result['truncated'] = True
                        raise ValueError("Provider response exceeds byte limit")
                    body.extend(chunk)
                html = body.decode(resp.encoding or "utf-8", errors="replace")

        malformed = False
        rows_seen = 0
        for match in re.finditer(r'<tr\b[^>]*>(.*?)</tr\s*>', html, re.S | re.I):
            cells = re.findall(r'<td\b[^>]*>(.*?)</td\s*>', match.group(1), re.S | re.I)
            if not cells:
                continue
            if len(cells) == 1 and _text(cells[0]) in ("No matching records found", "No data available in table"):
                continue
            rows_seen += 1
            if rows_seen > 100 or len(result['results']) >= limit:
                result['truncated'] = True
                break
            if len(cells) != 4:
                malformed = True
                # Retain legacy dork-only extraction, without inventing metadata.
                if len(cells) == 1 and not category:
                    dork = _text(cells[0])
                    if len(dork) <= 2048 and re.search(r'\b(?:inurl|filetype|intitle|intext):', dork, re.I):
                        result['results'].append({"dork": dork, "category": "extracted",
                            "google_link": f"https://www.google.com/search?q={quote(dork)}"})
                continue
            fields = [_text(cell) for cell in cells]
            if any(len(field) > 2048 for field in fields):
                malformed = True
                result['truncated'] = True
                continue
            date_added, dork, category_name, author = fields
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date_added) or not dork:
                malformed = True
                continue
            if category and category_name != category:
                malformed = True
                continue
            result['results'].append({"dork": dork, "category": category_name,
                "date_added": date_added, "author": author,
                "google_link": f"https://www.google.com/search?q={quote(dork)}"})

        explicit_empty = bool(re.search(
            r'<td\b[^>]*>\s*(?:No matching records found|No data available in table)\s*</td\s*>', html, re.I))
        if malformed or (not result['results'] and not explicit_empty):
            raise ValueError("Unrecognized or malformed provider rows")
        result.update(coverage_complete=not result['truncated'],
                      execution_status="partial" if result['truncated'] else "completed",
                      assessment="provider_records" if result['results'] else "no_results_in_response")
    except (httpx.HTTPError, ValueError, LookupError) as exc:
        # Never echo request URLs or provider-controlled exception messages.
        safe_errors = {"Provider response exceeds byte limit", "Unrecognized or malformed provider rows"}
        message = str(exc)
        result['error'] = message if (type(exc) is ValueError and
            (message in safe_errors or re.fullmatch(r'HTTP \d{3}', message))) else type(exc).__name__

    if not result['results'] and result['assessment'] == 'incomplete':
        result['source'] = 'builtin_templates'
        # Builtins have no GHDB category mapping; never pretend they satisfy it.
        templates = [] if category else [
            {"dork": dork, "category": "builtin", "key": key,
             "google_link": f"https://www.google.com/search?q={quote(dork)}"}
            for key, dork in DORK_TEMPLATES.items()
            if not query or query.lower() in key or query.lower() in dork.lower()]
        result['results'] = templates[:limit]
        result['truncated'] |= len(templates) > limit
        result['hint'] = "Builtin suggestions only; provider lookup incomplete"
    result['count'] = len(result['results'])
    return result


def _text(value):
    """Decode metadata and redact common credential forms before creating links."""
    value = unescape(re.sub(r'<[^>]+>', '', value)).strip()
    value = re.sub(r'''(?i)(\b(?:api[_-]?key|access[_-]?token|token|password|secret)\s*[=:]\s*)(["'])(.*?)\2''',
                   r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(\b(?:api[_-]?key|access[_-]?token|token|password|secret)\s*[=:]\s*)[^\s&<>"\']+',
                   r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(\bBearer\s+)\S+', r'\1[REDACTED]', value)
    return re.sub(r'(https?://)[^/\s@]+@', r'\1[REDACTED]@', value)

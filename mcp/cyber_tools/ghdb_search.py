"""Search Google Hacking Database (GHDB) from exploit-db.com — dork categories, sensitive files, login portals."""

import httpx, re
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
    results = []
    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
        # Try fetching from exploit-db
        try:
            params = {}
            if query:
                params["search"] = query
            if category:
                params["category"] = category

            url = GHDB_BASE
            if params:
                url += "?" + urlencode(params)

            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                html = resp.text

                # Extract dork entries from the table
                dork_rows = re.findall(
                    r'<tr[^>]*>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(.*?)</td>.*?</tr>',
                    html, re.DOTALL,
                )
                for row in dork_rows[:limit]:
                    date_added = re.sub(r'<[^>]+>', '', row[0]).strip()
                    dork = re.sub(r'<[^>]+>', '', row[1]).strip()
                    category_name = re.sub(r'<[^>]+>', '', row[2]).strip()
                    author = re.sub(r'<[^>]+>', '', row[3]).strip()

                    if dork:
                        # Create Google search link
                        google_link = f"https://www.google.com/search?q={quote(dork)}"
                        results.append({
                            "dork": dork,
                            "category": category_name,
                            "date_added": date_added,
                            "author": author,
                            "google_link": google_link,
                        })

                # Also extract from pagination if present
                if len(dork_rows) == 0:
                    # Try alternative extraction
                    dorks = re.findall(r'<td[^>]*>([^<]*(?:inurl|filetype|intitle|intext)[^<]*)</td>', html, re.I)
                    for dork in dorks[:limit]:
                        google_link = f"https://www.google.com/search?q={quote(dork)}"
                        results.append({
                            "dork": dork.strip(),
                            "category": "extracted",
                            "google_link": google_link,
                        })
        except Exception as e:
            results.append({"error": str(e)[:100]})

        # If no results from site, use built-in templates
        if not results or (len(results) == 1 and "error" in results[0]):
            # Provide useful built-in dorks
            builtin_dorks = []
            if query:
                query_lower = query.lower()
                for key, dork in DORK_TEMPLATES.items():
                    if query_lower in key or query_lower in dork.lower():
                        builtin_dorks.append({
                            "dork": dork,
                            "category": "builtin",
                            "key": key,
                            "google_link": f"https://www.google.com/search?q={quote(dork)}",
                        })
            else:
                # Return all built-in dorks
                for key, dork in DORK_TEMPLATES.items():
                    builtin_dorks.append({
                        "dork": dork,
                        "category": "builtin",
                        "key": key,
                        "google_link": f"https://www.google.com/search?q={quote(dork)}",
                    })

            return {
                "source": "builtin_templates",
                "count": len(builtin_dorks),
                "results": builtin_dorks[:limit],
                "categories": GHDB_CATEGORIES,
                "hint": "Use query param to filter (e.g., 'admin', 'password', 'config')",
            }

    return {
        "source": "exploit-db.com",
        "count": len(results),
        "results": results[:limit],
        "categories": GHDB_CATEGORIES,
    }

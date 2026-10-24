"""Dork → list URLs → bulk vulnerability scan pipeline."""

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

from cyber_tools.dork_gen import dork_gen
from cyber_tools.dork_scan import dork_scan
from cyber_tools.sqli_detect import sqli_detect
from cyber_tools.tech_detect import detect_technologies
from cyber_tools.vuln_scanner import scan_vulnerabilities
from cyber_tools.engagement_gate import validate_target

MAX_BULK_SCAN = 50


def _base_url(url: str) -> str:
    p = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    return f"{p.scheme}://{p.netloc}"


def _unique_bases(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        base = _base_url(u)
        if base not in seen:
            seen.add(base)
            out.append(base)
    return out


def _unique_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def _scan_one(
    url: str,
    tools: list[str],
    sem: asyncio.Semaphore,
) -> dict[str, Any]:
    async with sem:
        entry: dict[str, Any] = {
            "url": url,
            "tech": {},
            "vulnerabilities": [],
            "sqli": None,
            "error": None,
            "finding_count": 0,
        }
        if not validate_target(url)["validated"]:
            entry["error"] = "outside_authorized_scope"
            return entry
        try:
            if "tech_detect" in tools:
                entry["tech"] = await detect_technologies(url)
            if "vuln_scan" in tools:
                vulns = await scan_vulnerabilities(url)
                entry["vulnerabilities"] = vulns.get("vulnerabilities", [])
                entry["headers"] = vulns.get("headers", {})
            if "sqli_detect" in tools:
                sqli = await sqli_detect(url)
                entry["sqli"] = {
                    "vulnerable": sqli.get("vulnerable", False),
                    "hits": len(sqli.get("results", [])),
                    "results": sqli.get("results", [])[:3],
                }
            entry["finding_count"] = len(entry.get("vulnerabilities", []))
            if entry.get("sqli", {}).get("vulnerable"):
                entry["finding_count"] += entry["sqli"]["hits"]
        except Exception as e:
            entry["error"] = str(e)
        return entry


async def dork_and_scan(
    category: str = "vuln_sites",
    vuln_type: str = "",
    target: str = "",
    urls: str = "",
    engines: str = "ddg",
    max_dorks: int = 5,
    max_results: int = 10,
    max_scan: int = 30,
    scan_mode: str = "hosts",
    tools: str = "vuln_scan,tech_detect",
    concurrent: int = 5,
    delay: float = 1.0,
) -> dict[str, Any]:
    """Run dorks, collect URLs, then bulk-scan many targets in parallel.

    Args:
        scan_mode: ``hosts`` = unique domains only, ``urls`` = every discovered URL.
        tools: Comma-separated — ``vuln_scan``, ``tech_detect``, ``sqli_detect``.
        max_scan: Max targets to scan (up to 50).
        concurrent: Parallel scan workers (default 5).
    """
    max_scan = min(max(max_scan, 1), MAX_BULK_SCAN)
    tool_list = [t.strip() for t in tools.split(",") if t.strip()]
    if not tool_list:
        tool_list = ["vuln_scan", "tech_detect"]

    result: dict[str, Any] = {
        "target_scope": target or "global",
        "dorks_used": [],
        "discovered_urls": [],
        "websites": [],
        "scan_results": [],
        "summary": {
            "dorks": 0,
            "raw_urls": 0,
            "unique_hosts": 0,
            "scan_targets": 0,
            "scanned": 0,
            "with_findings": 0,
            "sqli_positive": 0,
            "high_or_critical": 0,
        },
        "warnings": [],
        "error": None,
    }

    raw: list[dict] = []

    if urls.strip():
        for u in re.split(r"[\n,]+", urls.strip()):
            u = u.strip()
            if u:
                raw.append({"url": u, "title": "", "engine": "manual", "dork": ""})
    else:
        gen = await dork_gen(category=category, vuln_type=vuln_type, target=target, limit=max_dorks)
        dorks = [d["dork"] if isinstance(d, dict) else d for d in gen.get("dorks", [])]
        if not dorks:
            result["error"] = gen.get("error") or "No dorks generated"
            return result

        result["dorks_used"] = dorks
        result["summary"]["dorks"] = len(dorks)

        raw = await dork_scan(
            dorks="\n".join(dorks),
            engines=engines,
            max_results=max_results,
            delay=delay,
        )
        if not raw:
            result["warnings"].append(
                "Search engines returned 0 URLs. Use engines=serpapi + SERPAPI_API_KEY, or pass urls=."
            )

    found_urls = [r["url"] for r in raw if r.get("url")]
    result["discovered_urls"] = raw
    result["summary"]["raw_urls"] = len(found_urls)

    hosts = _unique_bases(found_urls)
    result["summary"]["unique_hosts"] = len(hosts)

    if scan_mode == "urls":
        scan_targets = _unique_urls(found_urls)[:max_scan]
    else:
        scan_targets = hosts[:max_scan]

    authorized = [url for url in scan_targets if validate_target(url)["validated"]]
    if len(authorized) != len(scan_targets):
        result["warnings"].append(f"Skipped {len(scan_targets) - len(authorized)} out-of-scope targets before scanning")
    scan_targets = authorized
    result["websites"] = scan_targets
    result["summary"]["scan_targets"] = len(scan_targets)

    sem = asyncio.Semaphore(max(concurrent, 1))
    tasks = [_scan_one(url, tool_list, sem) for url in scan_targets]
    scan_results = await asyncio.gather(*tasks)
    result["scan_results"] = scan_results

    for entry in scan_results:
        result["summary"]["scanned"] += 1
        if entry.get("finding_count", 0) > 0:
            result["summary"]["with_findings"] += 1
        if (entry.get("sqli") or {}).get("vulnerable"):
            result["summary"]["sqli_positive"] += 1
        for v in entry.get("vulnerabilities", []):
            if v.get("severity") in ("critical", "high"):
                result["summary"]["high_or_critical"] += 1

    # Sort: most findings first
    result["scan_results"].sort(
        key=lambda x: (x.get("finding_count", 0), (x.get("sqli") or {}).get("hits", 0)),
        reverse=True,
    )

    return result

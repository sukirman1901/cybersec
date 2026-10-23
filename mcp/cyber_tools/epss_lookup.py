"""EPSS (FIRST) + CISA KEV intel lookup — prioritizes patching by real-world
exploitation probability instead of CVSS alone.

Same-origin safety contract: read-only lookups against FIRST and CISA feeds,
no target traffic, max 2 outbound requests per call, both JSON APIs."""
import json

import httpx

# CISA KEV item count allows a single ~1.5-2 MB occasionally; cache it
# process-wide so repeated calls do not refetch (budget discipline).
_KEV_CACHE: dict = {"data": None}


async def epss_lookup(cves: list, include_kev: bool = True) -> dict:
    """Return EPSS probability + percentile per CVE, optionally KEV membership.

    cves: list of CVE IDs (e.g. ["CVE-2026-109618", "CVE-2026-109619"]).
    """
    cves = [str(c).upper().strip() for c in cves if str(c).strip()][:25]
    if not cves:
        return {"entries": [], "count": 0, "error": "no CVE IDs provided"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        # FIRST EPSS supports comma-separated ids; one request covers all.
        query = ",".join(cves)
        resp = await client.get("https://api.first.org/data/v1/epss",
                                params={"cve": query})
        if resp.status_code != 200:
            return {"entries": [], "count": 0,
                    "error": f"FIRST API error: {resp.status_code}"}
        data = resp.json().get("data", [])

    kev_ids = set()
    if include_kev:
        kev_ids = await _kev_ids()
    entries = []
    for row in data:
        cve = row.get("cve", "")
        try:
            epss = round(float(row["epss"]), 6) if row.get("epss") is not None else None
        except (TypeError, ValueError):
            epss = None
        try:
            pct = round(float(row["percentile"]), 6) if row.get("percentile") is not None else None
        except (TypeError, ValueError):
            pct = None
        in_kev = cve in kev_ids
        entries.append({
            "cve": cve,
            "epss": epss,
            "percentile": pct,
            "in_kev": in_kev,
            "patch_priority": _priority({"epss": epss}, in_kev),
        })
    unknown = sorted(set(cves) - {e["cve"] for e in entries})
    return {
        "entries": entries,
        "count": len(entries),
        "unknown_not_in_feed": unknown,
        "references": ["https://www.first.org/epss/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    }


def _priority(row: dict, in_kev: bool) -> str:
    if in_kev:
        return "P0-patch-now (KEV: confirmed exploitation in the wild)"
    epss = float(row.get("epss") or 0)
    if epss >= 0.5:
        return "P1-high (EPSS >50% in 30 days)"
    if epss >= 0.1:
        return "P2-medium (EPSS >10% in 30 days)"
    return "P3-low"


async def _kev_ids() -> set:
    if _KEV_CACHE.get("data") is not None:
        return set(v["cveID"] for v in _KEV_CACHE["data"])
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                if vulns:  # never poison the cache with an empty payload
                    _KEV_CACHE["data"] = vulns
                    return set(v["cveID"] for v in vulns)
    except Exception:
        pass
    return set()

"""Read-only FIRST EPSS and CISA KEV intel, at most two feed requests per call.

Unknown/stale KEV evidence is never reported as a current negative. Scores and
global exploitation intel prioritize patching, not target exploit confirmation.
"""
import math
import re
from datetime import datetime, timezone
from time import monotonic

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TTL_SECONDS = 3600
_KEV_CACHE: dict = {"data": None}
_CVE = re.compile(r"CVE-\d{4}-\d{4,10}")


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _score(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return round(number, 6) if math.isfinite(number) and 0 <= number <= 1 else None


def _priority(row: dict, in_kev):
    if in_kev is True:
        return "P0-patch-now (KEV: confirmed exploitation in the wild)"
    epss = _score(row.get("epss"))
    if epss is None:
        return "unknown (EPSS unavailable; check KEV source status)"
    if epss >= 0.5:
        return "P1-high (EPSS >=50% in 30 days)"
    if epss >= 0.1:
        return "P2-medium (EPSS >=10% in 30 days)"
    return "P3-low"


async def _kev_evidence():
    now = monotonic()
    cached = _KEV_CACHE.get("data")
    age = max(0, now - _KEV_CACHE.get("monotonic_at", 0))
    usable = cached is not None and "monotonic_at" in _KEV_CACHE
    meta = {"url": KEV_URL, "status": "unavailable", "fetched_at": None,
            "source_date": None, "age_seconds": None, "ttl_seconds": KEV_TTL_SECONDS}
    if usable:
        meta.update(fetched_at=_KEV_CACHE.get("fetched_at"),
                    source_date=_KEV_CACHE.get("source_date"), age_seconds=round(age, 3))
        if age < KEV_TTL_SECONDS:
            meta["status"] = "cached"
            return cached, meta
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(KEV_URL)
            response.raise_for_status()
            payload = response.json()
            rows = payload["vulnerabilities"]
            if not isinstance(rows, list) or not rows:
                raise ValueError("empty or invalid KEV feed")
            if any(not isinstance(row, dict) or not isinstance(row.get("cveID"), str)
                   or not _CVE.fullmatch(row["cveID"]) for row in rows):
                raise ValueError("invalid KEV entry")
            ids = {row["cveID"] for row in rows}
            fetched = _utc_now()
            source_date = payload.get("dateReleased")
            source_date = source_date if isinstance(source_date, str) else None
            _KEV_CACHE.update(data=ids, monotonic_at=monotonic(), fetched_at=fetched,
                              source_date=source_date)
            meta.update(status="fresh", fetched_at=fetched, source_date=source_date,
                        age_seconds=0)
            return ids, meta
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        meta.update(status="stale" if usable else "unavailable",
                    error="KEV request failed or feed invalid")
        return cached if usable else set(), meta


async def epss_lookup(cves: list, include_kev: bool = True) -> dict:
    """Lookup up to 25 unique CVEs; in_kev is true/false/null.

    sources records retrieval/source dates and cache freshness. A stale cache is
    historical reference only (stale_in_kev). Feed errors are independent.
    """
    if not isinstance(cves, list):
        return {"entries": [], "count": 0, "error": "CVE IDs must be a list"}
    ids = list(dict.fromkeys(str(c).strip().upper() for c in cves
                            if _CVE.fullmatch(str(c).strip().upper())))[:25]
    if not ids:
        return {"entries": [], "count": 0, "error": "no valid CVE IDs provided"}

    epss_meta = {"url": EPSS_URL, "status": "unavailable", "fetched_at": None}
    by_cve = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(EPSS_URL, params={"cve": ",".join(ids)})
            response.raise_for_status()
            rows = response.json()["data"]
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError("invalid EPSS feed")
            by_cve = {row["cve"]: row for row in rows if row.get("cve") in ids}
            epss_meta.update(status="fresh", fetched_at=_utc_now())
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        epss_meta["error"] = "EPSS request failed or feed invalid"

    kev_ids, kev_meta = (await _kev_evidence() if include_kev else
                        (set(), {"url": KEV_URL, "status": "disabled", "fetched_at": None,
                                 "source_date": None, "age_seconds": None,
                                 "ttl_seconds": KEV_TTL_SECONDS}))
    current_kev = kev_meta["status"] in ("fresh", "cached")
    entries = []
    for cve in ids:
        row = by_cve.get(cve, {})
        in_kev = cve in kev_ids if current_kev else None
        entry = {"cve": cve, "epss": _score(row.get("epss")),
                 "percentile": _score(row.get("percentile")), "in_kev": in_kev,
                 "epss_date": row.get("date") if isinstance(row.get("date"), str) else None,
                 "kev_status": kev_meta["status"],
                 "patch_priority_basis": "KEV" if in_kev is True else "EPSS only"}
        entry["patch_priority"] = _priority(entry, in_kev)
        if kev_meta["status"] == "stale":
            entry["stale_in_kev"] = cve in kev_ids
        entries.append(entry)
    return {"entries": entries, "count": len(entries),
            "unknown_not_in_feed": sorted(set(ids) - by_cve.keys()),
            "sources": {"epss": epss_meta, "kev": kev_meta},
            "references": ["https://www.first.org/epss/",
                           "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]}

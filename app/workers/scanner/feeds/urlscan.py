"""
app/workers/scanner/feeds/urlscan.py
urlscan.io API — search for existing scans of a domain.
Uses the search API (no submission, passive only).
API key optional — raises rate limit without one.
"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SEARCH_URL = "https://urlscan.io/api/v1/search/"


def check(domain: str) -> list[dict]:
    """
    Search urlscan.io for existing scans of `domain`.
    Returns match dicts for scans flagged as malicious or suspicious.
    """
    headers = {"Content-Type": "application/json"}
    if settings.urlscan_api_key:
        headers["API-Key"] = settings.urlscan_api_key

    try:
        resp = httpx.get(
            SEARCH_URL,
            params={"q": f"domain:{domain}", "size": 10},
            headers=headers,
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.debug("urlscan_search_failed for %s: %s", domain, e)
        return []

    matches = []
    for result in data.get("results", []):
        verdict = result.get("verdicts", {})
        overall = verdict.get("overall", {})
        is_malicious = overall.get("malicious", False)
        is_suspicious = overall.get("suspicious", False)

        if not (is_malicious or is_suspicious):
            continue

        scan_url = result.get("result", "")
        page = result.get("page", {})
        matches.append({
            "feed_name": "urlscan",
            "feed_url": scan_url,
            "threat_type": "malicious" if is_malicious else "suspicious",
            "confidence": 0.80 if is_malicious else 0.60,
            "tags": ["urlscan"] + (overall.get("tags") or []),
            "raw_data": {
                "scan_url": scan_url,
                "page_domain": page.get("domain"),
                "page_ip": page.get("ip"),
                "malicious": is_malicious,
                "suspicious": is_suspicious,
                "score": overall.get("score", 0),
            },
        })

    return matches

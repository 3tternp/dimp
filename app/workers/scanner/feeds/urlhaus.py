"""
app/workers/scanner/feeds/urlhaus.py
Abuse.ch URLhaus API — free, no key required for lookups.
Uses the URLhaus lookup API to check individual domains.
"""
import logging

import httpx

logger = logging.getLogger(__name__)

LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def check(domain: str) -> list[dict]:
    """
    Query URLhaus for the given domain.
    Returns a list of match dicts if found in the database.
    """
    try:
        resp = httpx.post(
            LOOKUP_URL,
            data={"host": domain},
            timeout=10,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.debug("urlhaus_lookup_failed: %s", domain, e)
        return []

    if data.get("query_status") != "is_host":
        return []

    # Build match records from URLhaus URLs list
    matches = []
    urls = data.get("urls", []) or []
    for entry in urls[:5]:  # cap at 5 evidence items
        matches.append({
            "feed_name": "urlhaus",
            "feed_url": entry.get("url", ""),
            "threat_type": entry.get("threat", "malware"),
            "confidence": 0.85,
            "tags": ["urlhaus", entry.get("threat", "malware"), entry.get("url_status", "")],
            "raw_data": {
                "url": entry.get("url"),
                "url_status": entry.get("url_status"),
                "threat": entry.get("threat"),
                "date_added": entry.get("date_added"),
            },
        })

    return matches

"""
app/workers/scanner/feeds/threatfox.py
Abuse.ch ThreatFox API — free IOC database for malware/botnet domains.
No API key required.
"""
import logging

import httpx

logger = logging.getLogger(__name__)

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def check(domain: str) -> list[dict]:
    """
    Query ThreatFox for IOCs associated with the domain.
    Returns match dicts if found.
    """
    try:
        resp = httpx.post(
            API_URL,
            json={"query": "search_ioc", "search_term": domain},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.debug("threatfox_lookup_failed for %s: %s", domain, e)
        return []

    if data.get("query_status") != "ok":
        return []

    matches = []
    for entry in (data.get("data") or [])[:5]:
        ioc_type = entry.get("ioc_type", "")
        threat_type = entry.get("threat_type", "")
        malware = entry.get("malware_printable", "unknown")
        confidence_level = entry.get("confidence_level", 50)
        confidence = min(1.0, confidence_level / 100.0)

        matches.append({
            "feed_name": "threatfox",
            "feed_url": f"https://threatfox.abuse.ch/ioc/{entry.get('id', '')}",
            "threat_type": threat_type or ioc_type,
            "confidence": round(confidence, 3),
            "tags": [
                "threatfox",
                malware,
                threat_type,
                entry.get("malware_malpedia", ""),
            ],
            "raw_data": {
                "ioc": entry.get("ioc"),
                "ioc_type": ioc_type,
                "threat_type": threat_type,
                "malware": malware,
                "confidence_level": confidence_level,
                "first_seen": entry.get("first_seen_utc"),
                "last_seen": entry.get("last_seen_utc"),
                "reporter": entry.get("reporter"),
            },
        })

    return matches

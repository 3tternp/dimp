"""
app/workers/scanner/feeds/virustotal.py
VirusTotal API v3 — domain report lookup.
Requires VIRUSTOTAL_API_KEY in environment.
"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"


def check(domain: str) -> list[dict]:
    """
    Query VirusTotal for the domain's reputation report.
    Returns match dicts if any engine flags the domain as malicious/suspicious.
    """
    if not settings.virustotal_api_key:
        return []

    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        resp = httpx.get(
            f"{BASE_URL}/domains/{domain}",
            headers=headers,
            timeout=12,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.debug("virustotal_lookup_failed for %s: %s", domain, e)
        return []

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    if (malicious + suspicious) == 0:
        return []

    confidence = min(1.0, (malicious * 1.0 + suspicious * 0.5) / total * 3)

    return [{
        "feed_name": "virustotal",
        "feed_url": f"https://www.virustotal.com/gui/domain/{domain}",
        "threat_type": "malicious" if malicious > 0 else "suspicious",
        "confidence": round(confidence, 3),
        "tags": ["virustotal"] + list(attrs.get("tags", [])),
        "raw_data": {
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total,
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
        },
    }]

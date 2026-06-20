"""
app/workers/scanner/feeds/phishtank.py
PhishTank — free phishing URL database. No API key required for basic lookups.
Downloads the online CSV feed and checks domains against it.
"""
import logging
import time
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

FEED_URL = "http://data.phishtank.com/data/online-valid.csv"
_cache: dict = {"domains": {}, "fetched_at": 0}
CACHE_TTL = 3600


def _get_feed() -> dict[str, list[str]]:
    """Fetch and cache the PhishTank feed, indexed by domain."""
    now = time.time()
    if _cache["domains"] and (now - _cache["fetched_at"]) < CACHE_TTL:
        return _cache["domains"]

    try:
        resp = httpx.get(FEED_URL, timeout=30, follow_redirects=True)
        resp.raise_for_status()
        domains: dict[str, list[str]] = {}
        for line in resp.text.splitlines()[1:]:
            parts = line.split(",")
            if len(parts) >= 2:
                url = parts[1].strip().strip('"')
                try:
                    host = urlparse(url).netloc.lstrip("www.").lower()
                    if host:
                        domains.setdefault(host, []).append(url)
                except Exception:
                    continue
        _cache["domains"] = domains
        _cache["fetched_at"] = now
        logger.info("phishtank_feed_loaded entries=%d", len(domains))
        return domains
    except Exception as e:
        logger.warning("phishtank_fetch_failed: %s", e)
        return _cache.get("domains", {})


def check(domain: str) -> list[dict]:
    domain_lower = domain.lower()
    feed = _get_feed()
    matches = []

    matching_urls = feed.get(domain_lower, [])
    if not matching_urls:
        for host, urls in feed.items():
            if domain_lower in host or host in domain_lower:
                matching_urls.extend(urls)

    for url in matching_urls[:5]:
        matches.append({
            "feed_name": "phishtank",
            "feed_url": url,
            "threat_type": "phishing",
            "confidence": 0.92,
            "tags": ["phishing", "phishtank", "verified"],
            "raw_data": {"url": url, "source": "phishtank"},
        })

    return matches

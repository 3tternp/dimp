"""
app/workers/scanner/feeds/openphish.py
OpenPhish public feed — no API key required.
Fetches the live phishing URL list and checks if the target domain appears.
"""
import logging
import time
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

FEED_URL = "https://openphish.com/feed.txt"
_cache: dict = {"urls": set(), "fetched_at": 0}
CACHE_TTL = 3600  # 1 hour


def _get_feed() -> set[str]:
    """Fetch and cache the OpenPhish URL list."""
    now = time.time()
    if _cache["urls"] and (now - _cache["fetched_at"]) < CACHE_TTL:
        return _cache["urls"]

    try:
        resp = httpx.get(FEED_URL, timeout=15, follow_redirects=True)
        resp.raise_for_status()
        urls: set[str] = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                urls.add(line.lower())
        _cache["urls"] = urls
        _cache["fetched_at"] = now
        logger.info("openphish_feed_loaded", count=len(urls))
        return urls
    except Exception as e:
        logger.warning("openphish_fetch_failed: %s", e)
        return _cache.get("urls", set())


def check(domain: str) -> list[dict]:
    """
    Check if `domain` appears in the OpenPhish live feed.
    Returns a list of match dicts (empty if no match).
    """
    domain_lower = domain.lower()
    urls = _get_feed()
    matches = []

    for url in urls:
        try:
            host = urlparse(url).netloc.lstrip("www.")
            if host == domain_lower or domain_lower in host:
                matches.append({
                    "feed_name": "openphish",
                    "feed_url": url,
                    "threat_type": "phishing",
                    "confidence": 0.9,
                    "tags": ["phishing", "openphish"],
                    "raw_data": {"url": url},
                })
        except Exception:
            continue

    return matches

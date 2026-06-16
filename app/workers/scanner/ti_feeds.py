"""
app/workers/scanner/ti_feeds.py
Threat intelligence feed orchestrator.

Runs all configured feeds against a domain and persists
ThreatIntelMatch records to the database.

Feed registry:
  - openphish  (no key required)
  - urlhaus    (no key required)
  - urlscan    (optional API key)
  - virustotal (requires VIRUSTOTAL_API_KEY)
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import DiscoveredDomain, ThreatIntelMatch

logger = logging.getLogger(__name__)


def run_ti_checks(db: Session, domain_entry: DiscoveredDomain) -> int:
    """
    Run all enabled threat intel feeds against `domain_entry.domain`.
    Persists new ThreatIntelMatch records and returns the count of hits.
    """
    from app.workers.scanner.feeds import openphish, urlhaus, urlscan, virustotal

    domain = domain_entry.domain
    all_matches: list[dict] = []

    # Run feeds — each returns [] if no hit or unavailable
    feed_runners = [
        ("openphish", openphish.check),
        ("urlhaus", urlhaus.check),
        ("urlscan", urlscan.check),
        ("virustotal", virustotal.check),
    ]

    for feed_name, runner in feed_runners:
        try:
            hits = runner(domain)
            all_matches.extend(hits)
            if hits:
                logger.info("ti_hit", feed=feed_name, domain=domain, hits=len(hits))
        except Exception as e:
            logger.warning("ti_feed_error", feed=feed_name, domain=domain, error=str(e))

    # Deduplicate by feed_name + feed_url before persisting
    existing_urls = {
        m.feed_url for m in db.query(ThreatIntelMatch)
        .filter(ThreatIntelMatch.domain_id == str(domain_entry.id)).all()
    }

    new_count = 0
    for match in all_matches:
        if match.get("feed_url") in existing_urls:
            continue
        record = ThreatIntelMatch(
            domain_id=str(domain_entry.id),
            feed_name=match["feed_name"],
            feed_url=match.get("feed_url"),
            threat_type=match.get("threat_type"),
            confidence=match.get("confidence"),
            tags=match.get("tags"),
            raw_data=match.get("raw_data"),
            matched_at=datetime.now(timezone.utc),
        )
        db.add(record)
        existing_urls.add(match.get("feed_url"))
        new_count += 1

    if new_count:
        db.flush()

    return new_count

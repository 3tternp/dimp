"""
app/workers/scanner/whois_collector.py
Collects WHOIS / RDAP registration data for a domain.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def collect_whois(domain: str, timeout: int = 10) -> dict:
    """
    Query WHOIS for domain registration data.
    Returns a normalised dict with registration metadata.
    """
    import signal

    def _timeout_handler(signum, frame):
        raise TimeoutError(f"WHOIS lookup timed out for {domain}")

    try:
        import whois
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout)
        try:
            w = whois.whois(domain)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    except Exception as e:
        logger.debug("WHOIS failed for %s: %s", domain, e)
        return {}

    def _first(val):
        """Return first item if list, else the value itself."""
        if isinstance(val, list):
            return val[0] if val else None
        return val

    def _to_list(val):
        if val is None:
            return None
        return val if isinstance(val, list) else [val]

    return {
        "registrar": _first(w.registrar),
        "registrar_url": _first(getattr(w, "registrar_url", None)),
        "creation_date": _first(w.creation_date),
        "updated_date": _first(w.updated_date),
        "expiry_date": _first(w.expiration_date),
        "status": _to_list(w.status),
        "name_servers": [ns.lower() for ns in _to_list(w.name_servers) or []],
        "registrant_org": _first(getattr(w, "org", None)),
        "registrant_country": _first(getattr(w, "country", None)),
        "registrant_email": _first(getattr(w, "emails", None)),
        "privacy_protected": bool(
            "privacy" in str(getattr(w, "registrant_name", "") or "").lower()
            or "redacted" in str(getattr(w, "registrant_name", "") or "").lower()
        ),
        "raw_whois": str(w.text) if hasattr(w, "text") else None,
    }

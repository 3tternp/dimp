"""
app/workers/scanner/risk_scorer.py
Risk scoring engine — assigns a 0-100 score to a discovered domain
and maps it to a Severity level.

Factors and their max weight contributions:
  Domain similarity     : 25 pts
  Keyword match         : 10 pts
  Domain age            : 10 pts
  Visual similarity     : 15 pts
  HTML/content sim      : 5  pts
  Favicon match         : 5  pts
  Login form            : 10 pts
  External form action  : 5  pts
  Has MX records        : 3  pts
  Has active website    : 2  pts
  Threat intel hit      : 10 pts  (capped)
  Hosting reputation    : 5  pts
  SSL presence          : -5 pts  (reduces score — legit indicator)
  Free/suspicious TLD   : 5  pts
  Country mismatch      : 3  pts
  Recent cert           : 2  pts
  ─────────────────────────────
  Max raw               : ~115 pts (capped at 100)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.models import DiscoveredDomain, Severity

logger = logging.getLogger(__name__)

# TLDs commonly used for free/suspicious hosting
SUSPICIOUS_TLDS = {"xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "loan", "win", "download", "stream"}

# ASNs known for bulletproof / frequently abused hosting
SUSPICIOUS_ASNS = {
    "AS197695",  # Reg.ru
    "AS202468",  # Creanova Hosting Solutions
    "AS9009",    # M247
    "AS60068",   # CDN77
}

# Suspicious keywords in domain names
SUSPICIOUS_KEYWORDS = {
    "login", "secure", "verify", "account", "support", "update",
    "wallet", "bank", "mfa", "auth", "signin", "pay", "confirm",
    "validation", "recover", "reset", "security", "official",
}


def _similarity_pts(domain: DiscoveredDomain) -> int:
    """Up to 25 pts based on string edit distance similarity to the protected domain."""
    # Similarity is pre-computed in the similarity_results relation
    # We use overall_similarity_score (0-1) if available
    if domain.similarity_results:
        latest = domain.similarity_results[-1]
        if latest.overall_similarity_score is not None:
            return round(latest.overall_similarity_score * 25)
    # Fallback: simple heuristic based on detection type
    from app.models import DetectionType
    type_scores = {
        DetectionType.typosquatting: 18,
        DetectionType.homoglyph: 22,
        DetectionType.lookalike: 15,
        DetectionType.extra_word: 12,
        DetectionType.tld_variation: 10,
        DetectionType.subdomain_abuse: 14,
        DetectionType.cert_transparency: 8,
        DetectionType.phishing_feed: 20,
        DetectionType.cloned_page: 25,
        DetectionType.brand_keyword: 10,
        DetectionType.urlscan: 12,
    }
    return type_scores.get(domain.detection_type, 10)


def _keyword_pts(domain: DiscoveredDomain) -> int:
    """Up to 10 pts if the domain name contains suspicious keywords."""
    domain_lower = domain.domain.lower()
    matched = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain_lower)
    return min(matched * 3, 10)


def _age_pts(domain: DiscoveredDomain) -> int:
    """Up to 10 pts for recently registered domains (< 30 days old)."""
    if not domain.whois_record or not domain.whois_record.creation_date:
        return 5  # unknown age is mildly suspicious
    age_days = (datetime.now(timezone.utc) - domain.whois_record.creation_date).days
    if age_days < 7:
        return 10
    if age_days < 30:
        return 8
    if age_days < 90:
        return 4
    return 0


def _visual_sim_pts(domain: DiscoveredDomain) -> int:
    """Up to 15 pts based on screenshot pHash similarity score."""
    if not domain.similarity_results:
        return 0
    score = domain.similarity_results[-1].visual_similarity_score or 0
    return round(score * 15)


def _html_sim_pts(domain: DiscoveredDomain) -> int:
    """Up to 5 pts based on HTML/content TF-IDF similarity."""
    if not domain.similarity_results:
        return 0
    score = domain.similarity_results[-1].tfidf_score or 0
    return round(score * 5)


def _favicon_pts(domain: DiscoveredDomain) -> int:
    """5 pts if favicon hash matches the protected domain's favicon."""
    if not domain.similarity_results:
        return 0
    return 5 if domain.similarity_results[-1].favicon_hash_match else 0


def _login_form_pts(domain: DiscoveredDomain) -> int:
    """Up to 10 pts for credential-harvesting indicators."""
    if not domain.snapshots:
        return 0
    snap = domain.snapshots[-1]
    pts = 0
    if snap.has_login_form:
        pts += 6
    if snap.has_credential_fields:
        pts += 4
    return pts


def _external_form_pts(domain: DiscoveredDomain) -> int:
    """5 pts if a form on the page posts to an external (different) domain."""
    if domain.snapshots and domain.snapshots[-1].external_form_action:
        return 5
    return 0


def _mx_pts(domain: DiscoveredDomain) -> int:
    """3 pts if the domain has MX records (active mail — phishing capability)."""
    has_mx = any(r.record_type == "MX" for r in domain.dns_records)
    return 3 if has_mx else 0


def _website_pts(domain: DiscoveredDomain) -> int:
    """2 pts if domain resolves to an active website."""
    return 2 if domain.is_active_website else 0


def _threat_intel_pts(domain: DiscoveredDomain) -> int:
    """Up to 10 pts based on threat intelligence feed hits."""
    if not domain.threat_intel_matches:
        return 0
    hit_count = len(domain.threat_intel_matches)
    return min(hit_count * 5, 10)


def _hosting_pts(domain: DiscoveredDomain) -> int:
    """Up to 5 pts for suspicious hosting (free TLS certs, bulletproof ASNs)."""
    pts = 0
    if domain.asn in SUSPICIOUS_ASNS:
        pts += 3
    if domain.ssl_certificate and domain.ssl_certificate.issuer_org:
        if "Let's Encrypt" in domain.ssl_certificate.issuer_org:
            pts += 1  # free cert — weak signal on its own but adds up
    return min(pts, 5)


def _ssl_reduction(domain: DiscoveredDomain) -> int:
    """Subtract up to 5 pts if domain has a valid, non-expired SSL cert (legit indicator)."""
    cert = domain.ssl_certificate
    if not cert:
        return 0
    if cert.is_expired or cert.is_self_signed:
        return 0        # expired/self-signed doesn't earn the reduction
    return -5


def _suspicious_tld_pts(domain: DiscoveredDomain) -> int:
    """5 pts for free/commonly abused TLDs."""
    tld = domain.domain.rsplit(".", 1)[-1].lower()
    return 5 if tld in SUSPICIOUS_TLDS else 0


def _country_mismatch_pts(domain: DiscoveredDomain) -> int:
    """3 pts if hosted in a country strongly associated with phishing campaigns."""
    HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "NG", "RO", "UA", "PK"}
    if domain.country_code and domain.country_code.upper() in HIGH_RISK_COUNTRIES:
        return 3
    return 0


def _recent_cert_pts(domain: DiscoveredDomain) -> int:
    """2 pts if the SSL cert was issued within the last 7 days."""
    cert = domain.ssl_certificate
    if not cert or not cert.not_before:
        return 0
    age_days = (datetime.now(timezone.utc) - cert.not_before).days
    return 2 if age_days <= 7 else 0


# ── Public API ────────────────────────────────────────────────────────────────

def compute_risk_score(domain: DiscoveredDomain) -> tuple[int, Severity]:
    """
    Compute the risk score (0-100) and corresponding Severity for a domain.

    Returns:
        (score, severity) — caller should persist these on the model.
    """
    factors = [
        _similarity_pts(domain),
        _keyword_pts(domain),
        _age_pts(domain),
        _visual_sim_pts(domain),
        _html_sim_pts(domain),
        _favicon_pts(domain),
        _login_form_pts(domain),
        _external_form_pts(domain),
        _mx_pts(domain),
        _website_pts(domain),
        _threat_intel_pts(domain),
        _hosting_pts(domain),
        _ssl_reduction(domain),
        _suspicious_tld_pts(domain),
        _country_mismatch_pts(domain),
        _recent_cert_pts(domain),
    ]

    raw_score = sum(factors)
    score = max(0, min(100, raw_score))  # clamp to 0-100

    if score <= 30:
        severity = Severity.low
    elif score <= 60:
        severity = Severity.medium
    elif score <= 80:
        severity = Severity.high
    else:
        severity = Severity.critical

    logger.debug(
        "risk_score computed",
        domain=domain.domain,
        score=score,
        severity=severity.value,
        factors=factors,
    )
    return score, severity


def build_summary(domain: DiscoveredDomain, score: int) -> str:
    """Generate a human-readable summary explaining the risk score."""
    parts = []

    if domain.similarity_results and domain.similarity_results[-1].visual_similarity_score:
        sim = domain.similarity_results[-1].visual_similarity_score
        if sim > 0.7:
            parts.append(f"visual similarity {sim:.0%} to protected domain")

    if domain.snapshots and domain.snapshots[-1].has_login_form:
        parts.append("login form detected")

    if domain.snapshots and domain.snapshots[-1].external_form_action:
        parts.append("form posts to external domain")

    if domain.threat_intel_matches:
        feeds = list({m.feed_name for m in domain.threat_intel_matches})
        parts.append(f"flagged by {', '.join(feeds)}")

    if domain.whois_record and domain.whois_record.creation_date:
        age = (datetime.now(timezone.utc) - domain.whois_record.creation_date).days
        if age < 30:
            parts.append(f"registered {age} days ago")

    domain_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain.domain.lower()]
    if domain_kws:
        parts.append(f"suspicious keywords: {', '.join(domain_kws)}")

    if not parts:
        parts.append(f"domain pattern matches {domain.detection_type.value} heuristic")

    return f"Risk score {score}/100 — " + "; ".join(parts) + "."

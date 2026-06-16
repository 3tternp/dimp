"""
app/workers/scanner/domain_analyser.py
Orchestrates a complete analysis for a single discovered domain:
  1. Persist/update the DiscoveredDomain record
  2. Collect DNS, WHOIS, SSL, HTTP metadata
  3. Compute risk score
  4. Create or update a Finding if risk exceeds threshold
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import (
    DetectionType,
    DiscoveredDomain,
    DomainDNSRecord,
    DomainWhoisRecord,
    Finding,
    FindingStatus,
    MonitoredAsset,
    SSLCertificate,
    WebpageSnapshot,
)
from app.workers.scanner.dns_collector import collect_dns
from app.workers.scanner.http_collector import collect_http_metadata
from app.workers.scanner.risk_scorer import build_summary, compute_risk_score
from app.workers.scanner.ssl_collector import collect_ssl
from app.workers.scanner.whois_collector import collect_whois

logger = logging.getLogger(__name__)


def _get_or_create_domain(db: Session, domain: str, asset: MonitoredAsset, source: str) -> DiscoveredDomain:
    """Return existing DiscoveredDomain record or create a new one."""
    existing = (
        db.query(DiscoveredDomain)
        .filter(DiscoveredDomain.domain == domain, DiscoveredDomain.asset_id == str(asset.id))
        .first()
    )
    if existing:
        return existing

    # Determine detection type from discovery source
    source_type_map = {
        "typosquat_engine": DetectionType.typosquatting,
        "ct_log": DetectionType.cert_transparency,
        "openphish": DetectionType.phishing_feed,
        "urlhaus": DetectionType.phishing_feed,
        "phishtank": DetectionType.phishing_feed,
        "urlscan": DetectionType.urlscan,
    }
    detection_type = source_type_map.get(source, DetectionType.brand_keyword)

    domain_entry = DiscoveredDomain(
        asset_id=str(asset.id),
        domain=domain,
        detection_type=detection_type,
        discovery_source=source,
    )
    db.add(domain_entry)
    db.flush()
    return domain_entry


def _persist_dns(db: Session, domain_entry: DiscoveredDomain, dns_data: dict) -> None:
    """Delete stale DNS records and write fresh ones."""
    db.query(DomainDNSRecord).filter(DomainDNSRecord.domain_id == str(domain_entry.id)).delete()
    for rtype, records in dns_data.get("records", {}).items():
        for rec in records:
            db.add(DomainDNSRecord(
                domain_id=str(domain_entry.id),
                record_type=rtype,
                value=rec["value"],
                ttl=rec.get("ttl"),
                priority=rec.get("priority"),
            ))


def _persist_whois(db: Session, domain_entry: DiscoveredDomain, whois_data: dict) -> None:
    if not whois_data:
        return
    existing = db.query(DomainWhoisRecord).filter(DomainWhoisRecord.domain_id == str(domain_entry.id)).first()
    if existing:
        for k, v in whois_data.items():
            setattr(existing, k, v)
        existing.collected_at = datetime.now(timezone.utc)
    else:
        db.add(DomainWhoisRecord(domain_id=str(domain_entry.id), **whois_data))


def _persist_ssl(db: Session, domain_entry: DiscoveredDomain, ssl_data: dict) -> None:
    if not ssl_data:
        return
    existing = db.query(SSLCertificate).filter(SSLCertificate.domain_id == str(domain_entry.id)).first()
    if existing:
        for k, v in ssl_data.items():
            setattr(existing, k, v)
        existing.collected_at = datetime.now(timezone.utc)
    else:
        db.add(SSLCertificate(domain_id=str(domain_entry.id), **ssl_data))


def _persist_snapshot(db: Session, domain_entry: DiscoveredDomain, http_data: dict) -> WebpageSnapshot:
    snap = WebpageSnapshot(
        domain_id=str(domain_entry.id),
        html_hash=http_data.get("html_hash"),
        favicon_hash=http_data.get("favicon_hash"),
        page_title=http_data.get("page_title"),
        external_scripts=http_data.get("external_scripts"),
        form_action_urls=http_data.get("form_action_urls"),
        has_login_form=http_data.get("has_login_form", False),
        has_credential_fields=http_data.get("has_credential_fields", False),
        external_form_action=http_data.get("external_form_action", False),
        brand_keywords_found=http_data.get("brand_keywords_found"),
    )
    db.add(snap)
    db.flush()
    return snap


def analyse_domain(
    db: Session,
    domain: str,
    asset: MonitoredAsset,
    job_id: str,
    source: str = "typosquat_engine",
) -> Finding | None:
    """
    Full analysis pipeline for a single domain.
    Returns a Finding if the risk score exceeds the asset's threshold, else None.
    """
    logger.info("analysing domain", domain=domain, asset=asset.domain)

    # Get/create domain record
    domain_entry = _get_or_create_domain(db, domain, asset, source)

    # Collect brand keywords for this asset
    brand_keywords = [kw.keyword for kw in asset.brand_keywords if kw.is_active]

    # ── Phase 1: DNS ──────────────────────────────────────────────────────────
    dns_data = collect_dns(domain)
    _persist_dns(db, domain_entry, dns_data)

    domain_entry.resolves_dns = dns_data.get("resolves", False)

    # Short-circuit: if domain doesn't resolve, assign minimal score
    if not domain_entry.resolves_dns:
        score, severity = compute_risk_score(domain_entry)
        domain_entry.risk_score = max(5, score - 20)  # penalise non-resolving
        domain_entry.severity = severity
        domain_entry.last_checked_at = datetime.now(timezone.utc)
        db.commit()
        return None  # no finding for non-resolving domains unless it was in a feed

    # ── Phase 2: WHOIS ────────────────────────────────────────────────────────
    try:
        whois_data = collect_whois(domain)
        _persist_whois(db, domain_entry, whois_data)
    except Exception as e:
        logger.warning("whois_failed", domain=domain, error=str(e))

    # ── Phase 3: SSL ──────────────────────────────────────────────────────────
    try:
        ssl_data = collect_ssl(domain)
        _persist_ssl(db, domain_entry, ssl_data)
    except Exception as e:
        logger.warning("ssl_failed", domain=domain, error=str(e))

    # ── Phase 4: HTTP metadata ────────────────────────────────────────────────
    try:
        http_data = collect_http_metadata(domain, brand_keywords)
        domain_entry.is_active_website = http_data.get("is_active_website", False)
        domain_entry.http_status_code = http_data.get("http_status_code")
        domain_entry.redirect_chain = http_data.get("redirect_chain")
        domain_entry.page_title = http_data.get("page_title")
        domain_entry.meta_description = http_data.get("meta_description")
        domain_entry.favicon_url = http_data.get("favicon_url")
        _persist_snapshot(db, domain_entry, http_data)
    except Exception as e:
        logger.warning("http_collection_failed", domain=domain, error=str(e))

    db.flush()

    # ── Phase 5: Risk scoring ─────────────────────────────────────────────────
    db.refresh(domain_entry)
    score, severity = compute_risk_score(domain_entry)
    domain_entry.risk_score = score
    domain_entry.severity = severity
    domain_entry.last_checked_at = datetime.now(timezone.utc)

    db.flush()

    # ── Phase 6: Create/update Finding if above threshold ─────────────────────
    finding = None
    if score >= asset.risk_threshold:
        existing_finding = (
            db.query(Finding)
            .filter(
                Finding.asset_id == str(asset.id),
                Finding.domain_id == str(domain_entry.id),
                Finding.status.notin_([FindingStatus.false_positive, FindingStatus.resolved]),
            )
            .first()
        )

        summary = build_summary(domain_entry, score)

        if existing_finding:
            # Update score/severity on re-scan
            existing_finding.risk_score = score
            existing_finding.severity = severity
            existing_finding.summary = summary
            existing_finding.scan_job_id = job_id
            existing_finding.last_updated_at = datetime.now(timezone.utc)
            db.flush()
            finding = existing_finding
        else:
            finding = Finding(
                asset_id=str(asset.id),
                domain_id=str(domain_entry.id),
                scan_job_id=job_id,
                detection_type=domain_entry.detection_type,
                discovery_source=domain_entry.discovery_source,
                severity=severity,
                risk_score=score,
                status=FindingStatus.new,
                summary=summary,
                recommended_action=_recommend_action(score, severity),
            )
            db.add(finding)
            db.flush()

    db.commit()
    return finding


def _recommend_action(score: int, severity) -> str:
    """Generate a recommended action based on severity."""
    from app.models import Severity
    if severity == Severity.critical:
        return (
            "Immediate action required. File a UDRP complaint or submit an abuse report "
            "to the registrar. Notify security team and block domain in perimeter controls."
        )
    if severity == Severity.high:
        return (
            "Submit an abuse report to the domain registrar and hosting provider. "
            "Consider blocking at DNS/proxy layer. Monitor for phishing campaign activity."
        )
    if severity == Severity.medium:
        return (
            "Monitor closely. Submit to threat intelligence feeds. "
            "Review WHOIS for registrant contact and check for active phishing lures."
        )
    return "Log and monitor. Re-check on next scheduled scan."

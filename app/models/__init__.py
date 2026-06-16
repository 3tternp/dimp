"""
app/models/__init__.py
SQLAlchemy ORM models for all 14 database tables.

Table inventory:
  1.  users
  2.  monitored_assets
  3.  brand_keywords
  4.  allowed_domains
  5.  discovered_domains
  6.  domain_dns_records
  7.  domain_whois_records
  8.  ssl_certificates
  9.  webpage_snapshots
  10. similarity_results
  11. threat_intel_matches
  12. findings
  13. alerts
  14. scan_jobs
  15. reports          (bonus — needed for report API)
"""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


# ─────────────────────────── helpers ─────────────────────────────────────────

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ─────────────────────────── enums ───────────────────────────────────────────

class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class ScanFrequency(str, enum.Enum):
    hourly = "hourly"
    daily = "daily"
    weekly = "weekly"


class FindingStatus(str, enum.Enum):
    new = "new"
    under_review = "under_review"
    confirmed = "confirmed"
    false_positive = "false_positive"
    takedown_requested = "takedown_requested"
    resolved = "resolved"


class Severity(str, enum.Enum):
    low = "low"          # 0-30
    medium = "medium"    # 31-60
    high = "high"        # 61-80
    critical = "critical"  # 81-100


class DetectionType(str, enum.Enum):
    typosquatting = "typosquatting"
    homoglyph = "homoglyph"
    lookalike = "lookalike"
    extra_word = "extra_word"
    tld_variation = "tld_variation"
    subdomain_abuse = "subdomain_abuse"
    cert_transparency = "cert_transparency"
    phishing_feed = "phishing_feed"
    cloned_page = "cloned_page"
    brand_keyword = "brand_keyword"
    urlscan = "urlscan"


class ScanJobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AlertChannel(str, enum.Enum):
    email = "email"
    slack = "slack"
    teams = "teams"
    siem = "siem"


class AlertStatus(str, enum.Enum):
    pending = "pending"
    sent = "sent"
    failed = "failed"


class ReportFormat(str, enum.Enum):
    html = "html"
    pdf = "pdf"
    csv = "csv"
    json = "json"


# ═════════════════════════════════════════════════════════════════════════════
# 1. users
# ═════════════════════════════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.analyst)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # relationships
    scan_jobs = relationship("ScanJob", back_populates="triggered_by_user", lazy="select")
    reports = relationship("Report", back_populates="created_by_user", lazy="select")


# ═════════════════════════════════════════════════════════════════════════════
# 2. monitored_assets
# ═════════════════════════════════════════════════════════════════════════════

class MonitoredAsset(Base):
    __tablename__ = "monitored_assets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    scan_frequency = Column(Enum(ScanFrequency), default=ScanFrequency.daily, nullable=False)
    risk_threshold = Column(Integer, default=50, nullable=False)   # 0-100
    is_active = Column(Boolean, default=True, nullable=False)
    logo_path = Column(String(512), nullable=True)                 # uploaded logo file
    homepage_screenshot_path = Column(String(512), nullable=True)  # reference screenshot
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    # relationships
    brand_keywords = relationship("BrandKeyword", back_populates="asset", cascade="all, delete-orphan")
    allowed_domains = relationship("AllowedDomain", back_populates="asset", cascade="all, delete-orphan")
    discovered_domains = relationship("DiscoveredDomain", back_populates="asset", lazy="select")
    scan_jobs = relationship("ScanJob", back_populates="asset", lazy="select")
    findings = relationship("Finding", back_populates="asset", lazy="select")


# ═════════════════════════════════════════════════════════════════════════════
# 3. brand_keywords
# ═════════════════════════════════════════════════════════════════════════════

class BrandKeyword(Base):
    __tablename__ = "brand_keywords"
    __table_args__ = (UniqueConstraint("asset_id", "keyword", name="uq_asset_keyword"),)

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    keyword = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    asset = relationship("MonitoredAsset", back_populates="brand_keywords")


# ═════════════════════════════════════════════════════════════════════════════
# 4. allowed_domains
# ═════════════════════════════════════════════════════════════════════════════

class AllowedDomain(Base):
    __tablename__ = "allowed_domains"
    __table_args__ = (UniqueConstraint("asset_id", "domain", name="uq_asset_allowed_domain"),)

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False)
    domain = Column(String(255), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    asset = relationship("MonitoredAsset", back_populates="allowed_domains")


# ═════════════════════════════════════════════════════════════════════════════
# 5. discovered_domains
# ═════════════════════════════════════════════════════════════════════════════

class DiscoveredDomain(Base):
    __tablename__ = "discovered_domains"
    __table_args__ = (UniqueConstraint("asset_id", "domain", name="uq_asset_discovered_domain"),)

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    detection_type = Column(Enum(DetectionType), nullable=False)
    discovery_source = Column(String(128), nullable=False)  # e.g. "typosquat_engine", "crt.sh", "openphish"

    # resolution status
    resolves_dns = Column(Boolean, nullable=True)
    is_active_website = Column(Boolean, nullable=True)
    http_status_code = Column(Integer, nullable=True)
    redirect_chain = Column(JSONB, nullable=True)   # list of URLs
    page_title = Column(String(512), nullable=True)
    meta_description = Column(Text, nullable=True)
    favicon_url = Column(String(512), nullable=True)

    # IP / ASN / geo
    ip_address = Column(String(64), nullable=True)
    asn = Column(String(64), nullable=True)
    asn_org = Column(String(255), nullable=True)
    hosting_provider = Column(String(255), nullable=True)
    country_code = Column(String(8), nullable=True)
    country_name = Column(String(128), nullable=True)

    # scoring
    risk_score = Column(Integer, default=0, nullable=False)       # 0-100
    severity = Column(Enum(Severity), default=Severity.low, nullable=False)

    # timestamps
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    became_inactive_at = Column(DateTime(timezone=True), nullable=True)

    # relationships
    asset = relationship("MonitoredAsset", back_populates="discovered_domains")
    dns_records = relationship("DomainDNSRecord", back_populates="domain_entry", cascade="all, delete-orphan")
    whois_record = relationship("DomainWhoisRecord", back_populates="domain_entry", uselist=False, cascade="all, delete-orphan")
    ssl_certificate = relationship("SSLCertificate", back_populates="domain_entry", uselist=False, cascade="all, delete-orphan")
    snapshots = relationship("WebpageSnapshot", back_populates="domain_entry", cascade="all, delete-orphan")
    similarity_results = relationship("SimilarityResult", back_populates="domain_entry", cascade="all, delete-orphan")
    threat_intel_matches = relationship("ThreatIntelMatch", back_populates="domain_entry", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="domain_entry", lazy="select")


# ═════════════════════════════════════════════════════════════════════════════
# 6. domain_dns_records
# ═════════════════════════════════════════════════════════════════════════════

class DomainDNSRecord(Base):
    __tablename__ = "domain_dns_records"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    record_type = Column(String(16), nullable=False)   # A, AAAA, MX, NS, TXT, CNAME
    value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)
    priority = Column(Integer, nullable=True)           # MX priority
    collected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_entry = relationship("DiscoveredDomain", back_populates="dns_records")


# ═════════════════════════════════════════════════════════════════════════════
# 7. domain_whois_records
# ═════════════════════════════════════════════════════════════════════════════

class DomainWhoisRecord(Base):
    __tablename__ = "domain_whois_records"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, unique=True)
    registrar = Column(String(255), nullable=True)
    registrar_url = Column(String(512), nullable=True)
    creation_date = Column(DateTime(timezone=True), nullable=True)
    updated_date = Column(DateTime(timezone=True), nullable=True)
    expiry_date = Column(DateTime(timezone=True), nullable=True)
    status = Column(JSONB, nullable=True)               # list of status strings
    name_servers = Column(JSONB, nullable=True)         # list of NS strings
    registrant_org = Column(String(512), nullable=True)
    registrant_country = Column(String(64), nullable=True)
    registrant_email = Column(String(255), nullable=True)
    privacy_protected = Column(Boolean, nullable=True)
    raw_whois = Column(Text, nullable=True)             # raw WHOIS text (may be large)
    collected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_entry = relationship("DiscoveredDomain", back_populates="whois_record")


# ═════════════════════════════════════════════════════════════════════════════
# 8. ssl_certificates
# ═════════════════════════════════════════════════════════════════════════════

class SSLCertificate(Base):
    __tablename__ = "ssl_certificates"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, unique=True)
    issuer_cn = Column(String(512), nullable=True)
    issuer_org = Column(String(512), nullable=True)
    subject_cn = Column(String(512), nullable=True)
    subject_alt_names = Column(JSONB, nullable=True)    # list of SANs
    serial_number = Column(String(256), nullable=True)
    not_before = Column(DateTime(timezone=True), nullable=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    is_expired = Column(Boolean, nullable=True)
    is_self_signed = Column(Boolean, nullable=True)
    cert_fingerprint_sha256 = Column(String(128), nullable=True)
    tls_version = Column(String(16), nullable=True)
    collected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_entry = relationship("DiscoveredDomain", back_populates="ssl_certificate")


# ═════════════════════════════════════════════════════════════════════════════
# 9. webpage_snapshots
# ═════════════════════════════════════════════════════════════════════════════

class WebpageSnapshot(Base):
    __tablename__ = "webpage_snapshots"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    screenshot_path = Column(String(512), nullable=True)    # file path on disk
    html_path = Column(String(512), nullable=True)          # saved HTML source path
    html_hash = Column(String(128), nullable=True)          # SHA-256 of HTML
    favicon_hash = Column(String(128), nullable=True)       # pHash of favicon
    page_title = Column(String(512), nullable=True)
    external_scripts = Column(JSONB, nullable=True)         # list of external JS URLs
    form_action_urls = Column(JSONB, nullable=True)         # form action URLs
    has_login_form = Column(Boolean, default=False)
    has_credential_fields = Column(Boolean, default=False)
    external_form_action = Column(Boolean, default=False)   # form posts to different domain
    brand_keywords_found = Column(JSONB, nullable=True)     # keywords matched in page
    captured_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_entry = relationship("DiscoveredDomain", back_populates="snapshots")


# ═════════════════════════════════════════════════════════════════════════════
# 10. similarity_results
# ═════════════════════════════════════════════════════════════════════════════

class SimilarityResult(Base):
    __tablename__ = "similarity_results"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    snapshot_id = Column(UUID(as_uuid=False), ForeignKey("webpage_snapshots.id", ondelete="SET NULL"), nullable=True)

    # Visual similarity (perceptual hashing)
    phash_score = Column(Float, nullable=True)              # 0.0-1.0 (1.0 = identical)
    ahash_score = Column(Float, nullable=True)
    dhash_score = Column(Float, nullable=True)
    visual_similarity_score = Column(Float, nullable=True)  # combined visual score

    # Content similarity
    tfidf_score = Column(Float, nullable=True)              # TF-IDF cosine similarity
    dom_similarity_score = Column(Float, nullable=True)     # DOM structure similarity
    favicon_hash_match = Column(Boolean, nullable=True)

    # Composite score (0-100)
    overall_similarity_score = Column(Float, nullable=True)

    # Reference used for comparison
    reference_screenshot_path = Column(String(512), nullable=True)
    computed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_entry = relationship("DiscoveredDomain", back_populates="similarity_results")


# ═════════════════════════════════════════════════════════════════════════════
# 11. threat_intel_matches
# ═════════════════════════════════════════════════════════════════════════════

class ThreatIntelMatch(Base):
    __tablename__ = "threat_intel_matches"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    feed_name = Column(String(128), nullable=False)         # openphish, urlhaus, phishtank, urlscan, vt
    feed_url = Column(String(512), nullable=True)           # direct link to the intel item
    threat_type = Column(String(128), nullable=True)        # phishing, malware, c2, etc.
    confidence = Column(Float, nullable=True)               # feed-provided confidence 0.0-1.0
    tags = Column(JSONB, nullable=True)                     # additional tags from feed
    raw_data = Column(JSONB, nullable=True)                 # raw API response (truncated)
    matched_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    domain_entry = relationship("DiscoveredDomain", back_populates="threat_intel_matches")


# ═════════════════════════════════════════════════════════════════════════════
# 12. findings
# ═════════════════════════════════════════════════════════════════════════════

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("discovered_domains.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_job_id = Column(UUID(as_uuid=False), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)

    # Classification
    detection_type = Column(Enum(DetectionType), nullable=False)
    discovery_source = Column(String(128), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    risk_score = Column(Integer, nullable=False)             # 0-100
    status = Column(Enum(FindingStatus), default=FindingStatus.new, nullable=False, index=True)

    # Evidence summary
    summary = Column(Text, nullable=True)                   # human-readable reason
    evidence = Column(JSONB, nullable=True)                  # structured evidence dict
    recommended_action = Column(Text, nullable=True)
    takedown_evidence_path = Column(String(512), nullable=True)

    # Workflow
    assigned_to = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_by = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    # Timestamps
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # relationships
    asset = relationship("MonitoredAsset", back_populates="findings")
    domain_entry = relationship("DiscoveredDomain", back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings", foreign_keys=[scan_job_id])
    alerts = relationship("Alert", back_populates="finding", cascade="all, delete-orphan")


# ═════════════════════════════════════════════════════════════════════════════
# 13. alerts
# ═════════════════════════════════════════════════════════════════════════════

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(Enum(AlertChannel), nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.pending, nullable=False)
    recipient = Column(String(512), nullable=True)           # email address or webhook URL
    payload = Column(JSONB, nullable=True)                   # serialised alert payload sent
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    finding = relationship("Finding", back_populates="alerts")


# ═════════════════════════════════════════════════════════════════════════════
# 14. scan_jobs
# ═════════════════════════════════════════════════════════════════════════════

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("monitored_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    triggered_by = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    celery_task_id = Column(String(255), nullable=True, unique=True)

    status = Column(Enum(ScanJobStatus), default=ScanJobStatus.queued, nullable=False, index=True)
    is_manual = Column(Boolean, default=False)

    # Progress counters
    domains_discovered = Column(Integer, default=0)
    domains_analysed = Column(Integer, default=0)
    findings_created = Column(Integer, default=0)

    # Error tracking
    error_message = Column(Text, nullable=True)
    error_traceback = Column(Text, nullable=True)

    # Timestamps
    queued_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # relationships
    asset = relationship("MonitoredAsset", back_populates="scan_jobs")
    triggered_by_user = relationship("User", back_populates="scan_jobs", foreign_keys=[triggered_by])
    findings = relationship("Finding", back_populates="scan_job", foreign_keys="Finding.scan_job_id")


# ═════════════════════════════════════════════════════════════════════════════
# 15. reports
# ═════════════════════════════════════════════════════════════════════════════

class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("monitored_assets.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    format = Column(Enum(ReportFormat), nullable=False)
    title = Column(String(512), nullable=False)
    file_path = Column(String(512), nullable=True)
    file_size_bytes = Column(BigInteger, nullable=True)
    filter_params = Column(JSONB, nullable=True)             # query params used to build report
    findings_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # relationships
    created_by_user = relationship("User", back_populates="reports", foreign_keys=[created_by])

"""
app/schemas/__init__.py
Pydantic v2 request/response schemas for all API endpoints.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models import (
    AlertChannel,
    AlertStatus,
    DetectionType,
    FindingStatus,
    ReportFormat,
    ScanFrequency,
    ScanJobStatus,
    Severity,
    UserRole,
)


# ─────────────────────────── shared ──────────────────────────────────────────

class OrmBase(BaseModel):
    model_config = {"from_attributes": True}


# ═════════════════════════════════════════════════════════════════════════════
# Auth
# ═════════════════════════════════════════════════════════════════════════════

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ═════════════════════════════════════════════════════════════════════════════
# Users
# ═════════════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.analyst


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(OrmBase):
    id: UUID
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


# ═════════════════════════════════════════════════════════════════════════════
# Monitored assets
# ═════════════════════════════════════════════════════════════════════════════

class AssetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    display_name: str | None = None
    description: str | None = None
    scan_frequency: ScanFrequency = ScanFrequency.daily
    risk_threshold: int = Field(50, ge=0, le=100)

    @field_validator("domain")
    @classmethod
    def domain_lowercase(cls, v: str) -> str:
        return v.strip().lower()


class AssetUpdate(BaseModel):
    display_name: str | None = None
    description: str | None = None
    scan_frequency: ScanFrequency | None = None
    risk_threshold: int | None = Field(None, ge=0, le=100)
    is_active: bool | None = None


class AssetResponse(OrmBase):
    id: UUID
    domain: str
    display_name: str | None = None
    description: str | None = None
    scan_frequency: ScanFrequency
    risk_threshold: int
    is_active: bool
    last_scanned_at: datetime | None = None
    created_at: datetime


class AssetStats(BaseModel):
    asset_id: UUID
    domain: str
    total_discovered: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    open_findings: int
    last_scanned_at: datetime | None


# ═════════════════════════════════════════════════════════════════════════════
# Brand keywords
# ═════════════════════════════════════════════════════════════════════════════

class KeywordCreate(BaseModel):
    keyword: str = Field(..., min_length=1, max_length=255)


class KeywordResponse(OrmBase):
    id: UUID
    asset_id: UUID
    keyword: str
    is_active: bool
    created_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Allowed domains
# ═════════════════════════════════════════════════════════════════════════════

class AllowedDomainCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    reason: str | None = None


class AllowedDomainResponse(OrmBase):
    id: UUID
    asset_id: UUID
    domain: str
    reason: str | None = None
    created_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Discovered domains
# ═════════════════════════════════════════════════════════════════════════════

class DiscoveredDomainResponse(OrmBase):
    id: UUID
    asset_id: UUID
    domain: str
    detection_type: DetectionType
    discovery_source: str
    resolves_dns: bool | None = None
    is_active_website: bool | None = None
    http_status_code: int | None = None
    ip_address: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    hosting_provider: str | None = None
    risk_score: int
    severity: Severity
    first_seen_at: datetime
    last_checked_at: datetime | None = None


class DiscoveredDomainDetail(DiscoveredDomainResponse):
    """Extended response including related records."""
    page_title: str | None = None
    redirect_chain: list[str] | None = None
    asn: str | None = None
    asn_org: str | None = None


# ═════════════════════════════════════════════════════════════════════════════
# DNS records
# ═════════════════════════════════════════════════════════════════════════════

class DNSRecordResponse(OrmBase):
    id: UUID
    domain_id: UUID
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    collected_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# WHOIS
# ═════════════════════════════════════════════════════════════════════════════

class WhoisResponse(OrmBase):
    id: UUID
    domain_id: UUID
    registrar: str | None = None
    creation_date: datetime | None = None
    expiry_date: datetime | None = None
    name_servers: list[str] | None = None
    registrant_org: str | None = None
    registrant_country: str | None = None
    privacy_protected: bool | None = None
    collected_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# SSL certificates
# ═════════════════════════════════════════════════════════════════════════════

class SSLCertResponse(OrmBase):
    id: UUID
    domain_id: UUID
    issuer_cn: str | None = None
    issuer_org: str | None = None
    subject_cn: str | None = None
    subject_alt_names: list[str] | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    is_expired: bool | None = None
    is_self_signed: bool | None = None
    tls_version: str | None = None
    collected_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Webpage snapshots
# ═════════════════════════════════════════════════════════════════════════════

class SnapshotResponse(OrmBase):
    id: UUID
    domain_id: UUID
    screenshot_path: str | None = None
    has_login_form: bool
    has_credential_fields: bool
    external_form_action: bool
    brand_keywords_found: list[str] | None = None
    captured_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Similarity results
# ═════════════════════════════════════════════════════════════════════════════

class SimilarityResponse(OrmBase):
    id: UUID
    domain_id: UUID
    visual_similarity_score: float | None = None
    tfidf_score: float | None = None
    dom_similarity_score: float | None = None
    favicon_hash_match: bool | None = None
    overall_similarity_score: float | None = None
    computed_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Threat intel matches
# ═════════════════════════════════════════════════════════════════════════════

class ThreatIntelResponse(OrmBase):
    id: UUID
    domain_id: UUID
    feed_name: str
    threat_type: str | None = None
    confidence: float | None = None
    tags: list[str] | None = None
    matched_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Findings
# ═════════════════════════════════════════════════════════════════════════════

class FindingResponse(OrmBase):
    id: UUID
    asset_id: UUID
    domain_id: UUID
    domain_name: str | None = None
    scan_job_id: UUID | None = None
    detection_type: DetectionType
    discovery_source: str
    severity: Severity
    risk_score: int
    status: FindingStatus
    summary: str | None = None
    recommended_action: str | None = None
    first_seen_at: datetime
    last_updated_at: datetime
    resolved_at: datetime | None = None


class FindingDetail(FindingResponse):
    evidence: dict[str, Any] | None = None
    notes: str | None = None
    domain_entry: DiscoveredDomainDetail | None = None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    notes: str | None = None


class FindingListParams(BaseModel):
    """Query params for the findings list endpoint."""
    asset_id: UUID | None = None
    severity: Severity | None = None
    status: FindingStatus | None = None
    detection_type: DetectionType | None = None
    skip: int = Field(0, ge=0)
    limit: int = Field(50, ge=1, le=500)


# ═════════════════════════════════════════════════════════════════════════════
# Scan jobs
# ═════════════════════════════════════════════════════════════════════════════

class ScanJobTrigger(BaseModel):
    asset_id: UUID


class ScanJobResponse(OrmBase):
    id: UUID
    asset_id: UUID
    status: ScanJobStatus
    is_manual: bool
    domains_discovered: int
    domains_analysed: int
    findings_created: int
    queued_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


# ═════════════════════════════════════════════════════════════════════════════
# Alerts
# ═════════════════════════════════════════════════════════════════════════════

class AlertResponse(OrmBase):
    id: UUID
    finding_id: UUID
    channel: AlertChannel
    status: AlertStatus
    recipient: str | None = None
    sent_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Reports
# ═════════════════════════════════════════════════════════════════════════════

class ReportCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    format: ReportFormat
    asset_id: UUID | None = None
    filter_params: dict[str, Any] | None = None


class ReportResponse(OrmBase):
    id: UUID
    asset_id: UUID | None = None
    format: ReportFormat
    title: str
    file_size_bytes: int | None = None
    findings_count: int
    created_at: datetime


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard
# ═════════════════════════════════════════════════════════════════════════════

class DashboardStats(BaseModel):
    total_monitored_domains: int
    total_discovered_domains: int
    total_open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    newly_discovered_today: int
    confirmed_clones: int
    last_scan_at: datetime | None


class FindingsBySource(BaseModel):
    source: str
    count: int


class FindingsBySeverity(BaseModel):
    severity: str
    count: int


class FindingsByTLD(BaseModel):
    tld: str
    count: int


class FindingsTrend(BaseModel):
    date: str
    count: int

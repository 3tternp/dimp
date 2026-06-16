"""
app/api/v1/endpoints/findings.py
Findings list, detail view, and status/workflow update endpoints.
"""
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import AnalystOrAdmin, CurrentUser, DB, Pagination
from app.models import DiscoveredDomain, Finding, FindingStatus, Severity, DetectionType
from app.schemas import FindingDetail, FindingResponse, FindingStatusUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    db: DB,
    current_user: CurrentUser,
    page: Pagination,
    asset_id: UUID | None = Query(None),
    severity: Severity | None = Query(None),
    status: FindingStatus | None = Query(None),
    detection_type: DetectionType | None = Query(None),
):
    """
    List findings with optional filters.
    Supports filtering by asset, severity, status, and detection type.
    """
    q = select(Finding).order_by(Finding.first_seen_at.desc())

    if asset_id:
        q = q.where(Finding.asset_id == str(asset_id))
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    if detection_type:
        q = q.where(Finding.detection_type == detection_type)

    q = q.offset(page["skip"]).limit(page["limit"])
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(finding_id: UUID, db: DB, current_user: CurrentUser):
    """
    Full finding detail — includes DNS, WHOIS, SSL, snapshots, similarity,
    and threat intel data via eager-loaded relationships.
    """
    result = await db.execute(
        select(Finding)
        .options(
            selectinload(Finding.domain_entry).selectinload(DiscoveredDomain.dns_records),
            selectinload(Finding.domain_entry).selectinload(DiscoveredDomain.whois_record),
            selectinload(Finding.domain_entry).selectinload(DiscoveredDomain.ssl_certificate),
            selectinload(Finding.domain_entry).selectinload(DiscoveredDomain.snapshots),
            selectinload(Finding.domain_entry).selectinload(DiscoveredDomain.similarity_results),
            selectinload(Finding.domain_entry).selectinload(DiscoveredDomain.threat_intel_matches),
        )
        .where(Finding.id == str(finding_id))
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: UUID,
    body: FindingStatusUpdate,
    db: DB,
    current_user: AnalystOrAdmin,
):
    """Update a finding's workflow status (e.g. new → under_review → confirmed)."""
    result = await db.execute(select(Finding).where(Finding.id == str(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = body.status
    if body.notes:
        finding.notes = body.notes
    finding.reviewed_by = str(current_user.id)
    finding.reviewed_at = datetime.now(timezone.utc)

    if body.status == FindingStatus.resolved:
        finding.resolved_at = datetime.now(timezone.utc)

    db.add(finding)
    return finding

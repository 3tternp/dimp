"""
app/api/v1/endpoints/dashboard.py
Dashboard statistics endpoints — summary cards, charts, trends.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from sqlalchemy import cast, Date, func, select, text

from app.api.deps import CurrentUser, DB
from app.models import (
    DiscoveredDomain,
    Finding,
    FindingStatus,
    MonitoredAsset,
    Severity,
)
from app.schemas import (
    DashboardStats,
    FindingsBySeverity,
    FindingsBySource,
    FindingsByTLD,
    FindingsTrend,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: DB, current_user: CurrentUser):
    """Aggregate summary numbers for the dashboard header cards."""
    today = datetime.now(timezone.utc).date()
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)

    # Total monitored domains
    total_monitored = (await db.execute(
        select(func.count()).select_from(MonitoredAsset).where(MonitoredAsset.is_active == True)
    )).scalar_one()

    # Total discovered domains
    total_discovered = (await db.execute(
        select(func.count()).select_from(DiscoveredDomain)
    )).scalar_one()

    # Open findings by severity
    open_statuses = [FindingStatus.new, FindingStatus.under_review, FindingStatus.confirmed, FindingStatus.takedown_requested]

    def severity_count(sev: Severity):
        return select(func.count()).select_from(Finding).where(
            Finding.severity == sev,
            Finding.status.in_(open_statuses),
        )

    critical = (await db.execute(severity_count(Severity.critical))).scalar_one()
    high = (await db.execute(severity_count(Severity.high))).scalar_one()
    medium = (await db.execute(severity_count(Severity.medium))).scalar_one()
    low = (await db.execute(severity_count(Severity.low))).scalar_one()

    # Total open findings
    total_open = (await db.execute(
        select(func.count()).select_from(Finding).where(Finding.status.in_(open_statuses))
    )).scalar_one()

    # Newly discovered today
    newly_today = (await db.execute(
        select(func.count()).select_from(DiscoveredDomain)
        .where(DiscoveredDomain.first_seen_at >= today_start)
    )).scalar_one()

    # Confirmed clones (cloned_page detection type, confirmed status)
    from app.models import DetectionType
    confirmed_clones = (await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.detection_type == DetectionType.cloned_page,
            Finding.status == FindingStatus.confirmed,
        )
    )).scalar_one()

    # Last scan timestamp
    last_scan_result = (await db.execute(
        select(MonitoredAsset.last_scanned_at)
        .where(MonitoredAsset.last_scanned_at.isnot(None))
        .order_by(MonitoredAsset.last_scanned_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    return DashboardStats(
        total_monitored_domains=total_monitored,
        total_discovered_domains=total_discovered,
        total_open_findings=total_open,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        newly_discovered_today=newly_today,
        confirmed_clones=confirmed_clones,
        last_scan_at=last_scan_result,
    )


@router.get("/findings-by-severity", response_model=list[FindingsBySeverity])
async def findings_by_severity(db: DB, current_user: CurrentUser):
    rows = (await db.execute(
        select(Finding.severity, func.count().label("count"))
        .group_by(Finding.severity)
    )).all()
    return [FindingsBySeverity(severity=r.severity.value, count=r.count) for r in rows]


@router.get("/findings-by-source", response_model=list[FindingsBySource])
async def findings_by_source(db: DB, current_user: CurrentUser):
    rows = (await db.execute(
        select(Finding.discovery_source, func.count().label("count"))
        .group_by(Finding.discovery_source)
        .order_by(func.count().desc())
        .limit(20)
    )).all()
    return [FindingsBySource(source=r.discovery_source, count=r.count) for r in rows]


@router.get("/findings-by-tld", response_model=list[FindingsByTLD])
async def findings_by_tld(db: DB, current_user: CurrentUser):
    """Extract TLD from discovered domain names for the TLD distribution chart."""
    rows = (await db.execute(
        select(
            func.split_part(DiscoveredDomain.domain, ".", -1).label("tld"),
            func.count().label("count"),
        )
        .join(Finding, Finding.domain_id == DiscoveredDomain.id)
        .group_by(text("tld"))
        .order_by(func.count().desc())
        .limit(15)
    )).all()
    return [FindingsByTLD(tld=r.tld, count=r.count) for r in rows]


@router.get("/findings-trend", response_model=list[FindingsTrend])
async def findings_trend(db: DB, current_user: CurrentUser, days: int = 30):
    """Daily new finding counts for the past N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (await db.execute(
        select(
            cast(Finding.first_seen_at, Date).label("date"),
            func.count().label("count"),
        )
        .where(Finding.first_seen_at >= cutoff)
        .group_by(text("date"))
        .order_by(text("date"))
    )).all()
    return [FindingsTrend(date=str(r.date), count=r.count) for r in rows]

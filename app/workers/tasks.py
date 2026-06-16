"""
app/workers/tasks.py
Celery application definition and the core scan task pipeline.

Task chain for a full scan:
  run_full_scan
    ├─ discover_domains          (typosquat + CT log)
    ├─ For each discovered domain:
    │    ├─ collect_dns
    │    ├─ collect_whois
    │    ├─ collect_ssl
    │    ├─ collect_http_metadata
    │    ├─ capture_screenshot
    │    ├─ compute_similarity
    │    └─ run_risk_scorer
    └─ alert_on_high_findings
"""
import traceback
from datetime import datetime, timezone

from celery import Celery, chain, group
from celery.utils.log import get_task_logger

from app.core.config import settings

# ── Celery app ────────────────────────────────────────────────────────────────
celery_app = Celery(
    "dimp",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,                    # re-queue on worker crash
    worker_prefetch_multiplier=1,           # one task at a time per worker
    task_routes={
        "app.workers.tasks.run_full_scan": {"queue": "scans"},
        "app.workers.tasks.capture_screenshot": {"queue": "screenshots"},  # Playwright worker
    },
    beat_schedule={
        "scheduled-daily-scans": {
            "task": "app.workers.tasks.run_scheduled_scans",
            "schedule": 3600.0,             # every hour — filters by asset frequency inside
        }
    },
)

logger = get_task_logger(__name__)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _get_sync_db():
    """Return a synchronous SQLAlchemy session for use inside Celery tasks."""
    from app.db.session import SyncSessionFactory
    return SyncSessionFactory()


def _update_job(job_id: str, **kwargs):
    """Update ScanJob fields in the DB (sync, for Celery tasks)."""
    from app.models import ScanJob
    db = _get_sync_db()
    try:
        job = db.query(ScanJob).get(job_id)
        if job:
            for k, v in kwargs.items():
                setattr(job, k, v)
            db.commit()
    finally:
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Main orchestration task
# ═════════════════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, name="app.workers.tasks.run_full_scan", max_retries=2)
def run_full_scan(self, job_id: str, asset_id: str):
    """
    Orchestrates a complete scan cycle for one monitored asset.
    Updates ScanJob progress counters throughout.
    """
    from app.models import MonitoredAsset, ScanJob, ScanJobStatus
    from app.workers.scanner.discovery import generate_variants, query_ct_logs
    from app.workers.scanner.dns_collector import collect_dns
    from app.workers.scanner.http_collector import collect_http_metadata
    from app.workers.scanner.whois_collector import collect_whois
    from app.workers.scanner.ssl_collector import collect_ssl
    from app.workers.scanner.risk_scorer import compute_risk_score

    db = _get_sync_db()
    try:
        # Mark job as running
        _update_job(job_id, status=ScanJobStatus.running, started_at=datetime.now(timezone.utc))
        logger.info("scan_started", job_id=job_id, asset_id=asset_id)

        asset = db.query(MonitoredAsset).get(asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")

        # ── Phase 1: Discovery ────────────────────────────────────────────────
        variants = generate_variants(asset.domain)
        ct_domains = query_ct_logs(asset.domain)
        all_candidates = list(set(variants + ct_domains))

        logger.info("domains_discovered", count=len(all_candidates), job_id=job_id)
        _update_job(job_id, domains_discovered=len(all_candidates))

        # ── Phase 2: Analysis ────────────────────────────────────────────────
        from app.workers.scanner.domain_analyser import analyse_domain
        findings_created = 0

        for domain in all_candidates:
            try:
                finding = analyse_domain(
                    db=db,
                    domain=domain,
                    asset=asset,
                    job_id=job_id,
                )
                if finding:
                    findings_created += 1
            except Exception as e:
                logger.warning("domain_analysis_failed", domain=domain, error=str(e))
                continue

        # ── Phase 3: Alert on high/critical findings ──────────────────────────
        alert_on_new_findings.delay(job_id, asset_id)

        # Update asset last_scanned_at
        asset.last_scanned_at = datetime.now(timezone.utc)
        db.commit()

        _update_job(
            job_id,
            status=ScanJobStatus.completed,
            completed_at=datetime.now(timezone.utc),
            domains_analysed=len(all_candidates),
            findings_created=findings_created,
        )
        logger.info("scan_completed", job_id=job_id, findings=findings_created)

    except Exception as exc:
        logger.error("scan_failed", job_id=job_id, error=str(exc))
        _update_job(
            job_id,
            status=ScanJobStatus.failed,
            completed_at=datetime.now(timezone.utc),
            error_message=str(exc),
            error_traceback=traceback.format_exc(),
        )
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Scheduled scan dispatcher
# ═════════════════════════════════════════════════════════════════════════════

@celery_app.task(name="app.workers.tasks.run_scheduled_scans")
def run_scheduled_scans():
    """
    Celery Beat task — runs every hour.
    Dispatches run_full_scan for assets whose scan is due based on frequency.
    """
    from datetime import timedelta
    from app.models import MonitoredAsset, ScanFrequency, ScanJob, ScanJobStatus

    db = _get_sync_db()
    try:
        assets = db.query(MonitoredAsset).filter(MonitoredAsset.is_active == True).all()
        now = datetime.now(timezone.utc)
        dispatched = 0

        for asset in assets:
            if asset.last_scanned_at is None:
                due = True
            elif asset.scan_frequency == ScanFrequency.hourly:
                due = (now - asset.last_scanned_at) >= timedelta(hours=1)
            elif asset.scan_frequency == ScanFrequency.daily:
                due = (now - asset.last_scanned_at) >= timedelta(days=1)
            elif asset.scan_frequency == ScanFrequency.weekly:
                due = (now - asset.last_scanned_at) >= timedelta(weeks=1)
            else:
                due = False

            if due:
                job = ScanJob(
                    asset_id=asset.id,
                    is_manual=False,
                    status=ScanJobStatus.queued,
                )
                db.add(job)
                db.flush()
                task = run_full_scan.delay(str(job.id), str(asset.id))
                job.celery_task_id = task.id
                db.commit()
                dispatched += 1

        logger.info("scheduled_scans_dispatched", count=dispatched)
    finally:
        db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Alert dispatch task
# ═════════════════════════════════════════════════════════════════════════════

@celery_app.task(name="app.workers.tasks.alert_on_new_findings")
def alert_on_new_findings(job_id: str, asset_id: str):
    """Send alerts for any high/critical findings created in this scan job."""
    from app.models import Finding, FindingStatus, Severity
    from app.services.alerting_service import send_finding_alert

    db = _get_sync_db()
    try:
        findings = (
            db.query(Finding)
            .filter(
                Finding.scan_job_id == job_id,
                Finding.severity.in_([Severity.high, Severity.critical]),
                Finding.status == FindingStatus.new,
            )
            .all()
        )

        for finding in findings:
            try:
                send_finding_alert(finding)
            except Exception as e:
                logger.warning("alert_failed", finding_id=str(finding.id), error=str(e))
    finally:
        db.close()

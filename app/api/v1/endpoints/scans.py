"""
app/api/v1/endpoints/scans.py
Scan job management — trigger manual scans and view scan history.
"""
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.deps import AnalystOrAdmin, CurrentUser, DB, Pagination
from app.models import MonitoredAsset, ScanJob, ScanJobStatus
from app.schemas import ScanJobResponse, ScanJobTrigger

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(body: ScanJobTrigger, db: DB, current_user: AnalystOrAdmin):
    """
    Trigger a manual scan for a monitored asset.
    Creates a ScanJob record and dispatches a Celery task.
    Returns 202 Accepted — poll /scans/{job_id} for progress.
    """
    # Verify asset exists
    result = await db.execute(
        select(MonitoredAsset).where(MonitoredAsset.id == str(body.asset_id))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    job = ScanJob(
        asset_id=str(body.asset_id),
        triggered_by=str(current_user.id),
        is_manual=True,
        status=ScanJobStatus.queued,
    )
    db.add(job)
    await db.flush()  # get the job.id before dispatching

    # Run scan in a background thread (no Celery worker required)
    import logging
    import threading
    import traceback
    from datetime import datetime, timezone

    _job_id, _asset_id = str(job.id), str(body.asset_id)
    _logger = logging.getLogger("scan_runner")

    def _run_scan():
        from app.workers.scanner.domain_analyser import analyse_domain
        from app.workers.scanner.discovery import generate_variants, query_ct_logs
        from app.workers.tasks import _get_sync_db, _update_job
        from app.models import MonitoredAsset, ScanJobStatus

        scan_db = _get_sync_db()
        try:
            _update_job(_job_id, status=ScanJobStatus.running, started_at=datetime.now(timezone.utc))
            asset = scan_db.query(MonitoredAsset).get(_asset_id)
            if not asset:
                raise ValueError(f"Asset {_asset_id} not found")

            _logger.info("scan_started job=%s domain=%s", _job_id, asset.domain)

            variants = generate_variants(asset.domain)
            ct_domains = []
            try:
                ct_domains = query_ct_logs(asset.domain)
            except Exception as e:
                _logger.warning("ct_log_query_failed domain=%s: %s", asset.domain, e)

            all_candidates = list(set(variants + ct_domains))
            _logger.info("discovered %d candidate domains", len(all_candidates))
            _update_job(_job_id, domains_discovered=len(all_candidates))

            findings_created = 0
            analysed = 0
            consecutive_errors = 0
            for i, domain_candidate in enumerate(all_candidates):
                try:
                    finding = analyse_domain(db=scan_db, domain=domain_candidate, asset=asset, job_id=_job_id)
                    if finding:
                        findings_created += 1
                    analysed += 1
                    consecutive_errors = 0
                except Exception as e:
                    consecutive_errors += 1
                    _logger.debug("domain_analysis_failed domain=%s: %s", domain_candidate, e)
                    try:
                        scan_db.rollback()
                    except Exception:
                        pass
                    if consecutive_errors >= 20:
                        _logger.error("too_many_consecutive_errors job=%s, stopping", _job_id)
                        break
                    continue

                if (i + 1) % 25 == 0:
                    _update_job(_job_id, domains_analysed=analysed, findings_created=findings_created)
                    _logger.info("progress: %d/%d domains analysed, %d findings", i + 1, len(all_candidates), findings_created)

            asset.last_scanned_at = datetime.now(timezone.utc)
            scan_db.commit()
            _update_job(
                _job_id,
                status=ScanJobStatus.completed,
                completed_at=datetime.now(timezone.utc),
                domains_analysed=analysed,
                findings_created=findings_created,
            )
            _logger.info("scan_completed job=%s analysed=%d findings=%d", _job_id, analysed, findings_created)
        except Exception as exc:
            _logger.error("scan_failed job=%s: %s", _job_id, exc)
            try:
                scan_db.rollback()
            except Exception:
                pass
            _update_job(
                _job_id,
                status=ScanJobStatus.failed,
                completed_at=datetime.now(timezone.utc),
                error_message=str(exc),
                error_traceback=traceback.format_exc(),
            )
        finally:
            scan_db.close()

    threading.Thread(target=_run_scan, daemon=True).start()

    return job


@router.get("", response_model=list[ScanJobResponse])
async def list_scan_jobs(
    db: DB,
    current_user: CurrentUser,
    page: Pagination,
    asset_id: UUID | None = None,
):
    """List scan job history, optionally filtered by asset."""
    q = select(ScanJob).order_by(ScanJob.queued_at.desc())
    if asset_id:
        q = q.where(ScanJob.asset_id == str(asset_id))
    q = q.offset(page["skip"]).limit(page["limit"])
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{job_id}", response_model=ScanJobResponse)
async def get_scan_job(job_id: UUID, db: DB, current_user: CurrentUser):
    """Poll a scan job for its current status and progress counters."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == str(job_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job

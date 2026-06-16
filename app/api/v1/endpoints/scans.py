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

    # Dispatch Celery task (imported here to avoid circular imports)
    try:
        from app.workers.tasks import run_full_scan
        task = run_full_scan.delay(str(job.id), str(body.asset_id))
        job.celery_task_id = task.id
        db.add(job)
    except Exception as e:
        # Celery may not be available in dev — job stays queued
        job.error_message = f"Failed to dispatch task: {e}"
        db.add(job)

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

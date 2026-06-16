"""
app/api/v1/endpoints/reports.py
Report generation and download endpoints.
"""
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.api.deps import AnalystOrAdmin, CurrentUser, DB, Pagination
from app.models import Report
from app.schemas import ReportCreate, ReportResponse

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportResponse])
async def list_reports(db: DB, current_user: CurrentUser, page: Pagination):
    result = await db.execute(
        select(Report).order_by(Report.created_at.desc())
        .offset(page["skip"]).limit(page["limit"])
    )
    return result.scalars().all()


@router.post("", response_model=ReportResponse, status_code=202)
async def create_report(
    body: ReportCreate,
    background_tasks: BackgroundTasks,
    db: DB,
    current_user: AnalystOrAdmin,
):
    """
    Queue a report for generation.
    Returns 202 immediately; the file is available once status shows a file_path.
    Generation happens in the background via BackgroundTasks (small reports)
    or Celery (for large ones).
    """
    report = Report(
        asset_id=str(body.asset_id) if body.asset_id else None,
        created_by=str(current_user.id),
        format=body.format,
        title=body.title,
        filter_params=body.filter_params,
        findings_count=0,
    )
    db.add(report)
    await db.flush()

    # Dispatch generation task
    report_id = str(report.id)
    background_tasks.add_task(_generate_report_task, report_id)

    return report


async def _generate_report_task(report_id: str) -> None:
    """Background task stub — delegates to the report service."""
    try:
        from app.services.report_service import generate_report
        await generate_report(report_id)
    except Exception as exc:
        import structlog
        structlog.get_logger().error("report_generation_failed", report_id=report_id, error=str(exc))


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: UUID, db: DB, current_user: CurrentUser):
    result = await db.execute(select(Report).where(Report.id == str(report_id)))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/download")
async def download_report(report_id: UUID, db: DB, current_user: CurrentUser):
    """Download the generated report file."""
    result = await db.execute(select(Report).where(Report.id == str(report_id)))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.file_path:
        raise HTTPException(status_code=425, detail="Report is not yet generated. Try again shortly.")

    import os
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    media_type_map = {
        "html": "text/html",
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
    }
    return FileResponse(
        path=report.file_path,
        media_type=media_type_map.get(report.format.value, "application/octet-stream"),
        filename=f"dimp_report_{report_id}.{report.format.value}",
    )

"""
app/services/report_service.py
Report generation service — produces HTML, CSV, JSON outputs.
PDF generation via WeasyPrint is implemented in Phase 4.
"""
import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)


async def generate_report(report_id: str) -> None:
    """
    Generate a report file for the given report_id.
    Loads the Report record, fetches relevant findings,
    and writes to the configured report directory.
    """
    from app.db.session import AsyncSessionFactory
    from app.models import Finding, Report
    from sqlalchemy import select

    async with AsyncSessionFactory() as db:
        result = await db.execute(select(Report).where(Report.id == report_id))
        report = result.scalar_one_or_none()
        if not report:
            logger.error("report_not_found", report_id=report_id)
            return

        # Fetch findings
        q = select(Finding).order_by(Finding.risk_score.desc())
        if report.asset_id:
            q = q.where(Finding.asset_id == str(report.asset_id))
        findings_result = await db.execute(q)
        findings = findings_result.scalars().all()

        report_dir = Path(settings.report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        filename = f"dimp_report_{report_id}.{report.format.value}"
        file_path = report_dir / filename

        if report.format.value == "json":
            _write_json(file_path, findings)
        elif report.format.value == "csv":
            _write_csv(file_path, findings)
        elif report.format.value == "html":
            _write_html(file_path, findings, report.title)

        # Update report record
        stat = file_path.stat()
        report.file_path = str(file_path)
        report.file_size_bytes = stat.st_size
        report.findings_count = len(findings)
        await db.commit()
        logger.info("report_generated", report_id=report_id, path=str(file_path))


def _write_json(path: Path, findings) -> None:
    data = [
        {
            "id": str(f.id),
            "domain": f.domain_entry.domain if f.domain_entry else None,
            "severity": f.severity.value,
            "risk_score": f.risk_score,
            "status": f.status.value,
            "detection_type": f.detection_type.value,
            "discovery_source": f.discovery_source,
            "summary": f.summary,
            "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        }
        for f in findings
    ]
    path.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "findings": data}, indent=2))


def _write_csv(path: Path, findings) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "domain", "severity", "risk_score", "status", "detection_type", "source", "summary", "first_seen"])
        for f in findings:
            writer.writerow([
                str(f.id),
                f.domain_entry.domain if f.domain_entry else "",
                f.severity.value,
                f.risk_score,
                f.status.value,
                f.detection_type.value,
                f.discovery_source,
                f.summary or "",
                f.first_seen_at.isoformat() if f.first_seen_at else "",
            ])


def _write_html(path: Path, findings, title: str) -> None:
    rows = ""
    for f in findings:
        severity_colour = {"critical": "#E24B4A", "high": "#EF9F27", "medium": "#378ADD", "low": "#639922"}.get(f.severity.value, "#888")
        rows += f"""<tr>
          <td>{f.domain_entry.domain if f.domain_entry else ''}</td>
          <td style="color:{severity_colour};font-weight:500">{f.severity.value.upper()}</td>
          <td>{f.risk_score}</td>
          <td>{f.detection_type.value}</td>
          <td>{f.status.value}</td>
          <td>{f.first_seen_at.strftime('%Y-%m-%d') if f.first_seen_at else ''}</td>
          <td>{f.summary or ''}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
    h1 {{ font-size: 22px; color: #185FA5; }}
    p.meta {{ font-size: 12px; color: #666; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }}
    th {{ background: #185FA5; color: white; padding: 8px 12px; text-align: left; }}
    td {{ padding: 7px 12px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }}
    tr:nth-child(even) td {{ background: #f7f7f7; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Findings: {len(findings)}</p>
  <table>
    <thead><tr>
      <th>Domain</th><th>Severity</th><th>Score</th><th>Type</th><th>Status</th><th>First seen</th><th>Summary</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
    path.write_text(html)


async def generate_pdf_report(report_id: str) -> None:
    """Generate a PDF report using WeasyPrint + Jinja2."""
    from app.db.session import AsyncSessionFactory
    from app.models import Finding, Report
    from app.services.pdf_report import generate_pdf
    from sqlalchemy import select
    from pathlib import Path
    import os

    async with AsyncSessionFactory() as db:
        result = await db.execute(select(Report).where(Report.id == report_id))
        report = result.scalar_one_or_none()
        if not report:
            return

        q = select(Finding).order_by(Finding.risk_score.desc())
        if report.asset_id:
            q = q.where(Finding.asset_id == str(report.asset_id))
        findings_result = await db.execute(q)
        findings = findings_result.scalars().all()

        report_dir = Path(settings.report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        file_path = report_dir / f"dimp_report_{report_id}.pdf"

        pdf_bytes = generate_pdf(findings, report.title)
        file_path.write_bytes(pdf_bytes)

        stat = file_path.stat()
        report.file_path = str(file_path)
        report.file_size_bytes = stat.st_size
        report.findings_count = len(findings)
        await db.commit()

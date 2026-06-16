"""
app/services/pdf_report.py
PDF report generation using Jinja2 HTML template + WeasyPrint.
Produces a professional executive + technical findings report.
"""
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Jinja2 HTML template ──────────────────────────────────────────────────────
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @page { size: A4; margin: 20mm 18mm; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, Helvetica, sans-serif; font-size: 11px; color: #222; line-height: 1.5; }

  /* Header */
  .cover { border-bottom: 4px solid #185FA5; padding-bottom: 20px; margin-bottom: 24px; }
  .cover h1 { font-size: 22px; font-weight: 700; color: #185FA5; margin-bottom: 4px; }
  .cover .meta { font-size: 10px; color: #666; }
  .cover .org { font-size: 13px; font-weight: 600; margin-bottom: 4px; }

  /* Section headings */
  h2 { font-size: 14px; font-weight: 700; color: #185FA5; margin: 20px 0 8px;
       border-bottom: 1px solid #d0dce8; padding-bottom: 4px; page-break-after: avoid; }
  h3 { font-size: 12px; font-weight: 700; color: #333; margin: 14px 0 4px; page-break-after: avoid; }

  /* Executive summary boxes */
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0; }
  .stat-box { border-radius: 6px; padding: 12px 10px; text-align: center; }
  .stat-box .num { font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-box .lbl { font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; color: inherit; }
  .box-critical { background: #fef2f2; border: 1px solid #fca5a5; color: #991b1b; }
  .box-high     { background: #fffbeb; border: 1px solid #fcd34d; color: #92400e; }
  .box-medium   { background: #eff6ff; border: 1px solid #93c5fd; color: #1e40af; }
  .box-low      { background: #f0fdf4; border: 1px solid #86efac; color: #166534; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 10px; }
  th { background: #185FA5; color: #fff; padding: 6px 8px; text-align: left; font-weight: 600; }
  td { padding: 5px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  tr:nth-child(even) td { background: #f9fafb; }
  .sev-critical { color: #991b1b; font-weight: 700; }
  .sev-high     { color: #92400e; font-weight: 700; }
  .sev-medium   { color: #1e40af; font-weight: 600; }
  .sev-low      { color: #166534; }

  /* Finding detail cards */
  .finding-card { border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px 14px;
                  margin: 10px 0; page-break-inside: avoid; }
  .finding-card.critical { border-left: 4px solid #ef4444; }
  .finding-card.high     { border-left: 4px solid #f59e0b; }
  .finding-card.medium   { border-left: 4px solid #3b82f6; }
  .finding-card.low      { border-left: 4px solid #22c55e; }
  .fc-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
  .fc-domain { font-family: 'Courier New', monospace; font-size: 12px; font-weight: 700; color: #185FA5; }
  .badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 9px; font-weight: 700;
           text-transform: uppercase; }
  .badge-critical { background: #fef2f2; color: #991b1b; }
  .badge-high     { background: #fffbeb; color: #92400e; }
  .badge-medium   { background: #eff6ff; color: #1e40af; }
  .badge-low      { background: #f0fdf4; color: #166534; }

  .kv { display: flex; gap: 8px; margin: 3px 0; font-size: 10px; }
  .k  { color: #6b7280; min-width: 120px; flex-shrink: 0; }
  .v  { color: #111; }

  /* Action box */
  .action-box { background: #fffbeb; border: 1px solid #fcd34d; border-radius: 4px;
                padding: 8px 10px; margin-top: 8px; font-size: 10px; color: #78350f; }

  /* Footer */
  .footer { margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 10px;
            font-size: 9px; color: #9ca3af; display: flex; justify-content: space-between; }

  .page-break { page-break-before: always; }
</style>
</head>
<body>

<!-- Cover / header -->
<div class="cover">
  <div class="org">Domain Impersonation Monitoring Platform</div>
  <h1>{{ title }}</h1>
  <div class="meta">
    Generated: {{ generated_at }} &nbsp;|&nbsp;
    Total findings: {{ total_findings }} &nbsp;|&nbsp;
    Asset: {{ asset_domain or "All monitored assets" }}
  </div>
</div>

<!-- Executive summary -->
<h2>Executive summary</h2>
<div class="summary-grid">
  <div class="stat-box box-critical">
    <div class="num">{{ critical_count }}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="stat-box box-high">
    <div class="num">{{ high_count }}</div>
    <div class="lbl">High</div>
  </div>
  <div class="stat-box box-medium">
    <div class="num">{{ medium_count }}</div>
    <div class="lbl">Medium</div>
  </div>
  <div class="stat-box box-low">
    <div class="num">{{ low_count }}</div>
    <div class="lbl">Low</div>
  </div>
</div>

<p style="font-size:11px; color:#374151; margin: 10px 0 20px;">
  This report covers {{ total_findings }} domain impersonation findings detected by automated scanning.
  {% if critical_count > 0 %}
  <strong>{{ critical_count }} critical finding{{ "s" if critical_count != 1 }} require immediate action.</strong>
  {% endif %}
</p>

<!-- Risk-ranked findings table -->
<h2>Findings summary — ranked by risk score</h2>
<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Suspicious domain</th>
      <th>Severity</th>
      <th>Score</th>
      <th>Detection type</th>
      <th>Status</th>
      <th>First seen</th>
    </tr>
  </thead>
  <tbody>
    {% for f in findings %}
    <tr>
      <td>{{ loop.index }}</td>
      <td style="font-family:monospace; font-size:10px; color:#185FA5;">{{ f.domain }}</td>
      <td class="sev-{{ f.severity }}">{{ f.severity | upper }}</td>
      <td style="font-weight:700;">{{ f.risk_score }}/100</td>
      <td>{{ f.detection_type | replace("_", " ") | title }}</td>
      <td>{{ f.status | replace("_", " ") | title }}</td>
      <td>{{ f.first_seen }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<!-- Detailed findings — critical and high only to keep PDF manageable -->
<div class="page-break"></div>
<h2>Detailed findings — critical &amp; high severity</h2>

{% for f in findings %}
{% if f.severity in ("critical", "high") %}
<div class="finding-card {{ f.severity }}">
  <div class="fc-header">
    <span class="fc-domain">{{ f.domain }}</span>
    <span>
      <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
      &nbsp; Score: <strong>{{ f.risk_score }}/100</strong>
    </span>
  </div>

  <div class="kv"><span class="k">Detection type</span><span class="v">{{ f.detection_type | replace("_"," ") | title }}</span></div>
  <div class="kv"><span class="k">Discovery source</span><span class="v">{{ f.discovery_source }}</span></div>
  <div class="kv"><span class="k">Status</span><span class="v">{{ f.status | replace("_"," ") | title }}</span></div>
  <div class="kv"><span class="k">First seen</span><span class="v">{{ f.first_seen }}</span></div>

  {% if f.summary %}
  <div style="margin:8px 0; font-size:10px; color:#374151; background:#f9fafb;
    padding:8px; border-radius:4px; border-left:3px solid #f59e0b;">
    {{ f.summary }}
  </div>
  {% endif %}

  {% if f.recommended_action %}
  <div class="action-box">
    <strong>Recommended action:</strong> {{ f.recommended_action }}
  </div>
  {% endif %}
</div>
{% endif %}
{% endfor %}

<!-- Remediation guidance -->
<div class="page-break"></div>
<h2>Remediation guidance</h2>

<h3>Critical &amp; high severity</h3>
<p style="margin-bottom:8px; font-size:10px;">
  File a UDRP complaint with ICANN or submit an abuse report to the registrar.
  Block the domain at perimeter controls (DNS sinkhole, web proxy, firewall).
  Report to Google Safe Browsing, PhishTank, and relevant national CERT.
</p>

<h3>Takedown evidence package</h3>
<p style="margin-bottom:8px; font-size:10px;">
  Each critical/high finding contains DNS records, WHOIS data, SSL certificates,
  and screenshots captured at time of discovery. Export the finding JSON for
  submission to registrars, hosting providers, and law enforcement if required.
</p>

<h3>Monitoring continuity</h3>
<p style="font-size:10px;">
  Medium and low severity findings are monitored on the configured schedule.
  Re-scan after takedown confirmation to verify resolution.
</p>

<div class="footer">
  <span>DIMP — Domain Impersonation Monitoring Platform</span>
  <span>Confidential — for internal use only</span>
  <span>{{ generated_at }}</span>
</div>

</body>
</html>
"""


def generate_pdf(findings: list, title: str, asset_domain: str | None = None) -> bytes:
    """
    Render findings into a PDF report using WeasyPrint.

    Args:
        findings: list of Finding ORM objects
        title: report title
        asset_domain: optional domain name for the report header

    Returns:
        PDF bytes
    """
    try:
        from jinja2 import Template
        from weasyprint import HTML
    except ImportError as e:
        logger.error("PDF dependencies missing: %s — install weasyprint and jinja2", e)
        raise

    now = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")

    # Severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    finding_data = []

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counts[sev] = counts.get(sev, 0) + 1
        domain = f.domain_entry.domain if f.domain_entry else "unknown"
        finding_data.append({
            "domain": domain,
            "severity": sev,
            "risk_score": f.risk_score,
            "detection_type": f.detection_type.value if hasattr(f.detection_type, "value") else str(f.detection_type),
            "discovery_source": f.discovery_source,
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
            "summary": f.summary or "",
            "recommended_action": f.recommended_action or "",
            "first_seen": f.first_seen_at.strftime("%d %b %Y") if f.first_seen_at else "—",
        })

    # Sort by risk score descending
    finding_data.sort(key=lambda x: x["risk_score"], reverse=True)

    template = Template(REPORT_TEMPLATE)
    html_content = template.render(
        title=title,
        generated_at=now,
        asset_domain=asset_domain,
        total_findings=len(findings),
        critical_count=counts.get("critical", 0),
        high_count=counts.get("high", 0),
        medium_count=counts.get("medium", 0),
        low_count=counts.get("low", 0),
        findings=finding_data,
    )

    pdf_bytes = HTML(string=html_content).write_pdf()
    logger.info("pdf_generated", pages=len(findings), title=title)
    return pdf_bytes

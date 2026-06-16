"""
app/services/alerting_service.py
Sends alerts for high/critical findings via email, Slack, and MS Teams.
"""
import json
import logging
from datetime import datetime, timezone

import httpx

from app.core.config import settings
from app.models import Alert, AlertChannel, AlertStatus, Finding, Severity

logger = logging.getLogger(__name__)


def _get_sync_db():
    from app.db.session import SyncSessionFactory
    return SyncSessionFactory()


def _severity_emoji(severity: Severity) -> str:
    return {
        Severity.critical: "🔴",
        Severity.high: "🟠",
        Severity.medium: "🟡",
        Severity.low: "🟢",
    }.get(severity, "⚪")


def _build_slack_payload(finding: Finding) -> dict:
    emoji = _severity_emoji(finding.severity)
    return {
        "text": f"{emoji} DIMP Alert — {finding.severity.value.upper()} finding",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} Domain Impersonation Detected"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Suspicious domain:*\n`{finding.domain_entry.domain if finding.domain_entry else 'unknown'}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity.value.upper()}"},
                    {"type": "mrkdwn", "text": f"*Risk score:*\n{finding.risk_score}/100"},
                    {"type": "mrkdwn", "text": f"*Detection type:*\n{finding.detection_type.value}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{finding.summary or 'No summary available'}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommended action:*\n{finding.recommended_action or 'Review finding in dashboard'}"},
            },
        ],
    }


def _build_teams_payload(finding: Finding) -> dict:
    emoji = _severity_emoji(finding.severity)
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000" if finding.severity.value in ("critical", "high") else "FFA500",
        "summary": f"DIMP Alert — {finding.severity.value.upper()} finding",
        "sections": [
            {
                "activityTitle": f"{emoji} Domain Impersonation Detected",
                "activitySubtitle": f"Severity: {finding.severity.value.upper()} | Score: {finding.risk_score}/100",
                "facts": [
                    {"name": "Suspicious domain", "value": finding.domain_entry.domain if finding.domain_entry else "unknown"},
                    {"name": "Detection type", "value": finding.detection_type.value},
                    {"name": "Discovery source", "value": finding.discovery_source},
                    {"name": "Summary", "value": finding.summary or "N/A"},
                    {"name": "Recommended action", "value": finding.recommended_action or "Review in dashboard"},
                ],
            }
        ],
    }


def _send_slack(finding: Finding) -> None:
    if not settings.slack_webhook_url:
        return
    payload = _build_slack_payload(finding)
    resp = httpx.post(settings.slack_webhook_url, json=payload, timeout=10)
    resp.raise_for_status()


def _send_teams(finding: Finding) -> None:
    if not settings.teams_webhook_url:
        return
    payload = _build_teams_payload(finding)
    resp = httpx.post(settings.teams_webhook_url, json=payload, timeout=10)
    resp.raise_for_status()


def _send_siem(finding: Finding) -> None:
    if not settings.siem_webhook_url:
        return
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "domain_impersonation_finding",
        "finding_id": str(finding.id),
        "asset_id": str(finding.asset_id),
        "domain": finding.domain_entry.domain if finding.domain_entry else None,
        "severity": finding.severity.value,
        "risk_score": finding.risk_score,
        "detection_type": finding.detection_type.value,
        "discovery_source": finding.discovery_source,
        "summary": finding.summary,
    }
    resp = httpx.post(settings.siem_webhook_url, json=payload, timeout=10)
    resp.raise_for_status()


def send_finding_alert(finding: Finding) -> None:
    """
    Dispatch alerts for a finding across all configured channels.
    Records Alert objects with sent/failed status.
    """
    db = _get_sync_db()
    try:
        channels: list[tuple[AlertChannel, callable]] = []

        if settings.slack_webhook_url:
            channels.append((AlertChannel.slack, _send_slack))
        if settings.teams_webhook_url:
            channels.append((AlertChannel.teams, _send_teams))
        if settings.siem_webhook_url:
            channels.append((AlertChannel.siem, _send_siem))

        for channel, send_fn in channels:
            alert = Alert(
                finding_id=str(finding.id),
                channel=channel,
                status=AlertStatus.pending,
            )
            db.add(alert)
            db.flush()

            try:
                send_fn(finding)
                alert.status = AlertStatus.sent
                alert.sent_at = datetime.now(timezone.utc)
                logger.info("alert_sent", channel=channel.value, finding_id=str(finding.id))
            except Exception as e:
                alert.status = AlertStatus.failed
                alert.error_message = str(e)
                logger.warning("alert_failed", channel=channel.value, error=str(e))

        db.commit()
    finally:
        db.close()

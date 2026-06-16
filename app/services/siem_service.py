"""
app/services/siem_service.py
SIEM integration — forwards finding events as structured JSON
to a configurable webhook endpoint or syslog UDP socket.

Supports:
  - Generic JSON webhook (POST)
  - UDP syslog (RFC 5424 structured data)
  - Splunk HEC compatible payload
  - Microsoft Sentinel / Elastic / QRadar compatible fields
"""
import json
import logging
import socket
import struct
from datetime import datetime, timezone

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


# ── Payload builder ────────────────────────────────────────────────────────────

def _build_event(finding, event_type: str = "domain_impersonation_finding") -> dict:
    """Build a normalised SIEM event payload from a Finding object."""
    now = datetime.now(timezone.utc)
    domain = finding.domain_entry
    return {
        # Standard fields
        "timestamp": now.isoformat(),
        "event_type": event_type,
        "source": "DIMP",
        "source_version": "1.0.0",

        # Finding fields
        "finding_id": str(finding.id),
        "finding_status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "risk_score": finding.risk_score,
        "detection_type": finding.detection_type.value if hasattr(finding.detection_type, "value") else str(finding.detection_type),
        "discovery_source": finding.discovery_source,
        "summary": finding.summary,
        "recommended_action": finding.recommended_action,

        # Asset
        "asset_id": str(finding.asset_id),
        "monitored_domain": finding.asset.domain if finding.asset else None,

        # Suspicious domain
        "suspicious_domain": domain.domain if domain else None,
        "ip_address": domain.ip_address if domain else None,
        "asn": domain.asn if domain else None,
        "hosting_provider": domain.hosting_provider if domain else None,
        "country_code": domain.country_code if domain else None,
        "is_active_website": domain.is_active_website if domain else None,
        "http_status": domain.http_status_code if domain else None,

        # Timestamps
        "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
        "last_updated_at": finding.last_updated_at.isoformat() if finding.last_updated_at else None,
    }


# ── Webhook ────────────────────────────────────────────────────────────────────

def send_webhook(event: dict, url: str | None = None) -> bool:
    """POST event JSON to the configured SIEM webhook URL."""
    target = url or settings.siem_webhook_url
    if not target:
        return False
    try:
        resp = httpx.post(
            target,
            json=event,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("siem_webhook_sent", url=target, event_type=event.get("event_type"))
        return True
    except Exception as e:
        logger.warning("siem_webhook_failed", url=target, error=str(e))
        return False


# ── Splunk HEC ─────────────────────────────────────────────────────────────────

def send_splunk_hec(event: dict, hec_url: str, hec_token: str) -> bool:
    """Send event to Splunk HTTP Event Collector."""
    payload = {
        "time": datetime.now(timezone.utc).timestamp(),
        "sourcetype": "dimp:finding",
        "source": "dimp",
        "event": event,
    }
    try:
        resp = httpx.post(
            hec_url,
            json=payload,
            headers={"Authorization": f"Splunk {hec_token}"},
            timeout=10,
            verify=False,
        )
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.warning("splunk_hec_failed", error=str(e))
        return False


# ── UDP syslog ─────────────────────────────────────────────────────────────────

def send_syslog_udp(event: dict, host: str = "127.0.0.1", port: int = 514) -> bool:
    """
    Send event as RFC 5424 syslog message over UDP.
    Facility 1 (user) + Severity 4 (warning) = priority 12.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        msg_body = json.dumps(event)
        # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        syslog_msg = (
            f"<13>1 {now} dimp dimp - - - "
            f"[DIMP@0 severity=\"{event.get('severity')}\" "
            f"domain=\"{event.get('suspicious_domain')}\" "
            f"score=\"{event.get('risk_score')}\"] "
            f"{msg_body}"
        ).encode("utf-8")[:65507]  # UDP max payload

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(syslog_msg, (host, port))
        return True
    except Exception as e:
        logger.warning("syslog_udp_failed", host=host, port=port, error=str(e))
        return False


# ── Public API ─────────────────────────────────────────────────────────────────

def forward_finding_to_siem(finding) -> None:
    """
    Forward a finding event to all configured SIEM outputs.
    Called from the alerting service for high/critical findings.
    """
    event = _build_event(finding)

    if settings.siem_webhook_url:
        send_webhook(event)

    # Splunk HEC — configure via env (not in base settings, extend if needed)
    # send_splunk_hec(event, hec_url="https://splunk:8088/services/collector", hec_token="...")

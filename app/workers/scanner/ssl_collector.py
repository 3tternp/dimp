"""
app/workers/scanner/ssl_collector.py
Extracts SSL/TLS certificate details for a domain using Python's ssl module.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def collect_ssl(domain: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Connect to domain:443 and extract certificate metadata.
    Returns an empty dict if connection fails or domain has no HTTPS.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("SSL collection failed for %s: %s", domain, e)
        return {}

    # Parse subject / issuer
    def _field(rdns, key):
        for rdn in rdns:
            for k, v in rdn:
                if k == key:
                    return v
        return None

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    # SANs
    san_list = [
        v for k, v in cert.get("subjectAltName", ())
        if k == "DNS"
    ]

    # Validity dates
    def _parse_date(s: str | None) -> datetime | None:
        if not s:
            return None
        import email.utils
        try:
            return datetime(*email.utils.parsedate(s)[:6], tzinfo=timezone.utc)
        except Exception:
            return None

    not_before = _parse_date(cert.get("notBefore"))
    not_after = _parse_date(cert.get("notAfter"))
    now = datetime.now(timezone.utc)

    issuer_cn = _field(issuer, "commonName")
    issuer_org = _field(issuer, "organizationName")
    subject_cn = _field(subject, "commonName")

    return {
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "subject_cn": subject_cn,
        "subject_alt_names": san_list,
        "serial_number": str(cert.get("serialNumber", "")),
        "not_before": not_before,
        "not_after": not_after,
        "is_expired": not_after < now if not_after else None,
        "is_self_signed": issuer_cn == subject_cn,
        "tls_version": tls_version,
    }

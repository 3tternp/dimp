"""
app/workers/scanner/dns_collector.py
Collects DNS records (A, AAAA, MX, NS, TXT, CNAME) for a domain.
"""
import logging
from datetime import datetime, timezone

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def collect_dns(domain: str) -> dict:
    """
    Query DNS for all common record types.
    Returns a dict: {record_type: [(value, ttl, priority), ...]}
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8
    results: dict[str, list[dict]] = {}
    resolves = False

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                record = {
                    "value": rdata.to_text().rstrip("."),
                    "ttl": answers.ttl,
                    "priority": getattr(rdata, "preference", None),  # MX priority
                }
                records.append(record)
            results[rtype] = records
            if rtype == "A":
                resolves = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.DNSException as e:
            logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)

    return {"resolves": resolves, "records": results}

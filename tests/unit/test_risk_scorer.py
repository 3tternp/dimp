"""
tests/unit/test_risk_scorer.py
Unit tests for the risk scoring engine.
"""
import pytest
from unittest.mock import MagicMock, patch

from app.models import DetectionType, DiscoveredDomain, Severity
from app.workers.scanner.risk_scorer import compute_risk_score, build_summary


def _make_domain(
    domain="login-examplebank.com",
    detection_type=DetectionType.extra_word,
    has_login_form=False,
    has_credential_fields=False,
    external_form_action=False,
    resolves_dns=True,
    is_active_website=True,
    country_code="US",
    asn=None,
) -> DiscoveredDomain:
    """Factory for a minimal DiscoveredDomain mock."""
    d = MagicMock(spec=DiscoveredDomain)
    d.domain = domain
    d.detection_type = detection_type
    d.dns_records = []
    d.whois_record = None
    d.ssl_certificate = None
    d.snapshots = []
    d.similarity_results = []
    d.threat_intel_matches = []
    d.resolves_dns = resolves_dns
    d.is_active_website = is_active_website
    d.country_code = country_code
    d.asn = asn

    if has_login_form or has_credential_fields or external_form_action:
        snap = MagicMock()
        snap.has_login_form = has_login_form
        snap.has_credential_fields = has_credential_fields
        snap.external_form_action = external_form_action
        d.snapshots = [snap]

    return d


class TestComputeRiskScore:
    def test_low_severity_clean_domain(self):
        domain = _make_domain(domain="examplebank-typo.com", detection_type=DetectionType.typosquatting)
        score, severity = compute_risk_score(domain)
        assert 0 <= score <= 100
        assert severity == Severity.low or severity == Severity.medium

    def test_login_form_increases_score(self):
        without = _make_domain()
        with_login = _make_domain(has_login_form=True, has_credential_fields=True)

        score_without, _ = compute_risk_score(without)
        score_with, _ = compute_risk_score(with_login)
        assert score_with > score_without

    def test_external_form_action_adds_points(self):
        without = _make_domain()
        with_ext = _make_domain(external_form_action=True)

        score_without, _ = compute_risk_score(without)
        score_with, _ = compute_risk_score(with_ext)
        assert score_with > score_without

    def test_suspicious_keyword_in_domain(self):
        normal = _make_domain(domain="examplebank123.com")
        suspicious = _make_domain(domain="login-examplebank-verify.com")

        score_normal, _ = compute_risk_score(normal)
        score_sus, _ = compute_risk_score(suspicious)
        assert score_sus >= score_normal

    def test_severity_mapping(self):
        cases = [
            (5, Severity.low),
            (30, Severity.low),
            (31, Severity.medium),
            (60, Severity.medium),
            (61, Severity.high),
            (80, Severity.high),
            (81, Severity.critical),
            (100, Severity.critical),
        ]
        # Patch _similarity_pts to return a fixed value
        for expected_score, expected_severity in cases:
            with patch("app.workers.scanner.risk_scorer._similarity_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._keyword_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._age_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._visual_sim_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._html_sim_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._favicon_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._login_form_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._external_form_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._mx_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._website_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._threat_intel_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._hosting_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._ssl_reduction", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._suspicious_tld_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._country_mismatch_pts", return_value=0), \
                 patch("app.workers.scanner.risk_scorer._recent_cert_pts", return_value=expected_score):

                domain = _make_domain()
                score, severity = compute_risk_score(domain)
                assert severity == expected_severity, f"Score {score} should map to {expected_severity}"

    def test_score_clamped_to_100(self):
        """Score should never exceed 100 regardless of factor accumulation."""
        domain = _make_domain(
            domain="login-verify-account-bank.xyz",
            detection_type=DetectionType.phishing_feed,
            has_login_form=True,
            has_credential_fields=True,
            external_form_action=True,
            country_code="KP",
        )
        # Add TI hits
        ti = MagicMock()
        ti.feed_name = "openphish"
        domain.threat_intel_matches = [ti, ti, ti]

        score, _ = compute_risk_score(domain)
        assert score <= 100


class TestDiscoveryEngine:
    def test_generate_variants_returns_list(self):
        from app.workers.scanner.discovery import generate_variants
        variants = generate_variants("examplebank.com")
        assert isinstance(variants, list)
        assert len(variants) > 0

    def test_original_domain_excluded(self):
        from app.workers.scanner.discovery import generate_variants
        domain = "examplebank.com"
        variants = generate_variants(domain)
        assert domain not in variants

    def test_tld_variants_included(self):
        from app.workers.scanner.discovery import generate_variants
        variants = generate_variants("examplebank.com")
        # Should include at least some TLD variants
        tld_variants = [v for v in variants if v.startswith("examplebank.")]
        assert len(tld_variants) > 3

    def test_extra_word_variants(self):
        from app.workers.scanner.discovery import generate_variants
        variants = generate_variants("examplebank.com")
        login_variants = [v for v in variants if "login" in v]
        assert len(login_variants) > 0

    def test_homoglyph_variants_generated(self):
        from app.workers.scanner.discovery import _homoglyph_variants
        variants = _homoglyph_variants("example", "com")
        assert len(variants) > 0

    def test_invalid_domain_returns_empty(self):
        from app.workers.scanner.discovery import generate_variants
        assert generate_variants("") == []
        assert generate_variants("notadomain") == []

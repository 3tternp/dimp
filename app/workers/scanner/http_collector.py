"""
app/workers/scanner/http_collector.py
Collects HTTP metadata: status code, redirect chain, page title,
meta description, favicon URL, login/credential form detection,
external script URLs, and form action URLs.
"""
import hashlib
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.core.config import settings

logger = logging.getLogger(__name__)

# Headers that mimic a realistic browser request
REQUEST_HEADERS = {
    "User-Agent": settings.http_user_agent,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

CREDENTIAL_INPUT_TYPES = {"password", "email", "tel"}
CREDENTIAL_INPUT_NAMES = {
    "username", "user", "email", "login", "password", "passwd",
    "pass", "credential", "otp", "mfa", "token",
}

SUSPICIOUS_KEYWORDS_IN_PAGE = {
    "login", "sign in", "sign-in", "password", "username", "verify",
    "confirm", "account", "secure", "bank", "wallet", "auth",
}


def _extract_favicon_url(soup: BeautifulSoup, base_url: str) -> str | None:
    """Extract the favicon URL from <link rel="icon"> tags."""
    for rel in ["icon", "shortcut icon", "apple-touch-icon"]:
        tag = soup.find("link", rel=lambda r: r and rel in r.lower() if r else False)
        if tag and tag.get("href"):
            return urljoin(base_url, tag["href"])
    return urljoin(base_url, "/favicon.ico")


def _detect_login_forms(soup: BeautifulSoup) -> tuple[bool, bool]:
    """
    Returns (has_login_form, has_credential_fields).
    Detects forms containing password or credential-related inputs.
    """
    has_login_form = False
    has_credential_fields = False

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        for inp in inputs:
            input_type = (inp.get("type") or "").lower()
            input_name = (inp.get("name") or inp.get("id") or "").lower()

            if input_type == "password":
                has_login_form = True
                has_credential_fields = True
                break

            if input_type in CREDENTIAL_INPUT_TYPES or any(kw in input_name for kw in CREDENTIAL_INPUT_NAMES):
                has_credential_fields = True

    return has_login_form, has_credential_fields


def _detect_external_form_action(soup: BeautifulSoup, domain: str) -> bool:
    """True if any form's action URL posts to a domain different from the page's domain."""
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if not action or action.startswith("#") or action.startswith("javascript"):
            continue
        if action.startswith("http"):
            action_host = urlparse(action).netloc.lstrip("www.")
            page_host = domain.lstrip("www.")
            if action_host and action_host != page_host:
                return True
    return False


def _extract_external_scripts(soup: BeautifulSoup, domain: str) -> list[str]:
    """Collect external <script src="..."> URLs hosted on domains other than the page."""
    scripts = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            host = urlparse(src).netloc.lstrip("www.")
            if host and host != domain.lstrip("www."):
                scripts.append(src)
    return list(set(scripts))[:50]  # cap at 50 unique


def _detect_brand_keywords(soup: BeautifulSoup, keywords: list[str]) -> list[str]:
    """Find brand/protected keywords anywhere in visible page text and title."""
    text = (soup.get_text(separator=" ") or "").lower()
    title = (soup.title.string if soup.title else "").lower()
    combined = text + " " + title
    return [kw for kw in keywords if kw.lower() in combined]


def collect_http_metadata(domain: str, brand_keywords: list[str] | None = None) -> dict:
    """
    Perform an HTTP GET on the domain, follow redirects, and extract page metadata.
    Returns a dict with all collected fields.
    """
    url = f"https://{domain}"
    redirect_chain: list[str] = []
    result: dict = {
        "is_active_website": False,
        "http_status_code": None,
        "redirect_chain": [],
        "page_title": None,
        "meta_description": None,
        "favicon_url": None,
        "favicon_hash": None,
        "html_hash": None,
        "has_login_form": False,
        "has_credential_fields": False,
        "external_form_action": False,
        "external_scripts": [],
        "form_action_urls": [],
        "brand_keywords_found": [],
    }

    try:
        with httpx.Client(
            timeout=settings.http_timeout,
            follow_redirects=True,
            headers=REQUEST_HEADERS,
            verify=False,  # we want to probe even invalid certs
        ) as client:
            response = client.get(url)
            redirect_chain = [str(r.url) for r in response.history] + [str(response.url)]
            result["http_status_code"] = response.status_code
            result["redirect_chain"] = redirect_chain
            result["is_active_website"] = response.status_code < 500

            html = response.text
            result["html_hash"] = hashlib.sha256(html.encode()).hexdigest()

            soup = BeautifulSoup(html, "lxml")

            # Page title
            if soup.title and soup.title.string:
                result["page_title"] = soup.title.string.strip()[:512]

            # Meta description
            meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
            if meta and meta.get("content"):
                result["meta_description"] = meta["content"][:512]

            # Favicon
            result["favicon_url"] = _extract_favicon_url(soup, str(response.url))

            # Login / credential form detection
            has_login, has_creds = _detect_login_forms(soup)
            result["has_login_form"] = has_login
            result["has_credential_fields"] = has_creds

            # External form action detection
            result["external_form_action"] = _detect_external_form_action(soup, domain)

            # Form action URLs
            result["form_action_urls"] = [
                f.get("action", "") for f in soup.find_all("form") if f.get("action")
            ][:20]

            # External scripts
            result["external_scripts"] = _extract_external_scripts(soup, domain)

            # Brand keyword matching
            if brand_keywords:
                result["brand_keywords_found"] = _detect_brand_keywords(soup, brand_keywords)

    except httpx.ConnectError:
        # Try HTTP fallback
        try:
            with httpx.Client(timeout=settings.http_timeout, follow_redirects=True, headers=REQUEST_HEADERS) as client:
                response = client.get(f"http://{domain}")
                result["http_status_code"] = response.status_code
                result["is_active_website"] = response.status_code < 500
        except Exception:
            pass
    except Exception as e:
        logger.debug("HTTP metadata collection failed for %s: %s", domain, e)

    return result

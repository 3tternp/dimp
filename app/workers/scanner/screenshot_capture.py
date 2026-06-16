"""
app/workers/scanner/screenshot_capture.py
Captures full-page screenshots using Playwright (Chromium headless).

Playwright must be installed in the worker container:
  pip install playwright && playwright install chromium --with-deps

Docker note: add --no-sandbox, --disable-dev-shm-usage args for container use.
"""
import hashlib
import logging
import os
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)


async def capture_screenshot_async(domain: str, screenshot_dir: str | None = None) -> dict:
    """
    Capture a full-page screenshot of the domain using Playwright async API.
    Returns a dict with screenshot_path and metadata.
    """
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.warning("Playwright not installed — screenshot capture skipped")
        return {}

    out_dir = Path(screenshot_dir or settings.screenshot_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    url = f"https://{domain}"
    filename = f"{domain.replace('/', '_').replace(':', '_')}.png"
    filepath = out_dir / filename

    result: dict = {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",
                "--ignore-certificate-errors",
            ],
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=settings.http_user_agent,
            ignore_https_errors=True,
        )
        page = await context.new_page()

        try:
            await page.goto(url, timeout=20_000, wait_until="domcontentloaded")
            await page.wait_for_timeout(1500)  # let JS render
            await page.screenshot(path=str(filepath), full_page=False, type="png")
            result["screenshot_path"] = str(filepath)
            logger.info("screenshot_captured", domain=domain, path=str(filepath))
        except PWTimeout:
            logger.warning("screenshot_timeout", domain=domain)
        except Exception as e:
            logger.warning("screenshot_failed", domain=domain, error=str(e))
            # Try HTTP fallback
            try:
                await page.goto(f"http://{domain}", timeout=15_000, wait_until="domcontentloaded")
                await page.screenshot(path=str(filepath), full_page=False, type="png")
                result["screenshot_path"] = str(filepath)
            except Exception:
                pass
        finally:
            await page.close()
            await context.close()
            await browser.close()

    return result


def capture_screenshot_sync(domain: str, screenshot_dir: str | None = None) -> dict:
    """
    Synchronous wrapper for use inside Celery tasks.
    Uses Playwright sync API.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.warning("Playwright not installed — screenshot capture skipped")
        return {}

    out_dir = Path(screenshot_dir or settings.screenshot_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{domain.replace('/', '_').replace(':', '_').replace('*', '_')}.png"
    filepath = out_dir / filename
    result: dict = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--ignore-certificate-errors",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=settings.http_user_agent,
            ignore_https_errors=True,
        )
        page = context.new_page()

        for url in [f"https://{domain}", f"http://{domain}"]:
            try:
                page.goto(url, timeout=18_000, wait_until="domcontentloaded")
                page.wait_for_timeout(1200)
                page.screenshot(path=str(filepath), full_page=False, type="png")
                result["screenshot_path"] = str(filepath)
                break
            except (PWTimeout, Exception) as e:
                logger.debug("screenshot_attempt_failed", url=url, error=str(e))

        page.close()
        context.close()
        browser.close()

    return result


def hash_favicon(favicon_path: str) -> str | None:
    """Compute pHash of a favicon image for comparison."""
    try:
        import imagehash
        from PIL import Image
        img = Image.open(favicon_path).convert("RGB").resize((32, 32))
        return str(imagehash.phash(img))
    except Exception as e:
        logger.debug("favicon_hash_failed", path=favicon_path, error=str(e))
        return None


def download_favicon(favicon_url: str, out_dir: str) -> str | None:
    """Download a favicon image to disk, return file path."""
    import httpx
    try:
        resp = httpx.get(favicon_url, timeout=8, follow_redirects=True, verify=False)
        resp.raise_for_status()
        ext = "ico"
        ct = resp.headers.get("content-type", "")
        if "png" in ct:
            ext = "png"
        elif "jpg" in ct or "jpeg" in ct:
            ext = "jpg"
        name = hashlib.sha256(favicon_url.encode()).hexdigest()[:16] + f".{ext}"
        path = Path(out_dir) / name
        path.write_bytes(resp.content)
        return str(path)
    except Exception as e:
        logger.debug("favicon_download_failed", url=favicon_url, error=str(e))
        return None

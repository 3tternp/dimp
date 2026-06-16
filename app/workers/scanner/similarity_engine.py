"""
app/workers/scanner/similarity_engine.py
Computes multi-signal similarity between a suspicious domain's webpage
and the legitimate protected domain's reference page.

Signals:
  1. Visual (pHash / aHash / dHash) — screenshot pixel-level similarity
  2. Content (TF-IDF cosine) — page text similarity
  3. DOM structure (tag frequency vector cosine) — layout similarity
  4. Favicon hash match — exact favicon comparison
  5. Combined weighted score (0.0–1.0)

Weights:
  visual   40%
  tfidf    25%
  dom      20%
  favicon  15%  (binary — match = 1.0, no match = 0.0)
"""
from __future__ import annotations

import logging
import math
from collections import Counter
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    pass

# ── Weights for the combined score ────────────────────────────────────────────
W_VISUAL  = 0.40
W_TFIDF   = 0.25
W_DOM     = 0.20
W_FAVICON = 0.15


# ── Visual similarity ─────────────────────────────────────────────────────────

def _phash_similarity(path_a: str, path_b: str) -> float | None:
    """
    Compute perceptual hash similarity between two screenshot images.
    Returns 0.0 (totally different) to 1.0 (identical).
    """
    try:
        import imagehash
        from PIL import Image

        img_a = Image.open(path_a).convert("RGB").resize((256, 256))
        img_b = Image.open(path_b).convert("RGB").resize((256, 256))

        ph_a = imagehash.phash(img_a)
        ph_b = imagehash.phash(img_b)
        distance = ph_a - ph_b          # Hamming distance 0–64
        score = 1.0 - (distance / 64.0)

        ah_a = imagehash.average_hash(img_a)
        ah_b = imagehash.average_hash(img_b)
        ah_dist = ah_a - ah_b
        ah_score = 1.0 - (ah_dist / 64.0)

        dh_a = imagehash.dhash(img_a)
        dh_b = imagehash.dhash(img_b)
        dh_dist = dh_a - dh_b
        dh_score = 1.0 - (dh_dist / 64.0)

        # Weighted combination: pHash most discriminative
        combined = (score * 0.5) + (ah_score * 0.25) + (dh_score * 0.25)
        return round(max(0.0, min(1.0, combined)), 4)
    except Exception as e:
        logger.debug("phash_similarity_failed: %s", e)
        return None


# ── Text / TF-IDF similarity ──────────────────────────────────────────────────

def _extract_visible_text(html: str) -> str:
    """Extract visible text from HTML, stripping tags and scripts."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        # Remove script / style / meta content
        for tag in soup(["script", "style", "meta", "link", "noscript"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)[:50_000]
    except Exception:
        return ""


def _tfidf_cosine(text_a: str, text_b: str) -> float:
    """Compute TF-IDF cosine similarity between two text strings."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np

        if not text_a.strip() or not text_b.strip():
            return 0.0

        vec = TfidfVectorizer(max_features=2000, stop_words="english", sublinear_tf=True)
        matrix = vec.fit_transform([text_a, text_b])
        score = cosine_similarity(matrix[0], matrix[1])[0][0]
        return round(float(score), 4)
    except Exception as e:
        logger.debug("tfidf_failed: %s", e)
        return 0.0


# ── DOM structure similarity ──────────────────────────────────────────────────

def _dom_tag_vector(html: str) -> dict[str, int]:
    """Build a frequency vector of HTML tag names from the document."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        return dict(Counter(tag.name for tag in soup.find_all()))
    except Exception:
        return {}


def _cosine(vec_a: dict, vec_b: dict) -> float:
    """Cosine similarity between two frequency dicts."""
    keys = set(vec_a) | set(vec_b)
    if not keys:
        return 0.0
    dot = sum(vec_a.get(k, 0) * vec_b.get(k, 0) for k in keys)
    mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
    mag_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if not mag_a or not mag_b:
        return 0.0
    return round(dot / (mag_a * mag_b), 4)


def _dom_similarity(html_a: str, html_b: str) -> float:
    vec_a = _dom_tag_vector(html_a)
    vec_b = _dom_tag_vector(html_b)
    return _cosine(vec_a, vec_b)


# ── Favicon similarity ─────────────────────────────────────────────────────────

def _favicon_match(hash_a: str | None, hash_b: str | None) -> bool | None:
    """Compare two favicon pHash strings. Threshold: ≤ 8 Hamming distance."""
    if not hash_a or not hash_b:
        return None
    try:
        import imagehash
        h_a = imagehash.hex_to_hash(hash_a)
        h_b = imagehash.hex_to_hash(hash_b)
        return (h_a - h_b) <= 8
    except Exception:
        return None


# ── Combined similarity ────────────────────────────────────────────────────────

def compute_similarity(
    *,
    reference_screenshot: str | None,
    suspicious_screenshot: str | None,
    reference_html: str | None = None,
    suspicious_html: str | None = None,
    reference_favicon_hash: str | None = None,
    suspicious_favicon_hash: str | None = None,
) -> dict:
    """
    Compute all similarity signals between a suspicious domain and the reference.

    Args:
        reference_screenshot: path to the legitimate domain's screenshot
        suspicious_screenshot: path to the suspicious domain's screenshot
        reference_html: HTML source of the legitimate domain (optional)
        suspicious_html: HTML source of the suspicious domain (optional)
        reference_favicon_hash: pHash hex of legitimate favicon (optional)
        suspicious_favicon_hash: pHash hex of suspicious favicon (optional)

    Returns:
        dict with individual scores and overall_similarity_score (0.0–1.0)
    """
    result: dict = {
        "phash_score": None,
        "ahash_score": None,
        "dhash_score": None,
        "visual_similarity_score": None,
        "tfidf_score": None,
        "dom_similarity_score": None,
        "favicon_hash_match": None,
        "overall_similarity_score": None,
    }

    # ── Visual ────────────────────────────────────────────────────────────────
    if reference_screenshot and suspicious_screenshot:
        import os
        if os.path.exists(reference_screenshot) and os.path.exists(suspicious_screenshot):
            result["visual_similarity_score"] = _phash_similarity(reference_screenshot, suspicious_screenshot)

    # ── Text (TF-IDF) ─────────────────────────────────────────────────────────
    if reference_html and suspicious_html:
        text_ref = _extract_visible_text(reference_html)
        text_sus = _extract_visible_text(suspicious_html)
        result["tfidf_score"] = _tfidf_cosine(text_ref, text_sus)
        result["dom_similarity_score"] = _dom_similarity(reference_html, suspicious_html)

    # ── Favicon ───────────────────────────────────────────────────────────────
    result["favicon_hash_match"] = _favicon_match(reference_favicon_hash, suspicious_favicon_hash)

    # ── Combined weighted score ───────────────────────────────────────────────
    parts: list[tuple[float, float]] = []  # (score, weight)

    if result["visual_similarity_score"] is not None:
        parts.append((result["visual_similarity_score"], W_VISUAL))
    if result["tfidf_score"] is not None:
        parts.append((result["tfidf_score"], W_TFIDF))
    if result["dom_similarity_score"] is not None:
        parts.append((result["dom_similarity_score"], W_DOM))
    if result["favicon_hash_match"] is not None:
        parts.append((1.0 if result["favicon_hash_match"] else 0.0, W_FAVICON))

    if parts:
        total_weight = sum(w for _, w in parts)
        weighted_sum = sum(s * w for s, w in parts)
        result["overall_similarity_score"] = round(weighted_sum / total_weight, 4)

    logger.info(
        "similarity_computed",
        visual=result["visual_similarity_score"],
        tfidf=result["tfidf_score"],
        dom=result["dom_similarity_score"],
        favicon_match=result["favicon_hash_match"],
        overall=result["overall_similarity_score"],
    )

    return result

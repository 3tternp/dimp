"""
app/workers/scanner/discovery.py
Domain discovery engine.

Generates candidate suspicious domains using:
  1. Typosquatting variants (addition, deletion, transposition, replacement, repetition)
  2. Homoglyph / punycode variants
  3. Common TLD swaps
  4. Extra-word prefix/suffix patterns
  5. Certificate Transparency log queries (crt.sh)
"""
import itertools
import logging
import time
from urllib.parse import quote

import httpx
import tldextract

logger = logging.getLogger(__name__)

# ── Homoglyph mapping (Latin lookalikes for common characters) ────────────────
HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["а", "ą", "à", "á", "â", "ã", "ä", "å"],   # Cyrillic а, Latin accents
    "e": ["е", "ę", "è", "é", "ê", "ë"],
    "i": ["і", "ì", "í", "î", "ï", "1", "l"],
    "o": ["о", "ò", "ó", "ô", "õ", "ö", "0"],
    "u": ["ü", "ù", "ú", "û"],
    "c": ["с", "ç"],
    "n": ["ñ"],
    "p": ["р"],                                         # Cyrillic р
    "x": ["х"],                                         # Cyrillic х
    "s": ["ѕ"],
    "l": ["1", "i", "ι"],
    "0": ["o", "о"],
    "rn": ["m"],
    "vv": ["w"],
    "w": ["vv"],
}

# ── Suspicious keyword patterns for extra-word generation ─────────────────────
EXTRA_WORDS = [
    "login", "secure", "verify", "account", "support", "update",
    "wallet", "bank", "mfa", "auth", "signin", "pay", "help",
    "service", "online", "portal", "official", "access", "customer",
]

# ── TLD variants to check ─────────────────────────────────────────────────────
COMMON_TLDS = [
    "com", "net", "org", "co", "io", "xyz", "info", "biz",
    "online", "site", "app", "cloud", "digital", "tech",
    "bank", "finance", "money", "pay",
    "com.np", "org.np", "net.np",       # Nepal-specific
    "co.uk", "com.au", "co.in",
]

# ── Keyboard adjacency map for substitution variants ─────────────────────────
QWERTY_ADJACENT: dict[str, str] = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "ersfxc", "e": "rdsw",
    "f": "rtgdcv", "g": "tyhfvb", "h": "yugjbn", "i": "uojk", "j": "uihknm",
    "k": "iojlm", "l": "opk", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "etdf", "s": "awedxz", "t": "ryfge",
    "u": "yihjk", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tugh",
    "z": "asx",
}


def _domain_parts(domain: str) -> tuple[str, str, str]:
    """Return (subdomain, domain_name, suffix) e.g. ('', 'examplebank', 'com')."""
    ext = tldextract.extract(domain)
    return ext.subdomain, ext.domain, ext.suffix


def _rebuild(name: str, suffix: str) -> str:
    return f"{name}.{suffix}"


# ── Variant generators ─────────────────────────────────────────────────────────

def _addition_variants(name: str, suffix: str) -> list[str]:
    """Insert a single character between each character pair."""
    variants = []
    charset = "abcdefghijklmnopqrstuvwxyz0123456789-"
    for i in range(len(name) + 1):
        for ch in charset:
            candidate = name[:i] + ch + name[i:]
            if candidate != name:
                variants.append(_rebuild(candidate, suffix))
    return variants


def _deletion_variants(name: str, suffix: str) -> list[str]:
    """Remove one character at a time."""
    return [
        _rebuild(name[:i] + name[i + 1:], suffix)
        for i in range(len(name))
        if len(name) > 3  # don't create very short names
    ]


def _transposition_variants(name: str, suffix: str) -> list[str]:
    """Swap adjacent characters."""
    variants = []
    for i in range(len(name) - 1):
        t = list(name)
        t[i], t[i + 1] = t[i + 1], t[i]
        variants.append(_rebuild("".join(t), suffix))
    return variants


def _substitution_variants(name: str, suffix: str) -> list[str]:
    """Replace each character with adjacent keys on QWERTY keyboard."""
    variants = []
    for i, ch in enumerate(name):
        for replacement in QWERTY_ADJACENT.get(ch.lower(), ""):
            candidate = name[:i] + replacement + name[i + 1:]
            variants.append(_rebuild(candidate, suffix))
    return variants


def _repetition_variants(name: str, suffix: str) -> list[str]:
    """Double each character in turn."""
    return [
        _rebuild(name[:i] + ch + name[i:], suffix)
        for i, ch in enumerate(name)
    ]


def _tld_variants(name: str, original_suffix: str) -> list[str]:
    """Try common alternative TLDs."""
    return [
        _rebuild(name, tld)
        for tld in COMMON_TLDS
        if tld != original_suffix
    ]


def _extra_word_variants(name: str, suffix: str) -> list[str]:
    """Prepend and append suspicious keywords with hyphens."""
    variants = []
    for word in EXTRA_WORDS:
        variants.append(_rebuild(f"{name}-{word}", suffix))
        variants.append(_rebuild(f"{word}-{name}", suffix))
    return variants


def _homoglyph_variants(name: str, suffix: str) -> list[str]:
    """Replace characters with visually similar Unicode lookalikes."""
    variants = []
    for i, ch in enumerate(name):
        for glyph in HOMOGLYPHS.get(ch.lower(), []):
            candidate = name[:i] + glyph + name[i + 1:]
            try:
                # encode as punycode to check it's valid
                encoded = candidate.encode("idna").decode("ascii")
                variants.append(_rebuild(encoded, suffix))
            except (UnicodeError, UnicodeDecodeError):
                pass
    # Multi-char substitutions (rn→m, vv→w)
    for seq, replacement in [("rn", "m"), ("vv", "w"), ("w", "vv")]:
        if seq in name:
            variants.append(_rebuild(name.replace(seq, replacement), suffix))
    return variants


def generate_variants(domain: str, max_total: int = 5000) -> list[str]:
    """
    Generate all typosquatting / lookalike variants for a protected domain.
    Returns a deduplicated list of candidate domain strings.
    """
    _, name, suffix = _domain_parts(domain)
    if not name or not suffix:
        logger.warning("generate_variants: could not parse domain '%s'", domain)
        return []

    candidates: set[str] = set()

    generators = [
        _transposition_variants,
        _deletion_variants,
        _substitution_variants,
        _repetition_variants,
        _extra_word_variants,
        _homoglyph_variants,
    ]

    for gen in generators:
        try:
            candidates.update(gen(name, suffix))
        except Exception as e:
            logger.warning("variant generator %s failed: %s", gen.__name__, e)

    # TLD variants always included (small set)
    candidates.update(_tld_variants(name, suffix))

    # Addition variants can be huge — limit to first 2000
    additions = _addition_variants(name, suffix)
    candidates.update(additions[:2000])

    # Remove the original domain from candidates
    candidates.discard(domain)
    candidates.discard(f"www.{domain}")

    result = list(candidates)[:max_total]
    logger.info("generate_variants: %d candidates for %s", len(result), domain)
    return result


# ── Certificate Transparency log query ─────────────────────────────────────────

def query_ct_logs(domain: str, timeout: int = 15) -> list[str]:
    """
    Query crt.sh for certificates issued for subdomains/domains containing
    the brand name. Returns a list of unique domain names found.
    """
    _, name, _ = _domain_parts(domain)
    results: list[str] = []

    # Query crt.sh JSON API
    url = f"https://crt.sh/?q=%25{quote(name)}%25&output=json"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            entries = response.json()

        seen: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            # name_value may contain multiple SANs separated by newlines
            for raw in name_value.split("\n"):
                raw = raw.strip().lstrip("*.")
                if raw and "." in raw and raw not in seen:
                    seen.add(raw)
                    results.append(raw)

        logger.info("ct_log_query: %d results for %s", len(results), domain)
    except Exception as e:
        logger.warning("ct_log_query failed for %s: %s", domain, e)

    # Rate-limit courtesy pause
    time.sleep(0.5)
    return results

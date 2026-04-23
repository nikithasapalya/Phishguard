"""
feature_extractor.py
Extracts 21 lexical and host-based features from a URL.
Used by both train_model.py and api/app.py — keep the order stable.
"""

import re
import socket
import urllib.parse
from datetime import datetime
from functools import lru_cache
from typing import Dict

# Common brands attackers spoof
SUSPICIOUS_BRANDS = [
    "paypal", "amazon", "google", "facebook", "apple",
    "netflix", "microsoft", "instagram", "linkedin", "twitter",
    "bank", "secure", "login", "verify", "account", "update",
]

# URL shortener domains
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "buff.ly", "shorte.st", "rb.gy", "is.gd",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking", "signin",
]


# ── Public API ────────────────────────────────────────────────────────────────

def extract_features(url: str, is_training: bool = False) -> Dict[str, float]:
    """Extracts 21 numerical features from a URL. Order MUST stay stable."""
    parsed = _safe_parse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    features: Dict[str, float] = {}

    # 1. Length features
    features["url_length"]    = float(len(url))
    features["domain_length"] = float(len(domain))
    features["path_length"]   = float(len(path))

    # 2. Character counts
    features["num_dots"]           = float(url.count("."))
    features["num_hyphens"]        = float(url.count("-"))
    features["num_underscores"]    = float(url.count("_"))
    features["num_slashes"]        = float(url.count("/"))
    features["num_at_symbols"]     = float(url.count("@"))
    features["num_question_marks"] = float(url.count("?"))
    features["num_equals"]         = float(url.count("="))
    features["num_ampersands"]     = float(url.count("&"))
    features["num_percent"]        = float(url.count("%"))
    features["num_digits"]         = float(sum(c.isdigit() for c in url))

    # 3. Structural flags
    features["has_ip_address"]  = float(_has_ip_address(domain))
    features["uses_https"]      = float(parsed.scheme == "https")
    features["has_port"]        = float(bool(parsed.port))
    features["subdomain_depth"] = float(_subdomain_depth(domain))
    features["is_url_shortener"] = float(_is_shortener(domain))

    # 4. Content features
    features["brand_in_subdomain"]  = float(_brand_in_subdomain(domain))
    features["suspicious_keywords"] = float(_count_suspicious_keywords(full_url))

    # 5. Host-based feature (#21)
    if is_training:
        # Avoid network calls during training
        features["is_new_domain"] = 0.0
    else:
        features["is_new_domain"] = float(get_domain_age_flag(url))

    return features


def features_to_list(url: str, is_training: bool = False) -> list:
    """Return features as an ordered list for model input."""
    return [float(v) for v in extract_features(url, is_training).values()]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_parse(url: str) -> urllib.parse.ParseResult:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urllib.parse.urlparse(url)


def _has_ip_address(domain: str) -> bool:
    ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    return bool(ipv4.match(domain.split(":")[0]))


def _subdomain_depth(domain: str) -> int:
    parts = [p for p in domain.split(".") if p]
    return max(0, len(parts) - 2)


def _is_shortener(domain: str) -> bool:
    return any(s in domain for s in URL_SHORTENERS)


def _brand_in_subdomain(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) > 2:
        sub = ".".join(parts[:-2])
        return any(b in sub for b in SUSPICIOUS_BRANDS)
    return False


def _count_suspicious_keywords(url: str) -> int:
    return sum(kw in url for kw in SUSPICIOUS_KEYWORDS)


@lru_cache(maxsize=512)
def get_domain_age_flag(url: str) -> int:
    """
    Returns 1 if domain looks 'new/risky' (< 30 days, IP-based, or unresolvable).
    Returns 0 if WHOIS shows the domain is older than 30 days.
    Cached so the same domain isn't queried repeatedly.
    """
    try:
        domain = url.split("//")[-1].split("/")[0].split(":")[0]
        if _has_ip_address(domain):
            return 1

        # Defensive import — keeps the module importable even if whois isn't installed
        try:
            import whois  # type: ignore
        except Exception:
            return 0  # Don't penalise if WHOIS lib missing

        socket.setdefaulttimeout(5)
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation and isinstance(creation, datetime):
            age_days = (datetime.now() - creation).days
            return 1 if age_days < 30 else 0
        return 0
    except Exception:
        # Don't punish a URL just because WHOIS server timed out
        return 0


if __name__ == "__main__":
    test = [
        "https://www.google.com",
        "http://paypal-secure-login.suspicious-domain.xyz/verify",
        "http://192.168.1.1/login",
    ]
    for u in test:
        print(u, "->", extract_features(u, is_training=True))

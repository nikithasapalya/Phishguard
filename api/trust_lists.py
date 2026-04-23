"""
trust_lists.py — Hybrid layer for the URL scanner.

Combines THREE signals before falling back to ML:
 1. ALLOWLIST  — globally trusted domains (Google, YouTube, banks, etc.)
                 → instant CLEAN, risk = 0.02
 2. BLOCKLIST_PATTERNS — obvious phishing structural red flags
                 → instant THREAT, risk = 0.97
 3. Otherwise  → defer to the ML model with calibrated risk bands.

This makes the scanner accurate on famous sites and obvious phishing,
while still letting the ML model judge the gray area.
"""
import re
import urllib.parse

# ── 1. Trusted domains (apex form, no scheme/www) ─────────────────────────────
# Top global + Indian sites users hit every day. Anything ending in one of
# these apex domains → instant CLEAN.
ALLOWLIST = {
    # Search / portals
    "google.com", "google.co.in", "bing.com", "duckduckgo.com", "yahoo.com",
    # Google ecosystem
    "youtube.com", "youtu.be", "gmail.com", "googleusercontent.com",
    "googleapis.com", "blogger.com", "blogspot.com",
    # Social
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com",
    "twitter.com", "x.com", "linkedin.com", "reddit.com", "pinterest.com",
    "tiktok.com", "snapchat.com", "discord.com", "telegram.org",
    # Tech / dev
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com", "python.org", "nodejs.org", "reactjs.org",
    "developer.mozilla.org", "npmjs.com", "pypi.org", "docker.com",
    "kubernetes.io", "wikipedia.org", "wikimedia.org",
    # Cloud / SaaS
    "microsoft.com", "office.com", "live.com", "outlook.com", "azure.com",
    "apple.com", "icloud.com", "adobe.com", "oracle.com", "ibm.com",
    "salesforce.com", "atlassian.com", "slack.com", "zoom.us",
    "cloudflare.com", "amazonaws.com", "digitalocean.com", "heroku.com",
    "vercel.com", "netlify.com", "render.com",
    # Shopping
    "amazon.com", "amazon.in", "flipkart.com", "myntra.com", "ebay.com",
    "walmart.com", "alibaba.com", "aliexpress.com", "shopify.com",
    "meesho.com", "ajio.com", "nykaa.com",
    # Streaming / media
    "netflix.com", "primevideo.com", "hotstar.com", "disneyplus.com",
    "spotify.com", "soundcloud.com", "twitch.tv", "vimeo.com",
    # News
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "ndtv.com", "thehindu.com",
    "indiatoday.in", "hindustantimes.com", "timesofindia.indiatimes.com",
    # Indian banks / fintech / govt
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "yesbank.in", "idfcfirstbank.com",
    "rbi.org.in", "uidai.gov.in", "incometax.gov.in", "india.gov.in",
    "irctc.co.in", "nic.in", "gov.in", "epfindia.gov.in",
    "paytm.com", "phonepe.com", "razorpay.com", "cred.club",
    # Global fintech
    "paypal.com", "stripe.com", "wise.com", "visa.com", "mastercard.com",
    "americanexpress.com",
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "geeksforgeeks.org", "w3schools.com", "leetcode.com", "hackerrank.com",
    # Yenepoya University & affiliated portals
    "yenepoya.edu.in", "ytincubator.com", "ydc.yenepoya.edu.in",
    # Food / travel
    "swiggy.com", "zomato.com", "ubereats.com", "uber.com", "ola.com",
    "makemytrip.com", "goibibo.com", "booking.com", "airbnb.com",
}

# ── 2. Blocklist patterns — obvious phishing red flags ────────────────────────
# These are DEAL-BREAKERS. If any match, mark as threat regardless of ML.
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",      # free TLDs heavily abused
    ".xyz", ".top", ".club", ".work", ".click", ".loan",
    ".country", ".stream", ".download", ".racing",
}

# Brand-spoof keywords that should NEVER appear inside an unrelated domain
SPOOF_BRANDS = [
    "paypal", "amazon", "google", "facebook", "apple", "microsoft",
    "netflix", "instagram", "linkedin", "whatsapp", "icloud", "outlook",
    "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe",
    "binance", "coinbase", "metamask",
]


def _apex(domain: str) -> str:
    """Naively extract the registrable domain (apex). Good enough for matching."""
    parts = [p for p in domain.lower().split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    # Handle common 2-part TLDs (.co.in, .co.uk, .gov.in, .com.au, etc.)
    if parts[-2] in {"co", "com", "gov", "net", "org", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _domain_of(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urllib.parse.urlparse(url).netloc.lower().split(":")[0]


def is_allowlisted(url: str) -> bool:
    domain = _domain_of(url)
    if not domain:
        return False
    apex = _apex(domain)
    if apex in ALLOWLIST:
        return True
    # Also accept exact subdomain matches like "mail.google.com" → google.com
    return any(domain == d or domain.endswith("." + d) for d in ALLOWLIST)


def hard_phishing_signals(url: str):
    """
    Returns a list of strong phishing signals. If non-empty, treat as THREAT
    even before the ML model runs.
    """
    signals = []
    domain = _domain_of(url)
    if not domain:
        return ["Malformed URL"]

    # IP literal as host
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        signals.append("Uses raw IP address instead of a domain name")

    # @ in URL (classic obfuscation)
    if "@" in url:
        signals.append("Contains '@' symbol — classic URL obfuscation trick")

    # Punycode (homograph attacks)
    if "xn--" in domain:
        signals.append("Punycode detected — possible homograph attack")

    # Brand name in subdomain pointing to an unrelated apex
    apex = _apex(domain)
    sub = domain[: -len(apex)].rstrip(".") if domain.endswith(apex) else domain
    if sub:
        for brand in SPOOF_BRANDS:
            if brand in sub and brand not in apex:
                signals.append(
                    f"Brand '{brand}' appears in subdomain of unrelated domain '{apex}'"
                )
                break

    # Suspicious TLD + login/verify keyword combo
    low = url.lower()
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) and any(
        k in low for k in ("login", "verify", "secure", "account", "update", "wallet")
    ):
        signals.append("Suspicious TLD combined with credential-harvesting keywords")

    return signals


def risk_band(score: float) -> tuple:
    """Map a 0-1 risk score into (severity, verdict)."""
    if score >= 0.80:
        return "high", "HIGH RISK — Likely phishing"
    if score >= 0.55:
        return "medium", "SUSPICIOUS — Treat with caution"
    if score >= 0.30:
        return "low", "LOW RISK — Some weak signals"
    return "safe", "CLEAN — No significant threat detected"

"""
modules/website_scan/phishing_check.py — URL Phishing Heuristics Analyzer

WHY THIS MATTERS FOR TRUST:
  Phishing URLs share structural patterns that legitimate sites rarely exhibit:
  using raw IP addresses instead of memorable domain names, extremely long URLs
  packed with noise to hide the real destination, @ symbols that confuse
  browsers about the actual host, suspicious keywords that impersonate
  banking or authentication flows, and high Shannon entropy that indicates
  encoded/obfuscated URL components.
HOW IT WORKS:
  Pure string analysis on the URL — no network call needed. We parse the URL
  with Python's urllib.parse module, then apply a series of checks.  Each
  triggered check adds a penalty to the heuristic_score (0–100).
RESEARCH NOTE:
  Shannon entropy is defined as: H = -Σ p(c) * log2(p(c))
  where p(c) is the frequency of character c in the URL.
  Legitimate URLs are human-readable (low entropy ≈ 3.5–4.5).
  Obfuscated/encoded URLs approach theoretical maximum (≈ 6.0+).
"""
import math
import re
from urllib.parse import urlparse
# ── Suspicious keyword sets ───────────────────────────────────────────────────
# These keywords frequently appear in phishing URLs that pretend to be banks,
# email providers, or government portals.
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "banking",
    "signin", "webscr", "password", "credential", "confirm", "suspend",
    "limited", "unusual", "activity", "access", "alert", "recover",
    "validate", "authenticate", "authorize", "checkout",
}
# High-risk TLDs frequently used by free abuse-prone registrars
HIGH_RISK_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "party", "pw", "cc", "icu"}
# Entropy threshold: URLs with Shannon entropy above this are flagged
ENTROPY_THRESHOLD = 4.8
def _shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of *text*.

    Entropy measures the unpredictability / randomness of characters.
    Human-readable text has low entropy; base64/encoded strings have high entropy.

    Parameters
    ----------
    text : str — The string to measure.

    Returns
    -------
    float — Entropy value (bits per character). Range: 0 (constant) → log2(N) (uniform).
    """
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())
def check_phishing_heuristics(url: str) -> dict:
    """
    Analyse the structure of *url* for common phishing indicators.

    This function performs NO network requests — everything is derived from
    the URL string itself using lexical + structural heuristics + entropy.

    Parameters
    ----------
    url : str
        The full URL to analyse, e.g. "https://secure-login.bank-verify.com/account".

    Returns
    -------
    dict with keys:
        risk_indicators  (list[str]) – Human-readable descriptions of each triggered flag.
        heuristic_score  (int)       – 0 = no indicators found; 100 = maximum suspicion.
        url_entropy      (float)     – Shannon entropy of the URL string.
        domain_entropy   (float)     – Shannon entropy of the domain component.
    """
    risk_indicators: list[str] = []
    # urlparse splits a URL into components:
    # scheme="https", netloc="user:pass@host:port", path="/page", ...
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url.lower()
    # ── Check 1: IP address instead of domain ────────────────────────────────
    # Legitimate sites use memorable domain names; phishing pages often use
    # raw IPs because they don't bother registering a domain.
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        risk_indicators.append("URL uses a raw IP address instead of a domain name.")
    # ── Check 2: Excessive subdomains ─────────────────────────────────────────
    # "secure.login.verify.paypal.com.evil.com" — attackers add many subdomains
    # to make the URL look legitimate at a glance.
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) > 4:
        risk_indicators.append(
            f"Excessive subdomain depth ({len(subdomain_parts)} labels) — possible domain spoofing."
        )
    # ── Check 3: @ symbol in the URL ─────────────────────────────────────────
    # Everything before @ in a URL is treated as user:password by browsers.
    # Attackers abuse this: "https://paypal.com@evil.com" actually goes to evil.com.
    if "@" in url:
        risk_indicators.append("URL contains '@' symbol — may be used to hide the real destination.")
    # ── Check 4: Excessive hyphens in domain ─────────────────────────────────
    # Legitimate domains rarely need more than one hyphen.
    # Phishing domains like "secure-verify-account-paypal.com" stack them.
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        risk_indicators.append(
            f"Domain contains {hyphen_count} hyphens — a common pattern in spoofed domains."
        )
    # ── Check 5: URL length ───────────────────────────────────────────────────
    # Legitimate URLs are typically short and human-readable.
    # Phishing URLs are often long to pack in redirect parameters or confusion.
    if len(url) > 75:
        risk_indicators.append(
            f"URL is unusually long ({len(url)} chars) — may be designed to obscure destination."
        )
    # ── Check 6: Suspicious keywords in hostname or path ─────────────────────
    hostname_tokens = set(re.split(r"[.\-]", hostname.lower()))
    path_tokens = set(re.split(r"[/\-_]", path.lower()))
    all_tokens = hostname_tokens | path_tokens
    matched_keywords = SUSPICIOUS_KEYWORDS & all_tokens
    if matched_keywords:
        risk_indicators.append(
            f"Suspicious keywords found: {', '.join(sorted(matched_keywords))} "
            f"— often used in credential-harvesting pages."
        )
    # ── Check 7: Punycode / non-ASCII characters in domain ───────────────────
    # "Homograph attacks" replace standard letters with lookalike Unicode chars.
    # "xn--" in the hostname is the Punycode encoding indicator.
    if "xn--" in hostname:
        risk_indicators.append(
            "Domain uses Punycode (internationalized characters) — possible homograph attack."
        )
    # ── Check 8: High-risk TLD ────────────────────────────────────────────────
    tld = subdomain_parts[-1] if subdomain_parts else ""
    if tld in HIGH_RISK_TLDS:
        risk_indicators.append(
            f"Domain uses high-risk TLD (.{tld}) — frequently associated with free abuse-prone registrars."
        )
    # ── Check 9: URL Shannon Entropy ─────────────────────────────────────────
    # High entropy in the full URL (path + query) suggests encoded/obfuscated
    # components — base64 tokens, hex-encoded payloads, or random redirect IDs.
    # We measure entropy on path+query (excluding scheme+host which are readable).
    url_entropy = _shannon_entropy(full_url)
    analysed_segment = (path + query).lower()
    segment_entropy = _shannon_entropy(analysed_segment) if analysed_segment else 0.0
    if segment_entropy > ENTROPY_THRESHOLD and len(analysed_segment) > 20:
        risk_indicators.append(
            f"URL path has high character entropy ({segment_entropy:.2f} bits) — "
            "suggests obfuscated or encoded payload."
        )
    # ── Check 10: URL shortener redirect ─────────────────────────────────────
    shortener_domains = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
    if hostname.lower() in shortener_domains:
        risk_indicators.append(
            "URL uses a shortener service — the real destination is hidden."
        )
    # ── Score computation ─────────────────────────────────────────────────────
    # Stepped penalties: each additional indicator increases suspicion non-linearly.
    count = len(risk_indicators)
    penalty_table = {0: 0, 1: 18, 2: 35, 3: 52, 4: 65, 5: 76, 6: 85, 7: 93, 8: 97, 9: 99, 10: 100}
    heuristic_score = penalty_table.get(count, penalty_table.get(min(count, 10), 100))
    return {
        "risk_indicators": risk_indicators,
        "heuristic_score": heuristic_score,
        "url_entropy": round(url_entropy, 3),
        "domain_entropy": round(_shannon_entropy(hostname), 3),
    }
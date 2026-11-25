"""
modules/email_scan/content_check.py — Email Body Content Heuristic Scanner

PURPOSE:
  Scam and phishing emails typically use a recognisable set of psychological
  manipulation tactics in their text.  This module scans the raw email body
  for these patterns and produces a heuristic suspicion score.

DETECTION CATEGORIES:
  1. Urgency language      — pressures the reader to act immediately.
  2. Credential requests   — asks for passwords, OTPs, PINs, login details.
  3. Financial requests    — asks for money transfers, gift cards, wire transfers.
  4. Threat language       — threatens account suspension, legal action, arrest.
  5. Prize/lottery bait    — "You've won!" claims requiring personal info.
  6. Suspicious URLs       — embeds links that fail phishing heuristics.
  7. Impersonation signals — claims to be a known brand with suspicious context.

SCORING:
  Each triggered indicator adds points to the heuristic_score (0–100).
  The score is capped at 100.  A higher score means MORE suspicious content.
  (The scoring engine inverts this: 0 suspicious = 100 safe.)

NOTE:
  This is a keyword/pattern-based system — NOT a trained ML model.
  False positives can occur with legitimate urgent emails (e.g. bank alerts).
  The LLM explanation layer adds nuance that pure rule-based scoring can't.
"""

import re
from urllib.parse import urlparse
from typing import Tuple

# Reuse phishing URL heuristics to check links embedded in email body.
# This avoids code duplication and ensures consistent URL scoring.
from app.modules.website_scan.phishing_check import check_phishing_heuristics


# ── Pattern dictionaries ──────────────────────────────────────────────────────
# Each entry: (pattern, point_value, label)
# The label appears in risk_indicators so users see what triggered the check.

URGENCY_PATTERNS = [
    (r"\bact now\b",            15, "urgency: 'act now'"),
    (r"\bimmediately\b",        10, "urgency: 'immediately'"),
    (r"\bverify.{0,20}(now|immediately|today)\b", 15, "urgency: verify immediately"),
    (r"\bwithin\s+\d+\s*(hour|minute|day)s?\b", 12, "urgency: time-limited deadline"),
    (r"\bexpire[sd]?\b",        10, "urgency: expiration threat"),
    (r"\blast.{0,10}(chance|opportunity|warning)\b", 12, "urgency: last chance"),
    (r"\bfinal.{0,10}notice\b", 12, "urgency: final notice"),
    (r"\baction required\b",    10, "urgency: action required"),
    (r"\burgent(ly)?\b",        10, "urgency: urgent language"),
]

CREDENTIAL_PATTERNS = [
    (r"\bpassword\b",           10, "credential request: password"),
    (r"\bOTP\b",                15, "credential request: OTP code"),
    (r"\bone.?time.?passcode?\b", 15, "credential request: one-time passcode"),
    (r"\bverify.{0,20}(account|identity|email)\b", 12, "credential request: account verification"),
    (r"\blog.?in.{0,20}(detail|credential|info)\b", 15, "credential request: login credentials"),
    (r"\bclick.{0,30}(link|here|below).{0,30}(confirm|verify)\b", 15, "credential request: click-to-verify link"),
    (r"\bSSN\b|social security",  20, "credential request: SSN/social security"),
    (r"\bcredit.?card\b",        12, "credential request: credit card info"),
]

FINANCIAL_PATTERNS = [
    (r"\bwire.?transfer\b",     20, "financial request: wire transfer"),
    (r"\bgift.?card\b",         20, "financial request: gift card"),
    (r"\bitunes|google play.{0,20}card\b", 20, "financial request: iTunes/Google Play card"),
    (r"\bsend.{0,20}(money|funds|payment)\b", 15, "financial request: send money"),
    (r"\bcrypto(currency)?\b|bitcoin|ethereum", 12, "financial request: cryptocurrency"),
    (r"\bpay.{0,10}(now|immediately|today)\b", 12, "financial request: pay immediately"),
]

THREAT_PATTERNS = [
    (r"\baccount.{0,20}(suspend|disabled?|blocked?|terminated)\b", 15, "threat: account suspension"),
    (r"\blegal.{0,20}(action|proceed)\b", 12, "threat: legal action"),
    (r"\barrest(ed)?\b",         15, "threat: arrest"),
    (r"\bwarrant\b",             15, "threat: warrant"),
    (r"\bfined?\b",              10, "threat: fine"),
    (r"\bcriminal\b",            10, "threat: criminal"),
]

PRIZE_PATTERNS = [
    (r"\byou.{0,10}(have won|are.{0,5}winner|win)\b", 20, "prize bait: 'you have won'"),
    (r"\blottery\b",             15, "prize bait: lottery"),
    (r"\bcongratulations?!\b",   10, "prize bait: congratulations"),
    (r"\bclaim.{0,20}(prize|reward|gift)\b", 15, "prize bait: claim prize"),
    (r"\bselected.{0,20}(winner|recipient)\b", 15, "prize bait: selected as winner"),
]


def _check_patterns(body_lower: str, patterns: list) -> Tuple[list, int]:
    """
    Run a set of regex patterns against the (lowercased) email body.

    Parameters
    ----------
    body_lower : str   — Email body converted to lowercase.
    patterns   : list  — List of (regex_pattern, point_value, label) tuples.

    Returns
    -------
    (indicators, total_score)
        indicators   : list of str labels for triggered patterns.
        total_score  : int, sum of point values for triggered patterns.
    """
    indicators = []
    total_score = 0

    for pattern, points, label in patterns:
        if re.search(pattern, body_lower, re.IGNORECASE):
            indicators.append(label)
            total_score += points

    return indicators, total_score


def _extract_urls(text: str) -> list:
    """
    Extract all URLs from the email body text.

    Uses a simple regex to find http/https URLs.  We'll run each through
    the phishing heuristic checker to flag suspicious embedded links.
    """
    url_pattern = r"https?://[^\s\]\"'>]+"
    return re.findall(url_pattern, text)


def check_email_content(body: str) -> dict:
    """
    Scan the email body for scam/phishing content patterns.

    Parameters
    ----------
    body : str
        The plain-text body of the email.  HTML is accepted but we'll
        parse it as text (tags may interfere — ideally strip HTML first,
        but we handle raw text too for simplicity).

    Returns
    -------
    dict with keys:
        risk_indicators  (list[str]) — Labels of all triggered patterns.
        heuristic_score  (int)       — 0=clean, 100=highly suspicious (capped at 100).
        url_count        (int)       — Number of URLs found in the body.
        suspicious_urls  (list[str]) — URLs that scored poorly on phishing heuristics.
        error            (str)       — Set if content check failed.
    """
    try:
        body_lower = body.lower()
        all_indicators = []
        total_score = 0

        # ── Run each category of pattern checks ───────────────────────────────
        for patterns in [URGENCY_PATTERNS, CREDENTIAL_PATTERNS, FINANCIAL_PATTERNS,
                         THREAT_PATTERNS, PRIZE_PATTERNS]:
            indicators, score = _check_patterns(body_lower, patterns)
            all_indicators.extend(indicators)
            total_score += score

        # ── Check embedded URLs for phishing signals ──────────────────────────
        urls = _extract_urls(body)
        suspicious_urls = []

        for url in urls[:10]:  # Limit to first 10 URLs to avoid slow scans.
            try:
                phishing_result = check_phishing_heuristics(url)
                if phishing_result.get("heuristic_score", 0) >= 30:
                    # Flag URLs that score 30+ on the phishing heuristic.
                    suspicious_urls.append(url)
                    all_indicators.append(f"suspicious URL: {url[:60]}...")
                    total_score += 15  # Penalise for suspicious embedded link.
            except Exception:
                pass  # Skip URLs that can't be parsed.

        # ── Cap the score at 100 ──────────────────────────────────────────────
        final_score = min(total_score, 100)

        return {
            "risk_indicators": all_indicators,
            "heuristic_score": final_score,
            "url_count":       len(urls),
            "suspicious_urls": suspicious_urls,
        }

    except Exception as exc:
        return {
            "risk_indicators": [],
            "heuristic_score": 0,
            "url_count":       0,
            "suspicious_urls": [],
            "error":           str(exc),
        }

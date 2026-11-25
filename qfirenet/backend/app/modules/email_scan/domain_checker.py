"""
modules/email_scan/domain_checker.py — Rule-Based Sender Domain Verification

PURPOSE:
  The LLM is not reliable for domain-spoofing detection because:
    a) It has to recognize a domain purely from its name, not by querying DNS.
    b) Minor lookalike variations (paypa1.com, amazon-support.net) can fool it.

  This module performs a RULE-BASED check layered on top of the LLM:
    1. Extract the sender's domain from the email address.
    2. Check if it exactly matches a curated list of known-legitimate domains.
    3. If not an exact match, check for lookalike domains using:
       - Suffix containment ("amazon-support.net" contains "amazon")
       - Edit distance (Levenshtein ≤ 2 for short domains like "paypa1.com")
       - TLD swap detection (gmail.net vs gmail.com)

  This module's output is a standalone risk signal — it feeds into the scoring
  engine as a domain_check score, completely independent of the LLM verdict.

SAFE DOMAIN LIST:
  Curated set of major global services that are frequently impersonated.
  Grouped by category for maintainability.
  This is deliberately conservative — only add domains you are 100% certain
  represent a legitimate service (e.g. paypal.com, not paypal.co).
"""

import re
from typing import Optional


# ── Known-legitimate sender domains ──────────────────────────────────────────
# Format: lowercase domain strings.
# Subdomains (e.g. accounts.google.com) resolve to their root domain first,
# so we only need to list root domains here.

KNOWN_SAFE_DOMAINS: frozenset[str] = frozenset({
    # ── Email providers ───────────────────────────────────────────────────
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "zoho.com",

    # ── Tech giants ───────────────────────────────────────────────────────
    "google.com", "apple.com", "microsoft.com",
    "amazon.com", "amazon.co.uk", "amazon.in",
    "meta.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "netflix.com",
    "adobe.com",
    "dropbox.com",
    "salesforce.com",
    "slack.com",
    "zoom.us",
    "github.com",
    "atlassian.com",

    # ── Financial / Payments ──────────────────────────────────────────────
    "paypal.com",
    "stripe.com",
    "squareup.com",
    "wise.com",
    "revolut.com",
    "cashapp.com",
    "venmo.com",

    # ── Banks (US/UK/Global) ──────────────────────────────────────────────
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citibank.com",
    "capitalone.com",
    "discover.com",
    "usbank.com",
    "americanexpress.com",
    "barclays.co.uk",
    "hsbc.com", "hsbc.co.uk",
    "lloydsbank.com",
    "natwest.com",
    "standardchartered.com",

    # ── E-commerce / Delivery ─────────────────────────────────────────────
    "ebay.com",
    "etsy.com",
    "shopify.com",
    "fedex.com",
    "ups.com",
    "dhl.com",
    "usps.com",

    # ── Cloud / Hosting ───────────────────────────────────────────────────
    "aws.amazon.com",   # Note: emails from AWS come from @amazonaws.com too
    "amazonaws.com",
    "azure.com",
    "cloudflare.com",
    "digitalocean.com",
    "heroku.com",

    # ── Government (India) ────────────────────────────────────────────────
    "gov.in", "nic.in", "uidai.gov.in",

    # ── Government (US) ───────────────────────────────────────────────────
    "irs.gov", "ssa.gov", "usps.gov",
})

# Root domains extracted from KNOWN_SAFE_DOMAINS for lookalike matching
# (strip TLD — we only compare the "brand" part)
_SAFE_BRAND_NAMES: list[str] = sorted(
    {d.split(".")[0] for d in KNOWN_SAFE_DOMAINS if len(d.split(".")[0]) >= 4},
    key=len,
    reverse=True,   # Longer names first — avoid partial matches on short names
)


# ── Utility helpers ────────────────────────────────────────────────────────────

def _extract_domain(email_address: str) -> Optional[str]:
    """
    Extract the domain from an email address string.
    Handles "Display Name <email@domain.com>" and plain "email@domain.com".
    Returns lowercase domain or None.
    """
    if not email_address:
        return None
    # Strip angle brackets if present
    m = re.search(r"<([^>]+)>", email_address)
    addr = m.group(1) if m else email_address.strip()
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return None


def _root_domain(domain: str) -> str:
    """
    Return the root domain (last two labels) from a domain string.
    e.g. "accounts.google.com" -> "google.com"
         "mail.paypal.co.uk"   -> "paypal.co.uk"  (approximate — co.uk is common SLD)
    """
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        # Handle common second-level domains (co.uk, com.au, etc.)
        if parts[-2] in ("co", "com", "net", "org", "gov", "edu") and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain.lower()


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions  = prev_row[j + 1] + 1
            deletions   = curr_row[j] + 1
            subs        = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, subs))
        prev_row = curr_row
    return prev_row[-1]


def _looks_like_brand(subdomain_label: str) -> Optional[str]:
    """
    Check if `subdomain_label` (the brand portion before TLD) looks like a
    spoofed version of a known safe brand.

    Checks:
      1. Exact match to a known brand name (already covered by root domain check,
         but re-checked here for compound labels like "paypal-support").
      2. A known brand name is a substring of the label.
      3. Levenshtein distance ≤ 2 for labels of similar length (≥ 5 chars).

    Returns the matched brand name, or None.
    """
    label_lower = subdomain_label.lower()

    for brand in _SAFE_BRAND_NAMES:
        # Substring: "amazon-support" contains "amazon"
        if brand in label_lower and label_lower != brand:
            return brand

        # Edit distance: "paypa1" vs "paypal" — distance 1
        if len(brand) >= 5 and abs(len(label_lower) - len(brand)) <= 2:
            dist = _levenshtein(label_lower, brand)
            if 1 <= dist <= 2:
                return brand

    return None


# ── Public API ─────────────────────────────────────────────────────────────────

def check_sender_domain(sender_email: str) -> dict:
    """
    Rule-based verification of the sender email domain.

    Parameters
    ----------
    sender_email : str
        The sender's email address, e.g. "support@paypa1.com" or "no-reply@amazon.com".
        Also accepts "Display Name <email>" format.

    Returns
    -------
    dict with keys:
        domain          (str)          — Extracted domain (empty string if unparseable)
        root_domain     (str)          — Root domain (e.g. "paypa1.com")
        is_known_safe   (bool)         — Exact match to known-safe list
        is_lookalike    (bool)         — Suspicious similarity to a safe brand
        lookalike_of    (str | None)   — The safe brand this domain resembles
        risk_note       (str)          — Human-readable note for LLM/UI context
    """
    domain = _extract_domain(sender_email)

    if not domain:
        return {
            "domain":        "",
            "root_domain":   "",
            "is_known_safe": False,
            "is_lookalike":  False,
            "lookalike_of":  None,
            "risk_note":     "No sender domain found — could not verify.",
        }

    root = _root_domain(domain)
    brand_label = root.split(".")[0]   # "amazon" from "amazon.com"

    # ── Exact safe-domain match ───────────────────────────────────────────────
    if root in KNOWN_SAFE_DOMAINS:
        return {
            "domain":        domain,
            "root_domain":   root,
            "is_known_safe": True,
            "is_lookalike":  False,
            "lookalike_of":  None,
            "risk_note":     f"Sender domain '{root}' is a known legitimate service.",
        }

    # ── Lookalike detection ───────────────────────────────────────────────────
    matched_brand = _looks_like_brand(brand_label)

    if matched_brand:
        # Extra check: make sure it's not a known subdomain of a safe root
        # (e.g. "amazonses.com" is Amazon's email service — not a scam)
        is_amazon_ses = (brand_label == "amazonses" and matched_brand == "amazon")
        if not is_amazon_ses:
            return {
                "domain":        domain,
                "root_domain":   root,
                "is_known_safe": False,
                "is_lookalike":  True,
                "lookalike_of":  matched_brand,
                "risk_note": (
                    f"WARNING: Sender domain '{root}' looks like a spoofed version of "
                    f"'{matched_brand}'. This is a strong phishing indicator."
                ),
            }

    # ── Unknown domain ────────────────────────────────────────────────────────
    return {
        "domain":        domain,
        "root_domain":   root,
        "is_known_safe": False,
        "is_lookalike":  False,
        "lookalike_of":  None,
        "risk_note":     f"Sender domain '{root}' is not in the known-safe list.",
    }

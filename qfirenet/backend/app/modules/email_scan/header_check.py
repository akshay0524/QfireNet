"""
modules/email_scan/header_check.py — Email Authentication Header Validator

PURPOSE:
  Modern email security relies on three DNS-based authentication mechanisms:
    • SPF  (Sender Policy Framework)  — verifies the sending mail server is
                                        authorised to send on behalf of the domain.
    • DKIM (DomainKeys Identified Mail) — cryptographic signature proving the
                                        email content wasn't modified in transit.
    • DMARC (Domain-based Message Auth, Reporting & Conformance) — policy that
                                        tells receivers what to do when SPF/DKIM fail.

  We parse the raw email headers that users paste into the text area, looking
  for the "Authentication-Results" or individual result headers that mail servers
  add during delivery.

  NOTE: We parse RECEIVED headers — we do not perform live DNS lookups here
  because the user pastes historical email text (live lookup would require the
  original sending context). Instead we parse what receiving servers reported.

INPUT FORMAT:
  Raw email headers or full raw email text (as copied from "View Source" /
  "Show Original" in Gmail, Outlook, etc.)

WHAT WE DETECT:
  - SPF result (pass/fail/neutral/softfail/none)
  - DKIM result (pass/fail/none)
  - DMARC result (pass/fail/none)
  - Sender domain mismatch (From: header domain ≠ Return-Path domain)
  - Reply-To domain mismatch (common phishing tactic)
"""

import re
from typing import Optional


def _extract_header_value(raw_headers: str, header_name: str) -> Optional[str]:
    """
    Extract the first value of a named email header from raw header text.

    Email headers can span multiple lines (folded headers with leading whitespace).
    We use a regex that captures the value up to the next non-folded header.

    Parameters
    ----------
    raw_headers : str   — Raw header block (may include body text too).
    header_name : str   — Header name without the colon (e.g. "From").

    Returns
    -------
    str | None  — The header value, or None if not found.
    """
    # Pattern: header name + colon + optional whitespace + value
    # (?mi) = multiline, case-insensitive
    pattern = rf"(?mi)^{re.escape(header_name)}\s*:\s*(.+?)(?=\n\S|\Z)"
    match = re.search(pattern, raw_headers, re.DOTALL)
    return match.group(1).strip() if match else None


def _parse_auth_results(raw_headers: str) -> dict:
    """
    Parse the Authentication-Results header(s) for SPF, DKIM, DMARC results.

    Mail servers (Gmail, Outlook, etc.) add Authentication-Results headers
    after verifying SPF, DKIM, and DMARC.  The format is:
        Authentication-Results: mx.google.com;
           spf=pass (google.com: domain of sender@example.com designates ...);
           dkim=pass header.i=@example.com;
           dmarc=pass (p=REJECT ...);

    We look for all Authentication-Results headers (there may be multiple —
    one per hop) and search each for spf=, dkim=, dmarc= keywords.
    """
    # Find all Authentication-Results blocks (case-insensitive).
    ar_blocks = re.findall(
        r"(?mi)^Authentication-Results\s*:(.+?)(?=\n\S|\Z)",
        raw_headers,
        re.DOTALL,
    )

    spf_result   = None
    dkim_result  = None
    dmarc_result = None

    for block in ar_blocks:
        block_lower = block.lower()

        # Extract SPF result if not yet found.
        if spf_result is None:
            m = re.search(r"spf\s*=\s*(\w+)", block_lower)
            if m:
                spf_result = m.group(1)  # e.g. "pass", "fail", "neutral", "softfail"

        # Extract DKIM result if not yet found.
        if dkim_result is None:
            m = re.search(r"dkim\s*=\s*(\w+)", block_lower)
            if m:
                dkim_result = m.group(1)  # e.g. "pass", "fail", "none"

        # Extract DMARC result if not yet found.
        if dmarc_result is None:
            m = re.search(r"dmarc\s*=\s*(\w+)", block_lower)
            if m:
                dmarc_result = m.group(1)  # e.g. "pass", "fail", "none"

    return {
        "spf":   spf_result,
        "dkim":  dkim_result,
        "dmarc": dmarc_result,
    }


def _extract_domain(address: str) -> Optional[str]:
    """
    Extract the domain part from an email address or header value.

    Handles formats like:
      - "John Doe <john@example.com>"  →  "example.com"
      - "john@example.com"             →  "example.com"
      - Angle-bracket only             →  "example.com"
    """
    if not address:
        return None

    # Try to find an email address inside angle brackets first.
    m = re.search(r"<([^>]+)>", address)
    addr = m.group(1) if m else address.strip()

    # Extract domain part after @.
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return None


def check_email_headers(raw_headers: str) -> dict:
    """
    Parse raw email headers and check SPF, DKIM, DMARC authentication results.

    Parameters
    ----------
    raw_headers : str
        Raw email header block as pasted by the user (can include the body).
        Typically obtained via "Show Original" / "View Source" in an email client.

    Returns
    -------
    dict with keys:
        spf_pass              (bool)  — True if SPF passed.
        dkim_pass             (bool)  — True if DKIM passed.
        dmarc_pass            (bool)  — True if DMARC passed.
        sender_domain_mismatch (bool) — True if From domain ≠ Return-Path domain.
        reply_to_mismatch     (bool)  — True if Reply-To domain ≠ From domain.
        from_address          (str)   — Raw From header value.
        return_path           (str)   — Raw Return-Path header value.
        reply_to              (str)   — Raw Reply-To header value (if present).
        auth_summary          (str)   — Human-readable summary for the LLM.
        error                 (str)   — Set if parsing failed completely.
    """
    try:
        # ── Parse Authentication-Results headers ──────────────────────────────
        auth = _parse_auth_results(raw_headers)

        spf_pass   = auth["spf"]   == "pass"
        dkim_pass  = auth["dkim"]  == "pass"
        dmarc_pass = auth["dmarc"] == "pass"

        # ── Extract key address headers ───────────────────────────────────────
        from_value       = _extract_header_value(raw_headers, "From") or ""
        return_path_value = _extract_header_value(raw_headers, "Return-Path") or ""
        reply_to_value   = _extract_header_value(raw_headers, "Reply-To") or ""

        from_domain        = _extract_domain(from_value)
        return_path_domain = _extract_domain(return_path_value)
        reply_to_domain    = _extract_domain(reply_to_value)

        # ── Check for domain mismatches ───────────────────────────────────────
        # A mismatch between From and Return-Path is a strong phishing indicator:
        # the display name shows a trusted brand, but replies go elsewhere.
        sender_domain_mismatch = bool(
            from_domain
            and return_path_domain
            and from_domain != return_path_domain
        )

        # Reply-To mismatch: even more suspicious — attacker wants your reply
        # to go to a different domain than the apparent sender.
        reply_to_mismatch = bool(
            reply_to_domain
            and from_domain
            and reply_to_domain != from_domain
        )

        # ── Build a summary for the LLM explainer ────────────────────────────
        auth_summary = (
            f"SPF: {auth['spf'] or 'not found'}, "
            f"DKIM: {auth['dkim'] or 'not found'}, "
            f"DMARC: {auth['dmarc'] or 'not found'}. "
            f"From domain: {from_domain or 'unknown'}, "
            f"Return-Path domain: {return_path_domain or 'unknown'}."
        )

        has_headers = bool(auth["spf"] or auth["dkim"] or auth["dmarc"] or from_value or return_path_value)

        return {
            "has_headers":            has_headers,
            "spf_pass":              spf_pass,
            "dkim_pass":             dkim_pass,
            "dmarc_pass":            dmarc_pass,
            "sender_domain_mismatch": sender_domain_mismatch,
            "reply_to_mismatch":     reply_to_mismatch,
            "from_address":          from_value,
            "return_path":           return_path_value,
            "reply_to":              reply_to_value,
            "auth_summary":          auth_summary,
        }

    except Exception as exc:
        return {
            "spf_pass":              False,
            "dkim_pass":             False,
            "dmarc_pass":            False,
            "sender_domain_mismatch": False,
            "reply_to_mismatch":     False,
            "from_address":          "",
            "return_path":           "",
            "reply_to":              "",
            "auth_summary":          "Could not parse headers.",
            "error":                 str(exc),
        }

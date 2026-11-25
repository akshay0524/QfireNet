"""
modules/website_scan/whois_check.py — WHOIS Domain Age & Registrar Inspector

WHY THIS MATTERS FOR TRUST:
  Phishing and scam sites are typically registered only days or weeks before
  they go live — attackers don't want to pay for a domain they'll abandon after
  a campaign.  Legitimate businesses almost always have domains that are months
  or years old.  A domain registered less than 90 days ago is a notable
  risk signal.

  The registrar name can also be informative: some registrars are well-known
  as havens for abusive registrations (though we keep that check simple here).

HOW IT WORKS:
  The python-whois library queries WHOIS servers (much like the `whois` CLI tool)
  and parses the unstructured text response into a Python object.
"""

from datetime import datetime, timezone
from typing import Union

import whois


def check_whois(hostname: str) -> dict:
    """
    Query the WHOIS database for *hostname* and extract domain-age signals.

    Parameters
    ----------
    hostname : str
        The bare domain name (no scheme, no path).
        Example: "example.com"

    Returns
    -------
    dict with keys:
        domain_age_days        (int | None) – Days since the domain was first registered.
        registrar              (str | None) – The registrar company name.
        creation_date          (str | None) – ISO-8601 creation date string.
        is_recently_registered (bool)       – True if domain is younger than 90 days.
        error                  (str | None) – Populated only on failure.
    """
    result = {
        "domain_age_days": None,
        "registrar": None,
        "creation_date": None,
        "is_recently_registered": None,
        "error": None,
    }

    try:
        # ── Query WHOIS ───────────────────────────────────────────────────────
        # whois.whois() contacts the appropriate WHOIS server and returns a
        # Who object with parsed fields.
        w = whois.whois(hostname)

        # ── Extract creation_date ─────────────────────────────────────────────
        # python-whois sometimes returns a list of dates (e.g. for domains with
        # multiple WHOIS records).  We always want the earliest date.
        creation_date: Union[datetime, None] = None

        raw_date = w.creation_date
        if isinstance(raw_date, list):
            # Filter out any None values, then pick the oldest (min) date.
            valid_dates = [d for d in raw_date if isinstance(d, datetime)]
            creation_date = min(valid_dates) if valid_dates else None
        elif isinstance(raw_date, datetime):
            creation_date = raw_date

        # ── Compute domain age ────────────────────────────────────────────────
        if creation_date:
            # Make both datetimes offset-aware before subtracting (Python requires this).
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            domain_age_days = (now - creation_date).days

            result.update(
                {
                    "domain_age_days": domain_age_days,
                    "creation_date": creation_date.isoformat(),
                    # Domains younger than 90 days are considered suspicious.
                    "is_recently_registered": domain_age_days < 90,
                }
            )
        else:
            # No creation date found — WHOIS record may be incomplete or redacted.
            result["error"] = "WHOIS creation_date not available (may be redacted by registrar)."

        # ── Extract registrar ─────────────────────────────────────────────────
        # w.registrar may be a string or a list; normalise to a single string.
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        result["registrar"] = registrar

    except whois.parser.PywhoisError as exc:
        # Raised when no WHOIS record exists (e.g. unregistered domain).
        result["error"] = f"WHOIS lookup failed: {exc}"

    except ConnectionError as exc:
        result["error"] = f"Could not reach WHOIS server: {exc}"

    except Exception as exc:
        # Catch-all — WHOIS parsing is notoriously fragile across TLDs.
        result["error"] = f"Unexpected WHOIS error: {exc}"

    return result

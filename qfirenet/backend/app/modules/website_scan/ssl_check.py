"""
modules/website_scan/ssl_check.py — SSL/TLS Certificate Inspector

WHY THIS MATTERS FOR TRUST:
  An expired or self-signed certificate means the site cannot be verified as
  authentic.  Attackers who clone legitimate sites often forget to renew the
  cert or use cheap/free certs from untrusted issuers.  Knowing the TLS version
  also flags sites still running outdated, vulnerable protocols (TLS 1.0/1.1).

HOW IT WORKS:
  We open a raw TCP socket to port 443, then wrap it with Python's ssl module to
  perform a TLS handshake.  The server presents its certificate during the
  handshake; we read it without making any HTTP request.
"""

import ssl
import socket
from datetime import datetime, timezone


def check_ssl(hostname: str) -> dict:
    """
    Connect to *hostname* on port 443 and inspect its TLS certificate.
    Parameters
    ----------
    hostname : str
        The bare domain name (no scheme, no path).
        Example: "example.com"  — NOT "https://example.com".
    Returns
    -------
    dict with keys:
        is_valid          (bool)  – True if cert is currently valid & not expired.
        issuer            (str)   – Organisation that signed the certificate.
        expiry_date       (str)   – ISO-8601 string of the cert's notAfter date.
        days_until_expiry (int)   – Negative means already expired.
        tls_version       (str)   – Negotiated TLS version string, e.g. "TLSv1.3".
        error             (str)   – Populated only if something went wrong.
    """
    # Default / fallback result if the connection fails.
    result = {
        "is_valid": False,
        "issuer": None,
        "expiry_date": None,
        "days_until_expiry": None,
        "tls_version": None,
        "error": None,
    }

    try:
        # ── Step 1: Create a default SSL context ──────────────────────────────
        # ssl.create_default_context() sets up:
        #   • Certificate verification against the system CA store.
        #   • Hostname checking (prevents certificate for bank.com being used on evil.com).
        #   • Minimum TLS version of 1.2 by default.
        ctx = ssl.create_default_context()

        # ── Step 2: Open a TCP socket then upgrade it to TLS ─────────────────
        # We use a context manager (with … as …) so the socket is automatically
        # closed when we exit the block — even if an exception is raised.
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            # wrap_socket() performs the TLS handshake and returns a secure socket.
            # server_hostname is required for SNI (Server Name Indication), which
            # allows one IP to host multiple HTTPS sites.
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:

                # getpeercert() returns the server's certificate as a Python dict.
                cert = tls_sock.getpeercert()

                # version() returns the negotiated protocol string, e.g. "TLSv1.3"
                tls_version = tls_sock.version()

        # ── Step 3: Parse the certificate fields ─────────────────────────────
        # 'notAfter' is a string like "Jul 20 12:00:00 2025 GMT"
        expiry_str = cert.get("notAfter", "")
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

        # Make expiry timezone-aware so we can compare to utcnow (also tz-aware).
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        days_until_expiry = (expiry_dt - now).days

        # ── Step 4: Extract the issuer organisation ───────────────────────────
        # cert["issuer"] is a tuple of tuples:
        # (( ("countryName", "US"), ), ( ("organizationName", "DigiCert Inc"), ), ...)
        issuer_dict = {k: v for rdn in cert.get("issuer", []) for k, v in rdn}
        issuer = issuer_dict.get("organizationName", "Unknown")

        # ── Step 5: Populate the result dict ─────────────────────────────────
        result.update(
            {
                # is_valid = True only when the cert hasn't expired yet.
                "is_valid": days_until_expiry >= 0,
                "issuer": issuer,
                "expiry_date": expiry_dt.isoformat(),
                "days_until_expiry": days_until_expiry,
                "tls_version": tls_version,
                "error": None,
            }
        )

    except ssl.SSLCertVerificationError as exc:
        # The cert is invalid, self-signed, or the hostname doesn't match.
        result["error"] = f"SSL verification failed: {exc}"

    except socket.timeout:
        result["error"] = "Connection timed out while attempting SSL handshake."

    except ConnectionRefusedError:
        result["error"] = "Port 443 is closed — the host may not support HTTPS."

    except OSError as exc:
        # Catches DNS resolution failures and other low-level network errors.
        result["error"] = f"Network error: {exc}"

    except Exception as exc:
        # Catch-all so one bad scan never brings down the whole server.
        result["error"] = f"Unexpected error during SSL check: {exc}"

    return result

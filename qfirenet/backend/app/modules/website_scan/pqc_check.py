"""
modules/website_scan/pqc_check.py — Post-Quantum Cryptography Readiness Checker

WHY THIS MATTERS FOR TRUST (FUTURE RISK):
  Today's TLS connections rely on RSA and ECDH key exchange algorithms.  These
  are secure against classical computers.  However, a sufficiently powerful
  *quantum* computer running Shor's algorithm could break RSA-2048 in hours.

  NIST finalised its first PQC standards in 2024 (ML-KEM / Kyber for key
  encapsulation, ML-DSA / Dilithium for signatures).  Chrome and Cloudflare
  already support X25519Kyber768 hybrid key exchange.

  Most sites will show pqc_ready=False today — that is EXPECTED and is treated
  as an informational/future-risk signal, NOT a hard penalty.  We flag it so
  organisations can begin planning their migration.

HOW IT WORKS:
  We reuse the SSL socket connection to read the negotiated cipher suite and key
  exchange mechanism.  If the cipher string contains known PQC identifiers, we
  flag the site as PQC-ready.
"""

import ssl
import socket


# Known cipher/key-exchange strings that indicate PQC or PQC-hybrid support.
PQC_INDICATORS = {
    # X25519Kyber768 — the Google/Chrome hybrid KEM; appears in cipher name.
    "kyber",
    "x25519kyber",
    # NIST final standards (may appear in future OpenSSL builds).
    "mlkem",
    "ml-kem",
    "frodokm",
}


def check_pqc_readiness(hostname: str) -> dict:
    """
    Inspect the TLS cipher suite negotiated with *hostname* and determine
    whether Post-Quantum Cryptography key exchange is in use.

    Parameters
    ----------
    hostname : str
        Bare domain name (no scheme), e.g. "cloudflare.com".

    Returns
    -------
    dict with keys:
        cipher_suite (str | None) – The negotiated cipher suite string.
        pqc_ready    (bool)       – True only if a PQC/hybrid KEM is detected.
        note         (str)        – Context for the result (always present).
        error        (str | None) – Populated if the connection failed.

    Note
    ----
    The Python ssl module exposes the cipher name but does NOT (as of 3.11)
    expose the raw key_exchange extension.  Detection relies on the cipher
    string containing a PQC identifier.  As PQC support matures in OpenSSL,
    this detection will become more reliable.
    """
    result = {
        "cipher_suite": None,
        "pqc_ready": False,
        "note": None,
        "error": None,
    }

    try:
        # ── Open TLS connection ───────────────────────────────────────────────
        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:

                # cipher() returns a 3-tuple: (name, protocol, key_bits)
                # Example: ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
                cipher_info = tls_sock.cipher()

        if cipher_info:
            cipher_name = cipher_info[0]  # e.g. "TLS_AES_256_GCM_SHA384"
            result["cipher_suite"] = cipher_name

            # ── PQC detection ─────────────────────────────────────────────────
            # Lowercase comparison against known PQC identifiers.
            cipher_lower = cipher_name.lower()
            pqc_detected = any(indicator in cipher_lower for indicator in PQC_INDICATORS)

            if pqc_detected:
                result["pqc_ready"] = True
                result["note"] = (
                    f"PQC hybrid key exchange detected in cipher: {cipher_name}. "
                    "This site is actively protecting against harvest-now-decrypt-later attacks."
                )
            else:
                result["pqc_ready"] = False
                result["note"] = (
                    f"Cipher suite '{cipher_name}' uses classical cryptography only (RSA/ECC). "
                    "This is the industry norm in 2025 — PQC migration is still early-stage. "
                    "No immediate risk, but migration planning is recommended."
                )
        else:
            result["note"] = "Could not retrieve cipher information from the TLS handshake."

    except socket.timeout:
        result["error"] = "Connection timed out during PQC check."

    except ssl.SSLError as exc:
        result["error"] = f"SSL error during PQC check: {exc}"

    except OSError as exc:
        result["error"] = f"Network error during PQC check: {exc}"

    except Exception as exc:
        result["error"] = f"Unexpected error during PQC check: {exc}"

    return result

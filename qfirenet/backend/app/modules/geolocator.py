"""
modules/geolocator.py — IP/Domain Geolocation via ip-api.com

Geolocates a domain or IP address using ip-api.com's free tier (45 req/min).
This is used after high-risk scans to log ThreatEvent records for the globe.

PRIVACY:
  Only the FLAGGED ENTITY (website domain, email sender domain) is geolocated.
  The IP of the user submitting the scan is NEVER passed to this function.
"""

import socket
import httpx
import logging

log = logging.getLogger(__name__)

_GEO_API = "http://ip-api.com/json/{host}?fields=status,country,countryCode,city,lat,lon"

_DEFAULT = {
    "lat": 0.0,
    "lng": 0.0,
    "country": "Unknown",
    "country_code": "",
    "city": "",
}


def geolocate(host: str) -> dict:
    """
    Geolocate a hostname or IP address.

    Parameters
    ----------
    host : str
        A domain name (e.g. 'evil-phish.com') or raw IP address.

    Returns
    -------
    dict with keys: lat, lng, country, country_code, city
    Falls back to all-zero/Unknown on any error — never raises.
    """
    try:
        # Resolve domain → IP if necessary
        ip = _resolve(host)
        if not ip or ip.startswith(("127.", "192.168.", "10.", "172.")):
            return _DEFAULT.copy()

        url = _GEO_API.format(host=ip)
        resp = httpx.get(url, timeout=5.0)
        data = resp.json()

        if data.get("status") != "success":
            return _DEFAULT.copy()

        return {
            "lat":          float(data.get("lat", 0.0)),
            "lng":          float(data.get("lon", 0.0)),
            "country":      str(data.get("country", "Unknown")),
            "country_code": str(data.get("countryCode", "")),
            "city":         str(data.get("city", "")),
        }
    except Exception as exc:
        log.debug("Geolocation failed for %s: %s", host, exc)
        return _DEFAULT.copy()


def _resolve(host: str) -> str | None:
    """DNS-resolve a hostname to its first IPv4 address."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

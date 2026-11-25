"""
modules/apk_scan/risk_mapper.py — Android Permission Risk Classifier

PURPOSE:
  Not all Android permissions are equally dangerous.  INTERNET access is
  benign for any browser or social app; READ_SMS can expose banking OTPs
  and is frequently abused by malware.

  This module maps each Android permission to one of four risk tiers:
    • Critical — Can directly enable fraud, stalkerware, or spyware.
    • High     — Significant privacy or security risk; rarely needed by legit apps.
    • Medium   — Some privacy impact; commonly used but warrants review.
    • Low      — Normal, expected by most apps; minimal risk.

  We then compute an overall_risk_score (0–100, 100=highly dangerous) by
  weighting how many permissions land in each tier.

TIER WEIGHTS:
  Critical: 25 points each (capped at 100)
  High:     12 points each
  Medium:    5 points each
  Low:       1 point  each

REFERENCE:
  Tier classifications based on:
  - OWASP Mobile Top 10 (M1: Improper Platform Usage)
  - Android documentation: https://developer.android.com/reference/android/Manifest.permission
  - Academic literature on Android malware permission patterns.
"""


# ── Permission risk table ─────────────────────────────────────────────────────
# Maps Android permission names to risk tier strings.
# Uses the short form (after "android.permission." or "android.hardware.") but
# we match on the full string — the table keys are full permission names.

PERMISSION_RISK_TABLE = {
    # ── CRITICAL: Can directly enable fraud, surveillance, or device takeover ─
    "android.permission.READ_SMS":                   "Critical",
    "android.permission.RECEIVE_SMS":                "Critical",
    "android.permission.SEND_SMS":                   "Critical",
    "android.permission.READ_CALL_LOG":              "Critical",
    "android.permission.WRITE_CALL_LOG":             "Critical",
    "android.permission.PROCESS_OUTGOING_CALLS":     "Critical",
    "android.permission.BIND_DEVICE_ADMIN":          "Critical",  # Can lock/wipe device
    "android.permission.SYSTEM_ALERT_WINDOW":        "Critical",  # Overlay attacks (UI hijack)
    "android.permission.INSTALL_PACKAGES":           "Critical",  # Can install malware
    "android.permission.DELETE_PACKAGES":            "Critical",
    "android.permission.WRITE_SETTINGS":             "Critical",
    "android.permission.DISABLE_KEYGUARD":           "Critical",
    "android.permission.MANAGE_DEVICE_POLICY":       "Critical",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Critical",  # Keylogger potential

    # ── HIGH: Significant privacy or security risk ────────────────────────────
    "android.permission.ACCESS_FINE_LOCATION":       "High",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "High",  # Always-on GPS tracking
    "android.permission.READ_CONTACTS":              "High",
    "android.permission.WRITE_CONTACTS":             "High",
    "android.permission.READ_CALENDAR":              "High",
    "android.permission.WRITE_CALENDAR":             "High",
    "android.permission.RECORD_AUDIO":               "High",  # Microphone access
    "android.permission.CAPTURE_AUDIO_OUTPUT":       "High",
    "android.permission.CAMERA":                     "High",  # Can silently photograph
    "android.permission.WRITE_EXTERNAL_STORAGE":     "High",  # Access to all files
    "android.permission.READ_EXTERNAL_STORAGE":      "High",
    "android.permission.GET_ACCOUNTS":               "High",  # List all accounts on device
    "android.permission.AUTHENTICATE_ACCOUNTS":      "High",
    "android.permission.MANAGE_ACCOUNTS":            "High",
    "android.permission.READ_PROFILE":               "High",
    "android.permission.WRITE_PROFILE":              "High",
    "android.permission.BLUETOOTH_ADMIN":            "High",
    "android.permission.CHANGE_NETWORK_STATE":       "High",
    "android.permission.CHANGE_WIFI_STATE":          "High",
    "android.permission.PACKAGE_USAGE_STATS":        "High",  # App usage tracking

    # ── MEDIUM: Some privacy impact; commonly used but worth noting ───────────
    "android.permission.ACCESS_COARSE_LOCATION":     "Medium",
    "android.permission.ACCESS_WIFI_STATE":          "Medium",
    "android.permission.BLUETOOTH":                  "Medium",
    "android.permission.VIBRATE":                    "Medium",
    "android.permission.WAKE_LOCK":                  "Medium",
    "android.permission.FLASHLIGHT":                 "Medium",
    "android.permission.READ_PHONE_STATE":           "Medium",  # Device ID access
    "android.permission.READ_PHONE_NUMBERS":         "Medium",
    "android.permission.CALL_PHONE":                 "Medium",
    "android.permission.USE_BIOMETRIC":              "Medium",
    "android.permission.USE_FINGERPRINT":            "Medium",
    "android.permission.NFC":                        "Medium",
    "android.permission.BODY_SENSORS":               "Medium",
    "android.permission.FOREGROUND_SERVICE":         "Medium",
    "android.permission.REQUEST_INSTALL_PACKAGES":   "Medium",
    "android.permission.RECEIVE_BOOT_COMPLETED":     "Medium",  # Auto-starts on boot
    "android.permission.BROADCAST_SMS":              "Medium",

    # ── LOW: Normal, expected by most apps ────────────────────────────────────
    "android.permission.INTERNET":                   "Low",
    "android.permission.ACCESS_NETWORK_STATE":       "Low",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": "Low",
    "android.permission.REORDER_TASKS":              "Low",
    "android.permission.SET_WALLPAPER":              "Low",
    "android.permission.SET_WALLPAPER_HINTS":        "Low",
    "android.permission.EXPAND_STATUS_BAR":          "Low",
    "android.permission.KILL_BACKGROUND_PROCESSES":  "Low",
    "android.permission.GET_TASKS":                  "Low",
    "android.permission.RECEIVE_BOOT_COMPLETED":     "Low",
    "android.permission.BROADCAST_STICKY":           "Low",
    "android.permission.SET_ALARM":                  "Low",
    "android.permission.CHANGE_AUDIO_SETTINGS":      "Low",
}

# Risk tier point values — how many score points each permission in that tier adds.
# Critical is weighted very heavily because even ONE critical permission warrants serious scrutiny.
TIER_POINTS = {
    "Critical": 25,
    "High":     12,
    "Medium":    5,
    "Low":       1,
    "Unknown":   3,  # Unknown = not in our table = treat as mild risk.
}


def map_permission_risk(permissions: list) -> dict:
    """
    Map a list of Android permissions to risk tiers and compute an overall score.

    Parameters
    ----------
    permissions : list[str]
        List of full Android permission names, e.g.:
        ["android.permission.CAMERA", "android.permission.INTERNET", ...]

    Returns
    -------
    dict with keys:
        permission_breakdown (dict)  — Maps each permission to its risk tier.
        tier_counts          (dict)  — Count of permissions in each tier.
        overall_risk_score   (int)   — 0–100, higher = more dangerous app.
        high_risk_permissions (list) — Only Critical + High permissions listed.
        total_permissions    (int)   — Total permission count.
    """
    if not permissions:
        return {
            "permission_breakdown":  {},
            "tier_counts":           {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0},
            "overall_risk_score":    0,
            "high_risk_permissions": [],
            "total_permissions":     0,
        }

    # ── Classify each permission ──────────────────────────────────────────────
    breakdown = {}
    tier_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}

    for perm in permissions:
        tier = PERMISSION_RISK_TABLE.get(perm, "Unknown")
        breakdown[perm] = tier
        tier_counts[tier] += 1

    # ── Compute overall risk score ────────────────────────────────────────────
    # Weighted sum of all permission points, capped at 100.
    raw_score = sum(
        tier_counts[tier] * TIER_POINTS[tier]
        for tier in tier_counts
    )
    overall_risk_score = min(raw_score, 100)

    # ── Filter high-risk permissions for easy display ─────────────────────────
    high_risk = [
        p for p, t in breakdown.items()
        if t in ("Critical", "High")
    ]

    return {
        "permission_breakdown":  breakdown,
        "tier_counts":           tier_counts,
        "overall_risk_score":    overall_risk_score,
        "high_risk_permissions": high_risk,
        "total_permissions":     len(permissions),
    }

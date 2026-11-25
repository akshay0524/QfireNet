"""
tests/test_apk_scan.py — Unit Tests for APK Scan Modules

Tests:
  1. Risk mapper: Permission tier classification (Critical/High/Medium/Low)
  2. Risk mapper: Overall risk score computation from permission lists
  3. APK scoring: _score_apk_permissions() sub-function
  4. APK scoring: _score_apk_metadata() sub-function
  5. APK trust score fusion (integration tests with realistic APK profiles)

NOTE: We do NOT test extract_permissions() (it requires a real APK binary file).
      Instead we test with mock extracted permission lists that simulate real APKs.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.modules.apk_scan.risk_mapper import (
    map_permission_risk,
    PERMISSION_RISK_TABLE,
)
from app.scoring.engine import (
    calculate_apk_trust_score,
    _score_apk_permissions,
    _score_apk_metadata,
)


# ══════════════════════════════════════════════════════════════════════════════
# Simulated APK permission profiles (realistic real-world examples)
# ══════════════════════════════════════════════════════════════════════════════

# Clean navigation / maps app — mostly Low permissions
CLEAN_MAPS_APP = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.VIBRATE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
]

# Legitimate banking app (camera for cheque scan, biometrics)
BANKING_APP_SAFE = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.USE_BIOMETRIC",
    "android.permission.CAMERA",
    "android.permission.VIBRATE",
    "android.permission.FOREGROUND_SERVICE",
]

# Stalkerware / spyware with many Critical permissions
STALKERWARE_APK = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.CAMERA",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.GET_ACCOUNTS",
    "android.permission.INTERNET",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
]

# Moderate social-media-type app
MODERATE_RISK_APK = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.ACCESS_NETWORK_STATE",
]

EMPTY_PERMISSIONS = []


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Permission Risk Table Classification
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissionRiskTable:
    """Tests that individual permissions are assigned the correct risk tier."""

    def test_sms_read_is_critical(self):
        """READ_SMS can intercept banking OTPs -> Critical."""
        assert PERMISSION_RISK_TABLE.get("android.permission.READ_SMS") == "Critical"

    def test_send_sms_is_critical(self):
        """SEND_SMS can commit premium-rate fraud -> Critical."""
        assert PERMISSION_RISK_TABLE.get("android.permission.SEND_SMS") == "Critical"

    def test_accessibility_service_is_critical(self):
        """BIND_ACCESSIBILITY_SERVICE is a keylogger vector -> Critical."""
        assert PERMISSION_RISK_TABLE.get("android.permission.BIND_ACCESSIBILITY_SERVICE") == "Critical"

    def test_device_admin_is_critical(self):
        """BIND_DEVICE_ADMIN lets app lock/wipe the device -> Critical."""
        assert PERMISSION_RISK_TABLE.get("android.permission.BIND_DEVICE_ADMIN") == "Critical"

    def test_install_packages_is_critical(self):
        """INSTALL_PACKAGES can drop additional malware -> Critical."""
        assert PERMISSION_RISK_TABLE.get("android.permission.INSTALL_PACKAGES") == "Critical"

    def test_system_alert_window_is_critical(self):
        """SYSTEM_ALERT_WINDOW enables UI hijacking / overlay attacks -> Critical."""
        assert PERMISSION_RISK_TABLE.get("android.permission.SYSTEM_ALERT_WINDOW") == "Critical"

    def test_fine_location_is_high(self):
        """ACCESS_FINE_LOCATION enables persistent GPS tracking -> High."""
        assert PERMISSION_RISK_TABLE.get("android.permission.ACCESS_FINE_LOCATION") == "High"

    def test_camera_is_high(self):
        """CAMERA can silently photograph user -> High."""
        assert PERMISSION_RISK_TABLE.get("android.permission.CAMERA") == "High"

    def test_record_audio_is_high(self):
        """RECORD_AUDIO (microphone) can be used for eavesdropping -> High."""
        assert PERMISSION_RISK_TABLE.get("android.permission.RECORD_AUDIO") == "High"

    def test_internet_is_low(self):
        """INTERNET is expected by almost every app -> Low risk."""
        assert PERMISSION_RISK_TABLE.get("android.permission.INTERNET") == "Low"

    def test_vibrate_is_medium(self):
        """VIBRATE is a common, low-impact permission -> Medium."""
        assert PERMISSION_RISK_TABLE.get("android.permission.VIBRATE") == "Medium"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: map_permission_risk() Function
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissionRiskMapper:
    """Tests the permission-list to risk score computation."""

    def test_clean_maps_app_has_low_risk(self):
        """Clean maps app with basic permissions -> low risk score."""
        result = map_permission_risk(CLEAN_MAPS_APP)
        assert result["overall_risk_score"] < 40, (
            f"Maps app should have low risk, got {result['overall_risk_score']}"
        )
        assert result["tier_counts"]["Critical"] == 0

    def test_stalkerware_has_critical_risk(self):
        """Stalkerware with 8+ critical permissions -> overall score >= 80."""
        result = map_permission_risk(STALKERWARE_APK)
        assert result["overall_risk_score"] >= 80, (
            f"Stalkerware should score >=80, got {result['overall_risk_score']}"
        )
        assert result["tier_counts"]["Critical"] >= 5

    def test_moderate_app_has_no_critical(self):
        """Moderate social app with camera + mic but no critical perms."""
        result = map_permission_risk(MODERATE_RISK_APK)
        assert result["tier_counts"]["Critical"] == 0

    def test_empty_permissions_scores_zero(self):
        """APK with no permissions -> risk score = 0."""
        result = map_permission_risk(EMPTY_PERMISSIONS)
        assert result["overall_risk_score"] == 0
        assert result["tier_counts"]["Critical"] == 0
        assert result["total_permissions"] == 0

    def test_result_has_required_keys(self):
        """API contract: result must have all required keys."""
        result = map_permission_risk(CLEAN_MAPS_APP)
        required = {
            "overall_risk_score", "tier_counts",
            "high_risk_permissions", "total_permissions", "permission_breakdown",
        }
        assert required.issubset(set(result.keys()))

    def test_risk_score_capped_at_100(self):
        """Risk score must never exceed 100 even with many critical permissions."""
        result = map_permission_risk(STALKERWARE_APK)
        assert result["overall_risk_score"] <= 100

    def test_total_permissions_is_correct(self):
        """total_permissions must equal the input list length."""
        result = map_permission_risk(MODERATE_RISK_APK)
        assert result["total_permissions"] == len(MODERATE_RISK_APK)

    def test_high_risk_permissions_contains_only_critical_and_high(self):
        """high_risk_permissions list should only include Critical/High perms."""
        result = map_permission_risk(STALKERWARE_APK)
        breakdown = result["permission_breakdown"]
        for perm in result["high_risk_permissions"]:
            assert breakdown[perm] in ("Critical", "High"), (
                f"Unexpected tier for {perm}: {breakdown[perm]}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: APK Scoring Sub-Functions
# ══════════════════════════════════════════════════════════════════════════════

class TestAPKPermissionScoring:
    """Tests _score_apk_permissions() scoring sub-function."""

    def test_zero_permissions_scores_70(self):
        """0 total permissions -> unknown/neutral -> 70."""
        result = _score_apk_permissions({"overall_risk_score": 0, "total_permissions": 0})
        assert result == 70.0

    def test_low_risk_score_gives_high_trust(self):
        """overall_risk_score=10 -> trust = 100-10 = 90."""
        result = _score_apk_permissions({"overall_risk_score": 10, "total_permissions": 5})
        assert result == 90.0

    def test_high_risk_score_gives_low_trust(self):
        """overall_risk_score=90 -> trust = max(0, 100-90) = 10."""
        result = _score_apk_permissions({"overall_risk_score": 90, "total_permissions": 15})
        assert result == 10.0

    def test_volume_penalty_over_20_perms(self):
        """More than 20 permissions -> additional -10 penalty."""
        score_19 = _score_apk_permissions({"overall_risk_score": 20, "total_permissions": 19})
        score_21 = _score_apk_permissions({"overall_risk_score": 20, "total_permissions": 21})
        assert score_19 - score_21 == 10.0

    def test_volume_penalty_over_30_perms(self):
        """More than 30 permissions -> -15 penalty (greater than -10)."""
        score_19 = _score_apk_permissions({"overall_risk_score": 20, "total_permissions": 19})
        score_31 = _score_apk_permissions({"overall_risk_score": 20, "total_permissions": 31})
        assert score_19 - score_31 == 15.0

    def test_error_apk_scores_30(self):
        """Parse error -> assume high risk -> score 30."""
        result = _score_apk_permissions({"error": "Could not parse APK"})
        assert result == 30.0

    def test_score_never_below_zero(self):
        """Score must not go negative with max risk + volume penalty."""
        result = _score_apk_permissions({"overall_risk_score": 100, "total_permissions": 50})
        assert result >= 0.0


class TestAPKMetadataScoring:
    """Tests _score_apk_metadata() scoring sub-function."""

    def test_modern_sdk_34_scores_100(self):
        """Android 14 (SDK 34) -> fully modern -> 100."""
        result = _score_apk_metadata({"target_sdk": "34"})
        assert result == 100.0

    def test_boundary_sdk_26_scores_100(self):
        """Exactly SDK 26 -> boundary -> 100."""
        result = _score_apk_metadata({"target_sdk": "26"})
        assert result == 100.0

    def test_legacy_sdk_22_scores_70(self):
        """SDK 22 (Android 5.1) -> misses runtime permissions -> 70."""
        result = _score_apk_metadata({"target_sdk": "22"})
        assert result == 70.0

    def test_ancient_sdk_16_scores_40(self):
        """SDK 16 (Android 4.1) -> extremely old, untrusted -> 40."""
        result = _score_apk_metadata({"target_sdk": "16"})
        assert result == 40.0

    def test_extraction_error_scores_40(self):
        """Manifest parse failure -> conservative low score 40."""
        result = _score_apk_metadata({"error": "Manifest parse failed"})
        assert result == 40.0

    def test_missing_sdk_defaults_to_modern(self):
        """No SDK field in result -> defaults to 28 (Android 9) -> 100."""
        result = _score_apk_metadata({})
        assert result == 100.0


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: calculate_apk_trust_score() Integration Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAPKTrustScoreFusion:
    """Integration tests for the full APK trust score engine."""

    def test_clean_app_modern_sdk_is_low_risk(self):
        """Clean permissions (risk=10) + modern SDK -> Low Risk (>= 70)."""
        result = calculate_apk_trust_score({
            "risk":       {"overall_risk_score": 10, "total_permissions": 6, "error": None},
            "extraction": {"target_sdk": "34", "error": None},
        })
        assert result["overall_score"] >= 70.0
        assert result["risk_level"] == "Low"

    def test_stalkerware_is_high_risk(self):
        """Critical permissions + old SDK -> High Risk (< 40)."""
        result = calculate_apk_trust_score({
            "risk":       {"overall_risk_score": 95, "total_permissions": 21, "error": None},
            "extraction": {"target_sdk": "19", "error": None},  # Very old SDK
        })
        assert result["overall_score"] < 40.0
        assert result["risk_level"] == "High"

    def test_moderate_app_is_medium_risk(self):
        """Some High perms + modern SDK -> Medium Risk (40-70)."""
        result = calculate_apk_trust_score({
            "risk":       {"overall_risk_score": 45, "total_permissions": 12, "error": None},
            "extraction": {"target_sdk": "30", "error": None},
        })
        assert 40.0 <= result["overall_score"] < 70.0
        assert result["risk_level"] == "Medium"

    def test_result_has_all_required_keys(self):
        """API contract: response must include all required keys."""
        result = calculate_apk_trust_score({
            "risk":       {"overall_risk_score": 50, "total_permissions": 10},
            "extraction": {"target_sdk": "28"},
        })
        assert "overall_score" in result
        assert "risk_level" in result
        assert "breakdown" in result
        assert "Permission Risk Score" in result["breakdown"]
        assert "App Metadata Score" in result["breakdown"]

    def test_score_always_in_range(self):
        """Score must always be [0, 100] regardless of inputs."""
        result = calculate_apk_trust_score({
            "risk":       {"overall_risk_score": 200, "total_permissions": 100},
            "extraction": {"target_sdk": "1"},
        })
        assert 0.0 <= result["overall_score"] <= 100.0

    def test_empty_input_handled_gracefully(self):
        """Empty dicts must not crash the scorer."""
        result = calculate_apk_trust_score({"risk": {}, "extraction": {}})
        assert "overall_score" in result

    def test_permissions_75_percent_weight_dominates(self):
        """
        Permissions = 75% weight. Maximum permission risk = trust 0.
        Even with perfect metadata (25%) overall stays <= 25.
        """
        result = calculate_apk_trust_score({
            "risk":       {"overall_risk_score": 100, "total_permissions": 15, "error": None},
            "extraction": {"target_sdk": "34", "error": None},   # perfect metadata = 100
        })
        # 0*0.75 + 100*0.25 = 25.0
        assert result["overall_score"] <= 25.0
        assert result["risk_level"] == "High"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Realistic End-to-End APK Profile Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRealisticAPKProfiles:
    """
    End-to-end tests using real-world permission profiles.
    These demonstrate exactly what QFireNet produces for common app categories.
    """

    def test_profile_clean_maps_app(self):
        """Navigation app with location + internet -> should be trusted."""
        risk = map_permission_risk(CLEAN_MAPS_APP)
        result = calculate_apk_trust_score({
            "risk":       {**risk, "error": None},
            "extraction": {"target_sdk": "33", "error": None},
        })
        assert result["overall_score"] >= 55.0
        print(f"\n[PROFILE] Clean Maps App -> {result['overall_score']:.1f}/100 [{result['risk_level']} RISK]")

    def test_profile_stalkerware_apk(self):
        """Stalkerware with 8+ critical permissions + old SDK -> must be High Risk."""
        risk = map_permission_risk(STALKERWARE_APK)
        result = calculate_apk_trust_score({
            "risk":       {**risk, "error": None},
            "extraction": {"target_sdk": "19", "error": None},
        })
        assert result["risk_level"] == "High"
        assert result["overall_score"] < 40.0
        print(f"\n[PROFILE] Stalkerware APK -> {result['overall_score']:.1f}/100 [{result['risk_level']} RISK]")
        print(f"          Critical: {risk['tier_counts']['Critical']} | High: {risk['tier_counts']['High']}")
        print(f"          Flagged: {risk['high_risk_permissions'][:3]}...")

    def test_profile_moderate_social_app(self):
        """Social media app with camera + mic + contacts but no critical perms."""
        risk = map_permission_risk(MODERATE_RISK_APK)
        result = calculate_apk_trust_score({
            "risk":       {**risk, "error": None},
            "extraction": {"target_sdk": "31", "error": None},
        })
        print(f"\n[PROFILE] Moderate Social App -> {result['overall_score']:.1f}/100 [{result['risk_level']} RISK]")

    def test_profile_banking_app(self):
        """Legitimate banking app (biometrics + camera for cheque) -> Low or Medium."""
        risk = map_permission_risk(BANKING_APP_SAFE)
        result = calculate_apk_trust_score({
            "risk":       {**risk, "error": None},
            "extraction": {"target_sdk": "34", "error": None},
        })
        assert result["risk_level"] in ["Low", "Medium"]
        print(f"\n[PROFILE] Banking App -> {result['overall_score']:.1f}/100 [{result['risk_level']} RISK]")

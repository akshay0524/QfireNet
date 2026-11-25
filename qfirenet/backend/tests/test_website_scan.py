"""
tests/test_website_scan.py — Unit Tests for Website Scan Modules

Tests all four website signals:
  1. Phishing heuristics  (phishing_check.py)
  2. SSL scoring          (scoring/engine.py _score_ssl)
  3. WHOIS domain age     (scoring/engine.py _score_whois)
  4. PQC readiness        (scoring/engine.py _score_pqc)
  5. Full website trust score fusion

Each test is annotated with what it proves for the presentation.
"""

import pytest
import sys
import os

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.modules.website_scan.phishing_check import check_phishing_heuristics
from app.scoring.engine import (
    calculate_website_trust_score,
    _score_ssl,
    _score_whois,
    _score_pqc,
    _score_phishing,
    _get_risk_level,
)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Phishing Heuristics
# ══════════════════════════════════════════════════════════════════════════════

class TestPhishingHeuristics:
    """Tests the URL-based phishing heuristic engine."""

    def test_clean_google_url_is_safe(self):
        """google.com has no phishing signals -> heuristic_score should be 0."""
        result = check_phishing_heuristics("https://www.google.com")
        assert result["heuristic_score"] == 0
        assert result["risk_indicators"] == []

    def test_clean_github_url_is_safe(self):
        """github.com is a clean URL -> zero suspicion."""
        result = check_phishing_heuristics("https://github.com/torvalds/linux")
        assert result["heuristic_score"] == 0

    def test_ip_address_url_is_suspicious(self):
        """Phishing sites often use raw IP addresses instead of domain names."""
        result = check_phishing_heuristics("http://192.168.1.1/login/verify")
        assert result["heuristic_score"] > 0

    def test_at_symbol_in_url_is_suspicious(self):
        """The @ symbol confuses browsers about the real destination host."""
        result = check_phishing_heuristics("http://legit.com@malicious-site.xyz/steal")
        assert result["heuristic_score"] > 0
        assert any("@" in ind for ind in result["risk_indicators"])

    def test_high_risk_tld_flagged(self):
        """Free/abused TLDs like .tk, .ml, .xyz are commonly used in attacks."""
        result = check_phishing_heuristics("http://totally-real-bank.tk/secure/login")
        assert result["heuristic_score"] > 0

    def test_suspicious_keywords_flagged(self):
        """URLs with 'login', 'verify', 'account', 'password' etc. are flagged."""
        result = check_phishing_heuristics("http://paypal-verify-account-login.com")
        assert result["heuristic_score"] > 0

    def test_excessive_subdomains_flagged(self):
        """4+ subdomains is a phishing signal to obscure the real domain."""
        result = check_phishing_heuristics(
            "http://paypal.com.verify.account.login.malicious.xyz/"
        )
        assert result["heuristic_score"] > 0

    def test_very_long_url_flagged(self):
        """Phishing URLs are padded with noise to obscure the destination."""
        long_url = "http://secure-bank-verification.com/" + "a" * 150 + "/verify"
        result = check_phishing_heuristics(long_url)
        assert result["heuristic_score"] > 0

    def test_blatant_phishing_url_scores_high(self):
        """A URL with multiple stacked phishing signals should score >= 50."""
        result = check_phishing_heuristics(
            "http://192.168.1.1/paypal-secure-account-verify-login@phish.tk"
        )
        assert result["heuristic_score"] >= 50

    def test_result_has_required_keys(self):
        """API contract: result must always contain all required keys."""
        result = check_phishing_heuristics("https://example.com")
        required_keys = {"heuristic_score", "risk_indicators"}
        assert required_keys.issubset(set(result.keys()))

    def test_score_capped_at_100(self):
        """heuristic_score must never exceed 100 even with extreme inputs."""
        result = check_phishing_heuristics(
            "http://192.168.1.1@paypal-secure-account-verify-password-login-banking-"
            + "a" * 300 + ".tk/verify/confirm"
        )
        assert result["heuristic_score"] <= 100


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: SSL Score Sub-Function
# ══════════════════════════════════════════════════════════════════════════════

class TestSSLScoring:
    """Tests the SSL certificate scoring logic in isolation."""

    def test_valid_cert_long_validity_scores_100(self):
        """Certificate valid for 200 days -> full score 100."""
        assert _score_ssl({"is_valid": True, "days_until_expiry": 200}) == 100.0

    def test_cert_expiring_in_20_days_scores_65(self):
        """Cert expiring in 20 days -> warning score 65."""
        assert _score_ssl({"is_valid": True, "days_until_expiry": 20}) == 65.0

    def test_cert_expiring_in_10_days_scores_40(self):
        """Cert expiring in 10 days -> critical warning score 40."""
        assert _score_ssl({"is_valid": True, "days_until_expiry": 10}) == 40.0

    def test_expired_cert_scores_0(self):
        """Negative days -> already expired -> score 0."""
        assert _score_ssl({"is_valid": True, "days_until_expiry": -5}) == 0.0

    def test_invalid_cert_scores_0(self):
        """is_valid=False means hostname mismatch or untrusted CA -> score 0."""
        assert _score_ssl({"is_valid": False, "days_until_expiry": 300}) == 0.0

    def test_error_cert_scores_0(self):
        """Connection error -> assume worst case -> score 0."""
        assert _score_ssl({"error": "Connection refused"}) == 0.0

    def test_boundary_31_days_scores_100(self):
        """Exactly 31 days left still qualifies for full score."""
        assert _score_ssl({"is_valid": True, "days_until_expiry": 31}) == 100.0

    def test_boundary_14_days_scores_40(self):
        """Exactly 14 days left hits the critical threshold."""
        assert _score_ssl({"is_valid": True, "days_until_expiry": 14}) == 40.0


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: WHOIS Domain Age Score
# ══════════════════════════════════════════════════════════════════════════════

class TestWHOISScoring:
    """Tests the domain age scoring logic."""

    def test_domain_over_365_days_scores_100(self):
        assert _score_whois({"domain_age_days": 1095}) == 100.0

    def test_domain_6_to_12_months_scores_80(self):
        assert _score_whois({"domain_age_days": 270}) == 80.0

    def test_domain_3_to_6_months_scores_60(self):
        assert _score_whois({"domain_age_days": 120}) == 60.0

    def test_domain_1_to_3_months_scores_35(self):
        assert _score_whois({"domain_age_days": 60}) == 35.0

    def test_domain_under_30_days_scores_0(self):
        """Fresh throwaway domain -> maximum suspicion."""
        assert _score_whois({"domain_age_days": 15}) == 0.0

    def test_whois_redacted_scores_neutral_50(self):
        """Privacy-redacted WHOIS -> neutral 50 to avoid false positives."""
        assert _score_whois({"domain_age_days": None}) == 50.0

    def test_whois_error_scores_neutral_50(self):
        assert _score_whois({"error": "Timeout"}) == 50.0


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: PQC Readiness Score
# ══════════════════════════════════════════════════════════════════════════════

class TestPQCScoring:
    """Tests Post-Quantum Cryptography readiness scoring."""

    def test_pqc_ready_scores_100(self):
        """Sites using Kyber/ML-KEM hybrid key exchange get maximum bonus."""
        assert _score_pqc({"pqc_ready": True}) == 100.0

    def test_classical_tls_scores_60(self):
        """Classical TLS gets 60 -- not penalised since PQC adoption is early."""
        assert _score_pqc({"pqc_ready": False}) == 60.0

    def test_pqc_error_scores_neutral_50(self):
        assert _score_pqc({"error": "Socket timeout"}) == 50.0


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Risk Level Mapping
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskLevelMapping:
    """Tests the score -> risk level converter."""

    def test_score_100_is_low_risk(self):
        assert _get_risk_level(100.0) == "Low"

    def test_score_70_is_low_risk(self):
        assert _get_risk_level(70.0) == "Low"

    def test_score_69_is_medium_risk(self):
        assert _get_risk_level(69.0) == "Medium"

    def test_score_40_is_medium_risk(self):
        assert _get_risk_level(40.0) == "Medium"

    def test_score_39_is_high_risk(self):
        assert _get_risk_level(39.0) == "High"

    def test_score_0_is_high_risk(self):
        assert _get_risk_level(0.0) == "High"

    def test_boundary_70_is_low_not_medium(self):
        """Score exactly 70 should be LOW not MEDIUM."""
        assert _get_risk_level(70.0) == "Low"

    def test_boundary_40_is_medium_not_high(self):
        """Score exactly 40 should be MEDIUM not HIGH."""
        assert _get_risk_level(40.0) == "Medium"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: Full Website Trust Score Fusion (Integration Tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestWebsiteTrustScoreFusion:
    """Integration tests for the complete weighted fusion engine."""

    def test_perfect_site_scores_near_100(self):
        """All signals green -> trust score >= 90 (Low Risk)."""
        result = calculate_website_trust_score({
            "ssl":      {"is_valid": True, "days_until_expiry": 365},
            "whois":    {"domain_age_days": 2000},
            "phishing": {"heuristic_score": 0},
            "pqc":      {"pqc_ready": True},
        })
        assert result["overall_score"] >= 90.0
        assert result["risk_level"] == "Low"

    def test_phishing_site_scores_high_risk(self):
        """Fresh domain + blatant phishing URL + bad SSL -> HIGH RISK."""
        result = calculate_website_trust_score({
            "ssl":      {"error": "Certificate invalid"},
            "whois":    {"domain_age_days": 3},
            "phishing": {"heuristic_score": 90},
            "pqc":      {"pqc_ready": False},
        })
        assert result["overall_score"] < 40.0
        assert result["risk_level"] == "High"

    def test_medium_risk_new_legitimate_site(self):
        """Good SSL + 55-day old domain + moderate phishing score -> MEDIUM."""
        result = calculate_website_trust_score({
            "ssl":      {"is_valid": True, "days_until_expiry": 200},
            "whois":    {"domain_age_days": 55},
            "phishing": {"heuristic_score": 40},
            "pqc":      {"pqc_ready": False},
        })
        # SSL=100*0.25=25, WHOIS=35*0.25=8.75, Phishing=60*0.35=21, PQC=60*0.15=9 -> 63.75
        assert 40.0 <= result["overall_score"] < 70.0
        assert result["risk_level"] == "Medium"

    def test_result_structure_is_complete(self):
        """Verify the API response always contains all required keys."""
        result = calculate_website_trust_score({
            "ssl": {}, "whois": {}, "phishing": {"heuristic_score": 0}, "pqc": {}
        })
        assert "overall_score" in result
        assert "risk_level" in result
        assert "breakdown" in result
        assert isinstance(result["breakdown"], dict)

    def test_score_always_in_valid_range(self):
        """Score must always be between 0 and 100 inclusive."""
        result = calculate_website_trust_score({
            "ssl":      {"is_valid": False},
            "whois":    {"domain_age_days": 0},
            "phishing": {"heuristic_score": 100},
            "pqc":      {"error": "fail"},
        })
        assert 0.0 <= result["overall_score"] <= 100.0

    def test_missing_signals_dont_crash(self):
        """Missing keys must be handled gracefully."""
        result = calculate_website_trust_score({})
        assert "overall_score" in result
        assert 0.0 <= result["overall_score"] <= 100.0

    def test_phishing_weight_dominates(self):
        """
        Phishing at 35% is the single highest weight.
        Even with great SSL + old domain, extremely suspicious URL drags score below 70.
        """
        result = calculate_website_trust_score({
            "ssl":      {"is_valid": True, "days_until_expiry": 365},  # 100 x 0.25
            "whois":    {"domain_age_days": 2000},                      # 100 x 0.25
            "phishing": {"heuristic_score": 95},                        # 5 x 0.35 = 1.75
            "pqc":      {"pqc_ready": False},                           # 60 x 0.15
        })
        # 25 + 25 + 1.75 + 9 = 60.75 -> Medium
        assert result["overall_score"] < 70.0

    def test_breakdown_contains_all_signals(self):
        """Breakdown dict must list all four signal scores."""
        result = calculate_website_trust_score({
            "ssl":      {"is_valid": True, "days_until_expiry": 100},
            "whois":    {"domain_age_days": 500},
            "phishing": {"heuristic_score": 0},
            "pqc":      {"pqc_ready": False},
        })
        assert "SSL Certificate" in result["breakdown"]
        assert "Domain Age (WHOIS)" in result["breakdown"]
        assert "Phishing Heuristics" in result["breakdown"]
        assert "PQC Readiness" in result["breakdown"]

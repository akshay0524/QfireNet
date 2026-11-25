"""
tests/test_email_scan.py — Unit Tests for Email Scan Modules

Tests:
  1. Email header authentication (SPF / DKIM / DMARC parsing)
  2. Email content heuristics (urgency, credential requests, financial scams)
  3. Email trust score fusion (weighted scoring engine)
  4. Edge cases: missing headers, partial auth results

Each test uses realistic raw email snippets -- the same format users paste in.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.modules.email_scan.header_check import check_email_headers
from app.modules.email_scan.content_check import check_email_content
from app.scoring.engine import (
    calculate_email_trust_score,
    _score_email_headers,
    _score_email_content,
)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Email Header Authentication
# ══════════════════════════════════════════════════════════════════════════════

# ── Realistic raw email header samples ───────────────────────────────────────

HEADERS_ALL_PASS = """
Delivered-To: user@example.com
From: noreply@paypal.com
Return-Path: <noreply@paypal.com>
Reply-To: noreply@paypal.com
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of noreply@paypal.com designates 66.211.168.1 as permitted sender) smtp.mailfrom=noreply@paypal.com;
       dkim=pass header.i=@paypal.com header.s=pp-dkim1 header.b=signature123;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
"""

HEADERS_ALL_FAIL = """
Delivered-To: victim@example.com
From: security@paypa1.com
Return-Path: <bounce@malicious-server.ru>
Reply-To: hacker@gmail.com
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of security@paypa1.com does not designate any permitted senders) smtp.mailfrom=security@paypa1.com;
       dkim=fail reason="signature verification failed";
       dmarc=fail (p=REJECT sp=REJECT) header.from=paypa1.com
"""

HEADERS_PARTIAL_PASS = """
From: info@mystore.com
Return-Path: <info@mystore.com>
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=mystore.com;
       dkim=pass header.i=@mystore.com;
       dmarc=none
"""

HEADERS_DOMAIN_MISMATCH = """
From: secure@amazon.com
Return-Path: <noreply@amazn-accounts.net>
Reply-To: support@harvester.xyz
Authentication-Results: mx.google.com;
       spf=softfail smtp.mailfrom=amazn-accounts.net;
       dkim=none;
       dmarc=fail header.from=amazon.com
"""

HEADERS_NO_AUTH = """
From: someone@example.com
Subject: Hello
Date: Mon, 15 Sep 2025 10:00:00 +0530
"""


class TestEmailHeaderParsing:
    """Tests authentication header parsing: SPF, DKIM, DMARC detection."""

    def test_all_pass_headers_are_trusted(self):
        """Email with SPF+DKIM+DMARC all passing -> fully trusted authentication."""
        result = check_email_headers(HEADERS_ALL_PASS)
        assert result["spf_pass"] is True, "SPF should pass"
        assert result["dkim_pass"] is True, "DKIM should pass"
        assert result["dmarc_pass"] is True, "DMARC should pass"
        assert result["sender_domain_mismatch"] is False
        assert result["reply_to_mismatch"] is False

    def test_all_fail_headers_are_untrusted(self):
        """Email where all auth checks fail -> multiple red flags detected."""
        result = check_email_headers(HEADERS_ALL_FAIL)
        assert result["spf_pass"] is False, "SPF should fail"
        assert result["dkim_pass"] is False, "DKIM should fail"
        assert result["dmarc_pass"] is False, "DMARC should fail"

    def test_partial_pass_detected(self):
        """Email with SPF+DKIM pass but no DMARC -> partial authentication."""
        result = check_email_headers(HEADERS_PARTIAL_PASS)
        assert result["spf_pass"] is True
        assert result["dkim_pass"] is True
        assert result["dmarc_pass"] is False  # dmarc=none means no policy

    def test_domain_mismatch_detected(self):
        """From: amazon.com but Return-Path: amazn-accounts.net -> spoofing red flag."""
        result = check_email_headers(HEADERS_DOMAIN_MISMATCH)
        assert result["sender_domain_mismatch"] is True

    def test_no_auth_headers_handled_gracefully(self):
        """Email without authentication headers -> has_headers=False -> neutral result."""
        result = check_email_headers(HEADERS_NO_AUTH)
        # Should not crash; should return a result with has_headers indicator
        assert isinstance(result, dict)
        assert "spf_pass" in result

    def test_result_always_has_required_keys(self):
        """API contract: response always has all required keys."""
        result = check_email_headers(HEADERS_ALL_PASS)
        required = {"spf_pass", "dkim_pass", "dmarc_pass",
                    "sender_domain_mismatch", "reply_to_mismatch"}
        assert required.issubset(set(result.keys()))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: Email Content Heuristics
# ══════════════════════════════════════════════════════════════════════════════

# ── Realistic email body samples ─────────────────────────────────────────────

LEGIT_ORDER_EMAIL = """
Hi John,

Thank you for your recent purchase of Running Shoes (Size 10).

Your order #12345 has been shipped and will arrive by Wednesday.
You can track your delivery at: https://www.amazon.com/orders/track/12345

Best regards,
Amazon Customer Service
"""

PHISHING_BANK_EMAIL = """
Dear Customer,

Your account has been suspended due to unusual activity. You must verify your
identity immediately or your account will be permanently closed within 24 hours.

Act now: click here to verify your account and reset your password:
http://192.168.1.1/secure-login-verify.php

Please provide your OTP, username, and banking credentials to restore access.

URGENT: Final notice — failure to act immediately will result in permanent suspension.
"""

SCAM_LOTTERY_EMAIL = """
Congratulations! You have won $5,000,000 in the Microsoft International Lottery!

To claim your prize, wire transfer the processing fee of $500 via Western Union
to the claims office. Send your credit card details and SSN to claims@lottery-win.tk

You must respond within 24 hours or forfeit your winnings.
"""

GIFT_CARD_SCAM_EMAIL = """
Hello,

I need you to urgently purchase iTunes gift cards worth $500 and send me the
codes. It's very important. Please act now — I will explain later.

Please do not tell anyone about this request.
"""

LEGITIMATE_NEWSLETTER = """
Hi there,

Here's your weekly roundup from TechCrunch:

- Google announces new AI features
- Apple releases iOS update
- Meta reports quarterly earnings

Read more at techcrunch.com

You can unsubscribe at any time from our newsletter portal.
"""


class TestEmailContentHeuristics:
    """Tests the email body content heuristic scanner."""

    def test_legitimate_order_email_scores_low_suspicion(self):
        """A real order confirmation email should have very low or zero suspicion."""
        result = check_email_content(LEGIT_ORDER_EMAIL)
        # Legitimate order emails might trigger some keywords but should stay relatively low
        assert result["heuristic_score"] < 30, (
            f"Legit order email scored too high: {result['heuristic_score']}"
        )

    def test_phishing_bank_email_scores_very_high_suspicion(self):
        """Classic phishing email with urgency + credentials + threats -> HIGH score."""
        result = check_email_content(PHISHING_BANK_EMAIL)
        assert result["heuristic_score"] >= 60, (
            f"Bank phishing email should score >=60, got {result['heuristic_score']}"
        )
        assert len(result["risk_indicators"]) > 0

    def test_lottery_scam_email_scores_very_high(self):
        """Lottery scam with wire transfer + prize claims -> very HIGH suspicion."""
        result = check_email_content(SCAM_LOTTERY_EMAIL)
        assert result["heuristic_score"] >= 60, (
            f"Lottery scam email should score >=60, got {result['heuristic_score']}"
        )

    def test_gift_card_scam_scores_high(self):
        """Gift card scam is a very common fraud vector -> should be flagged."""
        result = check_email_content(GIFT_CARD_SCAM_EMAIL)
        assert result["heuristic_score"] > 20

    def test_legitimate_newsletter_scores_low(self):
        """Tech newsletter has no scam signals -> should score near 0."""
        result = check_email_content(LEGITIMATE_NEWSLETTER)
        assert result["heuristic_score"] < 25

    def test_result_always_has_required_keys(self):
        """API contract: response always has all required keys."""
        result = check_email_content(LEGIT_ORDER_EMAIL)
        required = {"heuristic_score", "risk_indicators"}
        assert required.issubset(set(result.keys()))

    def test_score_capped_at_100(self):
        """Even with extreme scam content, score must not exceed 100."""
        result = check_email_content(PHISHING_BANK_EMAIL + SCAM_LOTTERY_EMAIL)
        assert result["heuristic_score"] <= 100

    def test_score_not_negative(self):
        """Score must always be >= 0."""
        result = check_email_content(LEGITIMATE_NEWSLETTER)
        assert result["heuristic_score"] >= 0

    def test_empty_body_handled_gracefully(self):
        """Empty body should not crash the module."""
        result = check_email_content("")
        assert isinstance(result, dict)
        assert "heuristic_score" in result


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: Email Trust Score Scoring Engine
# ══════════════════════════════════════════════════════════════════════════════

class TestEmailHeaderScoring:
    """Tests _score_email_headers() sub-function."""

    def test_all_pass_scores_100(self):
        """SPF + DKIM + DMARC all passing = perfect 100."""
        result = _score_email_headers({
            "has_headers": True,
            "spf_pass": True,
            "dkim_pass": True,
            "dmarc_pass": True,
            "sender_domain_mismatch": False,
            "reply_to_mismatch": False,
        })
        assert result == 100.0

    def test_all_fail_scores_0(self):
        """No auth passing = 0."""
        result = _score_email_headers({
            "has_headers": True,
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "sender_domain_mismatch": False,
            "reply_to_mismatch": False,
        })
        assert result == 0.0

    def test_domain_mismatch_deducts_points(self):
        """Domain mismatch applies -20 penalty on top of auth score."""
        score_no_mismatch = _score_email_headers({
            "has_headers": True, "spf_pass": True, "dkim_pass": True,
            "dmarc_pass": True, "sender_domain_mismatch": False, "reply_to_mismatch": False,
        })
        score_with_mismatch = _score_email_headers({
            "has_headers": True, "spf_pass": True, "dkim_pass": True,
            "dmarc_pass": True, "sender_domain_mismatch": True, "reply_to_mismatch": False,
        })
        assert score_with_mismatch < score_no_mismatch
        assert score_with_mismatch == 80.0  # 100 - 20

    def test_no_headers_scores_neutral_50(self):
        """Email without authentication headers -> neutral 50."""
        result = _score_email_headers({"has_headers": False})
        assert result == 50.0

    def test_partial_auth_scores_partial(self):
        """Only SPF passes -> 33 points."""
        result = _score_email_headers({
            "has_headers": True,
            "spf_pass": True,
            "dkim_pass": False,
            "dmarc_pass": False,
            "sender_domain_mismatch": False,
            "reply_to_mismatch": False,
        })
        assert result == 33.0

    def test_score_never_below_0(self):
        """Multiple penalties should not push score below 0."""
        result = _score_email_headers({
            "has_headers": True,
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
            "sender_domain_mismatch": True,
            "reply_to_mismatch": True,
        })
        assert result >= 0.0


class TestEmailTrustScoreFusion:
    """Integration tests for the email weighted scoring engine."""

    def test_fully_authenticated_clean_email_scores_high(self):
        """Legit email: all auth passes + clean content -> Low Risk."""
        result = calculate_email_trust_score({
            "headers": {
                "has_headers": True, "spf_pass": True, "dkim_pass": True,
                "dmarc_pass": True, "sender_domain_mismatch": False, "reply_to_mismatch": False,
            },
            "content": {"heuristic_score": 0},
        })
        assert result["overall_score"] >= 70.0
        assert result["risk_level"] == "Low"

    def test_phishing_email_scores_high_risk(self):
        """Failed auth + high suspicion content -> High Risk."""
        result = calculate_email_trust_score({
            "headers": {
                "has_headers": True, "spf_pass": False, "dkim_pass": False,
                "dmarc_pass": False, "sender_domain_mismatch": True, "reply_to_mismatch": True,
            },
            "content": {"heuristic_score": 85},
        })
        assert result["overall_score"] < 40.0
        assert result["risk_level"] == "High"

    def test_no_headers_with_scam_content_is_medium_or_high(self):
        """Missing auth + moderate scam content -> Medium or High risk."""
        result = calculate_email_trust_score({
            "headers": {"has_headers": False},
            "content": {"heuristic_score": 55},
        })
        assert result["overall_score"] < 70.0

    def test_result_has_required_keys(self):
        result = calculate_email_trust_score({
            "headers": {"has_headers": False},
            "content": {"heuristic_score": 0},
        })
        assert "overall_score" in result
        assert "risk_level" in result
        assert "breakdown" in result

    def test_lookalike_domain_penalty_applied(self):
        """Domain lookalike detection applies extra -15 point penalty."""
        result_no_lookalike = calculate_email_trust_score(
            email_results={
                "headers": {
                    "has_headers": True, "spf_pass": True, "dkim_pass": True,
                    "dmarc_pass": True, "sender_domain_mismatch": False, "reply_to_mismatch": False,
                },
                "content": {"heuristic_score": 10},
            }
        )
        result_with_lookalike = calculate_email_trust_score(
            email_results={
                "headers": {
                    "has_headers": True, "spf_pass": True, "dkim_pass": True,
                    "dmarc_pass": True, "sender_domain_mismatch": False, "reply_to_mismatch": False,
                },
                "content": {"heuristic_score": 10},
            },
            domain_check={"is_lookalike": True, "is_known_safe": False},
        )
        assert result_with_lookalike["overall_score"] < result_no_lookalike["overall_score"]

    def test_llm_confidence_blended_when_provided(self):
        """When LLM confidence is provided, breakdown should include LLM Confidence key."""
        result = calculate_email_trust_score(
            email_results={
                "headers": {
                    "has_headers": True, "spf_pass": True, "dkim_pass": False,
                    "dmarc_pass": False, "sender_domain_mismatch": False, "reply_to_mismatch": False,
                },
                "content": {"heuristic_score": 30},
            },
            llm_confidence=80,
        )
        assert "LLM Confidence" in result["breakdown"]
        assert result["breakdown"]["LLM Confidence"] == 80.0

    def test_score_always_between_0_and_100(self):
        """Score must always be within [0, 100] regardless of inputs."""
        result = calculate_email_trust_score({
            "headers": {
                "has_headers": True, "spf_pass": False, "dkim_pass": False,
                "dmarc_pass": False, "sender_domain_mismatch": True, "reply_to_mismatch": True,
            },
            "content": {"heuristic_score": 100},
        })
        assert 0.0 <= result["overall_score"] <= 100.0

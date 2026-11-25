"""
seed_demo_data.py — Populate the database with realistic demo scan records.

Creates (or reuses) a demo user account and inserts a rich set of scam /
non-scam scan results across all three scan types (website, email, APK).

Usage (from the backend/ directory):
    python seed_demo_data.py

The demo account credentials:
    Email    : demo@qfirenet.com
    Password : Demo@12345
"""

import sys
import os
from datetime import datetime, timedelta, timezone

# Make sure `app` is importable
sys.path.insert(0, os.path.dirname(__file__))

from app.database import SessionLocal, engine, Base
from app.models.user import User
from app.models.scan import ScanResult
import app.models.threat_event  # noqa: F401 - ensure all tables are registered

# Create tables if they don't exist yet
Base.metadata.create_all(bind=engine, checkfirst=True)

from passlib.context import CryptContext
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

DEMO_EMAIL    = "demo@qfirenet.com"
DEMO_PASSWORD = "Demo@12345"


def _ago(days: float, hours: float = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days, hours=hours)


SEED_SCANS = [

    # ======================================================================
    # WEBSITE SCANS - SCAM / HIGH RISK
    # ======================================================================
    {
        "scan_type":     "website",
        "input_summary": "http://192.168.1.1/paypal-login-verify",
        "trust_score":   8.5,
        "risk_level":    "High",
        "scanned_at":    _ago(1, 3),
        "explanation": (
            "This URL uses a raw IP address instead of a domain name - a classic phishing "
            "tactic to hide the real host. The path /paypal-login-verify mimics PayPal's "
            "login flow. No valid SSL certificate was found, WHOIS data is completely "
            "redacted (registered 3 days ago), and multiple phishing keywords were "
            "detected in the URL. Treat this as a confirmed phishing page."
        ),
        "raw_results": {
            "phishing_score": 98,
            "ssl_score":      0,
            "whois_score":    0,
            "pqc_score":      0,
            "breakdown": {
                "Phishing Heuristics": 2,
                "SSL Certificate":     0,
                "WHOIS / Domain Age":  0,
                "PQC Readiness":       0,
            },
            "flags": [
                "IP address used instead of domain",
                "Keyword: login",
                "Keyword: verify",
                "Brand impersonation: paypal",
                "Domain registered < 7 days ago",
                "No valid SSL certificate",
            ],
        },
    },

    {
        "scan_type":     "website",
        "input_summary": "https://amazon-giftt-claim.tk/redeem?code=FREE500",
        "trust_score":   11.0,
        "risk_level":    "High",
        "scanned_at":    _ago(3, 1),
        "explanation": (
            "This site uses the .tk free-domain TLD heavily abused by scammers. "
            "The subdomain 'amazon-giftt' (double-t) is a typosquatting attempt on Amazon. "
            "A free gift-card lure in the URL path is a textbook social-engineering trick. "
            "SSL was self-signed and expired 14 days ago. Domain age: 11 days."
        ),
        "raw_results": {
            "phishing_score": 95,
            "ssl_score":      0,
            "whois_score":    0,
            "pqc_score":      50,
            "breakdown": {
                "Phishing Heuristics": 5,
                "SSL Certificate":     0,
                "WHOIS / Domain Age":  0,
                "PQC Readiness":       50,
            },
            "flags": [
                "High-risk TLD: .tk",
                "Typosquatting: amazon -> amazon-giftt",
                "Keyword: giftt, claim, redeem, FREE",
                "SSL certificate expired",
                "Domain age: 11 days",
            ],
        },
    },

    {
        "scan_type":     "website",
        "input_summary": "https://secure-banking-update.xyz/hdfc/login",
        "trust_score":   14.3,
        "risk_level":    "High",
        "scanned_at":    _ago(6, 2),
        "explanation": (
            "The .xyz TLD combined with 'secure-banking-update' is a hallmark phishing pattern. "
            "Attackers use alarming words like 'secure' and 'update' to create urgency. "
            "The path impersonates HDFC Bank's login portal. SSL is from a free issuer with "
            "a 30-day expiry. Domain was registered 18 days ago."
        ),
        "raw_results": {
            "phishing_score": 91,
            "ssl_score":      25,
            "whois_score":    0,
            "pqc_score":      50,
            "breakdown": {
                "Phishing Heuristics": 9,
                "SSL Certificate":     25,
                "WHOIS / Domain Age":  0,
                "PQC Readiness":       50,
            },
            "flags": [
                "High-risk TLD: .xyz",
                "Keyword: secure, banking, update, login",
                "Brand impersonation: hdfc",
                "SSL: Let's Encrypt 30-day cert (suspicious for a bank)",
                "Domain age: 18 days",
            ],
        },
    },

    {
        "scan_type":     "website",
        "input_summary": "http://netflix-reactivate.ru/account?token=xR8kP2",
        "trust_score":   6.0,
        "risk_level":    "High",
        "scanned_at":    _ago(10),
        "explanation": (
            "The .ru TLD for a Netflix reactivation page is immediately suspicious. "
            "Netflix operates exclusively on netflix.com domains. The token parameter is "
            "likely used for tracking victims. No HTTPS - all data transmitted in plain text. "
            "The domain was created 4 days ago."
        ),
        "raw_results": {
            "phishing_score": 97,
            "ssl_score":      0,
            "whois_score":    0,
            "pqc_score":      0,
            "breakdown": {
                "Phishing Heuristics": 3,
                "SSL Certificate":     0,
                "WHOIS / Domain Age":  0,
                "PQC Readiness":       0,
            },
            "flags": [
                "High-risk TLD: .ru",
                "Brand impersonation: netflix",
                "Keyword: reactivate, account, token",
                "No HTTPS (plain HTTP)",
                "Domain age: 4 days",
            ],
        },
    },

    # ======================================================================
    # WEBSITE SCANS - LEGITIMATE / LOW RISK
    # ======================================================================
    {
        "scan_type":     "website",
        "input_summary": "https://www.google.com",
        "trust_score":   97.5,
        "risk_level":    "Low",
        "scanned_at":    _ago(2),
        "explanation": (
            "Google.com is one of the most established domains on the internet, registered "
            "in 1997. The SSL certificate is valid for 90 days and issued by Google Trust "
            "Services. PQC readiness was detected via X25519Kyber768 hybrid key exchange. "
            "No phishing signals were found. This is a fully trusted domain."
        ),
        "raw_results": {
            "phishing_score": 0,
            "ssl_score":      100,
            "whois_score":    100,
            "pqc_score":      100,
            "breakdown": {
                "Phishing Heuristics": 100,
                "SSL Certificate":     100,
                "WHOIS / Domain Age":  100,
                "PQC Readiness":       100,
            },
            "flags": [],
            "pqc_details": {
                "status": "pqc_ready",
                "algorithm": "X25519Kyber768",
            },
        },
    },

    {
        "scan_type":     "website",
        "input_summary": "https://github.com",
        "trust_score":   95.2,
        "risk_level":    "Low",
        "scanned_at":    _ago(5),
        "explanation": (
            "GitHub.com is owned by Microsoft and has been a trusted platform since 2008. "
            "SSL is valid with an EV certificate from DigiCert. Domain age exceeds 15 years. "
            "PQC support is partially deployed. No phishing signals detected."
        ),
        "raw_results": {
            "phishing_score": 2,
            "ssl_score":      100,
            "whois_score":    100,
            "pqc_score":      60,
            "breakdown": {
                "Phishing Heuristics": 98,
                "SSL Certificate":     100,
                "WHOIS / Domain Age":  100,
                "PQC Readiness":       60,
            },
            "flags": [],
        },
    },

    {
        "scan_type":     "website",
        "input_summary": "https://www.sbi.co.in",
        "trust_score":   88.7,
        "risk_level":    "Low",
        "scanned_at":    _ago(8, 4),
        "explanation": (
            "State Bank of India's official domain. SSL certificate is valid and issued by "
            "DigiCert SHA2 Extended Validation Server CA. Domain registered since 1995. "
            "PQC readiness is not yet deployed (classical TLS 1.3 only), which is common "
            "for Indian banking infrastructure. No phishing signals detected."
        ),
        "raw_results": {
            "phishing_score": 3,
            "ssl_score":      100,
            "whois_score":    100,
            "pqc_score":      60,
            "breakdown": {
                "Phishing Heuristics": 97,
                "SSL Certificate":     100,
                "WHOIS / Domain Age":  100,
                "PQC Readiness":       60,
            },
            "flags": [],
        },
    },

    {
        "scan_type":     "website",
        "input_summary": "https://stackoverflow.com/questions/tagged/python",
        "trust_score":   93.1,
        "risk_level":    "Low",
        "scanned_at":    _ago(15),
        "explanation": (
            "Stack Overflow is a well-established developer community owned by Stack Exchange "
            "Inc., founded in 2008. Valid SSL from DigiCert. Domain age: 16+ years. "
            "No phishing signals. PQC not yet deployed."
        ),
        "raw_results": {
            "phishing_score": 1,
            "ssl_score":      100,
            "whois_score":    100,
            "pqc_score":      60,
            "breakdown": {
                "Phishing Heuristics": 99,
                "SSL Certificate":     100,
                "WHOIS / Domain Age":  100,
                "PQC Readiness":       60,
            },
            "flags": [],
        },
    },

    # ======================================================================
    # WEBSITE SCANS - MEDIUM RISK
    # ======================================================================
    {
        "scan_type":     "website",
        "input_summary": "https://quickloan-apply.online/personal",
        "trust_score":   42.0,
        "risk_level":    "Medium",
        "scanned_at":    _ago(4, 5),
        "explanation": (
            "This site uses a keyword-heavy domain ('quickloan-apply') on the .online TLD - "
            "a pattern common in both legitimate fintech startups and predatory loan scams. "
            "SSL is valid (Let's Encrypt). Domain age is 7 months - too recent for a financial "
            "service to be fully trusted. No active phishing indicators, but caution is warranted."
        ),
        "raw_results": {
            "phishing_score": 35,
            "ssl_score":      90,
            "whois_score":    35,
            "pqc_score":      50,
            "breakdown": {
                "Phishing Heuristics": 65,
                "SSL Certificate":     90,
                "WHOIS / Domain Age":  35,
                "PQC Readiness":       50,
            },
            "flags": [
                "Suspicious TLD: .online",
                "Keyword: loan, apply",
                "Domain age: 7 months (borderline)",
            ],
        },
    },

    # ======================================================================
    # EMAIL SCANS - SCAM / HIGH RISK
    # ======================================================================
    {
        "scan_type":     "email",
        "input_summary": "noreply@paypa1-security.com",
        "trust_score":   7.2,
        "risk_level":    "High",
        "scanned_at":    _ago(1, 6),
        "explanation": (
            "The sender domain 'paypa1-security.com' is a typosquat of PayPal - the digit '1' "
            "replaces the letter 'l'. SPF: FAIL. DKIM: FAIL. DMARC: not published. The email "
            "body contained extreme urgency: 'Your account will be suspended in 24 hours - verify "
            "now!' with a suspicious link to an IP address. Confirmed phishing email."
        ),
        "raw_results": {
            "header_score":  0,
            "content_score": 3,
            "breakdown": {
                "Header Authentication": 0,
                "Content Heuristics":    3,
                "Domain Reputation":     2,
                "Sender Analysis":       5,
            },
            "auth_results": {
                "spf":   "fail",
                "dkim":  "fail",
                "dmarc": "none",
            },
            "content_flags": [
                "Urgency: account suspended in 24 hours",
                "Action demanded: verify now",
                "Suspicious link: IP address href",
                "Brand impersonation: PayPal",
                "Keyword: password, verify, account",
            ],
            "domain_lookalike": True,
            "lookalike_target": "paypal.com",
        },
    },

    {
        "scan_type":     "email",
        "input_summary": "winner@lottery-international-prize.xyz",
        "trust_score":   4.5,
        "risk_level":    "High",
        "scanned_at":    _ago(7, 2),
        "explanation": (
            "Textbook advance-fee fraud (419 scam). Claims the recipient won 1,500,000 GBP in "
            "an international lottery they never entered. Requests personal info and a $150 "
            "'processing fee'. SPF and DKIM both fail. The .xyz domain was registered 3 weeks "
            "ago. Over 12 high-confidence scam keywords detected including 'congratulations', "
            "'prize', 'claim', 'confidential', and 'processing fee'."
        ),
        "raw_results": {
            "header_score":  0,
            "content_score": 2,
            "breakdown": {
                "Header Authentication": 0,
                "Content Heuristics":    2,
                "Domain Reputation":     3,
                "Sender Analysis":       4,
            },
            "auth_results": {
                "spf":   "fail",
                "dkim":  "fail",
                "dmarc": "none",
            },
            "content_flags": [
                "Lottery scam pattern detected",
                "Keywords: prize, winner, congratulations, claim",
                "Keywords: processing fee, bank details, confidential",
                "Requested personal info: bank account number",
                "High-risk TLD: .xyz",
                "Domain age: 3 weeks",
            ],
        },
    },

    {
        "scan_type":     "email",
        "input_summary": "support@amazon-delivery-alert.net",
        "trust_score":   12.0,
        "risk_level":    "High",
        "scanned_at":    _ago(12, 3),
        "explanation": (
            "Impersonates Amazon's delivery notification system. The domain "
            "'amazon-delivery-alert.net' is not affiliated with Amazon (which uses amazon.com). "
            "DKIM passes (attackers set up valid DKIM for their own domain), but SPF fails and "
            "DMARC is absent. Body prompts user to 'confirm your address' via a data-harvesting form."
        ),
        "raw_results": {
            "header_score":  20,
            "content_score": 8,
            "breakdown": {
                "Header Authentication": 20,
                "Content Heuristics":    8,
                "Domain Reputation":     5,
                "Sender Analysis":       10,
            },
            "auth_results": {
                "spf":   "fail",
                "dkim":  "pass",
                "dmarc": "none",
            },
            "content_flags": [
                "Brand impersonation: Amazon",
                "Keyword: delivery, confirm, address, package",
                "Data harvesting form link detected",
                "Domain mismatch: sender != amazon.com",
            ],
            "domain_lookalike": True,
            "lookalike_target": "amazon.com",
        },
    },

    {
        "scan_type":     "email",
        "input_summary": "irs-refund@tax-gov-usa.com",
        "trust_score":   5.8,
        "risk_level":    "High",
        "scanned_at":    _ago(20, 1),
        "explanation": (
            "Impersonates the US Internal Revenue Service. The real IRS only uses irs.gov - "
            "any email from a non-.gov domain claiming to be the IRS is fraudulent. This email "
            "claims the recipient is owed a $3,200 tax refund and must 'verify their SSN and "
            "bank account' within 48 hours. SPF: fail, DKIM: fail. Government impersonation scam."
        ),
        "raw_results": {
            "header_score":  0,
            "content_score": 3,
            "breakdown": {
                "Header Authentication": 0,
                "Content Heuristics":    3,
                "Domain Reputation":     2,
                "Sender Analysis":       3,
            },
            "auth_results": {
                "spf":   "fail",
                "dkim":  "fail",
                "dmarc": "none",
            },
            "content_flags": [
                "Government impersonation: IRS",
                "Keyword: refund, verify, SSN, bank account",
                "Urgency: 48 hours",
                "Domain impersonates .gov (not actually .gov)",
                "Sensitive data requested: Social Security Number",
            ],
        },
    },

    # ======================================================================
    # EMAIL SCANS - LEGITIMATE / LOW RISK
    # ======================================================================
    {
        "scan_type":     "email",
        "input_summary": "no-reply@accounts.google.com",
        "trust_score":   96.0,
        "risk_level":    "Low",
        "scanned_at":    _ago(3, 2),
        "explanation": (
            "Google account security notification. Sender domain accounts.google.com is a "
            "legitimate Google subdomain. SPF: pass, DKIM: pass (signed with google.com), "
            "DMARC: pass (strict policy p=reject). No urgency language, no suspicious links. "
            "Standard 2FA code notification. Fully trusted."
        ),
        "raw_results": {
            "header_score":  100,
            "content_score": 95,
            "breakdown": {
                "Header Authentication": 100,
                "Content Heuristics":    95,
                "Domain Reputation":     100,
                "Sender Analysis":       100,
            },
            "auth_results": {
                "spf":   "pass",
                "dkim":  "pass",
                "dmarc": "pass",
            },
            "content_flags": [],
        },
    },

    {
        "scan_type":     "email",
        "input_summary": "receipts@stripe.com",
        "trust_score":   94.5,
        "risk_level":    "Low",
        "scanned_at":    _ago(9),
        "explanation": (
            "Payment receipt from Stripe - a well-known payment processor (established 2010). "
            "SPF: pass, DKIM: pass, DMARC: pass. Email contains a standard payment receipt "
            "with order number and amount. No suspicious links or requests for sensitive info."
        ),
        "raw_results": {
            "header_score":  100,
            "content_score": 92,
            "breakdown": {
                "Header Authentication": 100,
                "Content Heuristics":    92,
                "Domain Reputation":     100,
                "Sender Analysis":       100,
            },
            "auth_results": {
                "spf":   "pass",
                "dkim":  "pass",
                "dmarc": "pass",
            },
            "content_flags": [],
        },
    },

    {
        "scan_type":     "email",
        "input_summary": "noreply@github.com",
        "trust_score":   95.8,
        "risk_level":    "Low",
        "scanned_at":    _ago(14, 6),
        "explanation": (
            "GitHub pull request notification from noreply@github.com. "
            "SPF: pass, DKIM: pass (signed with github.com), DMARC: pass. "
            "All links point to github.com. No phishing signals detected."
        ),
        "raw_results": {
            "header_score":  100,
            "content_score": 96,
            "breakdown": {
                "Header Authentication": 100,
                "Content Heuristics":    96,
                "Domain Reputation":     100,
                "Sender Analysis":       100,
            },
            "auth_results": {
                "spf":   "pass",
                "dkim":  "pass",
                "dmarc": "pass",
            },
            "content_flags": [],
        },
    },

    # ======================================================================
    # EMAIL SCANS - MEDIUM RISK
    # ======================================================================
    {
        "scan_type":     "email",
        "input_summary": "deals@shopdeals-today.net",
        "trust_score":   48.0,
        "risk_level":    "Medium",
        "scanned_at":    _ago(11, 4),
        "explanation": (
            "Promotional email from a lesser-known deals site. SPF passes but DKIM is absent "
            "and DMARC is not configured. Marketing keywords ('limited time offer', 'exclusive "
            "deal', 'click now') overlap with phishing patterns, but no brand impersonation or "
            "data harvesting detected. Domain age: 8 months. Likely legitimate but low-quality marketing."
        ),
        "raw_results": {
            "header_score":  55,
            "content_score": 45,
            "breakdown": {
                "Header Authentication": 55,
                "Content Heuristics":    45,
                "Domain Reputation":     50,
                "Sender Analysis":       48,
            },
            "auth_results": {
                "spf":   "pass",
                "dkim":  "none",
                "dmarc": "none",
            },
            "content_flags": [
                "Marketing keywords: limited offer, exclusive, click now",
                "No DKIM signature",
                "No DMARC policy",
                "Domain age: 8 months",
            ],
        },
    },

    # ======================================================================
    # APK SCANS - SCAM / HIGH RISK
    # ======================================================================
    {
        "scan_type":     "apk",
        "input_summary": "FlashLoan_v3.2_cracked.apk",
        "trust_score":   9.5,
        "risk_level":    "High",
        "scanned_at":    _ago(2, 8),
        "explanation": (
            "This APK claims to be a cracked loan app but exhibits stalkerware behaviour. "
            "Requests 23 permissions including READ_SMS (intercept OTPs), RECORD_AUDIO "
            "(covert microphone), ACCESS_FINE_LOCATION, CAMERA, and SEND_SMS. The manifest "
            "contains 4 embedded URLs pointing to known malware C2 servers. Package name "
            "(com.hacker.flashloan) is non-standard. Data-stealing trojan masquerading as a "
            "financial tool."
        ),
        "raw_results": {
            "permission_score":  5,
            "metadata_score":    12,
            "breakdown": {
                "Permission Risk":  5,
                "App Metadata":     12,
                "Embedded URLs":    0,
                "Manifest Flags":   8,
            },
            "permissions": {
                "critical": ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "PROCESS_OUTGOING_CALLS"],
                "high":     ["ACCESS_FINE_LOCATION", "CAMERA", "READ_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG"],
                "medium":   ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "FOREGROUND_SERVICE"],
                "normal":   ["INTERNET", "ACCESS_NETWORK_STATE"],
            },
            "flagged_permissions": ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "PROCESS_OUTGOING_CALLS"],
            "embedded_urls": [
                "http://185.220.101.45/upload",
                "http://c2server-hacked.ru/beacon",
            ],
            "package_name": "com.hacker.flashloan",
            "version": "3.2",
        },
    },

    {
        "scan_type":     "apk",
        "input_summary": "Spy_WhatsApp_Tracker_2024.apk",
        "trust_score":   6.0,
        "risk_level":    "High",
        "scanned_at":    _ago(5, 5),
        "explanation": (
            "Explicit stalkerware - its own name advertises covert tracking. Requests every "
            "sensitive permission: READ_SMS, RECEIVE_SMS, SEND_SMS, RECORD_AUDIO, CAMERA, "
            "READ_CONTACTS, ACCESS_FINE_LOCATION, READ_CALL_LOG, PROCESS_OUTGOING_CALLS, and "
            "BIND_ACCESSIBILITY_SERVICE (reads other apps' content). No visible UI - runs as "
            "a hidden background service. Immediately uninstall if found on a device."
        ),
        "raw_results": {
            "permission_score":  2,
            "metadata_score":    8,
            "breakdown": {
                "Permission Risk":  2,
                "App Metadata":     8,
                "Embedded URLs":    3,
                "Manifest Flags":   5,
            },
            "permissions": {
                "critical": ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "PROCESS_OUTGOING_CALLS", "BIND_ACCESSIBILITY_SERVICE"],
                "high":     ["ACCESS_FINE_LOCATION", "CAMERA", "READ_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG"],
                "medium":   ["FOREGROUND_SERVICE", "RECEIVE_BOOT_COMPLETED", "SYSTEM_ALERT_WINDOW"],
                "normal":   ["INTERNET"],
            },
            "flagged_permissions": ["READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "BIND_ACCESSIBILITY_SERVICE"],
            "package_name": "com.spy.whatsapp.tracker",
            "version": "2024.1",
        },
    },

    {
        "scan_type":     "apk",
        "input_summary": "FakeAntivirus_Pro_Premium.apk",
        "trust_score":   13.0,
        "risk_level":    "High",
        "scanned_at":    _ago(17, 3),
        "explanation": (
            "Fake antivirus / scareware APK. Requests BIND_DEVICE_ADMIN to gain device "
            "administrator rights (very hard to uninstall), WRITE_SETTINGS to alter system "
            "config, and ACCESS_FINE_LOCATION. Shows fake virus alerts pressuring users into "
            "purchasing a premium subscription via a third-party processor. Certificate is "
            "self-signed, issued the same day as installation."
        ),
        "raw_results": {
            "permission_score":  10,
            "metadata_score":    15,
            "breakdown": {
                "Permission Risk":  10,
                "App Metadata":     15,
                "Embedded URLs":    5,
                "Manifest Flags":   8,
            },
            "permissions": {
                "critical": ["BIND_DEVICE_ADMIN", "RECORD_AUDIO"],
                "high":     ["ACCESS_FINE_LOCATION", "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW"],
                "medium":   ["READ_EXTERNAL_STORAGE", "FOREGROUND_SERVICE"],
                "normal":   ["INTERNET", "ACCESS_NETWORK_STATE"],
            },
            "flagged_permissions": ["BIND_DEVICE_ADMIN", "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW"],
            "package_name": "com.fake.antivirus.pro",
            "version": "9.9",
        },
    },

    # ======================================================================
    # APK SCANS - LEGITIMATE / LOW RISK
    # ======================================================================
    {
        "scan_type":     "apk",
        "input_summary": "com.google.android.maps_11.23.apk",
        "trust_score":   88.0,
        "risk_level":    "Low",
        "scanned_at":    _ago(4, 1),
        "explanation": (
            "Google Maps official APK. Permissions appropriate for a mapping app: "
            "ACCESS_FINE_LOCATION (navigation), CAMERA (AR and Street View), RECORD_AUDIO "
            "(voice search), and INTERNET. Package name matches Google's official "
            "com.google.android.apps.maps. Certificate signed by Google LLC. "
            "No suspicious URLs or manifest flags."
        ),
        "raw_results": {
            "permission_score":  82,
            "metadata_score":    95,
            "breakdown": {
                "Permission Risk":  82,
                "App Metadata":     95,
                "Embedded URLs":    90,
                "Manifest Flags":   95,
            },
            "permissions": {
                "critical": [],
                "high":     ["ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO"],
                "medium":   ["READ_EXTERNAL_STORAGE", "FOREGROUND_SERVICE"],
                "normal":   ["INTERNET", "ACCESS_NETWORK_STATE", "VIBRATE"],
            },
            "flagged_permissions": [],
            "package_name": "com.google.android.apps.maps",
            "version": "11.23.0",
        },
    },

    {
        "scan_type":     "apk",
        "input_summary": "com.spotify.music_8.9.74.apk",
        "trust_score":   91.5,
        "risk_level":    "Low",
        "scanned_at":    _ago(13, 2),
        "explanation": (
            "Spotify music streaming app. Permission set is reasonable: INTERNET for streaming, "
            "READ_EXTERNAL_STORAGE for local files, RECORD_AUDIO for voice search, "
            "FOREGROUND_SERVICE for background playback. No critical or suspicious permissions. "
            "Certificate signed by Spotify AB. Official package name."
        ),
        "raw_results": {
            "permission_score":  90,
            "metadata_score":    95,
            "breakdown": {
                "Permission Risk":  90,
                "App Metadata":     95,
                "Embedded URLs":    95,
                "Manifest Flags":   95,
            },
            "permissions": {
                "critical": [],
                "high":     ["RECORD_AUDIO"],
                "medium":   ["READ_EXTERNAL_STORAGE", "FOREGROUND_SERVICE"],
                "normal":   ["INTERNET", "ACCESS_NETWORK_STATE", "RECEIVE_BOOT_COMPLETED", "VIBRATE"],
            },
            "flagged_permissions": [],
            "package_name": "com.spotify.music",
            "version": "8.9.74",
        },
    },

    # ======================================================================
    # APK SCANS - MEDIUM RISK
    # ======================================================================
    {
        "scan_type":     "apk",
        "input_summary": "FreeVPN_Unlimited_v2.apk",
        "trust_score":   44.0,
        "risk_level":    "Medium",
        "scanned_at":    _ago(22, 5),
        "explanation": (
            "Free VPN app with an oversized permission set. While VPN requires INTERNET and "
            "VPN permissions, this app also requests READ_CONTACTS and ACCESS_FINE_LOCATION - "
            "unnecessary for a VPN. Developer certificate is self-signed. One embedded URL "
            "points to a third-party analytics SDK with a poor privacy reputation. "
            "May monetise user data."
        ),
        "raw_results": {
            "permission_score":  45,
            "metadata_score":    48,
            "breakdown": {
                "Permission Risk":  45,
                "App Metadata":     48,
                "Embedded URLs":    40,
                "Manifest Flags":   55,
            },
            "permissions": {
                "critical": [],
                "high":     ["ACCESS_FINE_LOCATION", "READ_CONTACTS"],
                "medium":   ["READ_EXTERNAL_STORAGE", "FOREGROUND_SERVICE", "CHANGE_NETWORK_STATE"],
                "normal":   ["INTERNET", "ACCESS_NETWORK_STATE"],
            },
            "flagged_permissions": ["READ_CONTACTS", "ACCESS_FINE_LOCATION"],
            "package_name": "com.freevpn.unlimited",
            "version": "2.0",
        },
    },
]


def seed():
    db = SessionLocal()
    try:
        # 1. Create or find the demo user
        user = db.query(User).filter(User.email == DEMO_EMAIL).first()
        if not user:
            user = User(
                email=DEMO_EMAIL,
                hashed_password=pwd_ctx.hash(DEMO_PASSWORD),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"[+] Created demo user: {DEMO_EMAIL}")
        else:
            print(f"[=] Demo user already exists: {DEMO_EMAIL} (id={user.id})")

        # 2. Skip if already seeded (same number of records)
        existing = db.query(ScanResult).filter(ScanResult.user_id == user.id).count()
        if existing >= len(SEED_SCANS):
            print(f"[=] Already have {existing} seed records - skipping re-seed.")
            print(f"\n    Login: {DEMO_EMAIL} / {DEMO_PASSWORD}")
            return

        # 3. Insert scan records
        inserted = 0
        for record in SEED_SCANS:
            scan = ScanResult(
                user_id=user.id,
                scan_type=record["scan_type"],
                input_summary=record["input_summary"],
                trust_score=record["trust_score"],
                risk_level=record["risk_level"],
                raw_results=record["raw_results"],
                explanation=record["explanation"],
                scanned_at=record["scanned_at"],
            )
            db.add(scan)
            inserted += 1

        db.commit()

        website_count = sum(1 for r in SEED_SCANS if r["scan_type"] == "website")
        email_count   = sum(1 for r in SEED_SCANS if r["scan_type"] == "email")
        apk_count     = sum(1 for r in SEED_SCANS if r["scan_type"] == "apk")
        high_count    = sum(1 for r in SEED_SCANS if r["risk_level"] == "High")
        medium_count  = sum(1 for r in SEED_SCANS if r["risk_level"] == "Medium")
        low_count     = sum(1 for r in SEED_SCANS if r["risk_level"] == "Low")

        print(f"[+] Inserted {inserted} demo scan records.")
        print(f"\n{'='*55}")
        print(f"  Demo account ready!")
        print(f"  Email    : {DEMO_EMAIL}")
        print(f"  Password : {DEMO_PASSWORD}")
        print(f"  Records  : {inserted} scans in history")
        print(f"    - {website_count} website scans")
        print(f"    - {email_count} email scans")
        print(f"    - {apk_count} APK scans")
        print(f"    - {high_count} High risk")
        print(f"    - {medium_count} Medium risk")
        print(f"    - {low_count} Low risk")
        print(f"{'='*55}")

    except Exception as e:
        db.rollback()
        print(f"[ERROR] Seed failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()

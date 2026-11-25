"""
llm/explainer.py — Groq-Powered Trust Analysis + Plain-Language Explanation Generator

PURPOSE:
  Raw numbers (trust_score=62, ssl_score=100, whois_score=35) are meaningful to
  engineers but opaque to end users.  This module calls the Groq API to have an
  LLM translate those numbers into a concise, plain-English explanation that
  anyone can understand — including a non-technical employee deciding whether to
  click a link or install an app.

EMAIL-SPECIFIC ACCURACY IMPROVEMENTS (v2):
  The email analysis function uses a dedicated, highly structured prompt that:
    1. Checks for known phishing signals explicitly (domain spoofing, urgency,
       mismatched reply-to, suspicious links, generic greetings, credential/payment
       requests, grammar patterns, unusual attachments).
    2. Provides few-shot examples (2 legit, 2 scam, 1 uncertain) to anchor judgment.
    3. Requires JSON output with verdict, confidence score (0–100), triggered signals,
       and an explanation — so low-confidence results are flagged "UNCERTAIN" instead
       of confidently wrong.
    4. Logs all input/output pairs to backend/logs/email_llm_log.jsonl for iterative
       prompt refinement.

GROQ API:
  Groq provides ultra-fast inference on open-weight models.  We use
  'llama-3.3-70b-versatile' which balances speed with reasoning quality.
  The Python 'groq' SDK handles authentication and HTTP under the hood.

GRACEFUL DEGRADATION:
  If the Groq API is unavailable (timeout, rate limit, invalid key), we fall back
  to a template-based explanation built from the structured breakdown dict.
  The endpoint NEVER returns an error solely because of LLM unavailability.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from groq import Groq

from app.config import settings


# ── Logging setup for LLM I/O pairs ──────────────────────────────────────────
# Creates backend/logs/email_llm_log.jsonl so misclassifications can be reviewed.
_LOG_DIR = Path(__file__).resolve().parents[2] / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
_LLM_LOG_PATH = _LOG_DIR / "email_llm_log.jsonl"

logger = logging.getLogger(__name__)


def _log_llm_pair(input_payload: dict, output: dict) -> None:
    """Append an LLM input/output pair to the JSONL log file."""
    try:
        entry = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "input":  input_payload,
            "output": output,
        }
        with open(_LLM_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Never crash the endpoint because logging failed


# ── System prompt (website/APK/generic) ─────────────────────────────────────
SYSTEM_PROMPT = (
    "You are QFireNet, an AI cybersecurity analyst embedded in a digital trust platform. "
    "Your job is to explain scan results to non-technical users in a clear, calm, and helpful tone. "
    "Rules: "
    "(1) Write exactly 3–5 sentences. "
    "(2) Reference the 1–2 specific signals that had the most impact on the score. "
    "(3) Do NOT use unexplained jargon — briefly define any technical terms you use. "
    "(4) End with ONE actionable recommendation suited to the scan type. "
    "(5) Do NOT repeat the raw numbers — paraphrase them in plain language. "
    "(6) Do NOT use bullet points or lists — write in flowing paragraphs."
)


# ── Email-specific system prompt (structured phishing analysis) ───────────────
EMAIL_ANALYSIS_SYSTEM_PROMPT = """\
You are QFireNet, an expert email security analyst specializing in phishing and scam detection.
Your task is to analyze an email and determine whether it is a SCAM/PHISHING attempt, LEGITIMATE, or UNCERTAIN.

## Phishing Signals to Check
Carefully examine each of the following signals and note which ones are present:
1. DOMAIN_SPOOFING: Sender domain is a lookalike of a trusted brand (e.g. "paypa1.com", "amazon-support.net", "microsofi.com")
2. URGENCY_FEAR: Urgency or fear language ("act now", "account suspended", "immediate action required", "expires in 24 hours")
3. REPLY_TO_MISMATCH: Reply-To address differs from the From address domain
4. SUSPICIOUS_LINKS: Link display text says one domain but actual href goes elsewhere; URL shorteners (bit.ly, tinyurl); IP-based URLs
5. GENERIC_GREETING: Opens with "Dear Customer", "Dear User", "Dear Account Holder" instead of your name
6. CREDENTIAL_REQUEST: Asks for passwords, OTPs, PINs, Social Security Numbers, credit card details, or login credentials
7. PAYMENT_REQUEST: Asks for wire transfers, gift cards (iTunes, Google Play), cryptocurrency payments, or urgent money transfers
8. GRAMMAR_PATTERNS: Unusual phrasing, missing articles (typical of machine translation), inconsistent capitalization, awkward sentence structure
9. IMPERSONATION: Claims to be from a well-known brand (PayPal, Amazon, IRS, Microsoft, your bank) but fails authentication checks
10. ATTACHMENT_RISK: Requests to open unexpected attachments (.exe, .zip with password, invoice PDFs from unknown senders)

## Few-Shot Examples
The following examples illustrate the expected analysis format:

### Example 1 — LEGITIMATE (confidence: 92)
Email:
  From: security@google.com
  Subject: New sign-in on Windows
  Body: Hi John, We noticed a new sign-in to your Google Account. If this was you, you don't need to do anything. If this wasn't you, check your account activity...
Analysis: {"verdict":"LEGITIMATE","confidence":92,"triggered_signals":[],"explanation":"This email displays hallmarks of a genuine Google security notification: it addresses the recipient by name, comes from google.com (a verified Google domain), describes a specific event (new sign-in on Windows), and does not request any credentials or urgent action. The calm tone and lack of pressure tactics are consistent with legitimate security alert emails.","recommendation":"If you did not sign in from a new device, visit myaccount.google.com directly (do not click links in the email) to review your account activity."}

### Example 2 — LEGITIMATE (confidence: 88)
Email:
  From: orders@amazon.com
  Subject: Your order #112-3456789 has shipped
  Body: Hello Jane, Your package is on its way! Track your package: [tracking link]. Your order of 'USB-C Cable' shipped from our fulfillment center. Expected delivery: August 15.
Analysis: {"verdict":"LEGITIMATE","confidence":88,"triggered_signals":[],"explanation":"This appears to be a legitimate Amazon shipping notification from the official amazon.com domain. It references a specific order number and item, which is consistent with genuine transactional emails. No credentials, payments, or urgent actions are requested.","recommendation":"Track your package through the Amazon website or app directly rather than clicking the link in the email, as a best practice."}

### Example 3 — SCAM (confidence: 97)
Email:
  From: support@paypa1-security.com
  Subject: URGENT: Your PayPal account has been limited
  Body: Dear Customer, We have detected unusual activity. Your account will be permanently suspended within 24 hours unless you verify your information immediately. Click here to verify: http://paypa1-verify.net/login. Enter your username, password, and SSN.
Analysis: {"verdict":"SCAM","confidence":97,"triggered_signals":["DOMAIN_SPOOFING","URGENCY_FEAR","CREDENTIAL_REQUEST","SUSPICIOUS_LINKS","GENERIC_GREETING"],"explanation":"This is a highly suspicious phishing email. The sender domain 'paypa1-security.com' is a lookalike of PayPal (note the '1' instead of 'l'), which is a classic domain spoofing tactic. The email uses extreme urgency ('24 hours', 'permanently suspended') and a generic 'Dear Customer' greeting, and requests sensitive credentials including your Social Security Number — something PayPal would never ask for via email.","recommendation":"Do NOT click any links or enter any information. Delete this email immediately. If you are concerned about your PayPal account, go to paypal.com directly by typing it in your browser."}

### Example 4 — SCAM (confidence: 94)
Email:
  From: irs-refunds@gov-irs-refund.net
  Subject: You have a pending tax refund of $3,847
  Body: Dear Taxpayer, The Internal Revenue Service has processed a tax refund for you. To receive your refund, you must purchase $200 in iTunes gift cards and send us the card numbers within 48 hours. Failure to respond will result in legal action.
Analysis: {"verdict":"SCAM","confidence":94,"triggered_signals":["DOMAIN_SPOOFING","URGENCY_FEAR","PAYMENT_REQUEST","IMPERSONATION","GRAMMAR_PATTERNS"],"explanation":"This is clearly a scam impersonating the IRS. The domain 'gov-irs-refund.net' is not an official IRS domain (which is irs.gov). The IRS never requests gift card payments, and threatening legal action for not buying iTunes cards is a hallmark of gift card fraud schemes. The combination of impersonation, financial pressure, and gift card payment request makes this extremely high-confidence fraud.","recommendation":"The IRS only communicates via postal mail, never email or phone demanding gift cards. Report this to the IRS phishing email address: phishing@irs.gov."}

### Example 5 — UNCERTAIN (confidence: 52)
Email:
  From: newsletter@offers.shopdeals24.com
  Subject: Exclusive offer just for you!
  Body: Hi there, You've been selected for an exclusive 70% discount on all products. This offer expires tonight. Click to claim your discount at shopdeals24.com.
Analysis: {"verdict":"UNCERTAIN","confidence":52,"triggered_signals":["URGENCY_FEAR","GENERIC_GREETING"],"explanation":"This email has some characteristics of promotional spam or a scam, but is not conclusively fraudulent. The urgency language and generic greeting are mild red flags, but the sender domain is consistent with the linked website and no credentials or payments are requested. This could be a legitimate but aggressive promotional email or a low-sophistication scam.","recommendation":"Exercise caution. Do not enter payment information unless you independently verify the legitimacy of shopdeals24.com. Consider whether you signed up for offers from this sender."}

## Output Format
You MUST respond with ONLY a valid JSON object — no markdown, no code blocks, no extra text. Use exactly this schema:
{
  "verdict": "SCAM" | "LEGITIMATE" | "UNCERTAIN",
  "confidence": <integer 0-100>,
  "triggered_signals": [<list of signal names from the list above, or empty array>],
  "explanation": "<3-5 sentence plain-English explanation>",
  "recommendation": "<one actionable recommendation for the user>"
}
"""


def _build_email_analysis_prompt(
    sender_email: str,
    subject: str,
    body: str,
    header_result: dict,
    domain_check: dict,
) -> str:
    """
    Build the user-turn prompt for email scam analysis.
    Injects all available structured signals so the LLM can cross-reference them.
    """
    # Build header context
    spf  = "PASS" if header_result.get("spf_pass")   else "FAIL/UNKNOWN"
    dkim = "PASS" if header_result.get("dkim_pass")  else "FAIL/UNKNOWN"
    dmarc= "PASS" if header_result.get("dmarc_pass") else "FAIL/UNKNOWN"
    reply_to = header_result.get("reply_to", "") or "Not set"
    sender_mismatch = header_result.get("sender_domain_mismatch", False)
    reply_mismatch  = header_result.get("reply_to_mismatch", False)

    # Domain check context
    domain_note = domain_check.get("risk_note", "") if domain_check else ""
    is_lookalike = domain_check.get("is_lookalike", False) if domain_check else False
    lookalike_of = domain_check.get("lookalike_of", "") if domain_check else ""

    domain_context = ""
    if is_lookalike and lookalike_of:
        domain_context = (
            f"\n⚠️  RULE-BASED ALERT: Sender domain is a detected lookalike of '{lookalike_of}'. "
            "This is a strong phishing indicator confirmed independently of LLM analysis."
        )
    elif domain_note:
        domain_context = f"\nDomain check: {domain_note}"

    prompt = f"""Analyze the following email for scam/phishing signals:

=== EMAIL ===
From: {sender_email or "(not provided)"}
Subject: {subject or "(not provided)"}
Reply-To: {reply_to}
Body:
{body or "(no body text provided)"}

=== AUTHENTICATION SIGNALS (from mail server headers) ===
SPF:   {spf}
DKIM:  {dkim}
DMARC: {dmarc}
Sender domain mismatch (From ≠ Return-Path): {sender_mismatch}
Reply-To domain mismatch: {reply_mismatch}
{domain_context}

Now analyze this email and respond with the JSON object as specified."""

    return prompt


def _parse_llm_email_response(raw_response: str) -> dict:
    """
    Parse the LLM's JSON response for email analysis.

    The LLM is instructed to return only JSON, but we defensively handle:
    - Markdown code fences (```json ... ```)
    - Leading/trailing whitespace
    - Partial JSON with missing keys (filled with safe defaults)

    Returns a normalized dict with all required keys.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?\s*", "", raw_response).strip()
    cleaned = re.sub(r"```\s*$", "", cleaned).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        # Last resort: extract what we can with regex
        verdict_match     = re.search(r'"verdict"\s*:\s*"(SCAM|LEGITIMATE|UNCERTAIN)"', cleaned)
        confidence_match  = re.search(r'"confidence"\s*:\s*(\d+)', cleaned)
        explanation_match = re.search(r'"explanation"\s*:\s*"([^"]+)"', cleaned)

        return {
            "verdict":          verdict_match.group(1) if verdict_match else "UNCERTAIN",
            "confidence":       int(confidence_match.group(1)) if confidence_match else 50,
            "triggered_signals": [],
            "explanation":      explanation_match.group(1) if explanation_match else raw_response[:500],
            "recommendation":   "Exercise caution with this email.",
        }

    # Normalize and fill defaults
    verdict = data.get("verdict", "UNCERTAIN")
    if verdict not in ("SCAM", "LEGITIMATE", "UNCERTAIN"):
        verdict = "UNCERTAIN"

    confidence = data.get("confidence", 50)
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = 50

    # Force UNCERTAIN label for low-confidence results regardless of verdict
    if confidence < 60 and verdict != "UNCERTAIN":
        verdict = "UNCERTAIN"

    return {
        "verdict":           verdict,
        "confidence":        confidence,
        "triggered_signals": data.get("triggered_signals", []),
        "explanation":       data.get("explanation", ""),
        "recommendation":    data.get("recommendation", ""),
    }


def generate_email_analysis(
    sender_email: str,
    subject: str,
    body: str,
    header_result: dict,
    domain_check: dict | None,
    content_result: dict,
) -> dict:
    """
    Run the improved Groq LLM email scam analysis with structured output.

    Parameters
    ----------
    sender_email   : str   — The sender's email address.
    subject        : str   — Email subject line.
    body           : str   — Email body text.
    header_result  : dict  — Output from check_email_headers().
    domain_check   : dict  — Output from check_sender_domain(), or None.
    content_result : dict  — Output from check_email_content().

    Returns
    -------
    dict with keys:
        verdict           (str)        — "SCAM", "LEGITIMATE", or "UNCERTAIN".
        confidence        (int)        — 0–100 LLM confidence in verdict.
        triggered_signals (list[str])  — Phishing signals identified.
        explanation       (str)        — Plain-English explanation.
        recommendation    (str)        — Actionable user recommendation.
        full_explanation  (str)        — Combined explanation + recommendation (for UI).
        error             (str)        — Set if LLM call failed.
    """
    user_prompt = _build_email_analysis_prompt(
        sender_email  = sender_email,
        subject       = subject,
        body          = body,
        header_result = header_result,
        domain_check  = domain_check or {},
    )

    log_input = {
        "sender_email": sender_email,
        "subject":      subject,
        "body_length":  len(body),
        "domain_check": domain_check,
        "header_spf":   header_result.get("spf_pass"),
        "header_dkim":  header_result.get("dkim_pass"),
        "header_dmarc": header_result.get("dmarc_pass"),
        "content_score": content_result.get("heuristic_score"),
    }

    try:
        client = Groq(api_key=settings.GROQ_API_KEY)

        response = client.chat.completions.create(
            model    = settings.GROQ_MODEL,
            messages = [
                {"role": "system", "content": EMAIL_ANALYSIS_SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens  = 800,
            temperature = 0.1,   # Near-deterministic — structured JSON output
            response_format={"type": "json_object"},  # Force JSON mode (supported by Groq)
        )

        raw = response.choices[0].message.content.strip()
        result = _parse_llm_email_response(raw)

        # Build a combined explanation string for the UI (explanation + recommendation)
        result["full_explanation"] = (
            result["explanation"]
            + (" " + result["recommendation"] if result.get("recommendation") else "")
        )

        _log_llm_pair(log_input, result)
        return result

    except Exception as exc:
        logger.warning("Email LLM analysis failed: %s", exc)

        # Fallback: derive a verdict from heuristic signals
        heuristic_score = content_result.get("heuristic_score", 0)
        domain_lookalike = (domain_check or {}).get("is_lookalike", False)

        if heuristic_score >= 50 or domain_lookalike:
            fallback_verdict = "SCAM"
            fallback_confidence = 55
        elif heuristic_score <= 15:
            fallback_verdict = "LEGITIMATE"
            fallback_confidence = 55
        else:
            fallback_verdict = "UNCERTAIN"
            fallback_confidence = 40

        fallback = {
            "verdict":           fallback_verdict,
            "confidence":        fallback_confidence,
            "triggered_signals": content_result.get("risk_indicators", [])[:5],
            "explanation": (
                f"AI analysis is currently unavailable. "
                f"Based on automated heuristics, this email is classified as "
                f"{fallback_verdict.lower()} with limited confidence. "
                f"{'Suspicious content patterns were detected. ' if heuristic_score > 20 else ''}"
                f"{'The sender domain resembles a known trusted brand. ' if domain_lookalike else ''}"
            ),
            "recommendation":   "Treat this email with caution and verify independently before acting.",
            "full_explanation": "",
            "error":            str(exc),
        }
        fallback["full_explanation"] = fallback["explanation"] + " " + fallback["recommendation"]
        _log_llm_pair(log_input, fallback)
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING WEBSITE / APK ANALYSIS (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _build_website_summary(raw_results: dict, trust_score: dict) -> str:
    """Build a compact summary string for a website scan."""
    ssl      = raw_results.get("ssl", {})
    whois    = raw_results.get("whois", {})
    phishing = raw_results.get("phishing", {})
    pqc      = raw_results.get("pqc", {})
    breakdown = trust_score.get("breakdown", {})

    return f"""
WEBSITE TRUST SCAN — Score: {trust_score.get('overall_score')}/100 — Risk: {trust_score.get('risk_level')}

SSL Certificate: {'Valid' if ssl.get('is_valid') else 'INVALID'}, expires in {ssl.get('days_until_expiry', '?')} days, TLS {ssl.get('tls_version', '?')}
Domain Age: {whois.get('domain_age_days', '?')} days old, Registrar: {whois.get('registrar', '?')}, Recently registered: {whois.get('is_recently_registered', '?')}
Phishing Indicators: {phishing.get('risk_indicators') or 'None detected'}
Post-Quantum Crypto: {'Ready' if pqc.get('pqc_ready') else 'Not detected'}, Cipher: {pqc.get('cipher_suite', '?')}
Score breakdown: {', '.join(f'{k}: {v}/100' for k, v in breakdown.items())}
""".strip()


def _build_apk_summary(raw_results: dict, trust_score: dict) -> str:
    """Build a compact summary string for an APK scan."""
    extraction = raw_results.get("extraction", {})
    risk       = raw_results.get("risk", {})
    breakdown  = trust_score.get("breakdown", {})
    tier_counts = risk.get("tier_counts", {})

    return f"""
APK TRUST SCAN — Score: {trust_score.get('overall_score')}/100 — Risk: {trust_score.get('risk_level')}

App: {extraction.get('app_name', '?')} ({extraction.get('package_name', '?')})
Target SDK: {extraction.get('target_sdk', '?')}, Min SDK: {extraction.get('min_sdk_version', '?')}
Total permissions: {extraction.get('permission_count', 0)}
Permission breakdown — Critical: {tier_counts.get('Critical', 0)}, High: {tier_counts.get('High', 0)}, Medium: {tier_counts.get('Medium', 0)}, Low: {tier_counts.get('Low', 0)}
High-risk permissions: {risk.get('high_risk_permissions', [])[:5] or 'None'}
Score breakdown: {', '.join(f'{k}: {v}/100' for k, v in breakdown.items())}
""".strip()


def _build_fallback_explanation(scan_type: str, raw_results: dict, trust_score: dict) -> str:
    """
    Template-based fallback explanation when Groq is unavailable.

    Constructs a readable explanation from the structured data without any LLM.
    This ensures the endpoint always returns useful output.
    """
    score     = trust_score.get("overall_score", "N/A")
    risk      = trust_score.get("risk_level", "Unknown")
    breakdown = trust_score.get("breakdown", {})

    text = f"This {scan_type} received a trust score of {score}/100, indicating {risk} risk. "

    if scan_type == "website":
        ssl      = raw_results.get("ssl", {})
        whois    = raw_results.get("whois", {})
        phishing = raw_results.get("phishing", {})
        if ssl.get("is_valid") is False:
            text += "The SSL certificate is invalid or expired, which is a serious security warning. "
        if whois.get("is_recently_registered"):
            text += "The domain was registered very recently, which is a common trait of phishing sites. "
        indicators = phishing.get("risk_indicators", [])
        if indicators:
            text += f"Suspicious URL patterns were detected: {', '.join(indicators[:2])}. "

    elif scan_type == "apk":
        risk_data = raw_results.get("risk", {})
        tier_counts = risk_data.get("tier_counts", {})
        critical = tier_counts.get("Critical", 0)
        high = tier_counts.get("High", 0)
        if critical > 0:
            text += f"The app requests {critical} critical permission(s) that can enable fraud or surveillance. "
        if high > 0:
            text += f"Additionally, {high} high-risk permission(s) were found. "

    text += "(Note: AI explanation unavailable — automated summary provided.)"
    return text


def generate_explanation(scan_type: str, raw_results: dict, trust_score: dict) -> str:
    """
    Ask the Groq LLM to explain a trust-score analysis in plain English.

    NOTE: For email scans, use generate_email_analysis() directly instead —
    it returns a richer structured response with confidence and verdict.
    This function remains for website and APK scan types.

    Parameters
    ----------
    scan_type    : str   — "website" or "apk".
    raw_results  : dict  — Raw output from all check functions for this scan type.
    trust_score  : dict  — Output of the relevant calculate_*_trust_score() function.

    Returns
    -------
    str
        A 3–5 sentence explanation suitable for a non-technical audience.
        Falls back to a template-based explanation on any API error.
    """
    builders = {
        "website": _build_website_summary,
        "apk":     _build_apk_summary,
    }
    build_fn = builders.get(scan_type, _build_website_summary)
    scan_summary = build_fn(raw_results, trust_score)

    user_prompt = (
        f"Here are the results of a {scan_type} trust scan:\n\n{scan_summary}\n\n"
        "Please provide a plain-English explanation of what these results mean "
        "and whether the user should trust this resource."
    )

    try:
        client = Groq(api_key=settings.GROQ_API_KEY)

        response = client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens=settings.GROQ_MAX_TOKENS,
            temperature=0.4,
        )

        return response.choices[0].message.content.strip()

    except Exception:
        return _build_fallback_explanation(scan_type, raw_results, trust_score)

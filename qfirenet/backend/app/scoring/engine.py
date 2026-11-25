"""
scoring/engine.py — Weighted Trust Score Fusion Engine

PURPOSE:
  The check modules each return raw data — certificate details, domain age,
  phishing flags, cipher names, email headers, APK permissions.
  This module converts each into a 0–100 sub-score and then fuses them into
  a single overall trust score using a weighted average.

SCORING PHILOSOPHY:
  • High score (≥70) = trustworthy / Low risk
  • Medium score (40–69) = caution advised / Medium risk
  • Low score (<40) = strong warning / High risk

  We use INVERTED scoring where possible: every sub-score is 0–100 where
  100 = maximally safe.  This makes weighted averaging intuitive and consistent.

WEIGHTS DOCUMENTED INLINE for each scan type.
"""


# ─────────────────────────────────────────────────────────────────────────────
# WEBSITE SCAN SCORING
# Weights must sum to 1.0
# ─────────────────────────────────────────────────────────────────────────────

# Phishing heuristics: 35% — URL structure patterns are the most reliable and
# actionable phishing indicator available without live network context.
WEIGHT_PHISHING = 0.35

# SSL validity: 25% — An invalid/expired cert is a hard failure signal.
# Legitimate services virtually always maintain valid certs.
WEIGHT_SSL = 0.25

# WHOIS / domain age: 25% — Newly registered domains are a hallmark of
# phishing campaigns (attackers register throwaway domains).
WEIGHT_WHOIS = 0.25

# PQC readiness: 15% — Informational / forward-looking only.
# Most sites are NOT PQC-ready today; this is a soft signal, not punitive.
# It encourages adoption of post-quantum cryptography without penalising the majority.
WEIGHT_PQC = 0.15


def _score_ssl(ssl_result: dict) -> float:
    """
    Convert ssl_check output into a 0–100 SSL safety score.

    Scoring logic:
      - Error (host unreachable): 0 — can't verify, assume worst case.
      - Invalid/expired cert:     0 — hard failure.
      - Expires ≤14 days:        40 — critical warning (imminent expiry).
      - Expires ≤30 days:        65 — warning (expiry approaching).
      - Valid, >30 days:        100 — full marks.
    """
    if ssl_result.get("error") or not ssl_result.get("is_valid"):
        return 0.0

    days = ssl_result.get("days_until_expiry", 0) or 0

    if days < 0:
        return 0.0    # Already expired
    elif days <= 14:
        return 40.0   # Expiring very soon — likely neglected
    elif days <= 30:
        return 65.0   # Expiring soon — mild concern
    else:
        return 100.0  # Healthy certificate


def _score_whois(whois_result: dict) -> float:
    """
    Convert whois_check output into a 0–100 domain-age safety score.

    Scoring logic:
      - Error / no data:     50 — neutral (WHOIS is frequently privacy-redacted).
      - Age < 30 days:        0 — extremely suspicious (fresh throwaway domain).
      - Age 30–90 days:      35 — newly registered, suspicious.
      - Age 90–180 days:     60 — relatively new, mild concern.
      - Age 180–365 days:    80 — established enough to be credible.
      - Age > 365 days:     100 — well-established, normal.
    """
    if whois_result.get("error") or whois_result.get("domain_age_days") is None:
        return 50.0  # Neutral — penalising for redacted WHOIS would give false positives

    age = whois_result["domain_age_days"]

    if age < 30:
        return 0.0
    elif age < 90:
        return 35.0
    elif age < 180:
        return 60.0
    elif age < 365:
        return 80.0
    else:
        return 100.0


def _score_phishing(phishing_result: dict) -> float:
    """
    Convert phishing heuristic output into a 0–100 safety score.

    phishing_check returns heuristic_score as a suspicion score (0=safe, 100=dangerous).
    We invert it so all signals read consistently: higher = safer.
    """
    heuristic_score = phishing_result.get("heuristic_score", 0)
    return max(0.0, 100.0 - heuristic_score)


def _score_pqc(pqc_result: dict) -> float:
    """
    Convert PQC readiness result into a 0–100 score.

    This is INFORMATIONAL only — we don't punish sites for lacking PQC support
    because adoption is still early-stage globally (as of 2024–2025).
    We give a soft bonus for PQC-ready sites instead.

    Scoring:
      - Error: 50 — neutral.
      - PQC-ready (Kyber/hybrid cipher detected): 100 — bonus.
      - Classical TLS (industry default): 60 — no penalty.
    """
    if pqc_result.get("error"):
        return 50.0
    return 100.0 if pqc_result.get("pqc_ready") else 60.0


def calculate_website_trust_score(website_results: dict) -> dict:
    """
    Fuse all four website signal scores into one overall trust score.

    Parameters
    ----------
    website_results : dict
        Expected keys: "ssl", "whois", "phishing", "pqc"

    Returns
    -------
    dict:
        overall_score (float)  — Weighted average, 0–100.
        risk_level    (str)    — "Low", "Medium", or "High".
        breakdown     (dict)   — Individual score per signal.
    """
    ssl_score      = _score_ssl(website_results.get("ssl", {}))
    whois_score    = _score_whois(website_results.get("whois", {}))
    phishing_score = _score_phishing(website_results.get("phishing", {}))
    pqc_score      = _score_pqc(website_results.get("pqc", {}))

    overall_score = (
        ssl_score      * WEIGHT_SSL
        + whois_score  * WEIGHT_WHOIS
        + phishing_score * WEIGHT_PHISHING
        + pqc_score    * WEIGHT_PQC
    )
    overall_score = round(overall_score, 2)

    return {
        "overall_score": overall_score,
        "risk_level":    _get_risk_level(overall_score),
        "breakdown": {
            "SSL Certificate":      round(ssl_score, 2),
            "Domain Age (WHOIS)":   round(whois_score, 2),
            "Phishing Heuristics":  round(phishing_score, 2),
            "PQC Readiness":        round(pqc_score, 2),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL SCAN SCORING
# Weights must sum to 1.0
# ─────────────────────────────────────────────────────────────────────────────

# Email auth headers: 40% — SPF/DKIM/DMARC are the technical ground truth of
# whether an email is genuinely from the claimed domain. Failures here are
# definitive — legitimate bulk senders almost always implement all three.
WEIGHT_EMAIL_HEADERS = 0.40

# Content heuristics: 60% — The body content is the most user-visible signal
# and the primary mechanism of social engineering. Scam-keyword patterns are
# highly indicative of fraud even when authentication passes (e.g. compromised
# sending account).
WEIGHT_EMAIL_CONTENT = 0.60


def _score_email_headers(header_result: dict) -> float:
    """
    Convert email header check output to a 0–100 authentication score.

    If no headers were supplied in the scan input, return a neutral score (50.0).
    """
    if header_result.get("has_headers") is False:
        return 50.0

    score = 0.0

    # Each of SPF, DKIM, DMARC passing contributes roughly 1/3 of total.
    if header_result.get("spf_pass"):
        score += 33.0
    if header_result.get("dkim_pass"):
        score += 33.0
    if header_result.get("dmarc_pass"):
        score += 34.0

    # Domain mismatches are strong red flags — deduct points.
    if header_result.get("sender_domain_mismatch"):
        score -= 20.0  # From ≠ Return-Path: classic spoofing indicator

    if header_result.get("reply_to_mismatch"):
        score -= 15.0  # Reply goes to different domain: suspicious

    # Clamp to [0, 100]
    return max(0.0, min(100.0, score))


def _score_email_content(content_result: dict) -> float:
    """
    Convert email content heuristic output to a 0–100 safety score.

    content_check returns heuristic_score as suspicion (0=safe, 100=dangerous).
    We invert to match our convention (higher = safer).
    """
    heuristic = content_result.get("heuristic_score", 0)
    return max(0.0, 100.0 - heuristic)


def calculate_email_trust_score(
    email_results: dict,
    llm_confidence: int | None = None,
    domain_check: dict | None = None,
) -> dict:
    """
    Compute the overall trust score for an email scan.

    Parameters
    ----------
    email_results : dict
        Expected keys: "headers", "content"
    llm_confidence : int | None
        LLM's confidence score (0–100) in its verdict, if available.
        When provided, it is blended in as a 3rd signal (20% weight),
        and headers/content weights are reduced proportionally.
    domain_check : dict | None
        Output of domain_checker.check_sender_domain(). If the sender domain
        is a lookalike of a known-safe brand, a -15 penalty is applied.

    Returns
    -------
    dict with overall_score, risk_level, breakdown.
    """
    header_score  = _score_email_headers(email_results.get("headers", {}))
    content_score = _score_email_content(email_results.get("content", {}))

    breakdown: dict[str, float] = {}

    if llm_confidence is not None:
        # 3-signal blend: headers 32%, content 48%, LLM confidence 20%
        overall_score = (
            header_score  * 0.32
            + content_score * 0.48
            + float(llm_confidence) * 0.20
        )
        breakdown["Email Authentication (SPF/DKIM/DMARC)"] = round(header_score, 2)
        breakdown["Content Heuristics"]                    = round(content_score, 2)
        breakdown["LLM Confidence"]                        = round(float(llm_confidence), 2)
    else:
        # 2-signal blend (fallback): headers 40%, content 60%
        overall_score = (
            header_score  * WEIGHT_EMAIL_HEADERS
            + content_score * WEIGHT_EMAIL_CONTENT
        )
        breakdown["Email Authentication (SPF/DKIM/DMARC)"] = round(header_score, 2)
        breakdown["Content Heuristics"]                    = round(content_score, 2)

    # ── Domain lookalike penalty (rule-based, independent of LLM) ─────────────
    domain_penalty = 0.0
    if domain_check and domain_check.get("is_lookalike"):
        domain_penalty = 15.0   # Hard penalty for spoofed domain
        breakdown["Domain Check (Lookalike)"] = round(max(0.0, header_score - domain_penalty), 2)
    elif domain_check:
        breakdown["Domain Check"] = 100.0 if domain_check.get("is_known_safe") else 50.0

    overall_score = round(max(0.0, min(100.0, overall_score - domain_penalty)), 2)

    return {
        "overall_score": overall_score,
        "risk_level":    _get_risk_level(overall_score),
        "breakdown":     breakdown,
    }


# ─────────────────────────────────────────────────────────────────────────────
# APK SCAN SCORING
# ─────────────────────────────────────────────────────────────────────────────
# The APK score is inverted from the risk mapper's overall_risk_score:
# risk_score 0 (clean) → trust_score 100 (safe)
# risk_score 100 (very dangerous) → trust_score 0
#
# We also apply a separate "permission volume" penalty:
# apps with >20 total permissions get a mild deduction — excessive permission
# requests are a common malware trait even if individual permissions are benign.

def _score_apk_permissions(risk_result: dict) -> float:
    """
    Convert APK risk mapper output to a 0–100 trust score.

    The risk_mapper gives us overall_risk_score (0=clean, 100=dangerous).
    We invert it and apply a volume bonus/penalty.

    Scoring tiers:
      - 0 permissions:         70 (unknown/empty — can't fully trust)
      - Pure inversion:        100 - overall_risk_score
      - >20 permissions:      -10 deduction (excessive requests)
      - >30 permissions:      -15 deduction
    """
    if risk_result.get("error"):
        return 30.0  # Error parsing APK — treat as high risk

    overall_risk = risk_result.get("overall_risk_score", 0)
    total_perms  = risk_result.get("total_permissions", 0)

    if total_perms == 0:
        return 70.0  # Empty APK or no permissions — neutral/unknown

    # Base score: invert the risk score
    base_score = max(0.0, 100.0 - overall_risk)

    # Volume penalty: too many permissions is suspicious
    volume_penalty = 0.0
    if total_perms > 30:
        volume_penalty = 15.0
    elif total_perms > 20:
        volume_penalty = 10.0

    final_score = max(0.0, base_score - volume_penalty)
    return round(final_score, 2)


def _score_apk_metadata(extraction_result: dict) -> float:
    """
    Score the APK metadata for risk signals.

    Currently checks:
      - target_sdk: very old SDK (< 23) means the app targets a pre-permission
        Android era and may not request runtime permissions properly — slight penalty.
      - Extraction error: hard penalty.

    Returns a 0–100 modifier score (100 = no issues).
    """
    if extraction_result.get("error"):
        return 40.0

    try:
        target_sdk = int(extraction_result.get("target_sdk") or 28)
    except (ValueError, TypeError):
        target_sdk = 28  # Assume modern if we can't parse

    if target_sdk < 21:
        # Android 5.0 or below: very old, likely abandoned/untrusted app.
        return 40.0
    elif target_sdk < 26:
        # Android 7 or below: misses runtime permission requirements.
        return 70.0
    else:
        return 100.0


def calculate_apk_trust_score(apk_results: dict) -> dict:
    """
    Compute the overall trust score for an APK scan.

    Parameters
    ----------
    apk_results : dict
        Expected keys: "extraction" (from permission_extractor), "risk" (from risk_mapper)

    Returns
    -------
    dict with overall_score, risk_level, breakdown.

    Weights:
      Permission risk score: 75% — The primary signal; directly measures dangerous permissions.
      Metadata score:        25% — SDK targeting and app integrity indicators.
    """
    perm_score     = _score_apk_permissions(apk_results.get("risk", {}))
    metadata_score = _score_apk_metadata(apk_results.get("extraction", {}))

    overall_score = (
        perm_score     * 0.75   # 75%: permission risks are the primary APK signal
        + metadata_score * 0.25  # 25%: metadata quality / SDK targeting
    )
    overall_score = round(overall_score, 2)

    return {
        "overall_score": overall_score,
        "risk_level":    _get_risk_level(overall_score),
        "breakdown": {
            "Permission Risk Score": round(perm_score, 2),
            "App Metadata Score":    round(metadata_score, 2),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# SHARED UTILITY
# ─────────────────────────────────────────────────────────────────────────────

def _get_risk_level(score: float) -> str:
    """
    Convert a numeric trust score into a human-readable risk level.

    Thresholds:
      ≥ 70 → Low    (trustworthy, proceed with normal caution)
      40–69 → Medium (caution advised, investigate further)
      < 40 → High   (strong warning, do not proceed)
    """
    if score >= 70:
        return "Low"
    elif score >= 40:
        return "Medium"
    else:
        return "High"


# Backwards-compatible alias — old routers that called calculate_trust_score
# will still work without modification.
calculate_trust_score = calculate_website_trust_score

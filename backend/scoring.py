"""
Hybrid Scoring Engine for RETRO_INTEL
=======================================
Domain-aware, explainable, false-positive resistant scoring system.

DESIGN PHILOSOPHY
-----------------
- ML is a SUPPORTING signal, never the dominant factor
- Trust bonuses reduce risk for legitimate, well-established domains
- Aggressive phishing penalties increase risk for malicious indicators
- Hard-protected domains are NEVER flagged as suspicious
- Every score is explainable with human-readable reasoning

BACKWARD COMPATIBILITY
----------------------
This module only ADDS intelligence. It does not modify or remove
any existing API fields consumed by the frontend.

All new fields are additive:
  score_components.trust_bonuses
  score_components.phishing_penalties
  score_components.hybrid_breakdown
  score_components.dynamic_confidence
  score_components.explainable_reasoning
"""

from __future__ import annotations

from typing import Any

# ======================================================================
# CONSTANTS
# ======================================================================

# Threat Level Thresholds: (lo, hi, label, severity)
THREAT_LEVELS: list[tuple[int, int, str, str]] = [
    (0, 10, "SAFE VERIFIED", "safe"),
    (11, 25, "LOW RISK", "low"),
    (26, 45, "SUSPICIOUS", "suspicious"),
    (46, 70, "HIGH RISK", "high"),
    (71, 100, "MALICIOUS / PHISHING", "critical"),
]

# Default component weights when no strong signals override
BASE_WEIGHTS: dict[str, float] = {
    "heuristics": 0.35,
    "security_headers": 0.20,
    "xgboost_ml": 0.20,
    "domain_reputation": 0.15,
    "ai_analysis": 0.10,
}

# Hard-protected domains — NEVER flagged as suspicious
# These are globally recognized trusted domains
HARD_PROTECT_DOMAINS: frozenset[str] = frozenset({
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "meta.com",
    "twitter.com", "linkedin.com", "reddit.com", "github.com", "gitlab.com",
    "paypal.com", "stripe.com", "square.com", "shopify.com",
    "openai.com", "deepmind.com", "anthropic.com",
    "cloudflare.com", "vercel.com", "netlify.com",
    "zoom.us", "slack.com", "dropbox.com", "adobe.com",
    "wikipedia.org", "stackoverflow.com", "npmjs.com",
    "docker.com", "kubernetes.io", "aws.amazon.com",
    "salesforce.com", "oracle.com", "ibm.com",
    "wordpress.com", "blogger.com", "medium.com",
    "spotify.com", "soundcloud.com", "vimeo.com",
    "samsung.com", "sony.com", "lg.com",
    "oracle.com", "cisco.com", "vmware.com",
    "intel.com", "amd.com", "nvidia.com",
    "harvard.edu", "stanford.edu", "mit.edu", "ox.ac.uk",
    "whitehouse.gov", "usa.gov", "gov.uk",
    "who.int", "nasa.gov", "nobelprize.org",
    "nytimes.com", "wsj.com", "bbc.co.uk", "reuters.com", "bloomberg.com",
    "tesla.com", "toyota.com", "honda.com", "ford.com", "bmw.com",
    "nike.com", "adidas.com", "cocacola.com",
    "booking.com", "expedia.com", "airbnb.com", "uber.com",
    "fedex.com", "dhl.com", "ups.com", "usps.com",
    "steampowered.com", "epicgames.com", "xbox.com", "playstation.com", "nintendo.com",
})

# Trusted registrar keywords
TRUSTED_REGISTRARS: frozenset[str] = frozenset({
    "markmonitor", "safenames", "csc corporate", "cscglobal",
    "nominalia", "gandi", "namecheap", "godaddy",
    "google", "amazon", "aws", "cloudflare",
    "network solutions", "enom", "tucows",
    "1&1 ionos", "ionos", "united domains",
})

# Trusted ASN keywords (major CDNs and cloud providers)
TRUSTED_ASN_KEYWORDS: frozenset[str] = frozenset({
    "google", "gcp", "amazon", "aws", "cloudflare",
    "facebook", "meta", "microsoft", "azure",
    "fastly", "akamai", "cloudfront",
    "digitalocean", "linode", "vultr",
    "ovh", "hetzner", "scaleway",
})

# ======================================================================
# HELPER FUNCTIONS
# ======================================================================

def clamp_score(score: int | float) -> int:
    """Clamp a score to 0-100 range."""
    return max(0, min(100, int(round(score))))


def get_threat_level(score: int) -> tuple[str, str]:
    """Return (label, severity) for a given score."""
    for lo, hi, label, severity in THREAT_LEVELS:
        if lo <= score <= hi:
            return label, severity
    return "SAFE VERIFIED", "safe"


def classify_score(score: int) -> str:
    """
    Legacy classification (aligned with THREAT_LEVELS).

    As of v1.2: thresholds now match classification_v2 so that
    11-25 = LOW RISK and 0-10 = SAFE VERIFIED. A domain at 27/100
    with missing SSL and headers should never be called SAFE.
    """
    if score >= 71:
        return "CRITICAL"
    if score >= 46:
        return "HIGH RISK"
    if score >= 26:
        return "SUSPICIOUS"
    if score >= 11:
        return "LOW RISK"
    return "SAFE"


def is_hard_protected(domain: str) -> bool:
    """Check if domain is in the hard-protected list."""
    clean = domain.strip().lower().removeprefix("www.").removesuffix(".")
    return clean in HARD_PROTECT_DOMAINS


def compute_domain_age_days(created_iso: str | None) -> int | None:
    """Compute domain age in days from creation date ISO string."""
    if not created_iso:
        return None
    from datetime import datetime, UTC
    try:
        created = datetime.fromisoformat(created_iso).replace(tzinfo=UTC)
        return max((datetime.now(UTC) - created).days, 0)
    except (ValueError, TypeError):
        return None


def get_major_brand(domain: str) -> str | None:
    """Extract major brand from a domain, if any."""
    clean = domain.strip().lower().removeprefix("www.").removesuffix(".")
    parts = clean.split(".")
    if len(parts) >= 2:
        name = parts[-2]
        # Check against known major brands
        major_brands = {
            "google", "youtube", "facebook", "instagram", "whatsapp",
            "microsoft", "apple", "amazon", "netflix", "meta",
            "twitter", "linkedin", "github", "paypal", "stripe",
            "openai", "cloudflare", "zoom", "slack", "dropbox",
            "adobe", "wikipedia", "docker", "salesforce", "oracle",
            "ibm", "samsung", "sony", "intel", "nvidia", "amd",
            "cisco", "vmware", "tesla", "toyota", "honda",
            "nike", "adidas", "cocacola", "booking", "expedia",
            "airbnb", "uber", "fedex", "dhl", "ups",
            "nytimes", "wsj", "bloomberg", "reuters",
            "harvard", "stanford", "mit", "ox",
        }
        if name in major_brands:
            return name
    return None


def has_trusted_registrar(registrar: str | None) -> bool:
    """Check if registrar is known and trusted."""
    if not registrar:
        return False
    r = registrar.lower()
    return any(keyword in r for keyword in TRUSTED_REGISTRARS)


def has_trusted_asn(asn: str | None) -> bool:
    """Check if ASN belongs to a trusted provider."""
    if not asn:
        return False
    a = asn.lower()
    return any(keyword in a for keyword in TRUSTED_ASN_KEYWORDS)


# ======================================================================
# TRUST BONUS COMPUTATION
# ======================================================================

def compute_trust_bonuses(
    domain: str,
    age_days: int | None,
    registrar: str | None,
    ssl_issuer: str | None,
    asn: str | None,
    hosting: str | None,
    has_dnssec: bool = False,
    has_valid_ssl: bool = False,
    has_mx: bool = False,
    has_nameservers: bool = False,
    has_impersonation: bool = False,
) -> dict[str, Any]:
    """
    Compute legitimacy trust bonuses.

    When has_impersonation is True (typosquatting, homoglyph, or combosquatting
    detected), trust bonuses are sharply reduced because the domain is
    visually or structurally impersonating another entity. Age and brand
    should NOT reduce risk for impersonating domains.

    Returns dict with total_bonus, breakdown list, and reasoning.
    """
    bonuses: dict[str, float] = {}
    reasons: list[str] = []

    # Domain age bonuses (reduced by 50% when impersonation detected)
    if age_days is not None:
        if age_days > 7300:  # >20 years
            val = 8.0 if has_impersonation else 15.0
            bonuses["very_old_domain"] = val
            reasons.append(f"TRUST: Domain is over 20 years old (-{val:.0f} risk).")
        elif age_days > 3650:  # >10 years
            val = 5.0 if has_impersonation else 10.0
            bonuses["old_domain"] = val
            reasons.append(f"TRUST: Domain is over 10 years old (-{val:.0f} risk).")
        elif age_days > 1825:  # >5 years
            val = 3.0 if has_impersonation else 5.0
            bonuses["established_domain"] = val
            reasons.append(f"TRUST: Domain is over 5 years old (-{val:.0f} risk).")

    # Major trusted company bonus — ELIMINATED entirely when impersonation
    # If the domain impersonates a brand, it should NOT get trust for looking like that brand.
    if not has_impersonation:
        brand = get_major_brand(domain)
        if brand and age_days and age_days > 365:
            bonuses["major_trusted_company"] = 20.0
            reasons.append(f"TRUST: Major global brand '{brand}' with established domain (-20 risk).")
        elif brand:
            bonuses["major_trusted_company"] = 10.0
            reasons.append(f"TRUST: Major global brand '{brand}' detected (-10 risk).")

    # Trusted registrar bonus (infrastructure-level, not ownership)
    if has_trusted_registrar(registrar):
        bonuses["trusted_registrar"] = 10.0
        reasons.append(f"TRUST: Registrar '{registrar}' is a known trusted provider (-10 risk).")

    # Trusted ASN bonus (infrastructure-level)
    if has_trusted_asn(asn):
        bonuses["trusted_asn"] = 10.0
        reasons.append(f"TRUST: ASN '{asn}' belongs to trusted infrastructure (-10 risk).")

    # Valid SSL bonus (infrastructure-level)
    if has_valid_ssl:
        bonuses["valid_ssl"] = 5.0
        reasons.append("TRUST: Valid SSL/TLS certificate present (-5 risk).")

    # DNSSEC bonus (infrastructure-level)
    if has_dnssec:
        bonuses["dnssec_enabled"] = 5.0
        reasons.append("TRUST: DNSSEC is enabled (-5 risk).")

    # Consistent MX + DNS + SSL bonus
    if has_mx and has_nameservers and has_valid_ssl:
        bonuses["consistent_infrastructure"] = 5.0
        reasons.append("TRUST: Consistent MX, DNS, and SSL infrastructure (-5 risk).")

    total = round(sum(bonuses.values()), 1)
    return {
        "total_bonus": total,
        "breakdown": {k: round(v, 1) for k, v in bonuses.items()},
        "reasons": reasons,
    }


# ======================================================================
# PHISHING PENALTY COMPUTATION
# ======================================================================

def compute_phishing_penalties(
    domain: str,
    age_days: int | None,
    privacy_protected: bool = False,
    suspicious_registrar: bool = False,
    is_ip_like: bool = False,
    has_typosquatting: bool = False,
    typosquatting_score: float = 0.0,
    has_homoglyph: bool = False,
    homoglyph_count: int = 0,
    has_digit_substitution: bool = False,
    has_combosquatting: bool = False,
    has_brand_only: bool = False,
    matched_keywords: list[str] | None = None,
    suspicious_tld: bool = False,
    tld: str = "",
    excessive_subdomains: bool = False,
    dark_web_tld: bool = False,
    has_password_form: bool = False,
    has_external_form_action: bool = False,
) -> dict[str, Any]:
    """
    Compute phishing penalties for suspicious indicators.
    Returns dict with total_penalty, breakdown list, and reasoning.
    """
    penalties: dict[str, float] = {}
    reasons: list[str] = []
    total_penalty = 0.0

    # Typosquatting penalty
    if has_typosquatting:
        p = 40.0
        penalties["typosquatting"] = p
        reasons.append(f"PHISHING: Typosquatting detected (+{p:.0f} risk).")
        total_penalty += p
    elif typosquatting_score > 0.80:
        p = 25.0
        penalties["near_typosquatting"] = p
        reasons.append(f"PHISHING: Near-typosquatting pattern detected (+{p:.0f} risk).")
        total_penalty += p

    # Homoglyph penalty
    if has_homoglyph:
        p = min(50.0, 20.0 + (homoglyph_count * 8.0))
        penalties["homoglyph"] = p
        reasons.append(f"PHISHING: Homoglyph/confusable characters detected (+{p:.0f} risk).")
        total_penalty += p

    # Digit substitution
    if has_digit_substitution:
        p = 15.0
        penalties["digit_substitution"] = p
        reasons.append(f"PHISHING: Digit substitution detected (e.g., 0→o, 1→l) (+{p:.0f} risk).")
        total_penalty += p

    # Combosquatting (brand + keyword)
    if has_combosquatting:
        p = 35.0
        penalties["brand_keyword_phishing"] = p
        reasons.append(f"PHISHING: Brand name combined with phishing keywords (+{p:.0f} risk).")
        total_penalty += p
    elif has_brand_only:
        p = 15.0
        penalties["brand_in_domain"] = p
        reasons.append(f"PHISHING: Brand name embedded in suspicious domain (+{p:.0f} risk).")
        total_penalty += p

    # Suspicious TLD
    if dark_web_tld:
        p = 55.0
        penalties["dark_web_tld"] = p
        reasons.append(f"PHISHING: Dark-web TLD '.{tld}' is inherently high risk (+{p:.0f} risk).")
        total_penalty += p
    elif suspicious_tld:
        p = 20.0
        penalties["suspicious_tld"] = p
        reasons.append(f"PHISHING: TLD '.{tld}' is associated with elevated phishing abuse (+{p:.0f} risk).")
        total_penalty += p

    # Very new domain
    if age_days is not None:
        if age_days < 7:
            p = 30.0
            penalties["very_new_domain"] = p
            reasons.append(f"PHISHING: Domain registered less than a week ago (+{p:.0f} risk).")
            total_penalty += p
        elif age_days < 30:
            p = 25.0
            penalties["new_domain_month"] = p
            reasons.append(f"PHISHING: Domain registered less than 30 days ago (+{p:.0f} risk).")
            total_penalty += p
        elif age_days < 90:
            p = 15.0
            penalties["new_domain"] = p
            reasons.append(f"PHISHING: Domain less than 90 days old (+{p:.0f} risk).")
            total_penalty += p

    # WHOIS privacy
    if privacy_protected:
        p = 10.0
        penalties["whois_privacy"] = p
        reasons.append(f"PHISHING: WHOIS privacy/redaction enabled (+{p:.0f} risk).")
        total_penalty += p

    # Suspicious registrar
    if suspicious_registrar:
        p = 15.0
        penalties["suspicious_registrar"] = p
        reasons.append(f"PHISHING: Suspicious registrar pattern detected (+{p:.0f} risk).")
        total_penalty += p

    # IP masquerading
    if is_ip_like:
        p = 25.0
        penalties["ip_masquerading"] = p
        reasons.append(f"PHISHING: IP-style address used as domain name (+{p:.0f} risk).")
        total_penalty += p

    # Excessive subdomains
    if excessive_subdomains:
        p = 20.0
        penalties["excessive_subdomains"] = p
        reasons.append(f"PHISHING: Excessive subdomain depth used to obscure intent (+{p:.0f} risk).")
        total_penalty += p

    # Website signals
    if has_password_form:
        p = 12.0
        penalties["password_form"] = p
        reasons.append(f"PHISHING: Password input present on page (+{p:.0f} risk).")
        total_penalty += p

    if has_external_form_action:
        p = 18.0
        penalties["external_form_action"] = p
        reasons.append(f"PHISHING: Form submits credentials to external domain (+{p:.0f} risk).")
        total_penalty += p

    # ---- BRAND CAMPAIGN: typosquatting + combosquatting combination ----
    # When a domain both visually impersonates (typosquatting) AND embeds
    # a brand + phishing keyword (combosquatting), this is an aggressive
    # phishing campaign that must overpower all trust signals.
    if has_typosquatting and has_combosquatting:
        p = 30.0
        penalties["brand_campaign_typo_combo"] = p
        reasons.append(f"PHISHING: Aggressive brand campaign — typosquatting + combosquatting combined (+{p:.0f} risk).")
        total_penalty += p

    # ---- TYPOSQUATTING + HOMOGLYPH + DIGIT SUBS: severe impersonation ----
    if has_typosquatting and has_homoglyph and has_digit_substitution:
        p = 15.0
        penalties["severe_impersonation"] = p
        reasons.append(f"PHISHING: Severe impersonation — typosquatting + homoglyph + digit substitution (+{p:.0f} risk).")
        total_penalty += p

    # Exponential increase for multiple phishing indicators
    penalty_count = sum(1 for v in penalties.values() if v > 0)
    if penalty_count >= 3:
        # Apply a 35% exponential multiplier for 3+ signals (increased from 20%)
        expo_bonus = round(total_penalty * 0.35, 1)
        penalties["multiple_indicators_exponential"] = expo_bonus
        reasons.append(f"PHISHING: {penalty_count} phishing indicators detected — applying exponential increase (+{expo_bonus:.1f} risk).")
        total_penalty += expo_bonus

    return {
        "total_penalty": round(total_penalty, 1),
        "breakdown": {k: round(v, 1) for k, v in penalties.items()},
        "reasons": reasons,
    }


# ======================================================================
# DYNAMIC CONFIDENCE
# ======================================================================

def compute_dynamic_confidence(
    heuristic_score: int,
    header_score: int,
    xgb_available: bool,
    xgb_score: float | None,
    xgb_verdict: str | None,
    ai_score: int | None,
    trust_bonus: float,
    phishing_penalty: float,
) -> dict[str, Any]:
    """
    Compute dynamic confidence based on signal agreement and strength.

    Returns:
        confidence_pct: 0-100 percentage
        confidence_level: "High", "Medium", "Low"
        reasoning: human-readable explanation
    """
    confidence = 0
    reasons: list[str] = []
    signal_count = 0

    # Heuristic signal strength
    if heuristic_score >= 50 or heuristic_score <= 10:
        confidence += 25
        signal_count += 1

    # Header signal
    if header_score >= 15 or header_score <= 5:
        confidence += 15
        signal_count += 1

    # XGBoost signal (when available)
    if xgb_available and xgb_score is not None:
        if xgb_score >= 70 or xgb_score <= 20:
            confidence += 20
        else:
            confidence += 10
        signal_count += 1

    # AI signal (when available)
    if ai_score is not None:
        if ai_score >= 70 or ai_score <= 20:
            confidence += 15
        else:
            confidence += 8
        signal_count += 1

    # Trust/phishing agreement boost
    if trust_bonus > 20 or phishing_penalty > 40:
        confidence += 10
        signal_count += 1

    # Strong agreement: multiple signals point same direction
    if heuristic_score >= 50 and xgb_available and (xgb_score or 0) >= 50:
        confidence += 10
        reasons.append("Multiple independent signals agree on elevated risk.")
    elif heuristic_score <= 15 and xgb_available and (xgb_score or 0) <= 30:
        confidence += 10
        reasons.append("Multiple independent signals agree on low risk.")

    # Normalize
    if signal_count >= 3:
        confidence = min(confidence, 98)
    elif signal_count >= 2:
        confidence = min(confidence, 90)
    else:
        confidence = min(confidence, 70)

    # Hard protect override
    confidence = max(confidence, 50)

    if confidence >= 85:
        level = "High"
    elif confidence >= 60:
        level = "Medium"
    else:
        level = "Low"

    return {
        "confidence_pct": clamp_score(confidence),
        "confidence_level": level,
        "reasoning": reasons,
    }


# ======================================================================
# COMPUTE HYBRID SCORE
# ======================================================================

def compute_hybrid_score(
    domain: str,
    heuristic_score: int,
    header_score: int,
    xgb_res: dict[str, Any],
    ai_score: int | None,
    age_days: int | None = None,
    registrar: str | None = None,
    ssl_issuer: str | None = None,
    asn: str | None = None,
    hosting: str | None = None,
    has_dnssec: bool = False,
    has_valid_ssl: bool = False,
    has_mx: bool = False,
    has_nameservers: bool = False,
    privacy_protected: bool = False,
    suspicious_registrar: bool = False,
    is_ip_like: bool = False,
    has_typosquatting: bool = False,
    typosquatting_score: float = 0.0,
    has_homoglyph: bool = False,
    homoglyph_count: int = 0,
    has_digit_substitution: bool = False,
    has_combosquatting: bool = False,
    has_brand_only: bool = False,
    matched_keywords: list[str] | None = None,
    suspicious_tld: bool = False,
    tld: str = "",
    excessive_subdomains: bool = False,
    dark_web_tld: bool = False,
    has_password_form: bool = False,
    has_external_form_action: bool = False,
) -> tuple[int, dict[str, Any], list[str]]:
    """
    Compute the final hybrid risk score.

    This is the main entry point for the scoring engine.

    Returns:
        (final_score, score_components, reasoning_findings)
    """
    reasoning_findings: list[str] = []

    xgb_available = bool(xgb_res.get("xgb_available"))
    xgb_score = float(xgb_res.get("xgb_score", 0.0) or 0.0) if xgb_available else None
    xgb_verdict = str(xgb_res.get("xgb_verdict", "") or "").lower()

    # ==================================================================
    # STEP 1: Hard-protect check
    # ==================================================================
    if is_hard_protected(domain):
        # Hard-protected domains are capped at LOW RISK regardless of ML score
        final_score = min(heuristic_score, 15)
        final_score = clamp_score(final_score)

        components: dict[str, Any] = {
            "heuristic_analysis": heuristic_score,
            "security_headers": header_score,
            "xgboost_ml": xgb_score,
            "ai_analysis": ai_score,
            "signal_strength": {
                "heuristic_analysis": "PRIMARY",
                "security_headers": "SUPPORTING",
                "xgboost_ml": "SUPPORTING",
                "ai_analysis": "CONFIDENCE BOOST",
            },
            "final_score": final_score,
            "classification": classify_score(final_score),
            "classification_v2": "SAFE VERIFIED",
            "trust_bonuses": {"hard_protected": 50.0},
            "phishing_penalties": {},
            "hybrid_breakdown": {"hard_protected_cap": 50.0},
            "dynamic_confidence": {
                "confidence_pct": 95,
                "confidence_level": "High",
                "reasoning": ["Domain is on the hard-protected trusted list."],
            },
            "explainable_reasoning": [
                f"Domain '{domain}' is on the hard-protected trusted list.",
                "Hard-protected domains are globally recognized and verified.",
                "Score capped at LOW RISK regardless of ML or heuristic signals.",
            ],
        }

        reasoning_findings.append(
            f"HARD PROTECT: '{domain}' is on the hard-protected trusted list. "
            "Score capped at LOW RISK regardless of ML, heuristic, or other signals."
        )

        return final_score, components, reasoning_findings

    # Determine if any impersonation signal is present
    has_impersonation = has_typosquatting or has_homoglyph or has_combosquatting or has_digit_substitution

    # ==================================================================
    # STEP 2: Compute trust bonuses (reduced when impersonation detected)
    # ==================================================================
    trust_info = compute_trust_bonuses(
        domain=domain,
        age_days=age_days,
        registrar=registrar,
        ssl_issuer=ssl_issuer,
        asn=asn,
        hosting=hosting,
        has_dnssec=has_dnssec,
        has_valid_ssl=has_valid_ssl,
        has_mx=has_mx,
        has_nameservers=has_nameservers,
        has_impersonation=has_impersonation,
    )
    trust_bonus = trust_info["total_bonus"]

    # ==================================================================
    # STEP 3: Compute phishing penalties
    # ==================================================================
    penalty_info = compute_phishing_penalties(
        domain=domain,
        age_days=age_days,
        privacy_protected=privacy_protected,
        suspicious_registrar=suspicious_registrar,
        is_ip_like=is_ip_like,
        has_typosquatting=has_typosquatting,
        typosquatting_score=typosquatting_score,
        has_homoglyph=has_homoglyph,
        homoglyph_count=homoglyph_count,
        has_digit_substitution=has_digit_substitution,
        has_combosquatting=has_combosquatting,
        has_brand_only=has_brand_only,
        matched_keywords=matched_keywords or [],
        suspicious_tld=suspicious_tld,
        tld=tld,
        excessive_subdomains=excessive_subdomains,
        dark_web_tld=dark_web_tld,
        has_password_form=has_password_form,
        has_external_form_action=has_external_form_action,
    )
    phishing_penalty = penalty_info["total_penalty"]

    # ==================================================================
    # STEP 4: Dynamic weights
    # ==================================================================
    weights = dict(BASE_WEIGHTS)

    # Decrease ML weight for trusted domains
    if trust_bonus > 20:
        weights["xgboost_ml"] = 0.10
        weights["domain_reputation"] = 0.25

    # Increase heuristic weight when phishing is obvious
    if phishing_penalty > 40:
        weights["heuristics"] = 0.45
        weights["xgboost_ml"] = 0.10

    # Normalize weights to sum to 1.0
    total_weight = sum(weights.values())
    weights = {k: v / total_weight for k, v in weights.items()}

    # ==================================================================
    # STEP 5: Raw score computation
    # ==================================================================
    # Base: weighted combination of signals
    weighted_heuristic = heuristic_score * weights["heuristics"]
    weighted_headers = header_score * weights["security_headers"]
    weighted_xgb = (xgb_score or 0) * weights["xgboost_ml"] if xgb_available else 0
    weighted_ai = (ai_score or 0) * weights["ai_analysis"] if ai_score is not None else 0

    base_score = weighted_heuristic + weighted_headers + weighted_xgb + weighted_ai

    # Apply trust bonuses (reduce risk)
    adjusted_score = base_score - trust_bonus

    # Apply phishing penalties (increase risk)
    adjusted_score += phishing_penalty

    # ---- SECURITY POSTURE PENALTY ----
    # Domains with missing SSL or poor security headers should get a
    # direct penalty that age/registrar trust cannot suppress.
    # This ensures a domain at 27/100 with all headers missing and no SSL
    # is never called SAFE.
    security_posture_penalty = 0.0
    if not has_valid_ssl:
        # Missing SSL is a significant security failure
        penalty = 15.0
        security_posture_penalty += penalty
        adjusted_score += penalty
        reasoning_findings.append(
            f"SECURITY POSTURE: No valid SSL/TLS detected — adding +{penalty:.0f} risk floor."
        )
    if header_score >= 10:
        # Multiple missing security headers indicate poor hygiene
        penalty = 8.0
        security_posture_penalty += penalty
        adjusted_score += penalty
        reasoning_findings.append(
            f"SECURITY POSTURE: Missing critical security headers "
            f"(header score={header_score}) — adding +{penalty:.0f} risk."
        )
    elif header_score >= 6:
        # Moderate header issues
        penalty = 4.0
        security_posture_penalty += penalty
        adjusted_score += penalty
        reasoning_findings.append(
            f"SECURITY POSTURE: Weak security header posture "
            f"(header score={header_score}) — adding +{penalty:.0f} risk."
        )

    # ==================================================================
    # STEP 6: False-positive reduction (SKIPPED when impersonation or
    #          poor security posture present)
    # ==================================================================
    # Poor security posture means the site has security hygiene issues
    # that should prevent score capping regardless of age or trust.
    poor_security = not has_valid_ssl or header_score >= 10
    
    # If impersonation or poor security is detected, do NOT apply caps
    if not has_impersonation and not poor_security:
        # If trust is high and phishing signals are low, aggressively reduce
        if trust_bonus > 15 and phishing_penalty < 10 and heuristic_score < 25:
            adjusted_score = min(adjusted_score, 18)
            reasoning_findings.append(
                "FALSE POSITIVE GUARD: Strong trust signals with minimal phishing "
                "indicators — score capped at LOW RISK."
            )

        # If domain is old, has SSL, major brand, and known ASN, cap at LOW
        brand = get_major_brand(domain)
        if (
            brand
            and age_days is not None
            and age_days > 365
            and has_valid_ssl
            and not phishing_penalty
        ):
            adjusted_score = min(adjusted_score, 12)
            reasoning_findings.append(
                f"FALSE POSITIVE GUARD: '{domain}' is a major brand ({brand}) with "
                f"established infrastructure and no phishing indicators."
            )

    # Cap: never go below 0
    adjusted_score = max(0, adjusted_score)

    # ==================================================================
    # STEP 7: Multi-signal escalation (includes impersonation signals)
    # ==================================================================
    strong_signals = 0
    if xgb_available and xgb_verdict == "phishing" and (xgb_score or 0) >= 80:
        strong_signals += 1
    if ai_score is not None and ai_score >= 85:
        strong_signals += 1
    if heuristic_score >= 75:
        strong_signals += 1
    if phishing_penalty >= 60:
        strong_signals += 1
    # Typosquatting + combosquatting together is a strong signal
    if has_typosquatting and has_combosquatting:
        strong_signals += 1
    # Typosquatting + homoglyph + digit substitution is extremely strong
    if has_typosquatting and has_homoglyph and has_digit_substitution:
        strong_signals += 1

    if strong_signals >= 2:
        adjusted_score = max(adjusted_score, 65)
        reasoning_findings.append(
            "MULTI-SIGNAL RISK: Multiple independent engines detected "
            "high-risk behavior — minimum score of 65 enforced."
        )

    # When typosquatting is present, ensure age-based trust doesn't suppress the score
    if has_typosquatting and phishing_penalty > 20:
        # Phishing penalties must be fully applied regardless of age
        implied_min = max(0, 25 + phishing_penalty - trust_bonus)
        adjusted_score = max(adjusted_score, min(implied_min, 100))
        reasoning_findings.append(
            "IMPERSONATION OVERRIDE: Typosquatting detected — trust bonuses "
            "do not suppress phishing evidence."
        )

    # ==================================================================
    # STEP 8: Finalize
    # ==================================================================
    final_score = clamp_score(adjusted_score)

    # Classification
    classification_label, classification_severity = get_threat_level(final_score)
    legacy_classification = classify_score(final_score)

    # Dynamic confidence
    confidence = compute_dynamic_confidence(
        heuristic_score=heuristic_score,
        header_score=header_score,
        xgb_available=xgb_available,
        xgb_score=xgb_score,
        xgb_verdict=xgb_verdict,
        ai_score=ai_score,
        trust_bonus=trust_bonus,
        phishing_penalty=phishing_penalty,
    )

    # Build explainable reasoning
    explainable_reasoning: list[str] = []
    explainable_reasoning.append(f"FINAL SCORE: {final_score}/100 ({classification_label})")
    explainable_reasoning.append(f"  Weighted base: {base_score:.1f}")
    explainable_reasoning.append(f"  Trust bonuses: -{trust_bonus:.1f}")
    explainable_reasoning.append(f"  Phishing penalties: +{phishing_penalty:.1f}")

    for r in trust_info["reasons"]:
        explainable_reasoning.append(f"  {r}")
    for r in penalty_info["reasons"]:
        explainable_reasoning.append(f"  {r}")

    # Build score components (backward compatible)
    components = {
        "heuristic_analysis": heuristic_score,
        "security_headers": header_score,
        "xgboost_ml": xgb_score,
        "ai_analysis": ai_score,
        "signal_strength": {
            "heuristic_analysis": "PRIMARY",
            "security_headers": "SUPPORTING",
            "xgboost_ml": "SUPPORTING",
            "ai_analysis": "CONFIDENCE BOOST",
        },
        "final_score": final_score,
        "classification": legacy_classification,
        # NEW FIELDS (additive, backward compatible)
        "classification_v2": classification_label,
        "classification_severity": classification_severity,
        "trust_bonuses": trust_info["breakdown"],
        "trust_bonus_total": trust_bonus,
        "phishing_penalties": penalty_info["breakdown"],
        "phishing_penalty_total": phishing_penalty,
        "hybrid_breakdown": {
            "weighted_heuristic": round(weighted_heuristic, 1),
            "weighted_headers": round(weighted_headers, 1),
            "weighted_xgboost_ml": round(weighted_xgb, 1),
            "weighted_ai": round(weighted_ai, 1),
            "base_score": round(base_score, 1),
            "trust_bonus_applied": round(-trust_bonus, 1),
            "phishing_penalty_applied": round(phishing_penalty, 1),
            "weights": {k: round(v, 3) for k, v in weights.items()},
        },
        "dynamic_confidence": confidence,
        "explainable_reasoning": explainable_reasoning,
    }

    # Add trust and penalty reasons to findings
    for r in trust_info["reasons"]:
        reasoning_findings.append(r)
    for r in penalty_info["reasons"]:
        reasoning_findings.append(r)
    for r in confidence["reasoning"]:
        reasoning_findings.append(f"CONFIDENCE: {r}")

    # Add explainable reasoning summary
    reasoning_findings.append(
        f"HYBRID SCORING: Base={base_score:.0f}, Trust=-{trust_bonus:.0f}, "
        f"Penalty=+{phishing_penalty:.0f}, Final={final_score}/100"
    )

    # Add confidence to findings
    reasoning_findings.append(
        f"CONFIDENCE: {confidence['confidence_level']} "
        f"({confidence['confidence_pct']}%)"
    )

    return final_score, components, reasoning_findings

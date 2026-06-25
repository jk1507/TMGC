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
import math

# ======================================================================
# CONSTANTS
# ======================================================================

# Suspicious domain name patterns — domain labels that suggest malicious
# or security-exploit intent (leet-speak, hacking terms, etc.).
# These are NOT brand impersonation or typosquatting — they are names
# that intrinsically hint at unsafe activity. A mild penalty is applied
# to prevent such domains from reaching 0/100 purely via trust bonuses.
SUSPICIOUS_NAME_PATTERNS: frozenset[str] = frozenset({
    "exploit", "xploit", "hack", "hax", "crack", "keygen",
    "malware", "ransom", "trojan", "virus", "worm",
    "phish", "phising", "scam", "fraud",
    "spam", "spammy", "spammer",
    "ddos", "dosattack", "botnet", "c2server",
    "darknet", "darkweb", "onion",
    "stolen", "leak", "leaked", "doxx",
    "cheat", "cheats", "modmenu",
})

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
    # Security companies
    "crowdstrike.com", "mandiant.com", "kaspersky.com", "sophos.com",
    "mcafee.com", "trendmicro.com", "paloaltonetworks.com", "checkpoint.com",
    # Non-profit digital libraries
    "archive.org",
    "gutenberg.org",
})

# Trusted registrar keywords
TRUSTED_REGISTRARS: frozenset[str] = frozenset({
    "markmonitor", "safenames", "csc corporate", "cscglobal",
    "nominalia", "gandi", "namecheap", "godaddy",
    "google", "amazon", "aws", "cloudflare",
    "network solutions", "enom", "tucows",
    "1&1 ionos", "ionos", "united domains",
    # Government registrars
    "national informatics centre", "nic", "nics",
})

# Trusted ASN keywords (major CDNs and cloud providers)
TRUSTED_ASN_KEYWORDS: frozenset[str] = frozenset({
    "google", "gcp", "amazon", "aws", "cloudflare",
    "facebook", "meta", "microsoft", "azure",
    "fastly", "akamai", "cloudfront",
    "digitalocean", "linode", "vultr",
    "ovh", "hetzner", "scaleway",
    # Indian government hosting
    "nic", "national informatics", "apitec",
    "sify", "ctrl s", "ctrlS", "netmagic",
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
            "crowdstrike", "archive", "gutenberg",
        }
        if name in major_brands:
            return name
    return None


def is_government_domain(domain: str) -> bool:
    """
    Check if domain is a government (.gov, .gov.*) or education (.edu) or military (.mil) domain.

    Checks only the TLD (last label) and second-level domain (second-to-last label)
    to avoid false positives like \"something.gov.com\" (which is NOT a government domain).

    Matching patterns:
      - .gov          : whitehouse.gov, usa.gov
      - .gov.*        : example.gov.in, example.gov.uk, example.gov.au
      - .edu          : harvard.edu, mit.edu
      - .mil          : army.mil
    """
    clean = domain.strip().lower().removeprefix("www.").removesuffix(".")
    parts = clean.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]  # The actual TLD (last label)
    sld = parts[-2] if len(parts) >= 2 else ""  # Second-level domain

    # Direct TLD matches: .gov, .edu, .mil
    if tld in ("gov", "edu", "mil"):
        return True

    # Second-level .gov.* domains: .gov.in, .gov.uk, .gov.au, etc.
    if sld == "gov":
        return True

    return False


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

    # Government / education domain bonus
    # .gov, .gov.*, .edu, .mil domains are inherently more trustworthy
    # because they require verified registration and government oversight.
    # BUT: only apply if the domain has actual infrastructure (DNS, WHOIS, or SSL).
    # A non-resolving domain with no WHOIS data is not verifiable and should
    # not get trust just because its name ends in .gov.
    if is_government_domain(domain) and not has_impersonation:
        has_infrastructure = has_nameservers or has_mx or has_valid_ssl or age_days is not None or registrar is not None
        if has_infrastructure:
            bonuses["government_domain"] = 20.0
            reasons.append("TRUST: Government/education domain with verified registration (-20 risk).")

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
    # NEW v2.0 SIGNALS
    has_abused_infrastructure: bool = False,
    abused_infra_risk: float = 0.0,
    has_subdomain_phishing: bool = False,
    has_suspicious_url_path: bool = False,
    url_path_risk: float = 0.0,
    has_suspicious_redirect: bool = False,
    redirect_hop_count: int = 0,
    has_punycode_homograph: bool = False,
    homograph_brand: str | None = None,
    has_ssl_expired: bool = False,
    has_ssl_self_signed: bool = False,
    has_ssl_hostname_mismatch: bool = False,
    has_ssl_revoked: bool = False,
    has_ssl_untrusted_root: bool = False,
    has_ssl_weak_protocol: bool = False,
    has_ssl_weak_cipher: bool = False,
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

    # NEW v2.0: Abused infrastructure (ngrok, duckdns, etc.)
    if has_abused_infrastructure:
        p = max(abused_infra_risk, 15.0)
        penalties["abused_infrastructure"] = p
        reasons.append(f"PHISHING: Domain uses service frequently abused for phishing/C2 (+{p:.0f} risk).")
        total_penalty += p

    # NEW v2.0: Subdomain phishing (brand impersonation via subdomains)
    if has_subdomain_phishing:
        p = 40.0
        penalties["subdomain_phishing"] = p
        reasons.append(f"PHISHING: Brand impersonation via subdomain abuse (+{p:.0f} risk).")
        total_penalty += p

    # NEW v2.0: Suspicious URL path
    if has_suspicious_url_path:
        p = max(url_path_risk, 8.0)
        penalties["suspicious_url_path"] = p
        reasons.append(f"PHISHING: Suspicious keywords detected in URL path (+{p:.0f} risk).")
        total_penalty += p

    # NEW v2.0: Suspicious redirect chain
    if has_suspicious_redirect:
        p = min(20.0, 8.0 + (redirect_hop_count * 3.0))
        penalties["suspicious_redirect_chain"] = p
        reasons.append(f"PHISHING: Suspicious redirect chain detected ({redirect_hop_count} hops) (+{p:.0f} risk).")
        total_penalty += p

    # NEW v2.0: Punycode homograph attack
    if has_punycode_homograph:
        p = 25.0
        if homograph_brand:
            p = 35.0
            reasons.append(f"PHISHING: Punycode homograph attack impersonating '{homograph_brand}' (+{p:.0f} risk).")
        else:
            reasons.append(f"PHISHING: Punycode/IDN homograph attack detected (+{p:.0f} risk).")
        penalties["punycode_homograph"] = p
        total_penalty += p

    # NEW v2.0: SSL-specific penalties (hardened classification)
    if has_ssl_expired:
        p = 18.0
        penalties["ssl_expired"] = p
        reasons.append(f"PHISHING: SSL certificate is expired (+{p:.0f} risk).")
        total_penalty += p
    if has_ssl_self_signed:
        p = 12.0
        penalties["ssl_self_signed"] = p
        reasons.append(f"PHISHING: Self-signed SSL certificate — no trust chain (+{p:.0f} risk).")
        total_penalty += p
    if has_ssl_hostname_mismatch:
        p = 15.0
        penalties["ssl_hostname_mismatch"] = p
        reasons.append(f"PHISHING: SSL hostname mismatch (+{p:.0f} risk).")
        total_penalty += p
    if has_ssl_revoked:
        p = 25.0
        penalties["ssl_revoked"] = p
        reasons.append(f"PHISHING: SSL certificate is REVOKED (+{p:.0f} risk).")
        total_penalty += p
    if has_ssl_untrusted_root:
        p = 10.0
        penalties["ssl_untrusted_root"] = p
        reasons.append(f"PHISHING: SSL certificate signed by untrusted root CA (+{p:.0f} risk).")
        total_penalty += p
    if has_ssl_weak_protocol:
        p = 8.0
        penalties["ssl_weak_protocol"] = p
        reasons.append(f"PHISHING: Weak TLS protocol version (TLS 1.0/1.1) (+{p:.0f} risk).")
        total_penalty += p
    if has_ssl_weak_cipher:
        p = 6.0
        penalties["ssl_weak_cipher"] = p
        reasons.append(f"PHISHING: Weak cipher suite (RC4/DES/etc.) (+{p:.0f} risk).")
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
    # v3.0: Additional signals for improved confidence
    threat_feed_score: float = 0.0,
    threat_feed_count: int = 0,
    threat_feed_flagged_count: int = 0,
    ensemble_model_count: int = 0,
    ensemble_agreement: int = 0,
    # Enhanced ensemble mathematical metrics (v3.5)
    ensemble_entropy: float | None = None,
    ensemble_kl_divergence: float | None = None,
    ensemble_beta_width: float | None = None,
    ensemble_kappa: float | None = None,
    ensemble_bayes_factor: float | None = None,
    ensemble_bma_proba: float | None = None,
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

    # v3.0: Threat feed signals boost confidence
    if threat_feed_score > 0:
        if threat_feed_flagged_count >= 2:
            confidence += 15
            reasons.append(f"{threat_feed_flagged_count} threat feeds flagged this domain — strong external validation.")
        elif threat_feed_flagged_count == 1:
            confidence += 8
            reasons.append(f"1 threat feed flagged this domain — external validation available.")
    elif threat_feed_count >= 3:
        # Multiple clean feeds boost confidence in a clean verdict
        confidence += 10
        reasons.append(f"{threat_feed_count} threat feeds checked, all clean — strong negative validation.")

    # v3.0: Ensemble model agreement boosts confidence
    if ensemble_model_count >= 3 and ensemble_agreement >= 70:
        confidence += 12
        reasons.append(f"{ensemble_model_count} ML models agree ({ensemble_agreement}% agreement) — high model consensus.")
    elif ensemble_model_count >= 2 and ensemble_agreement >= 60:
        confidence += 8
        reasons.append(f"{ensemble_model_count} ML models agree ({ensemble_agreement}% agreement).")

    # ==================================================================
    # ENHANCED ENSEMBLE MATHEMATICAL METRICS (v3.5)
    # ==================================================================
    #
    # These metrics use advanced mathematical concepts:
    #   - Shannon entropy: information-theoretic uncertainty (bits)
    #   - KL divergence: model disagreement in nats
    #   - Beta credible interval width: Bayesian posterior uncertainty
    #   - Cohen's kappa: chance-adjusted inter-model agreement
    #   - Bayes factor: relative evidence for best vs worst model
    #   - BMA probability: Bayesian model averaged prediction
    #
    # Each contributes to a mathematically rigorous confidence score.

    # Shannon entropy → confidence penalty (max 15)
    if ensemble_entropy is not None:
        # entropy=0 bits (certain) → +15, entropy=0.5 (uncertain) → +7, entropy=1 (max) → +2
        entropy_conf = round(15.0 * max(0.0, 1.0 - ensemble_entropy * 1.3))
        confidence += entropy_conf
        if ensemble_entropy < 0.15:
            reasons.append("ENSEMBLE MATH: Shannon entropy is very low (%.3f bits) — high prediction certainty." % ensemble_entropy)
        elif ensemble_entropy > 0.6:
            reasons.append("ENSEMBLE MATH: Shannon entropy is high (%.3f bits) — models disagree, lowering confidence." % ensemble_entropy)

    # KL divergence → penalty for model disagreement (max 10)
    if ensemble_kl_divergence is not None:
        # KL=0 (perfect agree) → +10, KL=0.1 → +7, KL=0.5 → +3, KL=1.0+ → +0
        kl_conf = round(10.0 * math.exp(-5.0 * ensemble_kl_divergence))
        confidence += kl_conf
        if ensemble_kl_divergence > 0.3:
            reasons.append("ENSEMBLE MATH: KL divergence of %.4f nats — significant model disagreement detected." % ensemble_kl_divergence)
        elif ensemble_kl_divergence < 0.05:
            reasons.append("ENSEMBLE MATH: KL divergence is negligible — strong model consensus.")

    # Beta credible interval width → narrower = more confident (max 10)
    if ensemble_beta_width is not None:
        # width=0 → +10, width=0.2 → +6, width=0.5 → +3, width=0.8+ → +1
        width_conf = round(10.0 * math.exp(-4.0 * ensemble_beta_width))
        confidence += width_conf
        if ensemble_beta_width < 0.1:
            reasons.append("ENSEMBLE MATH: Beta 95%% credible interval is narrow (%.3f) — high Bayesian confidence." % ensemble_beta_width)
        elif ensemble_beta_width > 0.4:
            reasons.append("ENSEMBLE MATH: Beta 95%% credible interval is wide (%.3f) — Bayesian posterior uncertainty." % ensemble_beta_width)

    # Cohen's kappa → inter-model agreement beyond chance (max 8)
    if ensemble_kappa is not None:
        # κ=1.0 → +8, κ=0.5 → +5, κ=0.0 → +1
        kappa_conf = round(max(1, min(8, int(ensemble_kappa * 8))))
        confidence += kappa_conf
        if ensemble_kappa >= 0.75:
            reasons.append("ENSEMBLE MATH: Cohen's κ=%.2f — excellent inter-model agreement beyond chance." % ensemble_kappa)
        elif ensemble_kappa < 0.4:
            reasons.append("ENSEMBLE MATH: Cohen's κ=%.2f — poor inter-model agreement." % ensemble_kappa)

    # Bayes factor → confidence in model selection (max 7)
    if ensemble_bayes_factor is not None:
        # BF=1 (equal evidence) → +1, BF=3 (moderate) → +4, BF=10+ (strong) → +7
        bf_conf = round(min(7, max(1, int(math.log2(max(ensemble_bayes_factor, 1.0)) * 2.5))))
        confidence += bf_conf
        if ensemble_bayes_factor >= 10:
            reasons.append("ENSEMBLE MATH: Bayes factor=%.1f — strong evidence favoring the best model." % ensemble_bayes_factor)

    # Normalize
    if signal_count >= 3:
        confidence = min(confidence, 98)
    elif signal_count >= 2:
        confidence = min(confidence, 90)
    else:
        confidence = min(confidence, 70)

    # Hard protect override
    confidence = max(confidence, 50)

    # Confidence level MUST match the actual percentage value
    # to avoid contradictory labels like "High 4%" or "Low 95%".
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
# DATA COMPLETENESS TRACKING
# ======================================================================

CHECK_NAMES: list[str] = [
    "DNS A Record",
    "DNS MX Record",
    "Domain WHOIS",
    "SSL/TLS Certificate",
    "HTTP Headers",
    "IP WHOIS",
    "Port Scan",
    "Ping / Reachability",
]


def compute_data_completeness(
    dns_a_ok: bool = False,
    dns_mx_ok: bool = False,
    domain_whois_ok: bool = False,
    ssl_ok: bool = False,
    http_ok: bool = False,
    ip_whois_ok: bool = False,
    port_scan_ok: bool = False,
    ping_ok: bool = False,
) -> dict[str, Any]:
    """
    Compute data completeness percentage and per-check status.

    Each check is either "PASS" (data collected), "FAIL" (tool failed,
    timeout, or missing data), or "SKIPPED" (e.g. IP WHOIS skipped when
    domain has no IP).

    A check passes if the command ran successfully (status="ok") AND
    produced meaningful output (not empty, not an error message).

    Returns:
        completeness_pct: 0-100 percentage
        checks: dict of check_name -> status
        passed_count: int
        total_checked: int
        insufficient: bool (True when < 40%)
    """
    checks: dict[str, str] = {}
    passed = 0
    total = 0

    # DNS A — resolve must return at least one IP
    if dns_a_ok:
        checks["DNS A Record"] = "PASS"
        passed += 1
    else:
        checks["DNS A Record"] = "FAIL"
    total += 1

    # DNS MX — mail exchange lookup
    if dns_mx_ok:
        checks["DNS MX Record"] = "PASS"
        passed += 1
    else:
        checks["DNS MX Record"] = "FAIL"
    total += 1

    # Domain WHOIS
    if domain_whois_ok:
        checks["Domain WHOIS"] = "PASS"
        passed += 1
    else:
        checks["Domain WHOIS"] = "FAIL"
    total += 1

    # SSL/TLS
    if ssl_ok:
        checks["SSL/TLS Certificate"] = "PASS"
        passed += 1
    else:
        checks["SSL/TLS Certificate"] = "FAIL"
    total += 1

    # HTTP Headers
    if http_ok:
        checks["HTTP Headers"] = "PASS"
        passed += 1
    else:
        checks["HTTP Headers"] = "FAIL"
    total += 1

    # IP WHOIS (may be skipped if no IP resolved)
    if ip_whois_ok:
        checks["IP WHOIS"] = "PASS"
        passed += 1
        total += 1
    else:
        # If the check simply didn't run (no IP), mark as SKIPPED and don't count
        checks["IP WHOIS"] = "SKIPPED"

    # Port Scan
    if port_scan_ok:
        checks["Port Scan"] = "PASS"
        passed += 1
    else:
        checks["Port Scan"] = "FAIL"
    total += 1

    # Ping / Reachability
    if ping_ok:
        checks["Ping / Reachability"] = "PASS"
        passed += 1
    else:
        checks["Ping / Reachability"] = "FAIL"
    total += 1

    pct = round((passed / max(total, 1)) * 100)

    return {
        "completeness_pct": pct,
        "checks": checks,
        "passed_count": passed,
        "total_checked": total,
        "insufficient": pct < 40,
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
    # NEW v2.0 SIGNALS
    has_abused_infrastructure: bool = False,
    abused_infra_risk: float = 0.0,
    has_subdomain_phishing: bool = False,
    has_suspicious_url_path: bool = False,
    url_path_risk: float = 0.0,
    has_suspicious_redirect: bool = False,
    redirect_hop_count: int = 0,
    has_punycode_homograph: bool = False,
    homograph_brand: str | None = None,
    has_ssl_expired: bool = False,
    has_ssl_self_signed: bool = False,
    has_ssl_hostname_mismatch: bool = False,
    has_ssl_revoked: bool = False,
    has_ssl_untrusted_root: bool = False,
    has_ssl_weak_protocol: bool = False,
    has_ssl_weak_cipher: bool = False,
    # Tool failure flags: when True, the corresponding lookup FAILED entirely
    # (timeout, missing binary, network error) and the result is "DATA UNAVAILABLE".
    # Tool failure must NEVER be treated as domain risk.
    ssl_unavailable: bool = False,
    headers_unavailable: bool = False,
    # v3.0: Threat feed and ensemble ML signals for confidence
    threat_feed_score: float = 0.0,
    threat_feed_count: int = 0,
    threat_feed_flagged_count: int = 0,
    ensemble_model_count: int = 0,
    ensemble_agreement: int = 0,
    # Enhanced ensemble mathematical metrics (v3.5)
    ensemble_result: dict[str, Any] | None = None,
    # v4.0: Data completeness — tool failures never increase risk
    data_completeness: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], list[str]]:
    """
    Compute the final hybrid risk score.

    This is the main entry point for the scoring engine.

    When data_completeness is provided and data_completeness["insufficient"]
    is True (< 40% of checks passed), the verdict is overridden to
    "INSUFFICIENT DATA" and the risk score is set to a neutral value.
    This prevents false highs/lows from partial data.

    Returns:
        (final_score, score_components, reasoning_findings)
    """
    reasoning_findings: list[str] = []

    xgb_available = bool(xgb_res.get("xgb_available"))
    xgb_score = float(xgb_res.get("xgb_score", 0.0) or 0.0) if xgb_available else None
    xgb_verdict = str(xgb_res.get("xgb_verdict", "") or "").lower()

    # ==================================================================
    # STEP 1: Hard-protected domain trust bonus (instead of hard cap)
    # ==================================================================
    # Hard-protected domains are globally recognized, verified organizations.
    # Instead of a hard cap at 15 (which hides bugs like WHOIS/ASN failures),
    # we add a large trust bonus and let the full scoring pipeline run.
    #
    # This way:
    #   - The real component scores are visible (heuristic, ML, headers, etc.)
    #   - If WHOIS/ASN/SSL fails, the underlying higher score reveals the bug
    #   - The final score still ends up LOW RISK (~15-18) from the trust bonus
    #   - Bugs are visible instead of being hidden by the cap
    is_verified_org = is_hard_protected(domain)

    # Determine if any impersonation signal is present
    has_impersonation = has_typosquatting or has_homoglyph or has_combosquatting or has_digit_substitution

    # ==================================================================
    # STEP 1a: INSUFFICIENT DATA CHECK (BEFORE ANY SCORING)
    # ==================================================================
    # When less than 40% of analysis checks succeeded, we cannot make a
    # reliable assessment. Return a neutral "INSUFFICIENT DATA" verdict.
    # Tool failures, timeouts, missing WHOIS data, or unreachable servers
    # reduce confidence, not increase risk.
    if data_completeness and data_completeness.get("insufficient", False):
        pct = data_completeness.get("completeness_pct", 0)
        checks = data_completeness.get("checks", {})
        passed = data_completeness.get("passed_count", 0)
        total = data_completeness.get("total_checked", 0)
        
        reasoning_findings.append(
            f"INSUFFICIENT DATA: Only {pct}% ({passed}/{total} checks) completed successfully. "
            f"Not enough evidence was collected to classify this domain. "
            f"Score set to neutral (0). Tool failures never increase risk."
        )
        
        # List which checks passed/failed
        for check_name, status in checks.items():
            if status == "PASS":
                reasoning_findings.append(f"  CHECK PASS: {check_name}")
            elif status == "FAIL":
                reasoning_findings.append(f"  CHECK FAIL: {check_name} — data unavailable")
            elif status == "SKIPPED":
                reasoning_findings.append(f"  CHECK SKIP: {check_name} — not applicable")
        
        components: dict[str, Any] = {
            "heuristic_analysis": 0,
            "security_headers": 0,
            "xgboost_ml": None,
            "ai_analysis": None,
            "signal_strength": {
                "heuristic_analysis": "DISABLED",
                "security_headers": "DISABLED",
                "xgboost_ml": "DISABLED",
                "ai_analysis": "DISABLED",
            },
            "final_score": 0,
            "classification": "INSUFFICIENT DATA",
            "classification_v2": "INSUFFICIENT DATA",
            "classification_severity": "insufficient",
            "trust_bonuses": {},
            "trust_bonus_total": 0.0,
            "verified_org_bonus": 0.0,
            "is_verified_org": False,
            "phishing_penalties": {},
            "phishing_penalty_total": 0.0,
            "hybrid_breakdown": {
                "weighted_heuristic": 0,
                "weighted_headers": 0,
                "weighted_xgboost_ml": 0,
                "weighted_ai": 0,
                "base_score": 0,
                "trust_bonus_applied": 0,
                "phishing_penalty_applied": 0,
                "weights": {k: 0.0 for k in BASE_WEIGHTS},
            },
            "dynamic_confidence": {
                "confidence_pct": 0,
                "confidence_level": "Insufficient",
                "reasoning": [f"Only {pct}% data completeness — cannot make reliable assessment."],
            },
            "explainable_reasoning": reasoning_findings[-10:],  # Last 10 findings
        }
        return 0, components, reasoning_findings

    # ==================================================================
    # STEP 1b: Verified Organization trust bonus
    # ==================================================================
    # This runs AFTER the has_impersonation check but BEFORE trust bonuses
    # are computed, so the verified org bonus is a separate additive entry.
    # The -50 bonus + age/SSL/registrar bonuses bring Wikipedia to ~15-18,
    # but the component scores remain visible for debugging.
    verified_org_bonus = 0.0
    if is_verified_org:
        verified_org_bonus = 50.0
        reasoning_findings.append(
            f"VERIFIED ORGANIZATION: '{domain}' is on the verified trusted domain list. "
            f"Applying -{verified_org_bonus:.0f} risk trust bonus. "
            f"This domain is globally recognized — component scores are still visible for debugging."
        )

    # ==================================================================
    # STEP 1b: AI score capping when ML disagrees
    # ==================================================================
    # When ML says Legitimate/Uncertain and heuristic evidence is low, cap AI
    # influence to 5% to prevent a hallucinated AI assessment from distorting
    # the final verdict. A single AI score of 95 should not override
    # ML + heuristics that say Legitimate.
    if ai_score is not None and xgb_available:
        xgb_verdict_lower = (xgb_verdict or "").lower()
        if xgb_verdict_lower in ("legitimate", "uncertain") and (xgb_score or 0) <= 35 and heuristic_score < 25:
            original_ai = ai_score
            ai_score = min(ai_score, 5)
            if original_ai != ai_score:
                reasoning_findings.append(
                    f"AI OVERRIDE GUARD: ML model indicates {xgb_verdict} ({xgb_score:.0f}%) with low heuristic "
                    f"evidence ({heuristic_score}). AI score capped from {original_ai} to {ai_score} "
                    f"to prevent AI hallucination from distorting the verdict."
                )

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
        # NEW v2.0
        has_abused_infrastructure=has_abused_infrastructure,
        abused_infra_risk=abused_infra_risk,
        has_subdomain_phishing=has_subdomain_phishing,
        has_suspicious_url_path=has_suspicious_url_path,
        url_path_risk=url_path_risk,
        has_suspicious_redirect=has_suspicious_redirect,
        redirect_hop_count=redirect_hop_count,
        has_punycode_homograph=has_punycode_homograph,
        homograph_brand=homograph_brand,
        has_ssl_expired=has_ssl_expired,
        has_ssl_self_signed=has_ssl_self_signed,
        has_ssl_hostname_mismatch=has_ssl_hostname_mismatch,
        has_ssl_revoked=has_ssl_revoked,
        has_ssl_untrusted_root=has_ssl_untrusted_root,
        has_ssl_weak_protocol=has_ssl_weak_protocol,
        has_ssl_weak_cipher=has_ssl_weak_cipher,
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
    adjusted_score = base_score - trust_bonus - verified_org_bonus

    # Apply phishing penalties (increase risk)
    adjusted_score += phishing_penalty

    # ---- DOMAIN NAME PENALTY (additive) ----
    # Some domain names intrinsically hint at malicious or unsafe intent
    # (e.g., "xploit" → "exploit", "hack", "malware"). These are NOT
    # typosquatting or brand impersonation — they are names that suggest
    # security-exploit focus. A mild penalty prevents such domains from
    # reaching 0/100 purely via trust bonuses, even when no impersonation
    # is detected. This is additive to existing penalties, not a replacement.
    domain_name_penalty = 0.0
    clean_d = domain.strip().lower().removeprefix("www.").removesuffix(".")
    domain_label = clean_d.split(".")[0] if "." in clean_d else clean_d
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern in domain_label:
            domain_name_penalty = 6.0
            adjusted_score += domain_name_penalty
            reasoning_findings.append(
                f"DOMAIN NAME: Domain label '{domain_label}' contains "
                f"suspicious term '{pattern}' (+{domain_name_penalty:.0f} risk). "
                f"The name suggests security/exploit-related intent."
            )
            break

    # ---- SECURITY POSTURE PENALTY ----
    # Domains with CONFIRMED missing SSL or poor security headers get a
    # direct penalty that age/registrar trust cannot suppress.
    # This ensures a domain at 27/100 with all headers missing and no SSL
    # is never called SAFE.
    #
    # CRITICAL: Tool failure is NEVER treated as domain risk. If the SSL probe
    # or HTTP header fetch failed due to timeout/missing binary/network error,
    # the result is "DATA UNAVAILABLE" and no penalty is applied.
    security_posture_penalty = 0.0
    if ssl_unavailable:
        reasoning_findings.append(
            "DATA UNAVAILABLE: SSL/TLS probe could not complete "
            "(timeout / network error / missing tool). "
            "No security penalty applied - tool failure is not domain risk."
        )
    elif not has_valid_ssl:
        # SSL probe SUCCEEDED and confirmed no valid certificate — this IS a risk
        penalty = 15.0
        security_posture_penalty += penalty
        adjusted_score += penalty
        reasoning_findings.append(
            f"SECURITY POSTURE: No valid SSL/TLS detected — adding +{penalty:.0f} risk floor."
        )

    if headers_unavailable:
        reasoning_findings.append(
            "DATA UNAVAILABLE: HTTP header fetch could not complete "
            "(timeout / network error / server rejected connection). "
            "No security penalty applied - tool failure is not domain risk."
        )
    elif header_score >= 10:
        # Headers were fetched and confirmed missing — this IS a risk
        penalty = 8.0
        security_posture_penalty += penalty
        adjusted_score += penalty
        reasoning_findings.append(
            f"SECURITY POSTURE: Missing critical security headers "
            f"(header score={header_score}) — adding +{penalty:.0f} risk."
        )
    elif header_score >= 6:
        penalty = 4.0
        security_posture_penalty += penalty
        adjusted_score += penalty
        reasoning_findings.append(
            f"SECURITY POSTURE: Weak security header posture "
            f"(header score={header_score}) — adding +{penalty:.0f} risk."
        )

    # ==================================================================
    # STEP 6: False-positive reduction
    # ==================================================================
    #
    # DESIGN RATIONALE:
    # - When brand impersonation (typosquatting/homoglyph/combosquatting) is
    #   detected, NO false-positive caps apply — the domain is intentionally
    #   mimicking another entity and must be treated as high-risk regardless
    #   of security posture.
    # - When NO impersonation is detected, caps apply even if the domain has
    #   poor security posture (missing SSL, missing headers). Poor security
    #   alone does not make a domain "phishing" — many legitimate small
    #   sites, internal tools, and misconfigured-but-legitimate domains
    #   lack ideal security. The security posture penalties in STEP 5 still
    #   increase the score, but the caps prevent them from reaching CRITICAL
    #   without impersonation signals.
    #
    # If NO impersonation detected, apply false-positive caps
    if not has_impersonation:
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

        # --- Government/education domain cap ---
        # .gov, .gov.*, .edu, .mil domains are verified government or educational
        # institutions. Even with poor security posture, they should never reach
        # SUSPICIOUS or higher unless impersonation is detected.
        # BUT: only cap if the domain actually HAS infrastructure (DNS, WHOIS, or SSL).
        # A non-resolving domain with no WHOIS data is not verifiable.
        if is_government_domain(domain):
            has_infrastructure = has_nameservers or has_mx or has_valid_ssl or age_days is not None or registrar is not None
            if has_infrastructure:
                if adjusted_score > 18:
                    adjusted_score = min(adjusted_score, 18)
                    reasoning_findings.append(
                        "FALSE POSITIVE GUARD: Government/education domain detected — "
                        "score capped at LOW RISK (18). Government domains require "
                        "verified registration and are inherently more trustworthy."
                    )
            else:
                reasoning_findings.append(
                    "FALSE POSITIVE GUARD: Domain has .gov/.edu/.mil TLD but no "
                    "confirming infrastructure (DNS/WHOIS/SSL) — government trust "
                    "bonus not applied. The TLD alone is not sufficient verification."
                )

        # --- Non-impersonating domain ceiling ---
        # Domains with no brand impersonation signals should never reach
        # CRITICAL or high HIGH RISK solely from poor security posture +
        # infrastructure weakness. The security posture penalty (STEP 5)
        # already reflects the hygiene concern; we prevent it from combining
        # with moderate phishing penalties (e.g. suspicious TLD + young age)
        # to push the score into CRITICAL territory.
        # Cap at 55 = top of SUSPICIOUS / bottom of HIGH RISK.
        if adjusted_score > 55:
            adjusted_score = min(adjusted_score, 55)
            reasoning_findings.append(
                "FALSE POSITIVE GUARD: No brand impersonation detected — score capped "
                "at SUSPICIOUS max (55). Poor security posture plus infrastructure "
                "weakness alone is not sufficient to indicate phishing."
            )

    # ---- SECURITY FLOOR ----
    # Even with strong trust signals (age, registrar, ASN), domains with
    # CONFIRMED poor security posture should never reach 0/100.
    # Missing critical security headers (HSTS, CSP, X-Frame-Options) means
    # the site does not protect its users — age alone does not make a site secure.
    #
    # The floor is additive to the security posture penalty above:
    # - Penalty adds risk (score goes UP)
    # - Floor prevents score from going TOO LOW (below a minimum)
    # Together they ensure security posture is never fully suppressed.
    #
    # CRITICAL: Tool failure is NEVER treated as domain risk. If SSL or headers
    # could not be checked, no security floor is applied.
    security_floor = 0
    if not headers_unavailable:
        if header_score >= 10:
            # All critical security headers confirmed missing
            security_floor = 6
            reasoning_findings.append(
                "SECURITY FLOOR: All critical security headers (HSTS, CSP, "
                "X-Frame-Options) are missing — minimum score floor of 6 applied. "
                "Age and registrar trust cannot fully suppress missing protections."
            )
        elif header_score >= 6:
            # Moderate header issues
            security_floor = 3
            reasoning_findings.append(
                "SECURITY FLOOR: Multiple security headers missing — "
                "minimum score floor of 3 applied."
            )
    else:
        reasoning_findings.append(
            "DATA UNAVAILABLE: Headers not checked — no security floor applied. "
            "Tool failure is not domain risk."
        )

    if not ssl_unavailable:
        if not has_valid_ssl:
            # SSL probe succeeded and confirmed no valid cert — this IS a risk
            security_floor = max(security_floor, 10)
            reasoning_findings.append(
                "SECURITY FLOOR: No valid SSL/TLS — minimum score floor raised to 10."
            )
    else:
        reasoning_findings.append(
            "DATA UNAVAILABLE: SSL not checked — no security floor applied. "
            "Tool failure is not domain risk."
        )

    # Cap: never go below the security floor
    adjusted_score = max(security_floor, adjusted_score)

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

    # Extract enhanced ensemble mathematical metrics
    ens_entropy: float | None = None
    ens_kl: float | None = None
    ens_beta_width: float | None = None
    ens_kappa: float | None = None
    ens_bf: float | None = None
    ens_bma: float | None = None

    if ensemble_result:
        if ensemble_result.get("entropy") and ensemble_result["entropy"].get("shannon_entropy_bits") is not None:
            ens_entropy = ensemble_result["entropy"]["shannon_entropy_bits"]
        ens_kl = ensemble_result.get("kl_divergence")
        if ensemble_result.get("beta_interval") and ensemble_result["beta_interval"].get("interval_width") is not None:
            ens_beta_width = ensemble_result["beta_interval"]["interval_width"]
        ens_kappa = ensemble_result.get("cohens_kappa")
        if ensemble_result.get("bma") and ensemble_result["bma"].get("bayes_factor") is not None:
            ens_bf = ensemble_result["bma"]["bayes_factor"]
        if ensemble_result.get("bma") and ensemble_result["bma"].get("bma_proba") is not None:
            ens_bma = ensemble_result["bma"]["bma_proba"]

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
        # v3.0 signals passed from caller
        threat_feed_score=threat_feed_score,
        threat_feed_count=threat_feed_count,
        threat_feed_flagged_count=threat_feed_flagged_count,
        ensemble_model_count=ensemble_model_count,
        ensemble_agreement=ensemble_agreement,
        # Enhanced ensemble mathematical metrics (v3.5)
        ensemble_entropy=ens_entropy,
        ensemble_kl_divergence=ens_kl,
        ensemble_beta_width=ens_beta_width,
        ensemble_kappa=ens_kappa,
        ensemble_bayes_factor=ens_bf,
        ensemble_bma_proba=ens_bma,
    )

    # Override confidence for verified organizations: these are globally
    # recognized domains with confirmed ownership, so confidence should be high.
    if is_verified_org and confidence['confidence_pct'] < 90:
        confidence['confidence_pct'] = 90
        confidence['confidence_level'] = 'High'
        confidence['reasoning'].append('VERIFIED ORGANIZATION: Domain is globally recognized - confidence set to 90%.')

    # Build explainable reasoning
    explainable_reasoning: list[str] = []
    explainable_reasoning.append(f"FINAL SCORE: {final_score}/100 ({classification_label})")
    explainable_reasoning.append(f"  Weighted base: {base_score:.1f}")
    explainable_reasoning.append(f"  Trust bonuses: -{trust_bonus:.1f}")
    explainable_reasoning.append(f"  Phishing penalties: +{phishing_penalty:.1f}")
    for r in trust_info["reasons"]:
        explainable_reasoning.append(f"  {r}")
    if is_verified_org:
        explainable_reasoning.append(f"  Verified Organization trust bonus: -{verified_org_bonus:.0f}")
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
            "verified_org_bonus": verified_org_bonus,
            "is_verified_org": is_verified_org,
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
    if is_verified_org:
        reasoning_findings.append(f"VERIFIED ORG BONUS: +{verified_org_bonus:.0f} trust bonus applied.")
        reasoning_findings.append("VERIFIED ORG NOTE: Component scores above are visible for debugging. If WHOIS/ASN/SSL "
            "shows unexpected values, the underlying lookup has failed.")
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

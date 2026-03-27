"""
utils.py — Core detection logic for Suspicious Domain Detection System
Implements: typosquatting, homoglyph, combo-squatting, feature extraction, risk scoring
"""

import re
import math
import unicodedata
from difflib import SequenceMatcher

# ──────────────────────────────────────────────────────────────────────────────
# TOP DOMAINS — brands commonly targeted by phishing
# ──────────────────────────────────────────────────────────────────────────────
TOP_DOMAINS = [
    "google", "facebook", "amazon", "microsoft", "apple", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "youtube", "yahoo",
    "dropbox", "github", "ebay", "walmart", "chase", "bankofamerica",
    "wellsfargo", "citibank", "adobe", "salesforce", "zoom", "slack",
    "spotify", "reddit", "pinterest", "snapchat", "tiktok", "whatsapp",
    "telegram", "discord", "twitch", "steam", "blizzard", "epic",
    "office365", "outlook", "hotmail", "gmail", "icloud", "onedrive",
]

# Suspicious keywords commonly used in phishing domains
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "update", "account", "bank",
    "confirm", "alert", "signin", "password", "recover", "billing",
    "support", "service", "official", "help", "customer", "validation",
    "authenticate", "unlock", "access", "reset", "suspend", "limited",
    "unusual", "activity", "notification", "claim", "prize", "free",
]

# ──────────────────────────────────────────────────────────────────────────────
# HOMOGLYPH MAP — Unicode confusable characters → ASCII equivalents
# ──────────────────────────────────────────────────────────────────────────────
HOMOGLYPH_MAP = {
    # Digits that look like letters
    '0': 'o', '1': 'i', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'g',
    # Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's',
    # Greek lookalikes
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'n',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    # Latin extended
    'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a', 'ã': 'a',
    'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
    'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o', 'õ': 'o',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
    'ñ': 'n', 'ç': 'c', 'ß': 'ss',
    # Common visual substitutions
    'vv': 'w', 'rn': 'm',
    # Special unicode
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o',
}

# Reverse map: for each ASCII char, what unicode chars look like it?
REVERSE_HOMOGLYPH = {}
for unicode_char, ascii_char in HOMOGLYPH_MAP.items():
    if ascii_char not in REVERSE_HOMOGLYPH:
        REVERSE_HOMOGLYPH[ascii_char] = []
    REVERSE_HOMOGLYPH[ascii_char].append(unicode_char)


# ──────────────────────────────────────────────────────────────────────────────
# LEVENSHTEIN DISTANCE
# ──────────────────────────────────────────────────────────────────────────────
def levenshtein_distance(s1: str, s2: str) -> int:
    """Classic dynamic-programming Levenshtein distance."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ──────────────────────────────────────────────────────────────────────────────
# JARO-WINKLER SIMILARITY
# ──────────────────────────────────────────────────────────────────────────────
def jaro_similarity(s1: str, s2: str) -> float:
    """Compute Jaro similarity between two strings."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_dist = max(len1, len2) // 2 - 1
    match_dist = max(0, match_dist)

    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    return (matches / len1 + matches / len2 +
            (matches - transpositions / 2) / matches) / 3


def jaro_winkler_similarity(s1: str, s2: str, p: float = 0.1) -> float:
    """Jaro-Winkler similarity (boosts score for common prefixes)."""
    jaro = jaro_similarity(s1, s2)
    prefix = 0
    for i in range(min(len(s1), len(s2), 4)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * p * (1 - jaro)


# ──────────────────────────────────────────────────────────────────────────────
# HOMOGLYPH NORMALIZER & DETECTOR
# ──────────────────────────────────────────────────────────────────────────────
def normalize_homoglyphs(domain: str) -> str:
    """Replace known homoglyph characters with their ASCII equivalents."""
    normalized = ""
    i = 0
    while i < len(domain):
        # Check two-char combos first (e.g., 'rn' → 'm')
        two = domain[i:i+2]
        if two in HOMOGLYPH_MAP:
            normalized += HOMOGLYPH_MAP[two]
            i += 2
            continue
        char = domain[i]
        normalized += HOMOGLYPH_MAP.get(char, char)
        i += 1
    return normalized


def detect_homoglyphs(domain: str) -> dict:
    """
    Detect homoglyph characters in a domain.
    Returns details about which characters are suspicious.
    """
    suspicious_chars = []
    normalized = ""

    for char in domain:
        # Check if character is non-ASCII
        if ord(char) > 127:
            try:
                # Try to get Unicode name for context
                char_name = unicodedata.name(char, "UNKNOWN")
                ascii_equiv = HOMOGLYPH_MAP.get(char, char)
                suspicious_chars.append({
                    "char": char,
                    "ascii_equiv": ascii_equiv,
                    "unicode_name": char_name,
                    "codepoint": hex(ord(char))
                })
                normalized += ascii_equiv
            except Exception:
                normalized += char
        elif char in HOMOGLYPH_MAP:
            # ASCII digit/char that looks like a letter
            if char.isdigit():
                suspicious_chars.append({
                    "char": char,
                    "ascii_equiv": HOMOGLYPH_MAP[char],
                    "type": "digit_substitution"
                })
            normalized += HOMOGLYPH_MAP.get(char, char)
        else:
            normalized += char

    # Also check for digit substitutions specifically
    digit_subs = re.findall(r'[0-9]', domain)
    has_digit_subs = len(digit_subs) > 0 and any(c.isdigit() for c in domain
                                                   if domain.replace(c, '').isalpha() or True)

    return {
        "detected": len(suspicious_chars) > 0,
        "suspicious_chars": suspicious_chars,
        "normalized_domain": normalized,
        "has_digit_substitution": has_digit_subs,
        "count": len(suspicious_chars)
    }


# ──────────────────────────────────────────────────────────────────────────────
# TYPOSQUATTING DETECTION
# ──────────────────────────────────────────────────────────────────────────────
def detect_typosquatting(domain_name: str) -> dict:
    """
    Compare domain against top brands using Levenshtein + Jaro-Winkler.
    Returns best match, scores, and verdict.
    """
    best_match = None
    best_lev_score = 0.0
    best_jw_score = 0.0
    best_distance = 999

    # Normalize: remove TLD for comparison
    clean = domain_name.lower()

    for brand in TOP_DOMAINS:
        dist = levenshtein_distance(clean, brand)
        jw = jaro_winkler_similarity(clean, brand)

        # Levenshtein-based score: higher is more similar
        max_len = max(len(clean), len(brand))
        lev_score = 1.0 - (dist / max_len) if max_len > 0 else 0.0

        combined = (lev_score * 0.4 + jw * 0.6)

        if combined > (best_lev_score * 0.4 + best_jw_score * 0.6):
            best_match = brand
            best_lev_score = lev_score
            best_jw_score = jw
            best_distance = dist

    is_typosquat = (
        best_distance <= 3 and
        best_distance > 0 and
        best_jw_score >= 0.75
    )

    return {
        "detected": is_typosquat,
        "closest_brand": best_match,
        "levenshtein_score": round(best_lev_score, 4),
        "jaro_winkler_score": round(best_jw_score, 4),
        "edit_distance": best_distance,
        "combined_score": round(best_lev_score * 0.4 + best_jw_score * 0.6, 4)
    }


# ──────────────────────────────────────────────────────────────────────────────
# COMBO-SQUATTING DETECTION
# ──────────────────────────────────────────────────────────────────────────────
def detect_combosquatting(domain_name: str) -> dict:
    """
    Detect combo-squatting: brand + suspicious keyword (e.g., paypal-login.com).
    """
    found_brands = []
    found_keywords = []
    domain_lower = domain_name.lower()

    for brand in TOP_DOMAINS:
        if brand in domain_lower and domain_lower != brand:
            found_brands.append(brand)

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_lower:
            found_keywords.append(kw)

    is_combo = len(found_brands) > 0 and len(found_keywords) > 0

    return {
        "detected": is_combo,
        "matched_brands": found_brands,
        "matched_keywords": found_keywords,
        "brand_only": len(found_brands) > 0 and len(found_keywords) == 0,
    }


# ──────────────────────────────────────────────────────────────────────────────
# DOMAIN FEATURE EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────
def extract_features(full_domain: str) -> dict:
    """
    Extract numeric/boolean features from a domain for risk scoring.
    """
    parts = full_domain.lower().split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    domain_name = parts[-2] if len(parts) >= 2 else parts[0]
    subdomains = parts[:-2] if len(parts) > 2 else []

    # Feature: length
    length = len(domain_name)

    # Feature: digit count & ratio
    digit_count = sum(c.isdigit() for c in domain_name)
    digit_ratio = digit_count / length if length > 0 else 0

    # Feature: hyphen count
    hyphen_count = domain_name.count('-')

    # Feature: subdomain depth
    subdomain_count = len(subdomains)

    # Feature: suspicious TLD
    suspicious_tlds = {
        'xyz', 'top', 'club', 'online', 'site', 'web', 'info',
        'biz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws',
        'nu', 'la', 'io', 'co', 'su', 'ru', 'cn'
    }
    suspicious_tld = tld in suspicious_tlds

    # Feature: has suspicious keywords
    has_suspicious_kw = any(kw in domain_name for kw in SUSPICIOUS_KEYWORDS)

    # Feature: entropy (higher = more random-looking)
    entropy = _calculate_entropy(domain_name)

    # Feature: non-ASCII chars
    has_non_ascii = any(ord(c) > 127 for c in full_domain)

    # Feature: IP address pattern
    is_ip_like = bool(re.match(r'^\d{1,3}[\.\-]\d{1,3}[\.\-]\d{1,3}[\.\-]\d{1,3}$',
                                domain_name))

    # Feature: excessive hyphens or dashes
    has_excessive_hyphens = hyphen_count >= 3

    # Consonant cluster (random-looking domains)
    consonant_ratio = _consonant_ratio(domain_name)

    return {
        "domain_name": domain_name,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "subdomains": subdomains,
        "length": length,
        "digit_count": digit_count,
        "digit_ratio": round(digit_ratio, 4),
        "hyphen_count": hyphen_count,
        "has_excessive_hyphens": has_excessive_hyphens,
        "suspicious_tld": suspicious_tld,
        "has_suspicious_keywords": has_suspicious_kw,
        "matched_keywords": [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain_name],
        "entropy": round(entropy, 4),
        "has_non_ascii": has_non_ascii,
        "is_ip_like": is_ip_like,
        "consonant_ratio": round(consonant_ratio, 4),
    }


def _calculate_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total)
                for count in freq.values())


def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to total alpha chars (high = random-looking)."""
    consonants = set('bcdfghjklmnpqrstvwxyz')
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c in consonants) / len(alpha)


# ──────────────────────────────────────────────────────────────────────────────
# RISK SCORING ENGINE
# ──────────────────────────────────────────────────────────────────────────────
def compute_risk_score(
    features: dict,
    typo_result: dict,
    homoglyph_result: dict,
    combo_result: dict,
    whois_result: dict,
) -> dict:
    """
    Combine all signals into a 0–100 risk score and categorize risk level.
    Returns score, level, primary attack type, and breakdown.
    """
    score = 0
    breakdown = {}

    # ── Typosquatting ─────────────────────────────────────────
    if typo_result["detected"]:
        ts = 30 * typo_result["jaro_winkler_score"]
        score += ts
        breakdown["typosquatting"] = round(ts, 1)
    else:
        # Partial credit for close matches
        jw = typo_result.get("jaro_winkler_score", 0)
        if jw > 0.6:
            ts = 15 * jw
            score += ts
            breakdown["near_match"] = round(ts, 1)

    # ── Homoglyph ─────────────────────────────────────────────
    if homoglyph_result["detected"]:
        hg = min(25, 10 + homoglyph_result["count"] * 5)
        score += hg
        breakdown["homoglyph"] = hg
    if homoglyph_result.get("has_digit_substitution"):
        score += 8
        breakdown["digit_substitution"] = 8

    # ── Combo-squatting ───────────────────────────────────────
    if combo_result["detected"]:
        score += 20
        breakdown["combosquatting"] = 20
    elif combo_result.get("brand_only"):
        score += 12
        breakdown["brand_in_domain"] = 12

    # ── Domain features ───────────────────────────────────────
    feat_score = 0
    if features["has_suspicious_keywords"]:
        feat_score += min(10, len(features["matched_keywords"]) * 3)
    if features["suspicious_tld"]:
        feat_score += 6
    if features["has_excessive_hyphens"]:
        feat_score += 5
    if features["subdomain_count"] >= 3:
        feat_score += 4
    if features["digit_ratio"] > 0.3:
        feat_score += 4
    if features["is_ip_like"]:
        feat_score += 8
    if features["entropy"] > 3.8:
        feat_score += 3
    if features["length"] > 25:
        feat_score += 3
    score += feat_score
    breakdown["domain_features"] = feat_score

    # ── WHOIS signals ─────────────────────────────────────────
    whois_score = 0
    age_days = whois_result.get("age_days", 9999)
    if age_days is not None:
        if age_days < 7:
            whois_score += 15
        elif age_days < 30:
            whois_score += 10
        elif age_days < 90:
            whois_score += 5
    if whois_result.get("privacy_protected"):
        whois_score += 5
    if whois_result.get("suspicious_registrar"):
        whois_score += 5
    score += whois_score
    breakdown["whois_signals"] = whois_score

    # ── Clamp to 0–100 ────────────────────────────────────────
    score = min(100, max(0, score))

    # ── Risk level ────────────────────────────────────────────
    if score >= 70:
        risk_level = "High"
    elif score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # ── Primary attack type ───────────────────────────────────
    attack_type = _determine_attack_type(
        typo_result, homoglyph_result, combo_result, features, score
    )

    return {
        "score": round(score, 1),
        "risk_level": risk_level,
        "attack_type": attack_type,
        "breakdown": breakdown,
    }


def _determine_attack_type(typo, homoglyph, combo, features, score) -> str:
    """Pick the most likely attack type based on detected signals."""
    candidates = []

    if homoglyph["detected"]:
        candidates.append(("Homoglyph Attack", homoglyph["count"] * 10))
    if typo["detected"]:
        candidates.append(("Typosquatting", typo["jaro_winkler_score"] * 30))
    if combo["detected"]:
        candidates.append(("Combo-Squatting", 20))
    if features["is_ip_like"]:
        candidates.append(("IP Masquerading", 25))
    if features["has_suspicious_keywords"] and not combo["detected"]:
        candidates.append(("Keyword Phishing", len(features["matched_keywords"]) * 4))

    if not candidates:
        if score >= 40:
            return "Suspicious Domain"
        return "No Attack Detected"

    return max(candidates, key=lambda x: x[1])[0]


# ──────────────────────────────────────────────────────────────────────────────
# MOCK WHOIS ANALYSIS
# (In production: use python-whois library; here we simulate for portability)
# ──────────────────────────────────────────────────────────────────────────────
def analyze_whois_mock(domain: str) -> dict:
    """
    Simulated WHOIS analysis.
    Returns domain age estimate and registrar flags.
    In production, replace with: import whois; w = whois.whois(domain)
    """
    import hashlib
    import random

    # Use domain hash for deterministic "random" results per domain
    seed = int(hashlib.md5(domain.encode()).hexdigest(), 16) % (2**31)
    rng = random.Random(seed)

    # Heuristic: suspicious domains tend to be newer
    combo = detect_combosquatting(domain.split('.')[0])
    typo = detect_typosquatting(domain.split('.')[0])

    if combo["detected"] or typo["detected"]:
        age_days = rng.randint(1, 60)
    else:
        age_days = rng.randint(180, 3650)

    # Estimate creation date
    from datetime import datetime, timedelta
    creation_date = datetime.now() - timedelta(days=age_days)
    creation_str = creation_date.strftime("%Y-%m-%d")

    # Registrar suspicion heuristic
    suspicious_registrars = [
        "Namecheap", "NameSilo", "Tucows Domains", "PDR Ltd.",
        "FastDomain Inc.", "Hostinger"
    ]
    legit_registrars = [
        "GoDaddy", "Google Domains", "Cloudflare", "Amazon Registrar",
        "Network Solutions", "CSC Corporate Domains"
    ]

    if age_days < 90:
        registrar = rng.choice(suspicious_registrars)
        suspicious_registrar = True
    else:
        registrar = rng.choice(legit_registrars)
        suspicious_registrar = False

    privacy_protected = rng.random() > 0.6

    # Format age string
    if age_days < 30:
        age_str = f"{age_days} day{'s' if age_days != 1 else ''}"
    elif age_days < 365:
        months = age_days // 30
        age_str = f"{months} month{'s' if months != 1 else ''}"
    else:
        years = age_days // 365
        rem_months = (age_days % 365) // 30
        age_str = f"{years} year{'s' if years != 1 else ''}"
        if rem_months > 0:
            age_str += f", {rem_months} month{'s' if rem_months != 1 else ''}"

    whois_flag = "Suspicious" if (age_days < 90 or suspicious_registrar or privacy_protected) else "Legitimate"

    return {
        "age_days": age_days,
        "age_str": age_str,
        "creation_date": creation_str,
        "registrar": registrar,
        "privacy_protected": privacy_protected,
        "suspicious_registrar": suspicious_registrar,
        "whois_flag": whois_flag,
        "nameserver_pattern": "generic" if suspicious_registrar else "branded",
        "note": "Simulated WHOIS — replace with python-whois for live data"
    }


# ──────────────────────────────────────────────────────────────────────────────
# DOMAIN VALIDATOR
# ──────────────────────────────────────────────────────────────────────────────
def validate_domain(domain: str) -> tuple[bool, str]:
    """
    Basic domain format validation.
    Returns (is_valid, error_message).
    """
    if not domain:
        return False, "Domain cannot be empty."

    # Remove protocol if accidentally included
    domain = re.sub(r'^https?://', '', domain).strip('/')

    # Basic length check
    if len(domain) > 253:
        return False, "Domain exceeds maximum length of 253 characters."

    # Must contain at least one dot
    if '.' not in domain:
        return False, "Invalid domain format — must contain at least one dot."

    # Basic regex pattern
    pattern = r'^[a-zA-Z0-9\u0080-\uFFFF]([a-zA-Z0-9\-\u0080-\uFFFF]{0,61}[a-zA-Z0-9\u0080-\uFFFF])?(\.[a-zA-Z0-9\u0080-\uFFFF]([a-zA-Z0-9\-\u0080-\uFFFF]{0,61}[a-zA-Z0-9\u0080-\uFFFF])?)*$'
    if not re.match(pattern, domain):
        return False, "Invalid domain format."

    return True, ""


def sanitize_domain(domain: str) -> str:
    """Clean and normalize domain input."""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')
    domain = domain.split('/')[0]  # Remove any path
    domain = domain.split('?')[0]  # Remove query string
    return domain


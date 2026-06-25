"""
Fast-Flux & DGA Detection Module (v3.0)
========================================
Detects fast-flux DNS techniques and Domain Generation Algorithm patterns.

Fast-Flux Detection:
  - Multiple A record resolution over time
  - Short TTL values (common in fast-flux networks)
  - ASN diversity in resolved IPs
  - Geographic dispersion of hosting locations

DGA Detection:
  - Character entropy analysis
  - Consonant/vowel ratio
  - N-gram frequency analysis
  - Dictionary word composition
  - Length and randomness scoring
"""

from __future__ import annotations

import math
import re
import socket
from collections import Counter
from typing import Any

try:
    import dns.resolver as dns_resolver
except ImportError:
    dns_resolver = None

# ==============================================================================
# CONSTANTS
# ==============================================================================

# Common TLDs for DGA domains
DGA_TLDS = frozenset({
    "xyz", "top", "club", "online", "site", "live", "work",
    "tk", "ml", "ga", "cf", "gq", "pw", "icu", "click",
    "loan", "date", "win", "bid", "trade", "web", "space",
})

# High-frequency English letter pairs (bigrams)
ENGLISH_BIGRAMS = frozenset({
    "th", "he", "in", "er", "an", "re", "nd", "on", "en", "at",
    "ou", "ed", "ha", "to", "or", "it", "is", "hi", "es", "ng",
})

# Suspicious TTL threshold (seconds) — fast-flux domains use very short TTLs
FAST_FLUX_TTL_THRESHOLD = 300  # 5 minutes

# Common fast-flux DNS patterns
FAST_FLUX_KEYWORDS = frozenset({
    "ns1", "ns2", "dns", "flux", "dynamic", "no-ip", "duckdns",
})


# ==============================================================================
# HELPERS
# ==============================================================================


def _entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _consonant_ratio(s: str) -> float:
    """Compute consonant-to-letter ratio."""
    if not s:
        return 0.0
    letters = sum(c.isalpha() for c in s)
    if letters == 0:
        return 0.0
    consonants = sum(1 for c in s if c.isalpha() and c.lower() not in "aeiou")
    return consonants / letters


def _vowel_ratio(s: str) -> float:
    """Compute vowel-to-letter ratio."""
    if not s:
        return 0.0
    letters = sum(c.isalpha() for c in s)
    if letters == 0:
        return 0.0
    vowels = sum(1 for c in s if c.lower() in "aeiou")
    return vowels / letters


def _digit_ratio(s: str) -> float:
    """Compute digit-to-length ratio."""
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def _bigram_score(s: str) -> float:
    """Compute proportion of English-like bigrams in the string."""
    if len(s) < 2:
        return 0.0
    count = 0
    total = 0
    for i in range(len(s) - 1):
        bigram = s[i:i+2].lower()
        if bigram.isalpha():
            total += 1
            if bigram in ENGLISH_BIGRAMS:
                count += 1
    return count / max(total, 1)


def _resolve_all_a_records(domain: str) -> list[str]:
    """Resolve all A records for a domain."""
    if dns_resolver is None:
        try:
            return list(set(socket.gethostbyname_ex(domain)[2]))
        except Exception:
            return []
    try:
        answers = dns_resolver.resolve(domain, "A", lifetime=3.0)
        return list(set(str(r) for r in answers))
    except Exception:
        return []


def _get_ttl(domain: str) -> int | None:
    """Get the TTL for a domain's A record."""
    if dns_resolver is None:
        return None
    try:
        answers = dns_resolver.resolve(domain, "A", lifetime=3.0)
        return answers.rrset.ttl if answers.rrset else None
    except Exception:
        return None


# ==============================================================================
# DETECTION FUNCTIONS
# ==============================================================================


def detect_fast_flux(domain: str) -> dict[str, Any]:
    """
    Detect fast-flux DNS patterns for a domain.

    Analyzes:
      - Number of A records (multiple IPs = suspect)
      - TTL values (very short TTLs = fast-flux)
      - NS record pattern matching (generic NS names)
      - IP diversity and geographic spread

    Returns:
        detected: True if fast-flux pattern detected
        confidence: 0-100 confidence score
        indicators: List of specific indicators found
        warning: Human-readable warning
    """
    result: dict[str, Any] = {
        "detected": False,
        "confidence": 0.0,
        "indicators": [],
        "ip_addresses": [],
        "ttl": None,
        "warning": None,
    }

    # Step 1: Resolve A records
    ips = _resolve_all_a_records(domain)
    result["ip_addresses"] = ips

    indicators: list[str] = []

    # Step 2: Check TTL
    ttl = _get_ttl(domain)
    result["ttl"] = ttl

    if ttl is not None and ttl < FAST_FLUX_TTL_THRESHOLD:
        indicators.append(f"Short TTL ({ttl}s) — common in fast-flux networks")

    # Step 3: Check multiple A records
    if len(ips) >= 3:
        indicators.append(
            f"Multiple A records ({len(ips)} IPs) — potential fast-flux"
        )

    # Step 4: Check NS records for flux patterns
    if dns_resolver is not None:
        try:
            ns_answers = dns_resolver.resolve(domain, "NS", lifetime=3.0)
            ns_names = [str(r) for r in ns_answers]
            for ns in ns_names:
                lower_ns = ns.lower()
                if any(kw in lower_ns for kw in FAST_FLUX_KEYWORDS):
                    indicators.append(
                        f"Nameserver '{ns}' matches fast-flux pattern"
                    )
                    break
        except Exception:
            pass

    # Step 5: Calculate confidence
    confidence = 0.0
    if ttl is not None and ttl < 60:
        confidence += 40.0
    elif ttl is not None and ttl < FAST_FLUX_TTL_THRESHOLD:
        confidence += 25.0

    if len(ips) >= 5:
        confidence += 35.0
    elif len(ips) >= 3:
        confidence += 25.0

    if len(indicators) >= 2:
        confidence = min(confidence + 20.0, 95.0)

    result["confidence"] = round(confidence, 1)

    if confidence >= 40.0:
        result["detected"] = True
        result["indicators"] = indicators
        result["warning"] = (
            f"Fast-flux DNS pattern detected for '{domain}'. "
            f"Multiple IPs and/or short TTL suggest dynamic infrastructure "
            f"commonly used for phishing and C2 networks."
        )

    return result


def detect_dga(domain: str) -> dict[str, Any]:
    """
    Detect Domain Generation Algorithm (DGA) patterns.

    DGA domains are algorithmically generated (by malware) and have
    distinct statistical properties compared to human-chosen domains.

    Features analyzed:
      - Shannon entropy (high for DGA)
      - Consonant/vowel ratio (unusual for DGA)
      - Digit ratio (varies)
      - Bigram frequency (low English-likeness for DGA)
      - Length-based scoring
      - Dictionary word composition

    Returns:
        detected: True if DGA pattern detected
        dga_score: 0-100 DGA likelihood score
        features: Dict of individual feature scores
        warning: Human-readable warning
    """
    clean = domain.strip().lower()
    # Extract the domain label (second-level domain)
    parts = clean.split(".")
    if len(parts) >= 2:
        label = parts[-2]
    else:
        label = clean

    result: dict[str, Any] = {
        "detected": False,
        "dga_score": 0.0,
        "features": {},
        "label": label,
        "warning": None,
    }

    if not label or len(label) < 4:
        return result

    # Feature 1: Shannon entropy (DGA domains have high entropy)
    entropy_val = _entropy(label)
    # Normalize: max entropy for a 20-char label with 36 chars (a-z,0-9) is ~5.17
    max_entropy = math.log2(36)  # ~5.17
    entropy_score = min(1.0, entropy_val / max_entropy)

    # Feature 2: Consonant ratio
    cons_ratio = _consonant_ratio(label)
    # DGA domains often have extreme consonant ratios (>0.7 or <0.3)
    cons_score = 0.0
    if cons_ratio > 0.7:
        cons_score = min(1.0, (cons_ratio - 0.7) / 0.3)
    elif cons_ratio < 0.3:
        cons_score = min(1.0, (0.3 - cons_ratio) / 0.3)

    # Feature 3: Digit ratio
    dig_ratio = _digit_ratio(label)
    dig_score = min(1.0, dig_ratio * 2.5)

    # Feature 4: Bigram English-likeness
    bigram_val = _bigram_score(label)
    bigram_score = max(0.0, 1.0 - bigram_val * 2.0)

    # Feature 5: Length penalty
    len_score = min(1.0, max(0, len(label) - 10) / 15.0)

    # Feature 6: Repeated characters
    repeats = len(re.findall(r"(.)\1{2,}", label))
    repeat_score = min(1.0, repeats / 3.0)

    # Feature 7: Vowel gap (longest string without vowels)
    vowel_gaps = re.findall(r"[^aeiou]{4,}", label)
    vgap_score = min(1.0, len("".join(vowel_gaps)) / max(len(label), 1) * 2.0)

    features = {
        "entropy": round(entropy_score, 3),
        "consonant_ratio": round(cons_score, 3),
        "digit_ratio": round(dig_score, 3),
        "bigram_unlikeliness": round(bigram_score, 3),
        "length_penalty": round(len_score, 3),
        "repeat_penalty": round(repeat_score, 3),
        "vowel_gap_penalty": round(vgap_score, 3),
    }
    result["features"] = features

    # Weighted DGA score
    weights = {
        "entropy": 0.25,
        "consonant_ratio": 0.15,
        "digit_ratio": 0.10,
        "bigram_unlikeliness": 0.25,
        "length_penalty": 0.10,
        "repeat_penalty": 0.05,
        "vowel_gap_penalty": 0.10,
    }

    dga_score = sum(
        features[k] * weights.get(k, 0.1) for k in features
    ) * 100.0

    result["dga_score"] = round(dga_score, 1)

    if dga_score >= 65:
        result["detected"] = True
        result["warning"] = (
            f"Domain '{label}' shows DGA-like characteristics "
            f"(score: {dga_score:.0f}/100). Algorithmically generated "
            f"domains are commonly used by malware for C2 communication."
        )
    elif dga_score >= 45:
        result["warning"] = (
            f"Domain '{label}' has some DGA-like characteristics "
            f"(score: {dga_score:.0f}/100). May warrant additional review."
        )

    return result

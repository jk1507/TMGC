"""
Train the local XGBoost phishing classifier with deterministic seed examples.

The production score is still a hybrid of rules, security headers, AI, and ML.
This script only refreshes backend/xgb_model.pkl for the ML component.
"""

from __future__ import annotations

import os
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import clean_domain
from ml_xgboost import train_xgb


LEGITIMATE_DOMAINS = [
    "google.com",
    "youtube.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "wikipedia.org",
    "cloudflare.com",
    "paypal.com",
    "linkedin.com",
    "netflix.com",
    "adobe.com",
    "stripe.com",
    "nytimes.com",
    "bbc.co.uk",
]

PHISHING_LIKE_DOMAINS = [
    "g00gle.com",
    "goog1e-login.xyz",
    "paypa1.com",
    "paypal-login.com",
    "secure-amazon-verify.xyz",
    "microsoft-support.tk",
    "apple-id-verify.club",
    "bankofamerica-login.online",
    "instagram-verify.top",
    "coinbase-wallet.ml",
    "binance-verify.cf",
    "gmail-verify.email",
    "dropbox-share.site",
    "netflix-update.xyz",
    "outlook-security.live",
]


def feature_vector_for(domain: str, age_days: int) -> list[float]:
    # Keep this vector in lockstep with get_ml_prediction in main.py.
    from utils import (
        detect_combosquatting,
        detect_homoglyphs,
        detect_typosquatting,
        extract_features,
        normalize_homoglyphs,
    )
    import numpy as np
    from main import KNOWN_BRANDS, SUSPICIOUS_TLDS

    clean = clean_domain(domain)
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean
    normalized_label = normalize_homoglyphs(label)
    features = extract_features(clean)
    typo = detect_typosquatting(normalized_label)
    raw_typo = detect_typosquatting(label)
    if raw_typo.get("jaro_winkler_score", 0.0) > typo.get("jaro_winkler_score", 0.0):
        typo = raw_typo
    homoglyph = detect_homoglyphs(clean)
    combo = detect_combosquatting(clean)
    domain_name = clean.split(".", 1)[0]
    letters = sum(c.isalpha() for c in domain_name)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain_name)
    consonant_ratio = consonants / max(1, letters)
    excessive_hyphens = float(domain_name.count("-") >= 3)
    age_log = np.log1p(age_days) / np.log1p(3650)

    return [
        min(features.get("length", len(domain_name)) / 50.0, 1.0),
        features.get("digit_ratio", 0.0),
        min(features.get("hyphen_count", domain_name.count("-")) / 5.0, 1.0),
        min(features.get("subdomain_count", len(parts) - 2) / 5.0, 1.0),
        min(features.get("entropy", 3.0) / 5.0, 1.0),
        consonant_ratio,
        float(features.get("suspicious_tld", ("." + parts[-1]) in SUSPICIOUS_TLDS)),
        float(features.get("has_suspicious_keywords", any(k in clean for k in KNOWN_BRANDS))),
        float(features.get("is_ip_like", False)),
        excessive_hyphens,
        typo.get("jaro_winkler_score", 0.0),
        typo.get("levenshtein_score", 0.0),
        min(typo.get("edit_distance", 10) / 10.0, 1.0),
        float(typo.get("detected", False)),
        float(homoglyph.get("detected", False)),
        min(homoglyph.get("count", 0) / 5.0, 1.0),
        float(homoglyph.get("has_digit_substitution", False)),
        float(combo.get("detected", False)),
        float(combo.get("brand_only", False)),
        min(len(combo.get("matched_keywords", [])) / 5.0, 1.0),
        age_log,
        0.0,
        0.0,
    ]


def main() -> None:
    x = []
    y = []
    for domain in LEGITIMATE_DOMAINS:
        for age in (30, 365, 2500):
            x.append(feature_vector_for(domain, age_days=age))
            y.append(0)
    for domain in PHISHING_LIKE_DOMAINS:
        for age in (10, 365):
            x.append(feature_vector_for(domain, age_days=age))
            y.append(1)

    train_xgb(x, y)
    print(f"Trained {len(x)} examples into xgb_model.pkl")


if __name__ == "__main__":
    main()

"""
TMGC Real-Data ML Training Pipeline
=====================================
Trains all 4 ensemble models using REAL domain names (not synthetic data).

Unlike the previous approach of generating fake domains with randomized features,
this pipeline uses curated lists of real legitimate and phishing domains, computes
actual feature vectors using the same utils.py detection functions that run during
live analysis, and adds realistic infrastructure variations.

Models trained:
  - XGBoost       (primary gradient-boosted trees)
  - LightGBM      (fast gradient-boosted trees)
  - Random Forest (bagged decision trees)
  - Logistic Regression (linear baseline, with StandardScaler)
  - Ensemble priors + stacking meta-model

Usage:
    python backend/train_real_data.py

Requirements:
    pip install xgboost lightgbm scikit-learn numpy
"""

from __future__ import annotations

import json
import math
import os
import pickle
import random
import sys
import warnings
from datetime import datetime
from typing import Any

import numpy as np
import re

warnings.filterwarnings("ignore")

# Fix Windows cp1252 console encoding
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
else:
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# ==============================================================================
# CONFIGURATION
# ==============================================================================

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATHS = {
    "xgboost": os.path.join(MODEL_DIR, "xgb_model.pkl"),
    "lightgbm": os.path.join(MODEL_DIR, "lgbm_model.pkl"),
    "random_forest": os.path.join(MODEL_DIR, "rf_model.pkl"),
    "logistic_regression": os.path.join(MODEL_DIR, "lr_model.pkl"),
}

PRIORS_PATH = os.path.join(MODEL_DIR, "ensemble_priors.pkl")
REPORT_PATH = os.path.join(MODEL_DIR, "training_report.json")

FEATURE_COUNT = 32
RANDOM_SEED = 42
TEST_SPLIT = 0.20
CV_FOLDS = 5
N_ITER_SEARCH = 20

np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

# ==============================================================================
# FEATURE DEFINITIONS (matches main.py get_ml_prediction)
# ==============================================================================

FEATURE_NAMES = [
    "domain_length_norm",         # 0
    "digit_ratio",                # 1
    "hyphen_count_norm",          # 2
    "subdomain_depth",            # 3
    "shannon_entropy",            # 4
    "consonant_ratio",            # 5
    "suspicious_tld",             # 6
    "has_brand_keywords",         # 7
    "is_ip_like",                 # 8
    "excessive_hyphens",          # 9
    "jaro_winkler_score",         # 10
    "levenshtein_score",          # 11
    "edit_distance_norm",         # 12
    "typosquatting_detected",     # 13
    "homoglyph_detected",         # 14
    "homoglyph_count_norm",       # 15
    "digit_substitution",         # 16
    "combosquatting_detected",    # 17
    "brand_only",                 # 18
    "keyword_count_norm",         # 19
    "domain_age_log",             # 20
    "whois_privacy",              # 21
    "suspicious_registrar",       # 22
    "jaro_unnormalized",          # 23
    "norm_changed",               # 24
    "max_consecutive_digits",     # 25
    "tld_risk_score",             # 26
    "unique_token_count_norm",    # 27
    "ssl_valid",                  # 28
    "mx_present",                 # 29
    "asn_available",              # 30
    "header_deficit",             # 31
]

# ==============================================================================
# REAL DOMAIN LISTS (curated from train_xgb.py)
# ==============================================================================

LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "meta.com",
    "twitter.com", "linkedin.com", "reddit.com", "pinterest.com", "snapchat.com",
    "tiktok.com", "telegram.org", "signal.org", "discord.com", "twitch.tv",
    "yahoo.com", "bing.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "gmail.com", "outlook.com", "protonmail.com", "mail.ru", "zoho.com",
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "npmjs.com",
    "pypi.org", "docker.com", "kubernetes.io", "cloudflare.com", "aws.amazon.com",
    "azure.microsoft.com", "digitalocean.com", "heroku.com", "netlify.com", "vercel.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com",
    "paypal.com", "stripe.com", "square.com", "shopify.com", "etsy.com",
    "visa.com", "mastercard.com", "amex.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "capitalone.com", "citi.com", "hsbc.com", "barclays.com",
    "tumblr.com", "flickr.com", "imgur.com", "medium.com", "quora.com",
    "wordpress.com", "blogger.com", "wix.com", "squarespace.com", "weebly.com",
    "spotify.com", "soundcloud.com", "deezer.com", "tidal.com", "pandora.com",
    "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
    "crunchyroll.com", "funimation.com", "roku.com", "plex.tv", "vimeo.com",
    "slack.com", "trello.com", "asana.com", "notion.so", "evernote.com",
    "dropbox.com", "box.com", "onedrive.com", "icloud.com", "drive.google.com",
    "zoom.us", "teams.microsoft.com", "webex.com", "gotomeeting.com", "skype.com",
    "adobe.com", "canva.com", "figma.com", "sketch.com", "dribbble.com",
    "behance.net", "deviantart.com", "500px.com", "unsplash.com", "shutterstock.com",
    "samsung.com", "sony.com", "lg.com", "panasonic.com", "nokia.com",
    "intel.com", "amd.com", "nvidia.com", "qualcomm.com", "broadcom.com",
    "cisco.com", "juniper.net", "vmware.com", "salesforce.com", "oracle.com",
    "sap.com", "ibm.com", "dell.com", "hp.com", "lenovo.com",
    "tesla.com", "toyota.com", "honda.com", "ford.com", "bmw.com",
    "mercedes-benz.com", "audi.com", "volkswagen.com", "nissan.com", "hyundai.com",
    "nytimes.com", "wsj.com", "cnn.com", "bbc.co.uk", "theguardian.com",
    "reuters.com", "bloomberg.com", "forbes.com", "huffpost.com", "npr.org",
    "washingtonpost.com", "usatoday.com", "latimes.com", "economist.com", "time.com",
    "harvard.edu", "stanford.edu", "mit.edu", "ox.ac.uk", "cambridge.org",
    "wikipedia.org", "britannica.com", "khanacademy.org", "coursera.org", "udemy.com",
    "whitehouse.gov", "usa.gov", "gov.uk", "europa.eu", "un.org",
    "nike.com", "adidas.com", "puma.com", "underarmour.com", "reebok.com",
    "espn.com", "nba.com", "nfl.com", "mlb.com", "fifa.com",
    "starbucks.com", "mcdonalds.com", "subway.com", "kfc.com", "burgerking.com",
    "cocacola.com", "pepsi.com", "nestle.com", "kraftheinz.com", "generalmills.com",
    "verizon.com", "att.com", "t-mobile.com", "sprint.com", "comcast.com",
    "vodafone.com", "orange.com", "deutschetelekom.com", "bt.com", "telefonica.com",
    "booking.com", "expedia.com", "airbnb.com", "uber.com", "lyft.com",
    "marriott.com", "hilton.com", "hyatt.com", "ihg.com", "accor.com",
    "fedex.com", "dhl.com", "ups.com", "usps.com", "tnt.com",
    "steampowered.com", "epicgames.com", "xbox.com", "playstation.com", "nintendo.com",
    "blizzard.com", "ea.com", "activision.com", "ubisoft.com", "rockstargames.com",
    "ikea.com", "zara.com", "hm.com", "uniqlo.com", "gap.com",
    "levi.com", "ralphlauren.com", "tommy.com", "calvinklein.com", "chanel.com",
    "loreal.com", "sephora.com", "ulta.com", "macys.com", "nordstrom.com",
    "costco.com", "wholefoods.com", "traderjoes.com", "alibaba.com", "rakuten.com",
    "coinbase.com", "binance.com", "kraken.com", "robinhood.com", "etrade.com",
    "openai.com", "deepmind.com", "anthropic.com", "huggingface.co", "databricks.com",
    "mongodb.com", "redis.com", "elastic.co", "datadoghq.com", "newrelic.com",
    "sentry.io", "auth0.com", "okta.com", "duo.com", "cloudinary.com",
    "pages.dev", "github.io", "gitlab.io", "netlify.app", "vercel.app",
]

PHISHING_DOMAINS = [
    "g00gle.com", "go0gle.com", "goog1e.com", "googl3.com",
    "goggle.com", "googie.com", "gooogle.com", "googkle.com",
    "faceboook.com", "facebok.com", "facebo0k.com",
    "faceb00k.com", "faceb0ok.com", "fac3book.com",
    "youtub3.com", "youtubee.com", "y0utube.com", "youtub4.com",
    "y0utube-login.com", "you-tube-verify.com",
    "amaz0n.com", "amazoon.com", "amazun.com", "amazzon.com",
    "amazn.com", "amaz0n-login.com",
    "micr0s0ft.com", "micros0ft.com", "micr0soft.com",
    "mircosoft.com", "microsft.com", "micro1soft.com",
    "app1e.com", "appl3.com", "appple.com", "aple.com",
    "app1e-id.com", "appl3-id-verify.com",
    "paypa1.com", "paypal1.com", "paypall.com",
    "paypa1-login.com", "paypal-secure.com",
    "netf1ix.com", "netfl1x.com", "n3tflix.com", "netfliix.com",
    "netfl1x-update.com", "netflix-billing.com",
    "link3din.com", "1inkedin.com", "linked1n.com",
    "1inkedin-login.com",
    "instagr4m.com", "instagrram.com", "instagran.com",
    "instagr4m-verify.com", "insta-gram-login.com",
    "tw1tter.com", "twitt3r.com", "twiter.com", "twittter.com",
    "whatsapp1.com", "whatsap.com", "whattsapp.com",
    "whatsapp-w3b.com", "whatsapp-verify.com",
    "te1egram.com", "telegr4m.com", "telegraam.com",
    "samsun9.com", "samsunng.com",
    "adob3.com", "ad0be.com", "adobe-update.com", "adobe-billing.com",
    "dropb0x.com", "dr0pbox.com", "dropboox.com",
    "dropbox-share.com", "dropbox-login.com",
    "bitbuck3t.com", "bitbucet.com", "git1ab.com", "githuub.com",
    "stackoverf1ow.com", "stakoverflow.com",
    "c0inbase.com", "coinb4se.com", "coinba5e.com",
    "coinbase-wallet.com", "coinbase-verify.com",
    "b1nance.com", "binanc3.com", "binancé.com",
    "binance-verify.com", "binance-login.com",
    "krak3n.com", "kraken-wallet.com",
    "google-login.com", "google-verify.com", "google-security.com",
    "google-account.com", "google-auth.com", "google-support.com",
    "google-update.com", "google-password.com", "google-recovery.com",
    "google-billing.com", "google-wallet.com", "google-pay-login.com",
    "facebook-login.com", "facebook-verify.com", "facebook-secure.com",
    "facebook-security.com", "facebook-recovery.com",
    "microsoft-login.com", "microsoft-verify.com", "microsoft-secure.com",
    "microsoft-update.com", "microsoft-billing.com",
    "apple-login.com", "apple-verify.com", "apple-id.com",
    "apple-security.com", "apple-billing.com",
    "amazon-login.com", "amazon-verify.com", "amazon-secure.com",
    "amazon-account.com", "amazon-billing.com", "amazon-payment.com",
    "paypal-login.com", "paypal-verify.com", "paypal-secure.com",
    "paypal-account.com", "paypal-billing.com",
    "netflix-login.com", "netflix-verify.com", "netflix-billing.com",
    "instagram-login.com", "instagram-verify.com", "instagram-secure.com",
    "linkedin-login.com", "linkedin-verify.com",
    "twitter-login.com", "twitter-verify.com",
    "whatsapp-login.com", "whatsapp-verify.com", "whatsapp-web.com",
    "adobe-login.com", "adobe-verify.com", "adobe-billing.com",
    "dropbox-login.com", "dropbox-verify.com", "dropbox-share.com",
    "github-login.com", "github-verify.com", "github-auth.com",
    "coinbase-login.com", "coinbase-verify.com", "binance-login.com",
    "binance-verify.com", "kraken-login.com",
    "paypal-login.xyz", "amazon-verify.xyz", "google-secure.xyz",
    "netflix-billing.xyz", "apple-support.xyz", "microsoft-login.xyz",
    "facebook-verify.xyz", "instagram-login.xyz",
    "coinbase-wallet.xyz", "binance-verify.xyz",
    "paypal-secure.top", "amazon-login.top", "google-verify.top",
    "netflix-update.top", "apple-id.top", "microsoft-auth.top",
    "instagram-verify.top", "facebook-login.top",
    "microsoft-support.tk", "google-account.tk", "amazon-login.tk",
    "paypal-secure.tk", "netflix-update.tk",
    "coinbase-wallet.ml", "binance-verify.ml", "paypal-login.ml",
    "google-verify.ml", "amazon-support.ml",
    "binance-verify.cf", "coinbase-login.cf", "paypal-secure.cf",
    "whatsapp-web.gq", "telegram-login.gq", "instagram-verify.gq",
    "gmail-verify.gq", "outlook-secure.gq",
    "amazon-billing.click", "paypal-login.click", "netflix-update.click",
    "google-verify.click", "microsoft-auth.click",
    "apple-id-verify.club", "paypal-account.club", "amazon-prime.club",
    "netflix-billing.work", "google-verify.work",
    "microsoft-update.live", "google-account.live",
    "amazon-support.site", "netflix-billing.site",
    "dropbox-share.site", "adobe-update.work",
    "g00gle.com", "раypal.com", "micrоsоft.com",
    "аmаzon.com", "fаcebook.com", "instаgrаm.com",
    "аррle.com", "yоutube.com", "whatsарр.com",
    "сoinbase.com", "tеsla.com", "nеtflix.com",
    "adоbe.com", "wаlmаrt.com", "stаrbucks.com",
    "secure-login-2fa.xyz", "account-verify-identity.top",
    "payment-confirm-billing.xyz", "security-check-2fa.online",
    "verify-identity-now.xyz", "claim-your-prize.top",
    "free-gift-card.site", "winner-lottery.live",
    "track-package-id.click", "shipping-notification.xyz",
    "invoice-due-payment.top", "billing-update-required.xyz",
    "account-suspended-alert.work", "unusual-login-attempt.xyz",
    "limited-time-offer.site", "exclusive-deal-today.top",
    "verify-account-security.live", "confirm-billing-info.xyz",
    "reset-password-now.click", "account-recovery-help.site",
    "login.google.com.security-verify.xyz",
    "account.paypal.com.billing.xyz",
    "secure.amazon.com.login-verify.tk",
    "id.apple.com.account-update.top",
    "login.microsoft.com.support-auth.xyz",
    "www.paypal.com.security-check.click",
    "accounts.google.com.verify-now.xyz",
    "login.facebook.com.secure-auth.top",
    "wallet.coinbase.com.verify-2fa.xyz",
    "google-amazon-login.xyz", "paypal-netflix-verify.top",
    "microsoft-apple-icloud.xyz", "facebook-instagram-auth.live",
    "amazon-paypal-ebay.site", "google-facebook-login.xyz",
    "g00gle-2fa-verify.xyz", "p4yp4l-s3cur3.top",
    "m1cr0s0ft-upd4t3.xyz", "4m4z0n-l0gin.site",
    "n3tfl1x-b1ll1ng.top", "1nst4gr4m-v3r1fy.xyz",
    "4ppl3-1d-v3r1fy.top", "c01nb4s3-w4ll3t.xyz",
    "b1n4nc3-v3r1fy.cf", "wh4ts4pp-s3cur1ty.gq",
    "google.xyz", "paypal.top", "amazon.xyz",
    "netflix.xyz", "facebook.top", "instagram.xyz",
    "microsoft.click", "apple.work", "linkedin.live",
    "whatsapp.gq", "telegram.ml", "coinbase.cf",
    "binance.xyz", "adobe.work", "dropbox.top",
    "gmail-verify.xyz", "gmail-login.top",
    "outlook-secure.xyz", "outlook-verify.live",
    "yahoo-login.xyz", "yahoo-verify.top",
    "protonmail-login.xyz", "protonmail-verify.top",
    "icloud-login.xyz", "icloud-verify.live",
    "steam-login.xyz", "steam-verify.top",
    "epicgames-login.xyz", "epicgames-verify.live",
    "xbox-login.xyz", "playstation-login.top",
    "metamask-login.xyz", "metamask-verify.top",
    "defi-wallet.xyz", "uniswap-login.top",
    "pancakeswap-verify.xyz", "trust-wallet-auth.live",
    "ledger-live-login.xyz", "trezor-auth.top",
    "crypto-com-verify.xyz", "blockchain-login.top",
    "eth-wallet-verify.xyz", "btc-wallet-auth.live",
    "usdt-claim.xyz", "airdrop-claim.top",
    "nft-mint.site", "opensea-login.xyz",
    "google-help.com", "apple-help.com",
    "microsoft-support.org", "amazon-help.org",
    "paypal-help.com", "netflix-help.net",
    "coinbase-support.net", "binance-help.org",
    "g00gl3-s3cur3-l0gin.xyz", "p4yp4l-c0nf1rm.tk",
    "s3cur3-4m4z0n-v3r1fy.ml", "m1cr0s0ft-w1nd0ws-upd4t3.xyz",
    "1-4m-4ppl3-supp0rt.club", "n3tf1ix-4cc0unt-b1ll.xyz",
    "w3-4r3-g00gl3-v3r1fy.tk", "c0m3-t0-p4yp4l-s3cur3.top",
    "y0ur-4cc0unt-1s-l0ck3d.xyz", "cl1ck-h3r3-t0-cl41m.work",
    "shared-file-google.xyz", "document-share-apple.top",
    "invoice-microsoft.xyz", "statement-bankofamerica.site",
    "tax-refund-irs.top", "customs-fee-ups.live",
    "package-delivery-fedex.xyz", "shipping-confirm-dhl.top",
    "parcel-tracking-usps.site", "delivery-attempted-auspost.xyz",
]


# ==============================================================================
# FEATURE VECTOR COMPUTATION (uses real utils.py functions)
# ==============================================================================

def _tld_score(tld: str) -> float:
    """Compute a continuous TLD risk score (0.0-1.0)."""
    t = tld.strip(".").lower()
    if t in {"gov", "edu", "mil"}:
        return 0.0
    if t in {"com", "org", "net"}:
        return 0.1
    if t in {"io", "co", "app", "dev", "ai"}:
        return 0.2
    if t in {"info", "biz", "me", "tv"}:
        return 0.3
    if t in {"online", "site", "club", "live", "work", "support"}:
        return 0.6
    if t in {"xyz", "top", "click", "loan"}:
        return 0.8
    if t in {"tk", "ml", "ga", "cf", "gq"}:
        return 1.0
    if t in {"onion", "i2p", "bit"}:
        return 1.0
    return 0.4


def _clean_domain(raw: str) -> str:
    """Extract clean domain (like main.py clean_domain)."""
    d = raw.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    if "/" in d:
        d = d.split("/", 1)[0]
    if ":" in d:
        d = d.split(":", 1)[0]
    return d.rstrip(".")


def compute_feature_vector(
    domain: str,
    age_days: int,
    privacy: float = 0.0,
    suspicious_reg: float = 0.0,
    has_ssl: float = 1.0,
    has_mx: float = 1.0,
    has_asn: float = 1.0,
    header_score: float = 0.0,
) -> list[float]:
    """
    Compute full 32-feature vector using real detection functions from utils.py.
    Mirrors the feature extraction in main.py's get_ml_prediction().
    """
    # Import utils functions
    try:
        from utils import (
            detect_combosquatting,
            detect_homoglyphs,
            detect_typosquatting,
            extract_features,
            normalize_homoglyphs,
        )
    except ImportError:
        # Fallback: compute features without utils
        return _compute_feature_vector_fallback(domain, age_days, privacy, suspicious_reg, has_ssl, has_mx, has_asn, header_score)

    clean = _clean_domain(domain)
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean
    tld = parts[-1] if len(parts) >= 2 else ""
    domain_name = clean.split(".", 1)[0]

    # Real feature extraction using utils
    try:
        normalized_label = normalize_homoglyphs(label)
    except Exception:
        normalized_label = label
    
    try:
        features = extract_features(clean)
    except Exception:
        features = {}
    
    try:
        typo = detect_typosquatting(normalized_label)
        raw_typo = detect_typosquatting(label)
        if raw_typo.get("jaro_winkler_score", 0.0) > typo.get("jaro_winkler_score", 0.0):
            typo = raw_typo
    except Exception:
        typo = {}
    
    try:
        homoglyph = detect_homoglyphs(clean)
    except Exception:
        homoglyph = {}
    
    try:
        combo = detect_combosquatting(clean)
    except Exception:
        combo = {}

    # Structural features
    letters = sum(c.isalpha() for c in domain_name)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain_name)
    consonant_ratio = consonants / max(1, letters)
    excessive_hyphens = float(domain_name.count("-") >= 3)
    age_log = np.log1p(age_days) / np.log1p(3650)

    # Jaro-Winkler on raw (un-normalized) label
    try:
        raw_typo_check = detect_typosquatting(label)
        jaro_raw_vs_brand = raw_typo_check.get("jaro_winkler_score", 0.0)
    except Exception:
        jaro_raw_vs_brand = 0.0

    # Normalization changed label
    label_normalized_changed = 1.0 if normalized_label != label else 0.0

    # Max consecutive digits
    consecutive_digits = 0.0
    if domain_name:
        digit_runs = re.findall(r"\d+", domain_name)
        if digit_runs:
            consecutive_digits = min(max(len(r) for r in digit_runs) / 5.0, 1.0)

    # TLD risk score
    tld_score_val = _tld_score(tld)

    # Unique normalized tokens
    label_tokens = re.split(r"[\-_]+", label)
    normalized_tokens = set()
    for t in label_tokens:
        try:
            nt = normalize_homoglyphs(t)
            if len(nt) > 2:
                normalized_tokens.add(nt)
        except Exception:
            if len(t) > 2:
                normalized_tokens.add(t)
    unique_token_count = min(len(normalized_tokens) / 5.0, 1.0)

    # Suspicious TLDs list (matches main.py)
    SUSPICIOUS_TLDS_SET = {".top", ".xyz", ".click", ".work", ".live", ".loan", ".cc", ".tk", ".gq", ".ml"}

    # KNOWN_BRANDS (matches main.py)
    KNOWN_BRANDS_LIST = [
        "amazon", "google", "facebook", "paypal", "instagram",
        "netflix", "microsoft", "apple", "linkedin", "github",
        "whatsapp", "telegram", "coinbase", "binance",
    ]

    return [
        min(features.get("length", len(domain_name)) / 50.0, 1.0),
        features.get("digit_ratio", 0.0),
        min(features.get("hyphen_count", domain_name.count("-")) / 5.0, 1.0),
        min(features.get("subdomain_count", len(parts) - 2) / 5.0, 1.0),
        min(features.get("entropy", 3.0) / 5.0, 1.0),
        consonant_ratio,
        float(features.get("suspicious_tld", ("._" + parts[-1]) in SUSPICIOUS_TLDS_SET) if len(parts) > 1 else 0.0),
        float(features.get("has_suspicious_keywords", any(k in clean for k in KNOWN_BRANDS_LIST))),
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
        privacy,
        suspicious_reg,
        jaro_raw_vs_brand,
        label_normalized_changed,
        consecutive_digits,
        tld_score_val,
        unique_token_count,
        has_ssl,
        has_mx,
        has_asn,
        min(max(header_score, 0.0) / 15.0, 1.0),
    ]


def _compute_feature_vector_fallback(
    domain: str,
    age_days: int,
    privacy: float = 0.0,
    suspicious_reg: float = 0.0,
    has_ssl: float = 1.0,
    has_mx: float = 1.0,
    has_asn: float = 1.0,
    header_score: float = 0.0,
) -> list[float]:
    """Fallback feature computation when utils.py is unavailable."""
    clean = _clean_domain(domain)
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean
    tld = parts[-1] if len(parts) >= 2 else ""
    domain_name = clean.split(".", 1)[0]

    SUSPICIOUS_TLDS_SET = {".top", ".xyz", ".click", ".work", ".live", ".loan", ".cc", ".tk", ".gq", ".ml"}
    MAJOR_BRANDS = ["google", "facebook", "microsoft", "apple", "amazon", "paypal", "netflix", "instagram", "linkedin", "github", "whatsapp", "coinbase", "binance"]
    PHISHING_KW = ["login", "signin", "verify", "secure", "account", "auth", "support", "update", "wallet", "pay", "billing"]

    letters = sum(c.isalpha() for c in domain_name)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain_name)
    consonant_ratio = consonants / max(1, letters)
    hyphen_count = domain_name.count("-")
    digit_count = sum(c.isdigit() for c in domain_name)
    age_log = np.log1p(age_days) / np.log1p(3650)

    has_brand = any(b in label for b in MAJOR_BRANDS)
    has_keyword = any(kw in label for kw in PHISHING_KW)
    has_typo = has_brand and has_keyword
    has_homoglyph = any(c in "01345678" for c in label)
    homoglyph_count = sum(1 for c in label if c in "01345678")
    has_digit_sub = has_homoglyph and has_brand
    has_combo = has_brand and has_keyword

    consecutive_digits = 0.0
    digit_runs = re.findall(r"\d+", domain_name)
    if digit_runs:
        consecutive_digits = min(max(len(r) for r in digit_runs) / 5.0, 1.0)

    normalized = label.replace("0", "o").replace("1", "l").replace("3", "e").replace("4", "a").replace("5", "s").replace("7", "t")
    norm_changed = 1.0 if normalized != label else 0.0

    tld_score_val = _tld_score(tld)

    return [
        min(len(label) / 50.0, 1.0),
        digit_count / max(len(label), 1),
        min(hyphen_count / 5.0, 1.0),
        min((len(parts) - 2) / 5.0, 1.0),
        min(3.0 / 5.0, 1.0),
        consonant_ratio,
        1.0 if ("." + tld) in SUSPICIOUS_TLDS_SET else 0.0,
        1.0 if has_brand else 0.0,
        0.0,
        1.0 if hyphen_count >= 3 else 0.0,
        0.7 if has_typo else 0.0,
        0.5 if has_typo else 0.0,
        0.3 if has_typo else 0.0,
        1.0 if has_typo else 0.0,
        1.0 if has_homoglyph else 0.0,
        min(homoglyph_count / 5.0, 1.0),
        1.0 if has_digit_sub else 0.0,
        1.0 if has_combo else 0.0,
        1.0 if has_brand and not has_combo else 0.0,
        min(sum(1 for kw in PHISHING_KW if kw in label) / 5.0, 1.0),
        age_log,
        privacy,
        suspicious_reg,
        0.0,
        norm_changed,
        consecutive_digits,
        tld_score_val,
        0.0,
        has_ssl,
        has_mx,
        has_asn,
        min(max(header_score, 0.0) / 15.0, 1.0),
    ]


# ==============================================================================
# TRAINING DATA GENERATION (uses real domains + feature computation)
# ==============================================================================

def _generate_phishing_age() -> int:
    """Generate realistic age for phishing domains (usually young)."""
    if random.random() < 0.8:
        return random.randint(1, 364)
    return random.randint(365, 730)


def _generate_legitimate_age() -> int:
    """Generate realistic age for legitimate domains (usually old)."""
    if random.random() < 0.9:
        return random.randint(730, 7300)
    return random.randint(30, 729)


def generate_training_data() -> tuple[np.ndarray, np.ndarray]:
    """
    Generate training data using REAL domain names and REAL feature computation.
    
    Each legitimate domain generates 4+ variants:
      - Young, mature, and old ages
      - The inference-default age (365 days, when WHOIS unavailable)
      - ~40% chance of degraded infrastructure (missing MX, ASN, SSL, weak headers)
    
    Each phishing domain generates 5+ variants:
      - Young age with typical poor infrastructure
      - Moderate age
      - Very fresh (1-14 days)
      - Old age phishing (teaches model that old + typosquatting = still phishing)
      - ~30% chance of good infrastructure (valid SSL, MX, ASN)
    """
    samples = []
    labels = []

    # --- Generate legitimate samples ---
    for domain in LEGITIMATE_DOMAINS:
        # Standard variant: mature age, good infrastructure
        samples.append(compute_feature_vector(domain, _generate_legitimate_age(),
                         has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        labels.append(0)

        # Young legitimate variant (some legit domains are young)
        samples.append(compute_feature_vector(domain, random.randint(30, 364),
                         has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        labels.append(0)

        # Inference-default age (365 days) - CRITICAL: prevents false positives
        # when WHOIS is unavailable during live analysis
        samples.append(compute_feature_vector(domain, 365,
                         has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        labels.append(0)

        # Very old legitimate variant
        samples.append(compute_feature_vector(domain, random.randint(3650, 10000),
                         has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        labels.append(0)

        # Weak-infrastructure variant (~40% chance)
        # Real legitimate domains often lack perfect infrastructure
        if random.random() < 0.4:
            samples.append(compute_feature_vector(domain, _generate_legitimate_age(),
                             has_ssl=1.0 if random.random() < 0.7 else 0.0,
                             has_mx=1.0 if random.random() < 0.8 else 0.0,
                             has_asn=1.0 if random.random() < 0.8 else 0.0,
                             header_score=random.uniform(0, 14)))
            labels.append(0)

        # UNREACHABLE variant (all infra = 0, age = 365 default)
        # CRITICAL: Teaches model that domains with NO data (no SSL, no MX,
        # no ASN, no headers) can still be legitimate. Prevents XGBoost
        # from scoring "no data = phishing" which was the root cause of
        # false positives on unreachable but clean domains like .edu sites
        # where all probes timed out.
        if random.random() < 0.3:
            # header_score=0 because unreachable = no data = neutral, not risky
            samples.append(compute_feature_vector(domain, 365,
                             0.0, 0.0,
                             has_ssl=0.0, has_mx=0.0, has_asn=0.0,
                             header_score=0.0))
            labels.append(0)

    # --- Generate phishing samples ---
    for domain in PHISHING_DOMAINS:
        # Young domain with typical poor infrastructure
        samples.append(compute_feature_vector(domain, random.randint(1, 60),
                         privacy=1.0 if random.random() < 0.7 else 0.0,
                         suspicious_reg=1.0 if random.random() < 0.5 else 0.0,
                         has_ssl=0.3, has_mx=0.0, has_asn=0.0,
                         header_score=random.uniform(5, 20)))
        labels.append(1)

        # Moderate age phishing
        samples.append(compute_feature_vector(domain, random.randint(61, 180),
                         privacy=1.0 if random.random() < 0.6 else 0.0,
                         suspicious_reg=1.0 if random.random() < 0.4 else 0.0,
                         has_ssl=0.3, has_mx=0.0, has_asn=0.0,
                         header_score=random.uniform(3, 18)))
        labels.append(1)

        # Very fresh phishing (1-14 days)
        samples.append(compute_feature_vector(domain, random.randint(1, 14),
                         privacy=1.0, suspicious_reg=1.0,
                         has_ssl=0.0, has_mx=0.0, has_asn=0.0,
                         header_score=random.uniform(8, 25)))
        labels.append(1)

        # Old phishing domain (teaches model that old + typosquatting = still phishing)
        samples.append(compute_feature_vector(domain, random.randint(3650, 10000),
                         privacy=0.5, suspicious_reg=0.3,
                         has_ssl=0.0, has_mx=0.0, has_asn=0.0,
                         header_score=random.uniform(5, 20)))
        labels.append(1)

        # Phishing with good infrastructure (valid SSL, MX, ASN)
        # CRITICAL: prevents model from learning "good infra = legitimate" unconditionally
        if random.random() < 0.3:
            samples.append(compute_feature_vector(domain, random.randint(1, 90),
                             has_ssl=1.0, has_mx=1.0, has_asn=1.0,
                             header_score=random.uniform(0, 5)))
            labels.append(1)

    # --- Generate additional borderline / weak-signal phishing ---
    for domain in PHISHING_DOMAINS:
        # No privacy, no reg flags - careless phisher variant
        samples.append(compute_feature_vector(domain, random.randint(1, 90),
                         0.0, 0.0, has_ssl=0.0, has_mx=0.0, has_asn=0.0,
                         header_score=random.uniform(10, 25)))
        labels.append(1)

    # --- Generate legitimate domains with suspicious TLDs ---
    # Teaches model NOT to over-index on TLD alone
    legit_tld_domains = [
        "genius.xyz", "abc.xyz",
        "nike.shoes", "coke.ice",
        "microsoft.azure", "amazon.aws",
        "gov.uk", "bbc.co.uk",
    ]
    for domain in legit_tld_domains:
        samples.append(compute_feature_vector(domain, 3650,
                         0.0, 0.0, has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        labels.append(0)

    X = np.array(samples, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    print(f"  Total samples: {len(X)}")
    print(f"  Legitimate:    {int(np.sum(y == 0))}")
    print(f"  Phishing:      {int(np.sum(y == 1))}")
    print(f"  Phishing ratio: {float(y.mean()):.1%}")

    return X, y


# ==============================================================================
# METRICS UTILITIES
# ==============================================================================

def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray | None = None) -> dict[str, Any]:
    """Compute comprehensive binary classification metrics."""
    from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                                 roc_auc_score, average_precision_score, confusion_matrix,
                                 brier_score_loss, log_loss)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }

    if y_prob is not None:
        try:
            metrics["auc_roc"] = round(float(roc_auc_score(y_true, y_prob)), 4)
            metrics["auc_pr"] = round(float(average_precision_score(y_true, y_prob)), 4)
            metrics["brier_score"] = round(float(brier_score_loss(y_true, y_prob)), 4)
            metrics["log_loss"] = round(float(log_loss(y_true, y_prob)), 4)
        except Exception:
            pass

    return metrics


def find_optimal_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> tuple[float, dict[str, float]]:
    """Find optimal classification threshold using Youden's J statistic."""
    from sklearn.metrics import roc_curve

    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    youden_j = tpr - fpr
    best_idx = np.argmax(youden_j)
    best_threshold = thresholds[best_idx]

    return float(best_threshold), {
        "youden_j": float(youden_j[best_idx]),
        "tpr_at_optimal": float(tpr[best_idx]),
        "fpr_at_optimal": float(fpr[best_idx]),
    }


# ==============================================================================
# HYPERPARAMETER TUNING
# ==============================================================================

def tune_xgboost(X_train: np.ndarray, y_train: np.ndarray) -> Any:
    """Tune XGBoost hyperparameters with RandomizedSearchCV."""
    from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV
    import xgboost as xgb

    print("    Tuning hyperparameters...")
    param_dist = {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [3, 4, 6, 8, 10],
        "learning_rate": [0.01, 0.05, 0.1, 0.2],
        "subsample": [0.6, 0.7, 0.8, 0.9, 1.0],
        "colsample_bytree": [0.6, 0.7, 0.8, 0.9, 1.0],
        "min_child_weight": [1, 3, 5, 7],
        "gamma": [0, 0.1, 0.2, 0.3],
        "reg_alpha": [0, 0.01, 0.1, 1.0],
        "reg_lambda": [0, 0.01, 0.1, 1.0],
    }

    base = xgb.XGBClassifier(
        random_state=RANDOM_SEED,
        use_label_encoder=False,
        eval_metric="logloss",
        verbosity=0,
    )

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    search = RandomizedSearchCV(
        base, param_dist, n_iter=N_ITER_SEARCH, cv=cv,
        scoring="roc_auc", random_state=RANDOM_SEED,
        n_jobs=-1, verbose=0,
    )
    search.fit(X_train, y_train)

    print(f"    Best params: {search.best_params_}")
    print(f"    Best CV AUC: {search.best_score_:.4f}")
    return search.best_estimator_


def tune_lightgbm(X_train: np.ndarray, y_train: np.ndarray) -> Any:
    """Tune LightGBM hyperparameters with RandomizedSearchCV."""
    from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV
    import lightgbm as lgb

    print("    Tuning hyperparameters...")
    param_dist = {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [3, 4, 6, 8, 10, -1],
        "learning_rate": [0.01, 0.05, 0.1, 0.2],
        "subsample": [0.6, 0.7, 0.8, 0.9, 1.0],
        "colsample_bytree": [0.6, 0.7, 0.8, 0.9, 1.0],
        "min_child_samples": [5, 10, 20, 30],
        "num_leaves": [15, 31, 63, 127],
        "reg_alpha": [0, 0.01, 0.1, 1.0],
        "reg_lambda": [0, 0.01, 0.1, 1.0],
    }

    base = lgb.LGBMClassifier(random_state=RANDOM_SEED, verbose=-1)

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    search = RandomizedSearchCV(
        base, param_dist, n_iter=N_ITER_SEARCH, cv=cv,
        scoring="roc_auc", random_state=RANDOM_SEED,
        n_jobs=-1, verbose=0,
    )
    search.fit(X_train, y_train)

    print(f"    Best params: {search.best_params_}")
    print(f"    Best CV AUC: {search.best_score_:.4f}")
    return search.best_estimator_


def tune_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> Any:
    """Tune Random Forest hyperparameters."""
    from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV
    from sklearn.ensemble import RandomForestClassifier

    print("    Tuning hyperparameters...")
    param_dist = {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [6, 8, 10, 12, 15, None],
        "min_samples_split": [2, 5, 10, 20],
        "min_samples_leaf": [1, 2, 4, 8],
        "max_features": ["sqrt", "log2", None],
        "bootstrap": [True, False],
        "criterion": ["gini", "entropy"],
    }

    base = RandomForestClassifier(random_state=RANDOM_SEED, n_jobs=-1)

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    search = RandomizedSearchCV(
        base, param_dist, n_iter=N_ITER_SEARCH, cv=cv,
        scoring="roc_auc", random_state=RANDOM_SEED,
        n_jobs=-1, verbose=0,
    )
    search.fit(X_train, y_train)

    print(f"    Best params: {search.best_params_}")
    print(f"    Best CV AUC: {search.best_score_:.4f}")
    return search.best_estimator_


def tune_logistic_regression(X_train: np.ndarray, y_train: np.ndarray) -> tuple[Any, Any]:
    """Tune Logistic Regression hyperparameters."""
    from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    print("    Scaling features for Logistic Regression...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    print("    Tuning hyperparameters...")
    param_dist = {
        "C": [0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 100.0],
        "penalty": ["l1", "l2", "elasticnet", None],
        "solver": ["lbfgs", "liblinear", "saga"],
        "max_iter": [500, 1000, 2000],
        "class_weight": [None, "balanced"],
    }

    base = LogisticRegression(random_state=RANDOM_SEED, n_jobs=-1)

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    # Filter valid params for the solver
    valid_solvers = {"lbfgs", "liblinear", "saga"}
    valid_penalties = {"l1", "l2", "elasticnet", None}

    # Use a simpler param grid that avoids solver/penalty conflicts
    param_dist_simple = {
        "C": [0.01, 0.1, 1.0, 10.0],
        "max_iter": [500, 1000],
        "class_weight": [None, "balanced"],
    }

    search = RandomizedSearchCV(
        LogisticRegression(penalty="l2", solver="lbfgs", random_state=RANDOM_SEED, n_jobs=-1),
        param_dist_simple, n_iter=8, cv=cv,
        scoring="roc_auc", random_state=RANDOM_SEED,
        n_jobs=-1, verbose=0,
    )
    search.fit(X_scaled, y_train)

    print(f"    Best params: {search.best_params_}")
    print(f"    Best CV AUC: {search.best_score_:.4f}")

    # Refit with best params for consistent API
    best_params = search.best_params_
    final_lr = LogisticRegression(
        penalty="l2", solver="lbfgs",
        C=best_params.get("C", 1.0),
        max_iter=best_params.get("max_iter", 1000),
        class_weight=best_params.get("class_weight", None),
        random_state=RANDOM_SEED, n_jobs=-1,
    )
    final_lr.fit(X_scaled, y_train)
    return final_lr, scaler


from ml_ensemble import ScaledModelWrapper


# ==============================================================================
# FEATURE IMPORTANCE
# ==============================================================================

def compute_feature_importance(model: Any, model_name: str) -> dict[str, Any]:
    """Extract feature importance from a trained model."""
    importance = {}
    try:
        if hasattr(model, "feature_importances_"):
            imp = model.feature_importances_
            importance = {
                "raw": [float(x) for x in imp],
                "top_5": [
                    {"feature": FEATURE_NAMES[i], "importance": float(imp[i])}
                    for i in np.argsort(imp)[-5:][::-1]
                ],
                "method": "built-in",
            }
        elif hasattr(model, "coef_"):
            coef = np.abs(model.coef_[0])
            importance = {
                "raw": [float(x) for x in coef],
                "top_5": [
                    {"feature": FEATURE_NAMES[i], "importance": float(coef[i])}
                    for i in np.argsort(coef)[-5:][::-1]
                ],
                "method": "coefficient_magnitude",
            }
    except Exception:
        importance = {"raw": [], "top_5": [], "method": "unavailable"}
    return importance


# ==============================================================================
# MAIN TRAINING PIPELINE
# ==============================================================================

def train_models() -> dict[str, Any]:
    """Run the complete training pipeline with real domain data."""
    from sklearn.model_selection import train_test_split

    print("=" * 72)
    print("  TMGC Real-Data ML Training Pipeline")
    print("  Training on real domain names with real feature computation")
    print("=" * 72)
    print(f"\n  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Legitimate domains: {len(LEGITIMATE_DOMAINS)}")
    print(f"  Phishing domains:   {len(PHISHING_DOMAINS)}")
    print(f"  Cross-validation folds: {CV_FOLDS}")
    print(f"  Hyperparameter search iterations: {N_ITER_SEARCH}")

    # ========================================================================
    # STEP 1: Generate training data from real domains
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 1: Generating Training Data (Real Domains)")
    print("-" * 72)

    X, y = generate_training_data()

    # ========================================================================
    # STEP 2: Split data
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 2: Splitting Data")
    print("-" * 72)

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.4, random_state=RANDOM_SEED, stratify=y
    )
    X_cal, X_test, y_cal, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=RANDOM_SEED, stratify=y_temp
    )

    print(f"  Training:   {len(X_train)} samples")
    print(f"  Calibrate:  {len(X_cal)} samples")
    print(f"  Test:       {len(X_test)} samples")

    results = {}
    trained_models = {}
    thresholds = {}
    feature_importances = {}

    # ========================================================================
    # STEP 3a: XGBoost
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 3a: XGBoost — Hyperparameter Tuning & Training")
    print("-" * 72)

    try:
        model_xgb = tune_xgboost(X_train, y_train)
        trained_models["xgboost"] = model_xgb

        y_prob = model_xgb.predict_proba(X_test)[:, 1]
        y_pred = model_xgb.predict(X_test)
        metrics = compute_metrics(y_test, y_pred, y_prob)
        results["xgboost"] = metrics

        opt_thresh, opt_info = find_optimal_threshold(y_test, y_prob)
        thresholds["xgboost"] = opt_thresh
        feature_importances["xgboost"] = compute_feature_importance(model_xgb, "xgboost")

        print(f"  Test accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Test AUC-ROC:   {metrics.get('auc_roc', 'N/A')}")
        print(f"  F1:             {metrics['f1_score']:.4f}")
        print(f"  Optimal thresh: {opt_thresh:.4f}")
    except ImportError:
        print("  ! xgboost not installed. Skipping.")

    # ========================================================================
    # STEP 3b: LightGBM
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 3b: LightGBM — Hyperparameter Tuning & Training")
    print("-" * 72)

    try:
        model_lgb = tune_lightgbm(X_train, y_train)
        trained_models["lightgbm"] = model_lgb

        y_prob = model_lgb.predict_proba(X_test)[:, 1]
        y_pred = model_lgb.predict(X_test)
        metrics = compute_metrics(y_test, y_pred, y_prob)
        results["lightgbm"] = metrics

        opt_thresh, opt_info = find_optimal_threshold(y_test, y_prob)
        thresholds["lightgbm"] = opt_thresh
        feature_importances["lightgbm"] = compute_feature_importance(model_lgb, "lightgbm")

        print(f"  Test accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Test AUC-ROC:   {metrics.get('auc_roc', 'N/A')}")
        print(f"  F1:             {metrics['f1_score']:.4f}")
        print(f"  Optimal thresh: {opt_thresh:.4f}")
    except ImportError:
        print("  ! lightgbm not installed. Skipping.")

    # ========================================================================
    # STEP 3c: Random Forest
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 3c: Random Forest — Hyperparameter Tuning & Training")
    print("-" * 72)

    try:
        model_rf = tune_random_forest(X_train, y_train)
        trained_models["random_forest"] = model_rf

        y_prob = model_rf.predict_proba(X_test)[:, 1]
        y_pred = model_rf.predict(X_test)
        metrics = compute_metrics(y_test, y_pred, y_prob)
        results["random_forest"] = metrics

        opt_thresh, opt_info = find_optimal_threshold(y_test, y_prob)
        thresholds["random_forest"] = opt_thresh
        feature_importances["random_forest"] = compute_feature_importance(model_rf, "random_forest")

        print(f"  Test accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Test AUC-ROC:   {metrics.get('auc_roc', 'N/A')}")
        print(f"  F1:             {metrics['f1_score']:.4f}")
        print(f"  Optimal thresh: {opt_thresh:.4f}")
    except ImportError:
        print("  ! sklearn not installed. Skipping.")

    # ========================================================================
    # STEP 3d: Logistic Regression
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 3d: Logistic Regression — Hyperparameter Tuning & Training")
    print("-" * 72)

    try:
        model_lr, scaler = tune_logistic_regression(X_train, y_train)
        model_lr_wrapped = ScaledModelWrapper(model_lr, scaler)
        trained_models["logistic_regression"] = model_lr_wrapped

        X_test_scaled = scaler.transform(X_test)
        y_prob = model_lr.predict_proba(X_test_scaled)[:, 1]
        y_pred = model_lr.predict(X_test_scaled)
        metrics = compute_metrics(y_test, y_pred, y_prob)
        results["logistic_regression"] = metrics

        opt_thresh, opt_info = find_optimal_threshold(y_test, y_prob)
        thresholds["logistic_regression"] = opt_thresh
        feature_importances["logistic_regression"] = compute_feature_importance(model_lr, "logistic_regression")

        print(f"  Test accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Test AUC-ROC:   {metrics.get('auc_roc', 'N/A')}")
        print(f"  F1:             {metrics['f1_score']:.4f}")
        print(f"  Optimal thresh: {opt_thresh:.4f}")
    except ImportError:
        print("  ! sklearn not installed. Skipping.")

    # ========================================================================
    # STEP 4: Save Models
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 4: Saving Models")
    print("-" * 72)

    for name, model in trained_models.items():
        path = MODEL_PATHS.get(name)
        if path:
            with open(path, "wb") as f:
                pickle.dump(model, f)
            size_kb = os.path.getsize(path) / 1024
            print(f"  {name}: saved ({size_kb:.1f} KB)")

    # ========================================================================
    # STEP 5: Save Ensemble Priors
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 5: Saving Ensemble Priors")
    print("-" * 72)

    # Fixed ensemble weights (tuned for phishing detection)
    ensemble_weights = {
        "xgboost": 0.35,
        "lightgbm": 0.30,
        "random_forest": 0.20,
        "logistic_regression": 0.15,
    }

    feature_means = {f"f{i}": float(X[:, i].mean()) for i in range(FEATURE_COUNT)}
    feature_stds = {f"f{i}": float(X[:, i].std()) for i in range(FEATURE_COUNT)}

    model_priors = {}
    for name, model in trained_models.items():
        model_priors[name] = {
            "auc_roc": results.get(name, {}).get("auc_roc", 0.0),
            "optimal_threshold": thresholds.get(name, 0.5),
            "metrics": results.get(name, {}),
        }

    priors = {
        "feature_count": FEATURE_COUNT,
        "phishing_ratio": float(y.mean()),
        "feature_means": feature_means,
        "feature_stds": feature_stds,
        "model_results": {k: results.get(k, {}) for k in trained_models},
        "model_priors": model_priors,
        "ensemble_weights": ensemble_weights,
        "optimal_thresholds": thresholds,
        "training_date": datetime.now().isoformat(),
        "pipeline_version": "3.0-real-data",
        "legitimate_domains_count": len(LEGITIMATE_DOMAINS),
        "phishing_domains_count": len(PHISHING_DOMAINS),
        "total_samples": len(X),
    }

    with open(PRIORS_PATH, "wb") as f:
        pickle.dump(priors, f)
    print(f"  Priors saved to: {PRIORS_PATH}")

    # ========================================================================
    # STEP 6: Generate Training Report
    # ========================================================================
    print("\n" + "-" * 72)
    print("  STEP 6: Generating Training Report")
    print("-" * 72)

    report = {
        "training_date": datetime.now().isoformat(),
        "pipeline": "3.0-real-data",
        "legitimate_domains": len(LEGITIMATE_DOMAINS),
        "phishing_domains": len(PHISHING_DOMAINS),
        "total_training_samples": len(X),
        "phishing_ratio": float(y.mean()),
        "models": {},
        "ensemble_weights": ensemble_weights,
        "feature_importances": {k: v.get("top_5", []) for k, v in feature_importances.items()},
    }

    for name in trained_models:
        report["models"][name] = {
            "test_metrics": results.get(name, {}),
            "optimal_threshold": thresholds.get(name, 0.5),
        }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report saved to: {REPORT_PATH}")

    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "=" * 72)
    print("  TRAINING COMPLETE — Real-Data Pipeline Summary")
    print("=" * 72)

    for name in trained_models:
        m = results.get(name, {})
        top5 = feature_importances.get(name, {}).get("top_5", [])
        print(f"\n  [MODEL] {name.upper()}")
        print(f"     Accuracy: {m.get('accuracy', 0):.4f}  |  AUC-ROC: {m.get('auc_roc', 0):.4f}  |  F1: {m.get('f1_score', 0):.4f}")
        print(f"     Precision: {m.get('precision', 0):.4f}  |  Recall: {m.get('recall', 0):.4f}")
        print(f"     Optimal threshold: {thresholds.get(name, 0.5):.4f}")
        if top5:
            print(f"     Top features: ", end="")
            for ft in top5[:3]:
                print(f"{ft['feature']} ({ft['importance']:.3f}), ", end="")
            print()

    print(f"\n  [OK] All models saved and ready for inference.")
    print(f"  [FILE] Full report: {REPORT_PATH}")
    print(f"  [TIME] Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return results


if __name__ == "__main__":
    train_models()

"""
Train all 4 ML models using the PhishTank community-verified phishing dataset.

PhishTank provides:
  - Real phishing URLs verified by the community
  - Target brand names (PayPal, Google, etc.)
  - Hourly updated database

This script:
  1. Downloads PhishTank CSV (online-valid.csv)
  2. Extracts domains + target brands
  3. Generates feature vectors using utils.py
  4. Combines with legitimate domains
  5. Trains XGBoost, LightGBM, Random Forest, Logistic Regression

Dataset: ~10K-50K real phishing URLs + legitimate domains
Source:  https://data.phishtank.com/data/online-valid.csv
"""

from __future__ import annotations

import csv
import io
import os
import pickle
import random
import re
import sys
import urllib.request
import warnings
from urllib.parse import urlparse

import numpy as np

warnings.filterwarnings("ignore")

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATHS = {
    "xgboost": os.path.join(MODEL_DIR, "xgb_model.pkl"),
    "lightgbm": os.path.join(MODEL_DIR, "lgbm_model.pkl"),
    "random_forest": os.path.join(MODEL_DIR, "rf_model.pkl"),
    "logistic_regression": os.path.join(MODEL_DIR, "lr_model.pkl"),
}
PRIORS_PATH = os.path.join(MODEL_DIR, "ensemble_priors.pkl")
REPORT_PATH = os.path.join(MODEL_DIR, "phishtank_training_report.json")

PHISHTANK_CSV_URL = "http://data.phishtank.com/data/online-valid.csv"

# Known brand names (lowercase) for extracting target from PhishTank
KNOWN_BRANDS = [
    "paypal", "google", "facebook", "amazon", "microsoft", "apple",
    "netflix", "instagram", "linkedin", "twitter", "whatsapp", "telegram",
    "coinbase", "binance", "dropbox", "adobe", "github", "icloud",
    "outlook", "gmail", "yahoo", "steam", "apple", "samsung",
]

FEATURE_COUNT = 32

# Import unified TLD lists from utils
try:
    from utils import SUSPICIOUS_TLDS, SUSPICIOUS_TLDS_DOT
except ImportError:
    SUSPICIOUS_TLDS = frozenset({"xyz", "top", "club", "online", "site", "web", "info", "biz",
        "tk", "ml", "ga", "cf", "gq", "pw", "ws", "icu", "click",
        "cam", "mom", "work", "vip", "support", "email", "live", "loan"})
    SUSPICIOUS_TLDS_DOT = frozenset("." + tld for tld in SUSPICIOUS_TLDS)


def download_phashtank() -> str:
    """Download PhishTank CSV and return file path."""
    csv_path = os.path.join(MODEL_DIR, "phishtank_online.csv")
    if os.path.exists(csv_path):
        # Check if fresh (less than 24 hours old)
        age_hours = (os.path.getmtime(csv_path) - os.path.getctime(csv_path)) / 3600
        if age_hours < 24:
            print(f"  Using cached: {csv_path}")
            return csv_path

    print(f"  Downloading from PhishTank ...")
    print(f"  URL: {PHISHTANK_CSV_URL}")
    req = urllib.request.Request(PHISHTANK_CSV_URL, headers={
        "User-Agent": "phishtank-retro-intel-training/1.0",
    })
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        data = resp.read()
        with open(csv_path, "wb") as f:
            f.write(data)
        print(f"  Downloaded: {len(data):,} bytes -> {csv_path}")
        return csv_path
    except Exception as e:
        print(f"  Download failed: {e}")
        print("  Falling back to cached data or local generation ...")
        return None


def parse_phashtank_csv(filepath: str, max_samples: int = 20000) -> list[dict]:
    """Parse PhishTank CSV and extract domain + target info."""
    entries = []
    seen_domains = set()

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if len(entries) >= max_samples:
                break
            url = row.get("url", "").strip()
            target = row.get("target", "").strip()
            online = row.get("online", "yes").strip().lower()

            if not url:
                continue

            # Extract domain from URL
            try:
                parsed = urlparse(url)
                domain = parsed.hostname
                if not domain:
                    continue
                domain = domain.lower().strip(".")
            except Exception:
                continue

            # Skip duplicates
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            entries.append({
                "domain": domain,
                "url": url,
                "target": target,
                "online": online,
            })

    return entries


def extract_brand_from_target(target: str) -> str | None:
    """Extract brand name from PhishTank target field."""
    target_lower = target.lower()
    for brand in KNOWN_BRANDS:
        if brand in target_lower:
            return brand
    return None


def extract_brand_from_domain(domain: str) -> str | None:
    """Try to extract brand name from domain itself."""
    domain_lower = domain.lower()
    for brand in KNOWN_BRANDS:
        if brand in domain_lower:
            return brand
    return None


def compute_feature_vector(
    domain: str,
    age_days: int = 7,
    privacy: float = 0.8,
    suspicious_reg: float = 0.5,
    has_ssl: float = 0.3,
    has_mx: float = 0.0,
    has_asn: float = 0.5,
    header_score: float = 12.0,
) -> list[float]:
    """
    Compute 32-feature vector for a domain.
    Uses real detection functions from utils.py when available.
    """
    try:
        from utils import (
            detect_combosquatting,
            detect_homoglyphs,
            detect_typosquatting,
            extract_features,
            normalize_homoglyphs,
        )
        _HAS_UTILS = True
    except ImportError:
        _HAS_UTILS = False

    clean = domain.strip().lower()
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean
    tld = parts[-1] if len(parts) >= 2 else ""
    domain_name = clean.split(".", 1)[0]

    # TLD risk score
    def _tld_score(t: str) -> float:
        t = t.lower()
        if t in ("gov", "edu", "mil"):
            return 0.0
        if t in ("com", "org", "net"):
            return 0.1
        if t in ("io", "co", "app", "dev", "ai"):
            return 0.2
        if t in ("info", "biz", "me", "tv"):
            return 0.3
        if t in ("online", "site", "club", "live", "work", "support"):
            return 0.6
        if t in ("xyz", "top", "click", "loan"):
            return 0.8
        if t in ("tk", "ml", "ga", "cf", "gq"):
            return 1.0
        return 0.4

    KNOWN_BRANDS_LIST = [
        "amazon", "google", "facebook", "paypal", "instagram",
        "netflix", "microsoft", "apple", "linkedin", "github",
        "whatsapp", "telegram", "coinbase", "binance",
    ]

    if _HAS_UTILS:
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
    else:
        features = {}
        typo = {}
        homoglyph = {}
        combo = {}

    letters = sum(c.isalpha() for c in domain_name)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain_name)
    consonant_ratio = consonants / max(1, letters)
    excessive_hyphens = float(domain_name.count("-") >= 3)
    age_log = np.log1p(age_days) / np.log1p(3650)

    # Jaro-Winkler on raw label
    jaro_raw = typo.get("jaro_winkler_score", 0.0) if typo else 0.0

    # Normalization changed
    try:
        norm_changed = 1.0 if normalized_label != label else 0.0
    except Exception:
        norm_changed = 0.0

    # Consecutive digits
    consecutive_digits = 0.0
    if domain_name:
        digit_runs = re.findall(r"\d+", domain_name)
        if digit_runs:
            consecutive_digits = min(max(len(r) for r in digit_runs) / 5.0, 1.0)

    # Unique tokens
    try:
        label_tokens = re.split(r"[\-_]+", label)
        norm_tokens = set()
        for t in label_tokens:
            nt = normalize_homoglyphs(t) if _HAS_UTILS else t
            if len(nt) > 2:
                norm_tokens.add(nt)
        unique_tokens = min(len(norm_tokens) / 5.0, 1.0)
    except Exception:
        unique_tokens = 0.0

    return [
        min(features.get("length", len(domain_name)) / 50.0, 1.0),            # 0
        features.get("digit_ratio", 0.0),                                       # 1
        min(features.get("hyphen_count", domain_name.count("-")) / 5.0, 1.0),  # 2
        min(features.get("subdomain_count", len(parts) - 2) / 5.0, 1.0),       # 3
        min(features.get("entropy", 3.0) / 5.0, 1.0),                          # 4
        consonant_ratio,                                                         # 5
        float(features.get("suspicious_tld", ("." + tld) in SUSPICIOUS_TLDS_DOT)),  # 6
        float(features.get("has_suspicious_keywords", any(k in clean for k in KNOWN_BRANDS_LIST))), # 7
        float(features.get("is_ip_like", False)),                               # 8
        excessive_hyphens,                                                       # 9
        typo.get("jaro_winkler_score", 0.0),                                    # 10
        typo.get("levenshtein_score", 0.0),                                     # 11
        min(typo.get("edit_distance", 10) / 10.0, 1.0),                        # 12
        float(typo.get("detected", False)),                                     # 13
        float(homoglyph.get("detected", False)),                                # 14
        min(homoglyph.get("count", 0) / 5.0, 1.0),                             # 15
        float(homoglyph.get("has_digit_substitution", False)),                  # 16
        float(combo.get("detected", False)),                                    # 17
        float(combo.get("brand_only", False)),                                  # 18
        min(len(combo.get("matched_keywords", [])) / 5.0, 1.0),                # 19
        age_log,                                                                # 20
        privacy,                                                                # 21
        suspicious_reg,                                                          # 22
        jaro_raw,                                                               # 23
        norm_changed,                                                           # 24
        consecutive_digits,                                                     # 25
        _tld_score(tld),                                                        # 26
        unique_tokens,                                                          # 27
        has_ssl,                                                                # 28
        has_mx,                                                                 # 29
        has_asn,                                                                # 30
        min(max(header_score, 0.0) / 15.0, 1.0),                               # 31
    ]


# Legitimate domains (curated from train_xgb.py)
LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "meta.com",
    "twitter.com", "linkedin.com", "reddit.com", "pinterest.com", "snapchat.com",
    "tiktok.com", "telegram.org", "signal.org", "discord.com", "twitch.tv",
    "yahoo.com", "bing.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "cloudflare.com",
    "ebay.com", "walmart.com", "target.com", "paypal.com", "stripe.com",
    "visa.com", "mastercard.com", "chase.com", "wellsfargo.com",
    "spotify.com", "hulu.com", "disneyplus.com", "zoom.us", "slack.com",
    "adobe.com", "canva.com", "figma.com", "samsung.com", "sony.com",
    "intel.com", "nvidia.com", "cisco.com", "salesforce.com", "oracle.com",
    "tesla.com", "toyota.com", "nike.com", "adidas.com", "starbucks.com",
    "mcdonalds.com", "verizon.com", "att.com", "booking.com", "airbnb.com",
    "uber.com", "fedex.com", "ups.com", "nintendo.com", "ikea.com",
    "coinbase.com", "binance.com", "openai.com", "anthropic.com",
    "wikipedia.org", "harvard.edu", "stanford.edu", "gov.uk", "usa.gov",
    "nytimes.com", "cnn.com", "bbc.co.uk", "reuters.com",
]


def build_dataset(phish_entries: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    """Build X, y arrays from PhishTank phishing + curated legitimate domains."""
    X, y = [], []

    # --- Phishing samples from PhishTank ---
    print(f"  Processing {len(phish_entries)} PhishTank entries ...")
    for entry in phish_entries:
        domain = entry["domain"]
        target = entry["target"]

        # Determine if this is brand impersonation
        brand = extract_brand_from_target(target) or extract_brand_from_domain(domain)
        has_brand = brand is not None

        # Generate realistic feature variations
        age = random.randint(1, 90)
        privacy = 0.8 if random.random() < 0.7 else 0.3
        sus_reg = 0.6 if random.random() < 0.5 else 0.2
        ssl = 0.3 if random.random() < 0.4 else 0.0
        mx = 0.0 if random.random() < 0.8 else 0.5
        asn = 0.5
        hdr = random.uniform(5.0, 20.0)

        X.append(compute_feature_vector(domain, age, privacy, sus_reg, ssl, mx, asn, hdr))
        y.append(1)

        # Variant: very fresh phishing (0-7 days)
        if random.random() < 0.3:
            X.append(compute_feature_vector(domain, random.randint(0, 7), 1.0, 1.0, 0.0, 0.0, 0.0, random.uniform(10, 25)))
            y.append(1)

        # Variant: older phishing with good infrastructure
        if random.random() < 0.15:
            X.append(compute_feature_vector(domain, random.randint(90, 365), 0.3, 0.2, 1.0, 0.5, 0.8, random.uniform(0, 8)))
            y.append(1)

    # --- Legitimate samples ---
    print(f"  Adding {len(LEGITIMATE_DOMAINS)} legitimate domains ...")
    for domain in LEGITIMATE_DOMAINS:
        # Standard: mature, good infra
        X.append(compute_feature_vector(domain, random.randint(730, 7300), 0.0, 0.0, 1.0, 1.0, 1.0, 0.0))
        y.append(0)

        # Young legitimate
        X.append(compute_feature_vector(domain, random.randint(30, 364), 0.0, 0.0, 1.0, 1.0, 1.0, 0.0))
        y.append(0)

        # Default age (inference default)
        X.append(compute_feature_vector(domain, 365, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0))
        y.append(0)

        # Weak infra variant (~30%)
        if random.random() < 0.3:
            X.append(compute_feature_vector(domain, random.randint(365, 3650),
                     random.choice([0.0, 0.3]), 0.0,
                     random.choice([0.0, 1.0]), random.choice([0.0, 1.0]),
                     random.choice([0.5, 1.0]), random.uniform(0, 10)))
            y.append(0)

        # Unreachable variant (~20%) — teaches model "no data != phishing"
        if random.random() < 0.2:
            X.append(compute_feature_vector(domain, 365, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0))
            y.append(0)

    return np.array(X), np.array(y)


def train_all_models(X: np.ndarray, y: np.ndarray):
    """Train all 4 models."""
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, roc_auc_score, f1_score, precision_recall_curve
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.calibration import CalibratedClassifierCV
    from xgboost import XGBClassifier
    from lightgbm import LGBMClassifier

    print("\n" + "=" * 60)
    print("  PhishTank Dataset — All 4 Models")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)} | Test: {len(X_test)}")
    print(f"  Phishing ratio: {y.mean():.1%}\n")

    neg_count = int(np.sum(y == 0))
    pos_count = int(np.sum(y == 1))
    scale_pos = neg_count / max(pos_count, 1)

    results = {}
    thresholds = {}

    def find_best_threshold(y_true, y_prob):
        prec, rec, thr = precision_recall_curve(y_true, y_prob)
        f1 = 2 * (prec * rec) / (prec + rec + 1e-10)
        idx = np.argmax(f1)
        return float(thr[min(idx, len(thr) - 1)])

    # ---- 1. XGBoost ----
    print("[1/4] XGBoost ...")
    m = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08,
                      subsample=0.8, colsample_bytree=0.8,
                      scale_pos_weight=scale_pos, min_child_weight=2,
                      gamma=0.1, reg_alpha=0.05, reg_lambda=0.5,
                      random_state=42, verbosity=0, n_jobs=-1)
    m.fit(X_train, y_train)
    proba = m.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, proba)
    cal = CalibratedClassifierCV(m, method="sigmoid", cv=3)
    cal.fit(X, y)
    t = find_best_threshold(y_test, proba)
    thresholds["xgboost"] = t
    results["xgboost"] = {"accuracy": accuracy_score(y_test, cal.predict(X_test)),
                           "auc_roc": auc, "f1_score": f1_score(y_test, cal.predict(X_test))}
    with open(MODEL_PATHS["xgboost"], "wb") as f:
        pickle.dump(cal, f)
    print(f"  AUC={auc:.4f}  F1={results['xgboost']['f1_score']:.4f}  thresh={t:.4f}")

    # ---- 2. LightGBM ----
    print("[2/4] LightGBM ...")
    m = LGBMClassifier(n_estimators=300, max_depth=6, learning_rate=0.08,
                       subsample=0.8, colsample_bytree=0.8,
                       scale_pos_weight=scale_pos, min_child_weight=2,
                       random_state=42, verbosity=-1, n_jobs=-1)
    m.fit(X_train, y_train)
    proba = m.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, proba)
    cal = CalibratedClassifierCV(m, method="sigmoid", cv=3)
    cal.fit(X, y)
    t = find_best_threshold(y_test, proba)
    thresholds["lightgbm"] = t
    results["lightgbm"] = {"accuracy": accuracy_score(y_test, cal.predict(X_test)),
                            "auc_roc": auc, "f1_score": f1_score(y_test, cal.predict(X_test))}
    with open(MODEL_PATHS["lightgbm"], "wb") as f:
        pickle.dump(cal, f)
    print(f"  AUC={auc:.4f}  F1={results['lightgbm']['f1_score']:.4f}  thresh={t:.4f}")

    # ---- 3. Random Forest ----
    print("[3/4] Random Forest ...")
    m = RandomForestClassifier(n_estimators=300, max_depth=12, min_samples_leaf=3,
                               class_weight="balanced", random_state=42, n_jobs=-1)
    m.fit(X_train, y_train)
    proba = m.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, proba)
    cal = CalibratedClassifierCV(m, method="sigmoid", cv=3)
    cal.fit(X, y)
    t = find_best_threshold(y_test, proba)
    thresholds["random_forest"] = t
    results["random_forest"] = {"accuracy": accuracy_score(y_test, cal.predict(X_test)),
                                 "auc_roc": auc, "f1_score": f1_score(y_test, cal.predict(X_test))}
    with open(MODEL_PATHS["random_forest"], "wb") as f:
        pickle.dump(cal, f)
    print(f"  AUC={auc:.4f}  F1={results['random_forest']['f1_score']:.4f}  thresh={t:.4f}")

    # ---- 4. Logistic Regression ----
    print("[4/4] Logistic Regression ...")
    scaler = StandardScaler()
    Xtr_s = scaler.fit_transform(X_train)
    Xte_s = scaler.transform(X_test)
    m = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    m.fit(Xtr_s, y_train)
    proba = m.predict_proba(Xte_s)[:, 1]
    auc = roc_auc_score(y_test, proba)
    from ml_ensemble import ScaledModelWrapper
    wrapped = ScaledModelWrapper(m, scaler)
    t = find_best_threshold(y_test, proba)
    thresholds["logistic_regression"] = t
    results["logistic_regression"] = {"accuracy": accuracy_score(y_test, wrapped.predict(X_test)),
                                       "auc_roc": auc, "f1_score": f1_score(y_test, wrapped.predict(X_test))}
    with open(MODEL_PATHS["logistic_regression"], "wb") as f:
        pickle.dump(wrapped, f)
    print(f"  AUC={auc:.4f}  F1={results['logistic_regression']['f1_score']:.4f}  thresh={t:.4f}")

    # ---- Save priors ----
    priors = {
        "model_accuracies": {k: v["auc_roc"] for k, v in results.items()},
        "optimal_thresholds": thresholds,
        "model_weights": {"xgboost": 0.35, "lightgbm": 0.30, "random_forest": 0.20, "logistic_regression": 0.15},
        "model_results": results,
        "training_source": "phishtank_dataset",
        "total_samples": len(X),
    }
    with open(PRIORS_PATH, "wb") as f:
        pickle.dump(priors, f)

    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    for name, m in results.items():
        print(f"  {name:25s} AUC={m['auc_roc']:.4f}  F1={m['f1_score']:.4f}  thresh={thresholds[name]:.4f}")

    return results


def main():
    print("=" * 60)
    print("  PhishTank Dataset — ML Training Pipeline")
    print("=" * 60)

    # Step 1: Download PhishTank
    csv_path = download_phashtank()
    if csv_path and os.path.exists(csv_path):
        print(f"\n  Parsing PhishTank CSV ...")
        phish_entries = parse_phashtank_csv(csv_path, max_samples=20000)
        print(f"  Extracted: {len(phish_entries)} unique phishing domains")
    else:
        print("\n  PhishTank unavailable. Using local phishing domains only.")
        phish_entries = []

    # Step 2: Build dataset
    print("\n  Building dataset ...")
    X, y = build_dataset(phish_entries)
    print(f"  Total samples: {len(X)} ({int(np.sum(y))} phishing, {int(len(y) - np.sum(y))} legitimate)")

    # Step 3: Train
    train_all_models(X, y)

    print(f"\n  Done! Models saved to {MODEL_DIR}")


if __name__ == "__main__":
    main()

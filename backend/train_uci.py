"""
Train all 4 ML models using the UCI Phishing Websites Dataset.

The UCI dataset has 30 features (values: -1=phishing, 0=suspicious, 1=legitimate).
This script maps them to our 32-feature format and trains:
  - XGBoost
  - LightGBM
  - Random Forest
  - Logistic Regression
  - Ensemble priors

Dataset: 11,059 samples (real phishing websites + legitimate websites)
Source:  https://archive.ics.uci.edu/dataset/327/phishing+websites
"""

from __future__ import annotations

import csv
import io
import os
import pickle
import random
import sys
import urllib.request
import warnings
import zipfile

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
REPORT_PATH = os.path.join(MODEL_DIR, "uci_training_report.json")

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/327/phishing+websites.zip"
UCI_ARFF_NAME = "Training Dataset.arff"

# ============================================================
# UCI feature names (30 features, in ARFF order)
# ============================================================
UCI_FEATURES = [
    "having_IP_Address", "URL_Length", "Shortining_Service",
    "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
    "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
    "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor",
    "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
    "Google_Index", "Links_pointing_to_page", "Statistical_report",
]

# ============================================================
# Mapping: UCI 30 features -> our 32 features
# Our features (indices):
#   0:  domain_length_norm      -> approximate from URL_Length
#   1:  digit_ratio             -> 0.5 neutral (UCI has no direct equiv)
#   2:  hyphen_count_norm       -> 0.5 neutral
#   3:  subdomain_depth         -> from having_Sub_Domain
#   4:  shannon_entropy         -> 0.5 neutral
#   5:  consonant_ratio         -> 0.5 neutral
#   6:  suspicious_tld          -> from Prefix_Suffix (captures TLD tricks)
#   7:  has_brand_keywords      -> from Statistical_report (heuristic overlap)
#   8:  is_ip_like              -> from having_IP_Address
#   9:  excessive_hyphens       -> 0.5 neutral
#   10: jaro_winkler_score      -> from Shortining_Service (similarity proxy)
#   11: levenshtein_score       -> 0.5 neutral
#   12: edit_distance_norm      -> 0.5 neutral
#   13: typosquatting_detected  -> from Prefix_Suffix + URL_Length combo
#   14: homoglyph_detected      -> 0 (not in UCI)
#   15: homoglyph_count_norm    -> 0
#   16: digit_substitution      -> 0
#   17: combosquatting_detected -> from Prefix_Suffix
#   18: brand_only              -> 0
#   19: keyword_count_norm      -> 0
#   20: domain_age_log          -> from age_of_domain
#   21: whois_privacy           -> 0.5 neutral
#   22: suspicious_registrar    -> 0
#   23: jaro_unnormalized       -> from Shortining_Service
#   24: norm_changed            -> 0
#   25: max_consecutive_digits  -> 0
#   26: tld_risk_score          -> from Prefix_Suffix + URL_Length
#   27: unique_token_count_norm -> 0
#   28: ssl_valid               -> from SSLfinal_State
#   29: mx_present              -> from DNSRecord
#   30: asn_available           -> from DNSRecord
#   31: header_deficit          -> from On_Mouseover + RightClick + PopupWindow
# ============================================================

FEATURE_COUNT = 32


def download_uci_dataset() -> str:
    """Download and extract the UCI Phishing dataset, return ARFF path."""
    arff_path = os.path.join(MODEL_DIR, "uci_phishing.arff")
    if os.path.exists(arff_path):
        print(f"  Using cached: {arff_path}")
        return arff_path

    zip_path = os.path.join(MODEL_DIR, "uci_phishing.zip")
    if not os.path.exists(zip_path):
        print(f"  Downloading from {UCI_ZIP_URL} ...")
        req = urllib.request.Request(UCI_ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30)
        data = resp.read()
        with open(zip_path, "wb") as f:
            f.write(data)
        print(f"  Downloaded: {len(data)} bytes")

    print("  Extracting ARFF file ...")
    with zipfile.ZipFile(zip_path, "r") as z:
        for name in z.namelist():
            if name.endswith(".arff") and "old" not in name.lower():
                with z.open(name) as src, open(arff_path, "wb") as dst:
                    dst.write(src.read())
                break

    size = os.path.getsize(arff_path)
    print(f"  Extracted: {arff_path} ({size} bytes)")
    return arff_path


def parse_arff(filepath: str) -> tuple[list[list[float]], list[int]]:
    """Parse ARFF file and return X (feature matrix) and y (labels)."""
    X, y = [], []
    with open(filepath, "r") as f:
        in_data = False
        for line in f:
            line = line.strip()
            if line.lower() == "@data":
                in_data = True
                continue
            if not in_data or not line or line.startswith("@"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 31:
                continue
            try:
                features = [float(p) for p in parts[:30]]
                label = int(parts[30])
                # UCI labels: -1 = phishing, 1 = legitimate
                # Convert to: 0 = legitimate, 1 = phishing
                y_val = 1 if label == -1 else 0
                X.append(features)
                y.append(y_val)
            except (ValueError, IndexError):
                continue
    return X, y


def map_uci_to_our_features(uci_row: list[float]) -> list[float]:
    """
    Map 30 UCI features to our 32-feature format.

    UCI values: -1 (phishing), 0 (suspicious), 1 (legitimate)
    Our values: 0.0-1.0 continuous
    """
    # Normalize UCI: -1 -> 0.0, 0 -> 0.5, 1 -> 1.0
    def norm(val):
        return (val + 1.0) / 2.0

    ip = uci_row[0]         # having_IP_Address: -1 or 1
    url_len = uci_row[1]    # URL_Length: -1, 0, 1
    shortener = uci_row[2]  # Shortining_Service: -1 or 1
    at_symbol = uci_row[3]  # having_At_Symbol: -1 or 1
    double_slash = uci_row[4]  # double_slash_redirecting: -1 or 1
    prefix_suffix = uci_row[5] # Prefix_Suffix: -1 or 1
    subdomain = uci_row[6]  # having_Sub_Domain: -1, 0, 1
    ssl = uci_row[7]        # SSLfinal_State: -1, 0, 1
    domain_reg = uci_row[8] # Domain_registeration_length: -1 or 1
    favicon = uci_row[9]    # Favicon: -1 or 1
    port = uci_row[10]      # port: -1 or 1
    https_token = uci_row[11] # HTTPS_token: -1 or 1
    request_url = uci_row[12] # Request_URL: -1 or 1
    url_anchor = uci_row[13]  # URL_of_Anchor: -1, 0, 1
    links_tags = uci_row[14]  # Links_in_tags: -1, 0, 1
    sfh = uci_row[15]         # SFH: -1, 0, 1
    submit_email = uci_row[16] # Submitting_to_email: -1 or 1
    abnormal_url = uci_row[17] # Abnormal_URL: -1 or 1
    redirect = uci_row[18]     # Redirect: 0 or 1
    mouseover = uci_row[19]    # on_mouseover: -1 or 1
    rightclick = uci_row[20]   # RightClick: -1 or 1
    popup = uci_row[21]        # popUpWidnow: -1 or 1
    iframe = uci_row[22]       # Iframe: -1 or 1
    age = uci_row[23]          # age_of_domain: -1 or 1
    dns = uci_row[24]          # DNSRecord: -1 or 1
    traffic = uci_row[25]      # web_traffic: -1, 0, 1
    pagerank = uci_row[26]     # Page_Rank: -1 or 1
    google_idx = uci_row[27]   # Google_Index: -1 or 1
    links_page = uci_row[28]   # Links_pointing_to_page: -1, 0, 1
    stat_report = uci_row[29]  # Statistical_report: -1 or 1

    our_row = [0.0] * FEATURE_COUNT

    # 0: domain_length_norm — approximate from URL_Length
    # URL_Length: -1=long(phishing), 0=medium, 1=short(legit)
    our_row[0] = norm(url_len)  # short=1.0, long=0.0

    # 1: digit_ratio — no direct UCI equiv, use 0.5 neutral
    our_row[1] = 0.5

    # 2: hyphen_count_norm — approximate from double_slash_redirecting
    our_row[2] = norm(double_slash) * 0.3  # low weight

    # 3: subdomain_depth — from having_Sub_Domain
    our_row[3] = norm(subdomain)

    # 4: shannon_entropy — approximate from URL_Length + Shortining_Service
    entropy_proxy = (norm(url_len) + norm(shortener)) / 2.0
    our_row[4] = entropy_proxy

    # 5: consonant_ratio — no direct equiv
    our_row[5] = 0.5

    # 6: suspicious_tld — from Prefix_Suffix (hyphen in domain = suspicious)
    our_row[6] = 1.0 if prefix_suffix == -1 else 0.0

    # 7: has_brand_keywords — from Statistical_report + Google_Index
    our_row[7] = 1.0 if (stat_report == -1 or google_idx == -1) else 0.0

    # 8: is_ip_like — from having_IP_Address
    our_row[8] = 1.0 if ip == -1 else 0.0

    # 9: excessive_hyphens — from Prefix_Suffix + double_slash
    our_row[9] = 1.0 if (prefix_suffix == -1 and url_len == -1) else 0.0

    # 10: jaro_winkler_score — from Shortining_Service (URL shorteners change similarity)
    our_row[10] = 1.0 if shortener == -1 else 0.5

    # 11: levenshtein_score — approximate from URL_Length
    our_row[11] = norm(url_len) * 0.8

    # 12: edit_distance_norm — from Shortining_Service + Prefix_Suffix
    our_row[12] = (1.0 - norm(shortener)) * 0.5 + (1.0 - norm(prefix_suffix)) * 0.5

    # 13: typosquatting_detected — from Prefix_Suffix + URL_Length
    our_row[13] = 1.0 if (prefix_suffix == -1 and url_len <= 0) else 0.0

    # 14-16: homoglyph features — not in UCI
    our_row[14] = 0.0
    our_row[15] = 0.0
    our_row[16] = 0.0

    # 17: combosquatting_detected — from Prefix_Suffix + abnormal_url
    our_row[17] = 1.0 if (prefix_suffix == -1 and abnormal_url == -1) else 0.0

    # 18-19: brand-only features — not in UCI
    our_row[18] = 0.0
    our_row[19] = 0.0

    # 20: domain_age_log — from age_of_domain
    our_row[20] = norm(age)

    # 21: whois_privacy — from Domain_registeration_length
    our_row[21] = 1.0 if domain_reg == -1 else 0.0

    # 22: suspicious_registrar — from Domain_registeration_length
    our_row[22] = 1.0 if domain_reg == -1 else 0.0

    # 23: jaro_unnormalized — from Shortining_Service
    our_row[23] = 1.0 if shortener == -1 else 0.5

    # 24: norm_changed — 0
    our_row[24] = 0.0

    # 25: max_consecutive_digits — 0
    our_row[25] = 0.0

    # 26: tld_risk_score — from Prefix_Suffix + URL_Length
    if prefix_suffix == -1 and url_len == -1:
        our_row[26] = 0.8
    elif prefix_suffix == -1:
        our_row[26] = 0.5
    else:
        our_row[26] = 0.1

    # 27: unique_token_count_norm — 0
    our_row[27] = 0.0

    # 28: ssl_valid — from SSLfinal_State
    our_row[28] = norm(ssl)

    # 29: mx_present — from DNSRecord
    our_row[29] = norm(dns)

    # 30: asn_available — from DNSRecord + web_traffic
    our_row[30] = norm(dns) * 0.5 + norm(traffic) * 0.5

    # 31: header_deficit — from mouseover + rightclick + popup + iframe + sfh
    # Phishing sites: -1 on these (have suspicious behaviors)
    deficit_signals = sum(1 for s in [mouseover, rightclick, popup, iframe, sfh] if s == -1)
    our_row[31] = min(deficit_signals / 5.0, 1.0)

    return our_row


def train_all_models(X: np.ndarray, y: np.ndarray):
    """Train all 4 models with hyperparameter tuning."""
    from sklearn.model_selection import train_test_split, StratifiedKFold
    from sklearn.metrics import accuracy_score, roc_auc_score, f1_score, precision_score, recall_score
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.calibration import CalibratedClassifierCV
    from xgboost import XGBClassifier
    from lightgbm import LGBMClassifier

    print("\n" + "=" * 60)
    print("  UCI Dataset Training — All 4 Models")
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

    # ---- 1. XGBoost ----
    print("[1/4] XGBoost ...")
    xgb_model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=scale_pos, min_child_weight=2,
        gamma=0.1, reg_alpha=0.05, reg_lambda=0.5,
        random_state=42, verbosity=0, n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)
    xgb_proba = xgb_model.predict_proba(X_test)[:, 1]
    xgb_auc = roc_auc_score(y_test, xgb_proba)
    xgb_cal = CalibratedClassifierCV(xgb_model, method="sigmoid", cv=3)
    xgb_cal.fit(X, y)
    # Find optimal threshold
    from sklearn.metrics import precision_recall_curve
    precisions, recalls, threshs = precision_recall_curve(y_test, xgb_proba)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores)
    xgb_thresh = threshs[min(best_idx, len(threshs) - 1)]
    thresholds["xgboost"] = float(xgb_thresh)
    results["xgboost"] = {"accuracy": float(accuracy_score(y_test, xgb_cal.predict(X_test))),
                           "auc_roc": float(xgb_auc),
                           "f1_score": float(f1_score(y_test, xgb_cal.predict(X_test)))}
    with open(MODEL_PATHS["xgboost"], "wb") as f:
        pickle.dump(xgb_cal, f)
    print(f"  AUC={xgb_auc:.4f}  F1={results['xgboost']['f1_score']:.4f}  thresh={xgb_thresh:.4f}")

    # ---- 2. LightGBM ----
    print("[2/4] LightGBM ...")
    lgbm_model = LGBMClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.08,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=scale_pos, min_child_weight=2,
        random_state=42, verbosity=-1, n_jobs=-1,
    )
    lgbm_model.fit(X_train, y_train)
    lgbm_proba = lgbm_model.predict_proba(X_test)[:, 1]
    lgbm_auc = roc_auc_score(y_test, lgbm_proba)
    lgbm_cal = CalibratedClassifierCV(lgbm_model, method="sigmoid", cv=3)
    lgbm_cal.fit(X, y)
    precisions, recalls, threshs = precision_recall_curve(y_test, lgbm_proba)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores)
    lgbm_thresh = threshs[min(best_idx, len(threshs) - 1)]
    thresholds["lightgbm"] = float(lgbm_thresh)
    results["lightgbm"] = {"accuracy": float(accuracy_score(y_test, lgbm_cal.predict(X_test))),
                            "auc_roc": float(lgbm_auc),
                            "f1_score": float(f1_score(y_test, lgbm_cal.predict(X_test)))}
    with open(MODEL_PATHS["lightgbm"], "wb") as f:
        pickle.dump(lgbm_cal, f)
    print(f"  AUC={lgbm_auc:.4f}  F1={results['lightgbm']['f1_score']:.4f}  thresh={lgbm_thresh:.4f}")

    # ---- 3. Random Forest ----
    print("[3/4] Random Forest ...")
    rf_model = RandomForestClassifier(
        n_estimators=300, max_depth=12, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    rf_model.fit(X_train, y_train)
    rf_proba = rf_model.predict_proba(X_test)[:, 1]
    rf_auc = roc_auc_score(y_test, rf_proba)
    rf_cal = CalibratedClassifierCV(rf_model, method="sigmoid", cv=3)
    rf_cal.fit(X, y)
    precisions, recalls, threshs = precision_recall_curve(y_test, rf_proba)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores)
    rf_thresh = threshs[min(best_idx, len(threshs) - 1)]
    thresholds["random_forest"] = float(rf_thresh)
    results["random_forest"] = {"accuracy": float(accuracy_score(y_test, rf_cal.predict(X_test))),
                                 "auc_roc": float(rf_auc),
                                 "f1_score": float(f1_score(y_test, rf_cal.predict(X_test)))}
    with open(MODEL_PATHS["random_forest"], "wb") as f:
        pickle.dump(rf_cal, f)
    print(f"  AUC={rf_auc:.4f}  F1={results['random_forest']['f1_score']:.4f}  thresh={rf_thresh:.4f}")

    # ---- 4. Logistic Regression ----
    print("[4/4] Logistic Regression ...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    lr_model = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    lr_model.fit(X_train_s, y_train)
    lr_proba = lr_model.predict_proba(X_test_s)[:, 1]
    lr_auc = roc_auc_score(y_test, lr_proba)
    from ml_ensemble import ScaledModelWrapper
    lr_wrapped = ScaledModelWrapper(lr_model, scaler)
    precisions, recalls, threshs = precision_recall_curve(y_test, lr_proba)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores)
    lr_thresh = threshs[min(best_idx, len(threshs) - 1)]
    thresholds["logistic_regression"] = float(lr_thresh)
    results["logistic_regression"] = {"accuracy": float(accuracy_score(y_test, lr_wrapped.predict(X_test))),
                                       "auc_roc": float(lr_auc),
                                       "f1_score": float(f1_score(y_test, lr_wrapped.predict(X_test)))}
    with open(MODEL_PATHS["logistic_regression"], "wb") as f:
        pickle.dump(lr_wrapped, f)
    print(f"  AUC={lr_auc:.4f}  F1={results['logistic_regression']['f1_score']:.4f}  thresh={lr_thresh:.4f}")

    # ---- Save ensemble priors ----
    priors = {
        "model_accuracies": {k: v["auc_roc"] for k, v in results.items()},
        "optimal_thresholds": thresholds,
        "model_weights": {
            "xgboost": 0.35,
            "lightgbm": 0.30,
            "random_forest": 0.20,
            "logistic_regression": 0.15,
        },
        "model_results": results,
        "training_source": "uci_phishing_dataset",
        "total_samples": len(X),
    }
    with open(PRIORS_PATH, "wb") as f:
        pickle.dump(priors, f)
    print(f"\n  Ensemble priors -> {PRIORS_PATH}")

    # ---- Summary ----
    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    for name, m in results.items():
        print(f"  {name:25s} AUC={m['auc_roc']:.4f}  F1={m['f1_score']:.4f}  thresh={thresholds[name]:.4f}")

    return results


def main():
    print("=" * 60)
    print("  UCI Phishing Dataset — ML Training Pipeline")
    print("=" * 60)

    # Step 1: Download and parse
    arff_path = download_uci_dataset()
    print("\n  Parsing ARFF ...")
    X_raw, y = parse_arff(arff_path)
    print(f"  Parsed: {len(X_raw)} samples ({sum(y)} phishing, {len(y) - sum(y)} legitimate)")

    # Step 2: Map to our 32-feature format
    print("  Mapping UCI features -> 32-feature format ...")
    X = np.array([map_uci_to_our_features(row) for row in X_raw])
    print(f"  Feature matrix: {X.shape}")

    # Step 3: Train
    results = train_all_models(X, np.array(y))

    print(f"\n  Done! Models saved to {MODEL_DIR}")


if __name__ == "__main__":
    main()

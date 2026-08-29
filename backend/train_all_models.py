"""
Retrain ALL 4 ML models using the high-quality phishing domain examples
from train_xgb.py. This produces:
  - xgb_model.pkl
  - lgbm_model.pkl
  - rf_model.pkl
  - lr_model.pkl
  - ensemble_priors.pkl
"""

import os
import pickle
import random
import sys
import warnings

import numpy as np

warnings.filterwarnings("ignore")

# Import the phishing training data from train_xgb.py
from train_xgb import LEGITIMATE_DOMAINS, PHISHING_DOMAINS, feature_vector_for
from main import clean_domain

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))


def build_dataset():
    """Build X, y arrays from the same domain lists used in train_xgb.py."""
    x, y = [], []

    # Legitimate domains — label 0
    for domain in LEGITIMATE_DOMAINS:
        x.append(feature_vector_for(domain, random.randint(365, 3650), 0.0, 0.0,
                                    has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        y.append(0)

    # Phishing domains — label 1
    for domain in PHISHING_DOMAINS:
        age = random.randint(0, 60)
        privacy = random.choice([0.0, 1.0])
        has_ssl = random.choice([0.0, 0.0, 0.0, 1.0])
        has_mx = random.choice([0.0, 0.0, 1.0])
        has_asn = random.choice([0.0, 0.5, 1.0])
        header = random.uniform(5.0, 15.0)
        x.append(feature_vector_for(domain, age, privacy, 0.0,
                                    has_ssl=has_ssl, has_mx=has_mx, has_asn=has_asn, header_score=header))
        y.append(1)

    # Augmented variants for better generalization
    brands = ["paypal", "google", "facebook", "amazon", "microsoft", "apple", "netflix"]
    suffixes = ["-login", "-verify", "-secure", "-account", "-update", "-check"]
    tlds = [".xyz", ".top", ".click", ".work", ".live", ".loan", ".tk", ".cc"]
    for _ in range(500):
        brand = random.choice(brands)
        suffix = random.choice(suffixes)
        tld = random.choice(tlds)
        domain = f"{brand}{suffix}{tld}"
        x.append(feature_vector_for(domain, random.randint(0, 30), 1.0, 0.0,
                                    has_ssl=random.choice([0.0, 1.0]), has_mx=0.0,
                                    has_asn=random.choice([0.0, 0.5]),
                                    header_score=random.uniform(8.0, 15.0)))
        y.append(1)

    # Add some legitimate domains with suspicious TLDs (to avoid over-indexing on TLD)
    legit_tlds = ["genius.xyz", "abc.xyz", "microsoft.azure", "google.cloud",
                   "gov.uk", "bbc.co.uk", "harvard.edu"]
    for domain in legit_tlds:
        x.append(feature_vector_for(domain, 3650, 0.0, 0.0,
                                    has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        y.append(0)

    return np.array(x), np.array(y)


def train_all():
    from sklearn.model_selection import train_test_split, StratifiedKFold
    from sklearn.metrics import accuracy_score, roc_auc_score
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.calibration import CalibratedClassifierCV
    from xgboost import XGBClassifier
    from lightgbm import LGBMClassifier

    print("=" * 60)
    print("TMGC — Training ALL 4 ML Models")
    print("=" * 60)

    X, y = build_dataset()
    print(f"\nDataset: {len(X)} samples ({int(np.sum(y == 0))} legit, {int(np.sum(y == 1))} phishing)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Split:   {len(X_train)} train / {len(X_test)} test\n")

    neg_count = int(np.sum(y == 0))
    pos_count = int(np.sum(y == 1))
    scale_pos = neg_count / max(pos_count, 1)

    results = {}

    # ---- 1. XGBoost ----
    print("[1/4] XGBoost ...")
    xgb_model = XGBClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.06,
        subsample=0.80, colsample_bytree=0.80,
        scale_pos_weight=scale_pos, min_child_weight=2,
        gamma=0.1, reg_alpha=0.05, reg_lambda=0.5,
        random_state=42, verbosity=0, n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)
    xgb_proba = xgb_model.predict_proba(X_test)[:, 1]
    xgb_auc = roc_auc_score(y_test, xgb_proba)
    # Calibrate
    xgb_calibrated = CalibratedClassifierCV(xgb_model, method='sigmoid', cv=3)
    xgb_calibrated.fit(X, y)
    path = os.path.join(MODEL_DIR, "xgb_model.pkl")
    with open(path, "wb") as f:
        pickle.dump(xgb_calibrated, f)
    results["xgboost"] = xgb_auc
    print(f"  AUC={xgb_auc:.4f}  Saved -> {path}")

    # ---- 2. LightGBM ----
    print("[2/4] LightGBM ...")
    lgbm_model = LGBMClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.06,
        subsample=0.80, colsample_bytree=0.80,
        scale_pos_weight=scale_pos, min_child_weight=2,
        random_state=42, verbosity=-1, n_jobs=-1,
    )
    lgbm_model.fit(X_train, y_train)
    lgbm_proba = lgbm_model.predict_proba(X_test)[:, 1]
    lgbm_auc = roc_auc_score(y_test, lgbm_proba)
    lgbm_calibrated = CalibratedClassifierCV(lgbm_model, method='sigmoid', cv=3)
    lgbm_calibrated.fit(X, y)
    path = os.path.join(MODEL_DIR, "lgbm_model.pkl")
    with open(path, "wb") as f:
        pickle.dump(lgbm_calibrated, f)
    results["lightgbm"] = lgbm_auc
    print(f"  AUC={lgbm_auc:.4f}  Saved -> {path}")

    # ---- 3. Random Forest ----
    print("[3/4] Random Forest ...")
    rf_model = RandomForestClassifier(
        n_estimators=300, max_depth=12, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    rf_model.fit(X_train, y_train)
    rf_proba = rf_model.predict_proba(X_test)[:, 1]
    rf_auc = roc_auc_score(y_test, rf_proba)
    rf_calibrated = CalibratedClassifierCV(rf_model, method='sigmoid', cv=3)
    rf_calibrated.fit(X, y)
    path = os.path.join(MODEL_DIR, "rf_model.pkl")
    with open(path, "wb") as f:
        pickle.dump(rf_calibrated, f)
    results["random_forest"] = rf_auc
    print(f"  AUC={rf_auc:.4f}  Saved -> {path}")

    # ---- 4. Logistic Regression (needs scaling) ----
    print("[4/4] Logistic Regression ...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    lr_model = LogisticRegression(
        C=1.0, class_weight="balanced", max_iter=1000, random_state=42
    )
    lr_model.fit(X_train_scaled, y_train)
    lr_proba = lr_model.predict_proba(X_test_scaled)[:, 1]
    lr_auc = roc_auc_score(y_test, lr_proba)
    from ml_ensemble import ScaledModelWrapper
    lr_wrapped = ScaledModelWrapper(lr_model, scaler)
    path = os.path.join(MODEL_DIR, "lr_model.pkl")
    with open(path, "wb") as f:
        pickle.dump(lr_wrapped, f)
    results["logistic_regression"] = lr_auc
    print(f"  AUC={lr_auc:.4f}  Saved -> {path}")

    # ---- Ensemble priors ----
    priors = {
        "model_accuracies": results,
        "optimal_thresholds": {
            "xgboost": 0.70,
            "lightgbm": 0.70,
            "random_forest": 0.70,
            "logistic_regression": 0.70,
            "ensemble": 0.50,
        },
        "model_weights": {
            "xgboost": 0.35,
            "lightgbm": 0.30,
            "random_forest": 0.20,
            "logistic_regression": 0.15,
        },
    }
    priors_path = os.path.join(MODEL_DIR, "ensemble_priors.pkl")
    with open(priors_path, "wb") as f:
        pickle.dump(priors, f)
    print(f"\nEnsemble priors -> {priors_path}")

    print("\n" + "=" * 60)
    print("All models trained and saved!")
    for name, auc in results.items():
        print(f"  {name:25s} AUC = {auc:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    train_all()

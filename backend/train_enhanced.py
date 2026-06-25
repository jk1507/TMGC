"""
Enhanced ML Training Script — Train all ensemble models for phishing detection.

Trains:
  - XGBoost (primary model)
  - LightGBM
  - Random Forest
  - Logistic Regression
  - Ensemble priors

Usage:
    python train_enhanced.py

Requirements:
    pip install xgboost lightgbm scikit-learn numpy pandas joblib
"""

import json
import os
import pickle
import random
import sys
import warnings
from typing import Any

import numpy as np

warnings.filterwarnings("ignore")

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

# Feature count (must match get_ml_prediction in main.py)
FEATURE_COUNT = 32

# Training data parameters
TRAINING_SAMPLES = 10000
TEST_SPLIT = 0.2
RANDOM_SEED = 42


def generate_training_data(n_samples: int = 10000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data for phishing detection models.
    
    Features (32 total, matching main.py feature vector):
      0:  Normalized domain length
      1:  Digit ratio
      2:  Hyphen count (normalized)
      3:  Subdomain depth
      4:  Shannon entropy
      5:  Consonant ratio
      6:  Suspicious TLD
      7:  Has brand keywords
      8:  IP-like
      9:  Excessive hyphens
      10: Jaro-Winkler score (normalized)
      11: Levenshtein score (normalized)
      12: Edit distance (normalized)
      13: Typosquatting detected
      14: Homoglyph detected
      15: Homoglyph count
      16: Digit substitution
      17: Combosquatting detected
      18: Brand only
      19: Keyword count
      20: Domain age (log)
      21: WHOIS privacy
      22: Suspicious registrar
      23: Jaro-Winkler (unnormalized label)
      24: Normalization changed label
      25: Max consecutive digits
      26: TLD risk score
      27: Unique normalized tokens
      28: SSL valid
      29: MX present
      30: ASN available
      31: Header security deficit
    
    Labels:
      0 = legitimate, 1 = phishing
    """
    np.random.seed(RANDOM_SEED)
    random.seed(RANDOM_SEED)
    
    X = np.zeros((n_samples, FEATURE_COUNT), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.int32)
    
    for i in range(n_samples):
        # Generate random feature vector with realistic distributions
        
        # Base features — most domains are legitimate
        is_phishing = np.random.random() < 0.30  # 30% phishing in training
        
        # Feature 0: Domain length (normalized)
        if is_phishing:
            # Phishing domains tend to be longer
            X[i, 0] = np.random.uniform(0.15, 0.9)
        else:
            X[i, 0] = np.random.uniform(0.05, 0.6)
        
        # Feature 1: Digit ratio
        if is_phishing:
            X[i, 1] = np.random.uniform(0.0, 0.6)
        else:
            X[i, 1] = np.random.uniform(0.0, 0.25)
        
        # Feature 2: Hyphen count
        if is_phishing:
            X[i, 2] = np.random.uniform(0.0, 0.8)
        else:
            X[i, 2] = np.random.uniform(0.0, 0.2)
        
        # Feature 3: Subdomain depth
        if is_phishing:
            X[i, 3] = np.random.uniform(0.0, 0.6)
        else:
            X[i, 3] = np.random.uniform(0.0, 0.4)
        
        # Feature 4: Shannon entropy
        if is_phishing:
            X[i, 4] = np.random.uniform(0.2, 1.0)
        else:
            X[i, 4] = np.random.uniform(0.1, 0.8)
        
        # Feature 5: Consonant ratio
        if is_phishing:
            X[i, 5] = np.random.uniform(0.3, 1.0)
        else:
            X[i, 5] = np.random.uniform(0.3, 0.8)
        
        # Feature 6: Suspicious TLD
        if is_phishing:
            X[i, 6] = np.random.choice([0.0, 1.0], p=[0.6, 0.4])
        else:
            X[i, 6] = np.random.choice([0.0, 1.0], p=[0.95, 0.05])
        
        # Feature 7: Has brand keywords
        if is_phishing:
            X[i, 7] = np.random.choice([0.0, 1.0], p=[0.3, 0.7])
        else:
            X[i, 7] = np.random.choice([0.0, 1.0], p=[0.85, 0.15])
        
        # Feature 8: IP-like
        if is_phishing:
            X[i, 8] = np.random.choice([0.0, 1.0], p=[0.9, 0.1])
        else:
            X[i, 8] = np.random.choice([0.0, 1.0], p=[0.98, 0.02])
        
        # Feature 9: Excessive hyphens
        if is_phishing:
            X[i, 9] = np.random.choice([0.0, 1.0], p=[0.7, 0.3])
        else:
            X[i, 9] = np.random.choice([0.0, 1.0], p=[0.95, 0.05])
        
        # Feature 10: Jaro-Winkler score
        if is_phishing:
            X[i, 10] = np.random.uniform(0.5, 1.0)
        else:
            X[i, 10] = np.random.uniform(0.0, 0.6)
        
        # Feature 11: Levenshtein score
        if is_phishing:
            X[i, 11] = np.random.uniform(0.3, 1.0)
        else:
            X[i, 11] = np.random.uniform(0.0, 0.5)
        
        # Feature 12: Edit distance
        if is_phishing:
            X[i, 12] = np.random.uniform(0.1, 0.8)
        else:
            X[i, 12] = np.random.uniform(0.0, 0.3)
        
        # Feature 13: Typosquatting detected
        if is_phishing:
            X[i, 13] = np.random.choice([0.0, 1.0], p=[0.5, 0.5])
        else:
            X[i, 13] = np.random.choice([0.0, 1.0], p=[0.98, 0.02])
        
        # Feature 14: Homoglyph detected
        if is_phishing:
            X[i, 14] = np.random.choice([0.0, 1.0], p=[0.6, 0.4])
        else:
            X[i, 14] = np.random.choice([0.0, 1.0], p=[0.95, 0.05])
        
        # Feature 15: Homoglyph count
        if is_phishing and X[i, 14]:
            X[i, 15] = np.random.uniform(0.2, 1.0)
        
        # Feature 16: Digit substitution
        if is_phishing:
            X[i, 16] = np.random.choice([0.0, 1.0], p=[0.6, 0.4])
        else:
            X[i, 16] = np.random.choice([0.0, 1.0], p=[0.97, 0.03])
        
        # Feature 17: Combosquatting detected
        if is_phishing:
            X[i, 17] = np.random.choice([0.0, 1.0], p=[0.55, 0.45])
        else:
            X[i, 17] = np.random.choice([0.0, 1.0], p=[0.95, 0.05])
        
        # Feature 18: Brand only
        if is_phishing:
            X[i, 18] = np.random.choice([0.0, 1.0], p=[0.4, 0.6])
        else:
            X[i, 18] = np.random.choice([0.0, 1.0], p=[0.85, 0.15])
        
        # Feature 19: Keyword count
        if is_phishing:
            X[i, 19] = np.random.uniform(0.0, 1.0)
        else:
            X[i, 19] = np.random.uniform(0.0, 0.4)
        
        # Feature 20: Domain age (log)
        if is_phishing:
            X[i, 20] = np.random.uniform(0.0, 0.5)
        else:
            X[i, 20] = np.random.uniform(0.3, 1.0)
        
        # Feature 21: WHOIS privacy
        if is_phishing:
            X[i, 21] = np.random.choice([0.0, 1.0], p=[0.3, 0.7])
        else:
            X[i, 21] = np.random.choice([0.0, 1.0], p=[0.6, 0.4])
        
        # Feature 22: Suspicious registrar
        if is_phishing:
            X[i, 22] = np.random.choice([0.0, 1.0], p=[0.5, 0.5])
        else:
            X[i, 22] = np.random.choice([0.0, 1.0], p=[0.9, 0.1])
        
        # Features 23-27: Enhanced phishing signals
        if is_phishing:
            X[i, 23] = np.random.uniform(0.4, 1.0)  # Jaro-Winkler unnormalized
            X[i, 24] = np.random.choice([0.0, 1.0], p=[0.6, 0.4])  # Normalization changed
            X[i, 25] = np.random.uniform(0.0, 0.8)  # Max consecutive digits
            X[i, 26] = np.random.uniform(0.4, 1.0)  # TLD risk score
            X[i, 27] = np.random.uniform(0.0, 0.8)  # Unique tokens
        else:
            X[i, 23] = np.random.uniform(0.0, 0.6)
            X[i, 24] = np.random.choice([0.0, 1.0], p=[0.9, 0.1])
            X[i, 25] = np.random.uniform(0.0, 0.4)
            X[i, 26] = np.random.uniform(0.0, 0.4)
            X[i, 27] = np.random.uniform(0.0, 0.5)
        
        # Features 28-31: Inference-time features
        if is_phishing:
            X[i, 28] = np.random.choice([0.0, 1.0], p=[0.5, 0.5])  # SSL valid
            X[i, 29] = np.random.choice([0.0, 1.0], p=[0.4, 0.6])  # MX present
            X[i, 30] = np.random.choice([0.0, 1.0], p=[0.4, 0.6])  # ASN available
            X[i, 31] = np.random.uniform(0.3, 1.0)  # Header deficit
        else:
            X[i, 28] = np.random.choice([0.0, 1.0], p=[0.1, 0.9])
            X[i, 29] = np.random.choice([0.0, 1.0], p=[0.05, 0.95])
            X[i, 30] = np.random.choice([0.0, 1.0], p=[0.05, 0.95])
            X[i, 31] = np.random.uniform(0.0, 0.5)
        
        y[i] = 1 if is_phishing else 0
    
    return X, y


def train_models() -> dict[str, Any]:
    """Train all ensemble models."""
    print("=" * 60)
    print("TMGC Enhanced ML Training")
    print("=" * 60)
    
    print(f"\nGenerating {TRAINING_SAMPLES} training samples...")
    X, y = generate_training_data(TRAINING_SAMPLES)
    
    # Split into train/test
    split = int(TRAINING_SAMPLES * (1 - TEST_SPLIT))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]
    
    print(f"Training samples: {split}")
    print(f"Test samples: {TRAINING_SAMPLES - split}")
    print(f"Phishing ratio: {y.mean():.1%}")
    
    results = {}
    
    # ======================================================================
    # XGBoost
    # ======================================================================
    print("\n[1/4] Training XGBoost...")
    try:
        import xgboost as xgb
        
        model_xgb = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=RANDOM_SEED,
            use_label_encoder=False,
            eval_metric="logloss",
        )
        model_xgb.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False,
        )
        
        train_score = model_xgb.score(X_train, y_train)
        test_score = model_xgb.score(X_test, y_test)
        
        print(f"  Train accuracy: {train_score:.3f}")
        print(f"  Test accuracy:  {test_score:.3f}")
        
        with open(MODEL_PATHS["xgboost"], "wb") as f:
            pickle.dump(model_xgb, f)
        print(f"  Saved to: {MODEL_PATHS['xgboost']}")
        
        results["xgboost"] = {
            "train_accuracy": round(float(train_score), 4),
            "test_accuracy": round(float(test_score), 4),
        }
    except ImportError:
        print("  ⚠ xgboost not installed. Skipping.")
    
    # ======================================================================
    # LightGBM
    # ======================================================================
    print("\n[2/4] Training LightGBM...")
    try:
        import lightgbm as lgb
        
        model_lgb = lgb.LGBMClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=RANDOM_SEED,
            verbose=-1,
        )
        model_lgb.fit(X_train, y_train)
        
        train_score = model_lgb.score(X_train, y_train)
        test_score = model_lgb.score(X_test, y_test)
        
        print(f"  Train accuracy: {train_score:.3f}")
        print(f"  Test accuracy:  {test_score:.3f}")
        
        with open(MODEL_PATHS["lightgbm"], "wb") as f:
            pickle.dump(model_lgb, f)
        print(f"  Saved to: {MODEL_PATHS['lightgbm']}")
        
        results["lightgbm"] = {
            "train_accuracy": round(float(train_score), 4),
            "test_accuracy": round(float(test_score), 4),
        }
    except ImportError:
        print("  ⚠ lightgbm not installed. Skipping.")
    
    # ======================================================================
    # Random Forest
    # ======================================================================
    print("\n[3/4] Training Random Forest...")
    try:
        from sklearn.ensemble import RandomForestClassifier
        
        model_rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        model_rf.fit(X_train, y_train)
        
        train_score = model_rf.score(X_train, y_train)
        test_score = model_rf.score(X_test, y_test)
        
        print(f"  Train accuracy: {train_score:.3f}")
        print(f"  Test accuracy:  {test_score:.3f}")
        
        with open(MODEL_PATHS["random_forest"], "wb") as f:
            pickle.dump(model_rf, f)
        print(f"  Saved to: {MODEL_PATHS['random_forest']}")
        
        results["random_forest"] = {
            "train_accuracy": round(float(train_score), 4),
            "test_accuracy": round(float(test_score), 4),
        }
    except ImportError:
        print("  ⚠ sklearn not installed. Skipping.")
    
    # ======================================================================
    # Logistic Regression
    # ======================================================================
    print("\n[4/4] Training Logistic Regression...")
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        model_lr = LogisticRegression(
            C=1.0,
            max_iter=1000,
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        model_lr.fit(X_train_scaled, y_train)
        
        train_score = model_lr.score(X_train_scaled, y_train)
        test_score = model_lr.score(X_test_scaled, y_test)
        
        print(f"  Train accuracy: {train_score:.3f}")
        print(f"  Test accuracy:  {test_score:.3f}")
        
        with open(MODEL_PATHS["logistic_regression"], "wb") as f:
            pickle.dump(model_lr, f)
        print(f"  Saved to: {MODEL_PATHS['logistic_regression']}")
        
        results["logistic_regression"] = {
            "train_accuracy": round(float(train_score), 4),
            "test_accuracy": round(float(test_score), 4),
        }
    except ImportError:
        print("  ⚠ sklearn not installed. Skipping.")
    
    # ======================================================================
    # Ensemble Priors
    # ======================================================================
    print("\nSaving ensemble priors...")
    priors = {
        "feature_count": FEATURE_COUNT,
        "training_samples": TRAINING_SAMPLES,
        "phishing_ratio": float(y.mean()),
        "feature_means": {f"f{i}": float(X[:, i].mean()) for i in range(FEATURE_COUNT)},
        "feature_stds": {f"f{i}": float(X[:, i].std()) for i in range(FEATURE_COUNT)},
        "model_results": results,
    }
    
    with open(PRIORS_PATH, "wb") as f:
        pickle.dump(priors, f)
    print(f"  Saved to: {PRIORS_PATH}")
    
    # ======================================================================
    # Summary
    # ======================================================================
    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)
    for model_name, model_results in results.items():
        print(f"  {model_name}:")
        print(f"    Train: {model_results['train_accuracy']:.3f}")
        print(f"    Test:  {model_results['test_accuracy']:.3f}")
    
    return results


if __name__ == "__main__":
    train_models()

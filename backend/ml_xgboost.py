import os
import pickle
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xgb_model.pkl")
PRIORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ensemble_priors.pkl")

def load_xgb():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


def _load_xgb_threshold(default: float = 0.70) -> float:
    try:
        if not os.path.exists(PRIORS_PATH):
            return default
        with open(PRIORS_PATH, "rb") as f:
            priors = pickle.load(f)
        threshold = (
            priors.get("optimal_thresholds", {}).get("xgboost")
            or priors.get("model_priors", {}).get("xgboost", {}).get("optimal_threshold")
        )
        if isinstance(threshold, (int, float)) and 0.05 <= float(threshold) <= 0.99:
            return float(threshold)
    except Exception:
        pass
    return default


def train_xgb(X, y):
    from xgboost import XGBClassifier
    from sklearn.model_selection import train_test_split, StratifiedKFold
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
    import numpy as np

    X = np.array(X)
    y = np.array(y)

    # Compute class balance for scale_pos_weight
    neg_count = int(np.sum(y == 0))
    pos_count = int(np.sum(y == 1))
    scale_pos = neg_count / max(pos_count, 1)
    print(f"Training data: {len(X)} samples, {neg_count} legitimate, {pos_count} phishing")
    print(f"Scale pos weight: {scale_pos:.2f}")

    # Stratified split to preserve class distribution
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train XGBoost with optimized hyperparameters
    # Using moderate tree count + higher learning rate for good signal learning
    # The improved feature engineering (28 features with better typosquatting detection)
    # provides the model with real signal it can learn from.
    model = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.06,
        subsample=0.80,
        colsample_bytree=0.80,
        colsample_bylevel=0.80,
        scale_pos_weight=scale_pos,
        min_child_weight=2,
        gamma=0.1,
        reg_alpha=0.05,
        reg_lambda=0.5,
        eval_metric=['logloss', 'error', 'auc'],
        early_stopping_rounds=50,
        random_state=42,
        verbosity=1,
        n_jobs=-1,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_train, y_train), (X_test, y_test)],
        verbose=False
    )

    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\nXGBoost Model Results:")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC AUC:   {auc:.4f}")
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    # Feature importance
    if hasattr(model, 'feature_importances_'):
        fi = model.feature_importances_
        print(f"\nFeature Importances:")
        feature_names = [
            "length", "digit_ratio", "hyphen_count", "subdomain_count", "entropy",
            "consonant_ratio", "suspicious_tld", "has_keywords", "is_ip_like",
            "excessive_hyphens", "jaro_winkler", "levenshtein", "edit_distance",
            "typosquatting", "homoglyph", "homoglyph_count", "digit_substitution",
            "combosquatting", "brand_only", "keyword_count", "age_log",
            "privacy", "suspicious_reg",
            "jaro_raw", "label_changed", "consecutive_digits", "tld_score", "unique_tokens",
            "has_valid_ssl",
            "has_mx",
            "has_asn",
            "header_score_norm",
        ]
        sorted_idx = np.argsort(fi)[::-1]
        for idx in sorted_idx[:10]:
            print(f"  [{idx:2d}] {feature_names[idx]:20s}: {fi[idx]:.4f}")

    # Cross-validation for robustness
    best_iter = model.best_iteration if hasattr(model, 'best_iteration') and model.best_iteration else None
    n_est_cv = (best_iter + 1) if best_iter else 400

    kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = []
    for train_idx, val_idx in kfold.split(X, y):
        cv_model = XGBClassifier(
            n_estimators=n_est_cv,
            max_depth=6,
            learning_rate=0.06,
            subsample=0.80,
            colsample_bytree=0.80,
            colsample_bylevel=0.80,
            scale_pos_weight=scale_pos,
            min_child_weight=2,
            gamma=0.1,
            reg_alpha=0.05,
            reg_lambda=0.5,
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )
        cv_model.fit(X[train_idx], y[train_idx])
        cv_proba = cv_model.predict_proba(X[val_idx])[:, 1]
        cv_scores.append(roc_auc_score(y[val_idx], cv_proba))

    print(f"  5-Fold CV AUC: {np.mean(cv_scores):.4f} (+/- {np.std(cv_scores):.4f})")

    # Refit on full data for maximum strength
    final_model = XGBClassifier(
        n_estimators=n_est_cv,
        max_depth=6,
        learning_rate=0.06,
        subsample=0.80,
        colsample_bytree=0.80,
        colsample_bylevel=0.80,
        scale_pos_weight=scale_pos,
        min_child_weight=2,
        gamma=0.1,
        reg_alpha=0.05,
        reg_lambda=0.5,
        random_state=42,
        verbosity=0,
        n_jobs=-1,
    )
    final_model.fit(X, y)

    # Apply probability calibration to spread predictions across the full range
    # Use a proper train/calibration split to avoid data leakage:
    # 1. Split off a calibration set (20% of data)
    # 2. Train base model on remaining 80%
    # 3. Calibrate on calibration set using cv='prefit'
    # 4. Refit final calibrated model on full data
    print("\nApplying Probability Calibration (proper train/calib split)...")
    try:
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.model_selection import train_test_split
        
        # Split into train (80%) and calibration (20%) sets
        X_train_cal, X_cal, y_train_cal, y_cal = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train base model on train set only
        base_model = XGBClassifier(
            n_estimators=n_est_cv,
            max_depth=6,
            learning_rate=0.06,
            subsample=0.80,
            colsample_bytree=0.80,
            colsample_bylevel=0.80,
            scale_pos_weight=scale_pos,
            min_child_weight=2,
            gamma=0.1,
            reg_alpha=0.05,
            reg_lambda=0.5,
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )
        base_model.fit(X_train_cal, y_train_cal)
        
        # Calibrate on calibration set using cv='prefit' (no retraining)
        calibrated = CalibratedClassifierCV(base_model, method='sigmoid', cv='prefit')
        calibrated.fit(X_cal, y_cal)
        
        # Evaluate calibrated model on test set
        y_proba_cal = calibrated.predict_proba(X_test)[:, 1]
        auc_cal = roc_auc_score(y_test, y_proba_cal)
        print(f"  Calibrated AUC: {auc_cal:.4f}")
        print(f"  Raw XGBoost proba range on test set: {y_proba.min():.3f} - {y_proba.max():.3f}")
        print(f"  Calibrated proba range on test set:  {y_proba_cal.min():.3f} - {y_proba_cal.max():.3f}")
        
        # Refit final calibrated model on full data for production use
        # Train base on full data, then calibrate on full data
        final_base_model = XGBClassifier(
            n_estimators=n_est_cv,
            max_depth=6,
            learning_rate=0.06,
            subsample=0.80,
            colsample_bytree=0.80,
            colsample_bylevel=0.80,
            scale_pos_weight=scale_pos,
            min_child_weight=2,
            gamma=0.1,
            reg_alpha=0.05,
            reg_lambda=0.5,
            random_state=42,
            verbosity=0,
            n_jobs=-1,
        )
        final_base_model.fit(X, y)
        
        final_calibrated = CalibratedClassifierCV(final_base_model, method='sigmoid', cv='prefit')
        final_calibrated.fit(X, y)
        
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(final_calibrated, f)
        print(f"Calibrated model saved to {MODEL_PATH}")
        return final_calibrated
    except Exception as e:
        print(f"Calibration failed ({e}), saving raw model instead.")
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(final_model, f)
        print(f"XGBoost trained and saved to {MODEL_PATH}")
        return final_model


def predict_xgb(model, feature_vector):
    if model is None:
        return {"xgb_available": False}

    vec = np.array(feature_vector).reshape(1, -1)
    proba = float(model.predict_proba(vec)[0][1])
    phishing_threshold = _load_xgb_threshold()
    suspicious_threshold = max(0.35, phishing_threshold * 0.72)
    uncertain_threshold = max(0.20, suspicious_threshold * 0.55)

    if proba >= phishing_threshold:
        verdict = "Phishing"
    elif proba >= suspicious_threshold:
        verdict = "Suspicious"
    elif proba >= uncertain_threshold:
        verdict = "Uncertain"
    else:
        verdict = "Legitimate"

    return {
        "xgb_available": True,
        "xgb_score": round(proba * 100, 1),
        "xgb_verdict": verdict,
        "thresholds": {
            "phishing": round(phishing_threshold * 100, 1),
            "suspicious": round(suspicious_threshold * 100, 1),
            "uncertain": round(uncertain_threshold * 100, 1),
        },
    }

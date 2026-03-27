"""
ml_model.py — Machine Learning classifier for domain phishing detection
Uses a RandomForest trained on synthetic feature vectors.
Run this file directly to regenerate model.pkl
"""

import os
import pickle
import numpy as np

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE VECTOR BUILDER
# ──────────────────────────────────────────────────────────────────────────────
def build_feature_vector(
    features: dict,
    typo_result: dict,
    homoglyph_result: dict,
    combo_result: dict,
    whois_result: dict,
) -> list:
    """
    Convert all analysis results into a flat numeric feature vector
    suitable for ML classification.

    Feature index:
     0: domain_length
     1: digit_ratio
     2: hyphen_count
     3: subdomain_count
     4: entropy
     5: consonant_ratio
     6: has_suspicious_tld (0/1)
     7: has_suspicious_keywords (0/1)
     8: is_ip_like (0/1)
     9: has_excessive_hyphens (0/1)
    10: typo_jaro_winkler_score
    11: typo_levenshtein_score
    12: typo_edit_distance (normalized)
    13: typo_detected (0/1)
    14: homoglyph_detected (0/1)
    15: homoglyph_count
    16: has_digit_substitution (0/1)
    17: combo_detected (0/1)
    18: brand_only (0/1)
    19: combo_keyword_count
    20: whois_age_days (log-normalized)
    21: whois_privacy_protected (0/1)
    22: whois_suspicious_registrar (0/1)
    """
    age_days = whois_result.get("age_days", 365)
    if age_days is None:
        age_days = 365
    # Log-normalize age (prevents large values dominating)
    age_log = np.log1p(age_days) / np.log1p(3650)  # normalize to [0,1]

    vector = [
        min(features.get("length", 0) / 50.0, 1.0),          # 0
        features.get("digit_ratio", 0),                        # 1
        min(features.get("hyphen_count", 0) / 5.0, 1.0),      # 2
        min(features.get("subdomain_count", 0) / 5.0, 1.0),   # 3
        min(features.get("entropy", 0) / 5.0, 1.0),           # 4
        features.get("consonant_ratio", 0),                    # 5
        float(features.get("suspicious_tld", False)),          # 6
        float(features.get("has_suspicious_keywords", False)), # 7
        float(features.get("is_ip_like", False)),              # 8
        float(features.get("has_excessive_hyphens", False)),   # 9
        typo_result.get("jaro_winkler_score", 0),              # 10
        typo_result.get("levenshtein_score", 0),               # 11
        min(typo_result.get("edit_distance", 10) / 10.0, 1.0),# 12
        float(typo_result.get("detected", False)),             # 13
        float(homoglyph_result.get("detected", False)),        # 14
        min(homoglyph_result.get("count", 0) / 5.0, 1.0),     # 15
        float(homoglyph_result.get("has_digit_substitution", False)), # 16
        float(combo_result.get("detected", False)),            # 17
        float(combo_result.get("brand_only", False)),          # 18
        min(len(combo_result.get("matched_keywords", [])) / 5.0, 1.0), # 19
        age_log,                                               # 20
        float(whois_result.get("privacy_protected", False)),  # 21
        float(whois_result.get("suspicious_registrar", False)),# 22
    ]

    return vector


# ──────────────────────────────────────────────────────────────────────────────
# SYNTHETIC TRAINING DATA GENERATOR
# ──────────────────────────────────────────────────────────────────────────────
def generate_training_data(n_samples: int = 2000):
    """
    Generate synthetic labeled training data.
    Label 1 = phishing/malicious, 0 = legitimate
    """
    np.random.seed(42)
    X = []
    y = []

    # ── Legitimate domain profiles ────────────────────────────
    for _ in range(n_samples // 2):
        vec = [
            np.random.uniform(0.1, 0.4),   # length (short-medium)
            np.random.uniform(0.0, 0.1),   # low digit ratio
            np.random.uniform(0.0, 0.1),   # few hyphens
            np.random.uniform(0.0, 0.2),   # few subdomains
            np.random.uniform(0.4, 0.7),   # medium entropy
            np.random.uniform(0.4, 0.7),   # normal consonant ratio
            0.0,                            # no suspicious TLD
            0.0,                            # no suspicious keywords
            0.0,                            # not IP-like
            0.0,                            # no excessive hyphens
            np.random.uniform(0.0, 0.5),   # low JW similarity to brands
            np.random.uniform(0.0, 0.5),   # low levenshtein
            np.random.uniform(0.5, 1.0),   # high edit distance (different)
            0.0,                            # typo not detected
            0.0,                            # no homoglyphs
            0.0,                            # homoglyph count
            0.0,                            # no digit substitution
            0.0,                            # no combo-squat
            0.0,                            # no brand only
            0.0,                            # no keywords
            np.random.uniform(0.6, 1.0),   # old domain
            np.random.uniform(0.0, 0.3),   # privacy
            0.0,                            # legit registrar
        ]
        X.append(vec)
        y.append(0)

    # ── Phishing domain profiles ──────────────────────────────
    for _ in range(n_samples // 2):
        # Randomly pick a phishing profile
        profile = np.random.choice(['typo', 'homoglyph', 'combo', 'mixed'])

        vec = [0.0] * 23

        # Base suspicious traits
        vec[0] = np.random.uniform(0.3, 0.8)   # longer domain
        vec[1] = np.random.uniform(0.1, 0.4)   # more digits
        vec[2] = np.random.uniform(0.2, 0.8)   # more hyphens
        vec[3] = np.random.uniform(0.2, 0.8)   # more subdomains
        vec[4] = np.random.uniform(0.6, 1.0)   # high entropy
        vec[5] = np.random.uniform(0.5, 0.9)   # high consonant ratio
        vec[20] = np.random.uniform(0.0, 0.3)  # young domain
        vec[21] = np.random.choice([0, 1], p=[0.3, 0.7])  # privacy
        vec[22] = np.random.choice([0, 1], p=[0.3, 0.7])  # susp registrar

        if profile == 'typo':
            vec[6] = np.random.choice([0, 1], p=[0.6, 0.4])
            vec[10] = np.random.uniform(0.75, 0.99)  # high JW
            vec[11] = np.random.uniform(0.7, 0.99)
            vec[12] = np.random.uniform(0.0, 0.3)   # low edit dist
            vec[13] = 1.0

        elif profile == 'homoglyph':
            vec[14] = 1.0
            vec[15] = np.random.uniform(0.2, 0.8)
            vec[16] = np.random.choice([0, 1])
            vec[10] = np.random.uniform(0.6, 0.95)

        elif profile == 'combo':
            vec[7] = 1.0
            vec[17] = 1.0
            vec[18] = np.random.choice([0, 1])
            vec[19] = np.random.uniform(0.2, 0.8)
            vec[6] = np.random.choice([0, 1], p=[0.4, 0.6])

        else:  # mixed
            vec[10] = np.random.uniform(0.6, 0.95)
            vec[13] = np.random.choice([0, 1])
            vec[14] = np.random.choice([0, 1])
            vec[17] = np.random.choice([0, 1])
            vec[7] = np.random.choice([0, 1])

        # Add small gaussian noise
        vec = [max(0.0, min(1.0, v + np.random.normal(0, 0.02))) for v in vec]
        X.append(vec)
        y.append(1)

    return np.array(X), np.array(y)


# ──────────────────────────────────────────────────────────────────────────────
# TRAIN AND SAVE MODEL
# ──────────────────────────────────────────────────────────────────────────────
def train_and_save_model(model_path: str = "model.pkl"):
    """Train a RandomForest classifier and save to disk."""
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        from sklearn.metrics import classification_report, accuracy_score
    except ImportError:
        print("scikit-learn not available. Using rule-based scoring only.")
        return None

    print("Generating training data...")
    X, y = generate_training_data(n_samples=3000)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForest classifier...")
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(
            n_estimators=150,
            max_depth=10,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred,
                                  target_names=['Legitimate', 'Phishing']))

    # Save model
    with open(model_path, 'wb') as f:
        pickle.dump(pipeline, f)

    print(f"Model saved to {model_path}")
    return pipeline


# ──────────────────────────────────────────────────────────────────────────────
# LOAD MODEL
# ──────────────────────────────────────────────────────────────────────────────
def load_model(model_path: str = "model.pkl"):
    """Load model from disk; return None if unavailable."""
    if not os.path.exists(model_path):
        return None
    try:
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        print(f"Could not load model: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# ML PREDICT
# ──────────────────────────────────────────────────────────────────────────────
def ml_predict(model, feature_vector: list) -> dict:
    """
    Run ML prediction on a feature vector.
    Returns probability and verdict.
    """
    if model is None:
        return {"available": False, "ml_score": None, "ml_verdict": "N/A"}

    try:
        vec = np.array(feature_vector).reshape(1, -1)
        proba = model.predict_proba(vec)[0]
        phishing_prob = float(proba[1])
        verdict = "Phishing" if phishing_prob >= 0.5 else "Legitimate"

        return {
            "available": True,
            "ml_score": round(phishing_prob * 100, 1),
            "ml_verdict": verdict,
            "confidence": round(max(proba) * 100, 1),
        }
    except Exception as e:
        return {"available": False, "ml_score": None, "ml_verdict": "Error", "error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT — train model when run directly
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    train_and_save_model("model.pkl")
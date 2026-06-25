"""
Ensemble ML Module (v3.0)
==========================
Combines predictions from multiple ML models for robust threat classification.

Models:
  - XGBoost: Primary gradient-boosted tree model
  - LightGBM: Fast gradient-boosted tree model
  - Random Forest: Ensemble of decision trees
  - Logistic Regression: Linear baseline model

Returns ensemble-weighted predictions with entropy-based confidence metrics.
"""

from __future__ import annotations

import json
import math
import os
import pickle
import re
from typing import Any

import numpy as np

try:
    import xgboost as xgb
except ImportError:
    xgb = None

try:
    import lightgbm as lgbm
except ImportError:
    lgbm = None

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
except ImportError:
    RandomForestClassifier = None
    LogisticRegression = None
    StandardScaler = None


class ScaledModelWrapper:
    """
    Wraps a model with its StandardScaler for transparent inference.

    The wrapper implements predict() and predict_proba() by applying
    the scaler before delegating to the wrapped estimator.
    Used by Logistic Regression model which requires feature scaling.

    Note: No __getattr__ fallback to avoid pickle RecursionError
    """
    def __init__(self, model: Any, scaler: Any):
        self.model = model
        self.scaler = scaler

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(self.scaler.transform(X))

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(self.scaler.transform(X))

    def get_params(self, deep: bool = True) -> dict[str, Any]:
        if hasattr(self.model, "get_params"):
            return self.model.get_params(deep)
        return {}


# Model file paths
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATHS = {
    "xgboost": os.path.join(MODEL_DIR, "xgb_model.pkl"),
    "lightgbm": os.path.join(MODEL_DIR, "lgbm_model.pkl"),
    "random_forest": os.path.join(MODEL_DIR, "rf_model.pkl"),
    "logistic_regression": os.path.join(MODEL_DIR, "lr_model.pkl"),
}

PRIORS_PATH = os.path.join(MODEL_DIR, "ensemble_priors.pkl")

# Default ensemble weights (tuned for phishing detection)
ENSEMBLE_WEIGHTS: dict[str, float] = {
    "xgboost": 0.35,
    "lightgbm": 0.30,
    "random_forest": 0.20,
    "logistic_regression": 0.15,
}


def _sigmoid(x: float) -> float:
    """Sigmoid function for probability calibration."""
    return 1.0 / (1.0 + math.exp(-x))


def _softmax(values: list[float]) -> list[float]:
    """Compute softmax of a list of values."""
    e = [math.exp(v - max(values)) for v in values]
    s = sum(e)
    return [v / s for v in e]


def _load_model(model_key: str) -> Any | None:
    """Load a single model from disk."""
    path = MODEL_PATHS.get(model_key)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def _load_priors() -> dict[str, Any] | None:
    """Load ensemble priors (feature means, stds, etc.) from disk."""
    if not os.path.exists(PRIORS_PATH):
        return None
    try:
        with open(PRIORS_PATH, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def _compute_entropy(probabilities: list[float]) -> float:
    """
    Compute Shannon entropy of prediction probabilities.

    entropy = -sum(p * log2(p))

    0 bits = perfect certainty, 1 bit = maximum uncertainty (binary).
    """
    total = 0.0
    for p in probabilities:
        if p > 0:
            total += p * math.log2(p)
    return -total


def _compute_kl_divergence(p: list[float], q: list[float]) -> float:
    """
    Compute KL divergence between two probability distributions.
    Measures how much one distribution diverges from another.
    """
    total = 0.0
    for pi, qi in zip(p, q):
        if pi > 0 and qi > 0:
            total += pi * math.log(pi / qi)
    return total


def _compute_beta_interval(
    successes: int,
    trials: int,
    alpha_prior: float = 1.0,
    beta_prior: float = 1.0,
    confidence: float = 0.95,
) -> dict[str, float]:
    """
    Compute Bayesian credible interval using Beta distribution.

    Returns the posterior mean, lower bound, upper bound, and interval width.
    """
    a = alpha_prior + successes
    b = beta_prior + trials - successes
    mean = a / (a + b)

    # Approximate credible interval using normal approximation
    # (valid for large a+b); for small a+b, use exact Beta quantiles
    std = math.sqrt((a * b) / ((a + b) ** 2 * (a + b + 1)))

    try:
        import scipy.stats as stats  # type: ignore
        z = stats.norm.ppf(1.0 - (1.0 - confidence) / 2.0)
    except ImportError:
        # Fallback: use approximate z-score without scipy
        z = 1.96  # 95% confidence z-score
    lower = max(0.0, mean - z * std)
    upper = min(1.0, mean + z * std)

    return {
        "posterior_mean": mean,
        "lower_bound": lower,
        "upper_bound": upper,
        "interval_width": upper - lower,
    }


def _compute_cohens_kappa(p1: float, p2: float, threshold: float = 0.5) -> float:
    """
    Compute Cohen's kappa coefficient between two binary predictions.
    Measures inter-model agreement beyond chance.
    """
    # Convert probabilities to binary predictions
    y1 = 1 if p1 >= threshold else 0
    y2 = 1 if p2 >= threshold else 0

    # Observed agreement
    po = 1.0 if y1 == y2 else 0.0

    # Expected agreement by chance
    pe = (y1 / 2.0) * (y2 / 2.0) + (1 - y1 / 2.0) * (1 - y2 / 2.0)

    if pe >= 1.0:
        return 1.0

    return (po - pe) / (1.0 - pe)


def _compute_bayes_factor(
    best_model_proba: float,
    worst_model_proba: float,
) -> float:
    """
    Compute Bayes factor comparing best vs worst model prediction.

    BF > 1: evidence for best model
    BF > 3: moderate evidence
    BF > 10: strong evidence
    """
    eps = 1e-10
    return (best_model_proba + eps) / (worst_model_proba + eps)


def ensemble_predict(
    feature_vector: list[float],
    models: dict[str, Any] | None = None,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Run ensemble prediction using all available models.

    Args:
        feature_vector: 32-element feature vector.
        models: Optional pre-loaded models dict. If None, loads from disk.
        weights: Optional custom model weights. If None, uses defaults.

    Returns:
        Dict with ensemble verdict, score, model breakdown, and confidence metrics.
    """
    if models is None:
        models = {}
        for key in MODEL_PATHS:
            model = _load_model(key)
            if model is not None:
                models[key] = model

    model_weights = weights or ENSEMBLE_WEIGHTS
    X = np.array([feature_vector], dtype=np.float32)

    predictions: dict[str, float] = {}
    available_models: list[str] = []

    for model_key, model in models.items():
        try:
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X)[0]
                # Get phishing probability (index 1 if binary)
                if len(proba) >= 2:
                    predictions[model_key] = float(proba[1])
                else:
                    predictions[model_key] = float(proba[0])
            elif hasattr(model, "predict"):
                pred = model.predict(X)[0]
                predictions[model_key] = float(pred)
            else:
                continue
            available_models.append(model_key)
        except Exception:
            continue

    if not predictions:
        return {
            "ensemble_verdict": "unavailable",
            "ensemble_score": 0.0,
            "model_count": 0,
            "available_models": [],
            "model_predictions": {},
            "model_agreement": 0,
            "confidence": 0.0,
            "entropy": None,
            "kl_divergence": None,
            "beta_interval": None,
            "cohens_kappa": None,
            "bma": None,
        }

    # Compute weighted ensemble score
    total_weight = sum(model_weights.get(k, 0.2) for k in predictions)
    weighted_score = sum(
        predictions[k] * model_weights.get(k, 0.2) for k in predictions
    ) / max(total_weight, 1e-10)

    # Compute unweighted agreement
    scores_list = list(predictions.values())
    mean_score = sum(scores_list) / len(scores_list)

    # Verdict based on weighted score
    if weighted_score >= 0.6:
        verdict = "phishing"
    elif weighted_score >= 0.35:
        verdict = "suspicious"
    elif weighted_score >= 0.15:
        verdict = "uncertain"
    else:
        verdict = "legitimate"

    # Model agreement (percentage of models within 0.15 of weighted score)
    agreement_count = sum(
        1 for s in scores_list if abs(s - mean_score) <= 0.15
    )
    agreement_pct = round(agreement_count / max(len(scores_list), 1) * 100)

    # Confidence based on agreement and entropy
    entropy = _compute_entropy([weighted_score, 1.0 - weighted_score])

    # KL divergence between first two models (if available)
    kl_div = None
    if len(scores_list) >= 2:
        p_dist = _softmax([scores_list[0], 1.0 - scores_list[0]])
        q_dist = _softmax([scores_list[1], 1.0 - scores_list[1]])
        kl_div = _compute_kl_divergence(p_dist, q_dist)

    # Beta credible interval
    n_successes = sum(1 for s in scores_list if s >= 0.5)
    n_trials = len(scores_list)
    beta_interval = None
    try:
        beta_interval = _compute_beta_interval(n_successes, n_trials)
    except Exception:
        pass

    # Cohen's kappa (first vs second model)
    kappa = None
    if len(scores_list) >= 2:
        kappa = _compute_cohens_kappa(scores_list[0], scores_list[1])

    # Bayes factor (best vs worst model)
    bayes_factor = None
    if len(scores_list) >= 2:
        bayes_factor = _compute_bayes_factor(
            max(scores_list), min(scores_list)
        )

    # Bayesian Model Averaging
    bma_proba = None
    if len(scores_list) >= 2:
        # Equal prior weights
        prior_weights = [1.0 / len(scores_list)] * len(scores_list)
        bma_proba = sum(
            w * s for w, s in zip(prior_weights, scores_list)
        )

    return {
        "ensemble_verdict": verdict,
        "ensemble_score": round(weighted_score * 100, 1),
        "model_count": len(available_models),
        "available_models": available_models,
        "model_predictions": {k: round(v * 100, 1) for k, v in predictions.items()},
        "model_agreement": agreement_pct,
        "confidence": round(max(50.0, min(98.0, 100.0 - entropy * 30.0)), 1),
        "entropy": {
            "shannon_entropy_bits": round(entropy, 4),
            "interpretation": "low" if entropy < 0.3 else "medium" if entropy < 0.7 else "high",
        } if entropy is not None else None,
        "kl_divergence": round(kl_div, 4) if kl_div is not None else None,
        "beta_interval": beta_interval,
        "cohens_kappa": round(kappa, 4) if kappa is not None else None,
        "bma": {
            "bma_proba": round(bma_proba, 4) if bma_proba is not None else None,
            "bayes_factor": round(bayes_factor, 2) if bayes_factor is not None else None,
        } if bma_proba is not None or bayes_factor is not None else None,
    }

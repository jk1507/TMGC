"""
Continuous Learning Pipeline
=============================
Online training and incremental learning for anti-phishing models:
  - Live threat feed integration for training data
  - User feedback incorporation
  - Automated retraining triggers
  - Model drift detection
  - Validation workflow

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import os
import json
import time
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
_SKLEARN_AVAILABLE = False
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PIPELINE_DATA_DIR = os.path.join(os.path.dirname(__file__), "learning_data")
FEEDBACK_FILE = os.path.join(PIPELINE_DATA_DIR, "user_feedback.jsonl")
TRAINING_LOG_FILE = os.path.join(PIPELINE_DATA_DIR, "training_log.jsonl")
MODEL_METRICS_FILE = os.path.join(PIPELINE_DATA_DIR, "model_metrics.json")
DRIFT_LOG_FILE = os.path.join(PIPELINE_DATA_DIR, "drift_log.jsonl")

# Drift detection thresholds
DRIFT_ACCURACY_THRESHOLD = 0.85  # retrain if accuracy drops below
DRIFT_F1_THRESHOLD = 0.80
MIN_SAMPLES_FOR_RETRAIN = 50
RETRAIN_INTERVAL_HOURS = 24


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class FeedbackEntry:
    """User feedback on a scan result."""
    timestamp: str
    domain: str
    user_verdict: str  # "phishing", "legitimate", "suspicious"
    scan_score: int
    notes: str = ""
    features: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrainingRun:
    """Record of a training run."""
    timestamp: str
    samples_used: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    model_version: str
    drift_detected: bool = False
    retrain_trigger: str = ""


@dataclass
class DriftReport:
    """Model drift detection report."""
    detected: bool = False
    metric_name: str = ""
    current_value: float = 0.0
    threshold: float = 0.0
    recommendation: str = ""
    timestamp: str = ""


@dataclass
class PipelineStatus:
    """Overall pipeline status."""
    available: bool = True
    feedback_count: int = 0
    training_runs: int = 0
    last_training: str = ""
    last_drift_check: str = ""
    drift_detected: bool = False
    model_version: str = "v1.0"
    model_accuracy: float = 0.0
    model_f1: float = 0.0
    pending_retrain: bool = False
    findings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ensure data directory exists
# ---------------------------------------------------------------------------
def _ensure_data_dir():
    os.makedirs(PIPELINE_DATA_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# User Feedback Storage
# ---------------------------------------------------------------------------
def add_feedback(
    domain: str,
    user_verdict: str,
    scan_score: int,
    notes: str = "",
    features: dict[str, Any] = None,
) -> dict[str, Any]:
    """
    Record user feedback on a scan result.
    
    Args:
        domain: The scanned domain
        user_verdict: User's assessment ("phishing", "legitimate", "suspicious")
        scan_score: The system's risk score
        notes: Optional user notes
        features: Feature vector from the scan
    
    Returns:
        Confirmation with feedback count
    """
    _ensure_data_dir()

    entry = FeedbackEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        domain=domain,
        user_verdict=user_verdict,
        scan_score=scan_score,
        notes=notes,
        features=features or {},
    )

    try:
        with open(FEEDBACK_FILE, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
    except Exception as e:
        logger.warning("Failed to save feedback: %s", e)
        return {"success": False, "error": str(e)}

    count = _count_feedback()
    return {
        "success": True,
        "feedback_count": count,
        "message": f"Feedback recorded. {count} total feedback entries.",
    }


def get_feedback(limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve recent feedback entries."""
    entries = []
    if not os.path.exists(FEEDBACK_FILE):
        return entries

    try:
        with open(FEEDBACK_FILE, "r") as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except Exception:
        pass

    return entries


def _count_feedback() -> int:
    if not os.path.exists(FEEDBACK_FILE):
        return 0
    try:
        with open(FEEDBACK_FILE, "r") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Training Data Management
# ---------------------------------------------------------------------------
def _load_training_data() -> tuple[list[list[float]], list[int]]:
    """
    Load training data from feedback and synthetic sources.
    Returns (X, y) where X is feature vectors and y is labels.
    """
    X = []
    y = []

    # Load from user feedback
    feedback = get_feedback(limit=10000)
    for entry in feedback:
        features = entry.get("features", {})
        if not features:
            continue

        # Convert features to numeric vector
        vector = []
        for key in sorted(features.keys()):
            val = features[key]
            if isinstance(val, (int, float)):
                vector.append(float(val))
            elif isinstance(val, bool):
                vector.append(1.0 if val else 0.0)
            elif isinstance(val, str):
                vector.append(float(hash(val) % 1000) / 1000.0)
            else:
                vector.append(0.0)

        if vector:
            X.append(vector)
            verdict = entry.get("user_verdict", "unknown")
            if verdict == "phishing":
                y.append(1)
            elif verdict == "legitimate":
                y.append(0)
            else:
                y.append(0.5)  # suspicious

    return X, y


def _generate_synthetic_samples(n: int = 200) -> tuple[list[list[float]], list[int]]:
    """Generate synthetic training samples for initial model bootstrapping."""
    if not _SKLEARN_AVAILABLE:
        return [], []

    X = []
    y = []
    rng = np.random.default_rng(42)

    for _ in range(n):
        # Generate phishing-like features (higher risk indicators)
        if rng.random() < 0.5:
            features = [
                rng.uniform(0.5, 1.0),  # urgency
                rng.uniform(0.4, 1.0),  # credential_harvesting
                rng.uniform(0.3, 1.0),  # brand_impersonation
                rng.uniform(0.5, 1.0),  # url_risk
                rng.uniform(0.3, 0.8),  # domain_risk
                rng.uniform(0.4, 1.0),  # header_anomaly
                rng.uniform(0.2, 0.7),  # ml_score
            ]
            X.append(features)
            y.append(1)
        else:
            # Generate legitimate-like features
            features = [
                rng.uniform(0.0, 0.3),
                rng.uniform(0.0, 0.2),
                rng.uniform(0.0, 0.2),
                rng.uniform(0.0, 0.3),
                rng.uniform(0.0, 0.3),
                rng.uniform(0.0, 0.3),
                rng.uniform(0.0, 0.3),
            ]
            X.append(features)
            y.append(0)

    return X, y


# ---------------------------------------------------------------------------
# Model Training
# ---------------------------------------------------------------------------
def train_model(force: bool = False) -> dict[str, Any]:
    """
    Train or retrain the phishing detection model.
    
    Triggers:
    - Enough new feedback samples (>= MIN_SAMPLES_FOR_RETRAIN)
    - Drift detected
    - Force=True
    
    Returns training metrics.
    """
    if not _SKLEARN_AVAILABLE:
        return {
            "success": False,
            "error": "scikit-learn not available",
        }

    _ensure_data_dir()

    # Check if retrain is needed
    if not force:
        last_training = _get_last_training_time()
        if last_training:
            hours_since = (datetime.now(timezone.utc) - last_training).total_seconds() / 3600
            if hours_since < RETRAIN_INTERVAL_HOURS:
                feedback_count = _count_feedback()
                if feedback_count < MIN_SAMPLES_FOR_RETRAIN:
                    return {
                        "success": False,
                        "reason": f"Too soon for retrain ({hours_since:.1f}h since last, need {RETRAIN_INTERVAL_HOURS}h)",
                        "pending_feedback": feedback_count,
                    }

    # Load data
    X, y = _load_training_data()

    # Bootstrap with synthetic data if insufficient
    if len(X) < 20:
        synth_X, synth_y = _generate_synthetic_samples(200)
        X.extend(synth_X)
        y.extend(synth_y)

    if len(X) < 10:
        return {
            "success": False,
            "error": "Insufficient training data",
        }

    # Filter out ambiguous labels
    filtered_X = []
    filtered_y = []
    for xi, yi in zip(X, y):
        if yi != 0.5:
            filtered_X.append(xi)
            filtered_y.append(int(yi))

    if len(filtered_X) < 10:
        return {
            "success": False,
            "error": "Insufficient unambiguous training samples",
        }

    X_arr = np.array(filtered_X)
    y_arr = np.array(filtered_y)

    # Pad/truncate to uniform feature length
    max_len = max(len(x) for x in filtered_X)
    X_padded = np.zeros((len(filtered_X), max_len))
    for i, x in enumerate(filtered_X):
        X_padded[i, :len(x)] = x

    try:
        # Train model
        model = GradientBoostingClassifier(
            n_estimators=50,
            max_depth=4,
            learning_rate=0.1,
            random_state=42,
        )
        model.fit(X_padded, y_arr)

        # Evaluate with cross-validation
        if len(filtered_X) >= 20:
            cv_scores = cross_val_score(model, X_padded, y_arr, cv=min(5, len(filtered_X) // 5), scoring='f1')
            f1_mean = float(cv_scores.mean())
            accuracy = float(cv_scores.mean())
            precision = float(precision_score(y_arr, model.predict(X_padded), zero_division=0))
            recall = float(recall_score(y_arr, model.predict(X_padded), zero_division=0))
        else:
            preds = model.predict(X_padded)
            accuracy = float(accuracy_score(y_arr, preds))
            precision = float(precision_score(y_arr, preds, zero_division=0))
            recall = float(recall_score(y_arr, preds, zero_division=0))
            f1_mean = float(f1_score(y_arr, preds, zero_division=0))

        # Record training run
        version = f"v{int(time.time())}"
        run = TrainingRun(
            timestamp=datetime.now(timezone.utc).isoformat(),
            samples_used=len(filtered_X),
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1_mean,
            model_version=version,
        )

        _log_training_run(run)
        _save_model_metrics(accuracy, precision, recall, f1_mean, version)

        return {
            "success": True,
            "samples_used": len(filtered_X),
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1_mean, 4),
            "model_version": version,
        }

    except Exception as e:
        logger.warning("Training failed: %s", e)
        return {
            "success": False,
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Drift Detection
# ---------------------------------------------------------------------------
def detect_drift() -> dict[str, Any]:
    """
    Check for model drift by comparing recent feedback accuracy
    against historical model performance.
    """
    metrics = _load_model_metrics()
    if not metrics:
        return {
            "drift_detected": False,
            "message": "No model metrics available for drift comparison",
        }

    # Get recent feedback
    recent_feedback = get_feedback(limit=200)
    if len(recent_feedback) < 10:
        return {
            "drift_detected": False,
            "message": f"Insufficient recent feedback for drift detection ({len(recent_feedback)} entries)",
        }

    # Calculate recent accuracy against model predictions
    correct = 0
    total = 0
    for entry in recent_feedback:
        scan_score = entry.get("scan_score", 50)
        user_verdict = entry.get("user_verdict", "")
        predicted_phishing = scan_score >= 50
        actual_phishing = user_verdict == "phishing"

        if predicted_phishing == actual_phishing:
            correct += 1
        total += 1

    if total == 0:
        return {"drift_detected": False, "message": "No comparable feedback"}

    recent_accuracy = correct / total
    historical_accuracy = metrics.get("accuracy", 0.9)

    drift = False
    recommendation = ""
    if recent_accuracy < DRIFT_ACCURACY_THRESHOLD:
        drift = True
        recommendation = f"Accuracy dropped to {recent_accuracy:.2%} (threshold: {DRIFT_ACCURACY_THRESHOLD:.0%}). Retrain recommended."
    elif recent_accuracy < historical_accuracy * 0.9:
        drift = True
        recommendation = f"Accuracy declined significantly from {historical_accuracy:.2%} to {recent_accuracy:.2%}."

    drift_report = DriftReport(
        detected=drift,
        metric_name="accuracy",
        current_value=recent_accuracy,
        threshold=DRIFT_ACCURACY_THRESHOLD,
        recommendation=recommendation,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    if drift:
        _log_drift(drift_report)

    return {
        "drift_detected": drift,
        "current_accuracy": round(recent_accuracy, 4),
        "historical_accuracy": round(historical_accuracy, 4),
        "recommendation": recommendation,
        "samples_evaluated": total,
    }


# ---------------------------------------------------------------------------
# Storage Helpers
# ---------------------------------------------------------------------------
def _log_training_run(run: TrainingRun):
    _ensure_data_dir()
    try:
        with open(TRAINING_LOG_FILE, "a") as f:
            f.write(json.dumps(asdict(run)) + "\n")
    except Exception:
        pass


def _save_model_metrics(accuracy: float, precision: float, recall: float, f1: float, version: str):
    _ensure_data_dir()
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(MODEL_METRICS_FILE, "w") as f:
            json.dump(metrics, f, indent=2)
    except Exception:
        pass


def _load_model_metrics() -> dict[str, Any]:
    if not os.path.exists(MODEL_METRICS_FILE):
        return {}
    try:
        with open(MODEL_METRICS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _get_last_training_time() -> datetime | None:
    if not os.path.exists(TRAINING_LOG_FILE):
        return None
    try:
        with open(TRAINING_LOG_FILE, "r") as f:
            lines = f.readlines()
            if lines:
                last = json.loads(lines[-1].strip())
                return datetime.fromisoformat(last["timestamp"])
    except Exception:
        pass
    return None


def _log_drift(report: DriftReport):
    _ensure_data_dir()
    try:
        with open(DRIFT_LOG_FILE, "a") as f:
            f.write(json.dumps(asdict(report)) + "\n")
    except Exception:
        pass


def _get_training_runs(limit: int = 10) -> list[dict[str, Any]]:
    if not os.path.exists(TRAINING_LOG_FILE):
        return []
    try:
        with open(TRAINING_LOG_FILE, "r") as f:
            lines = f.readlines()
            return [json.loads(l.strip()) for l in lines[-limit:] if l.strip()]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_pipeline_status() -> dict[str, Any]:
    """Get overall continuous learning pipeline status."""
    metrics = _load_model_metrics()
    recent_runs = _get_training_runs(5)
    feedback_count = _count_feedback()
    last_training = _get_last_training_time()

    pending = False
    if last_training:
        hours_since = (datetime.now(timezone.utc) - last_training).total_seconds() / 3600
        if hours_since >= RETRAIN_INTERVAL_HOURS and feedback_count >= MIN_SAMPLES_FOR_RETRAIN:
            pending = True

    return {
        "available": True,
        "feedback_count": feedback_count,
        "training_runs": len(recent_runs),
        "last_training": last_training.isoformat() if last_training else None,
        "model_version": metrics.get("version", "none"),
        "model_accuracy": round(metrics.get("accuracy", 0.0), 4),
        "model_f1": round(metrics.get("f1", 0.0), 4),
        "pending_retrain": pending,
        "recent_runs": recent_runs,
        "sklearn_available": _SKLEARN_AVAILABLE,
    }


def submit_feedback_and_check_retrain(
    domain: str,
    user_verdict: str,
    scan_score: int,
    notes: str = "",
    features: dict[str, Any] = None,
) -> dict[str, Any]:
    """
    Submit feedback and automatically check if retrain is needed.
    Returns combined status.
    """
    feedback_result = add_feedback(domain, user_verdict, scan_score, notes, features)

    retrain_result = None
    if feedback_result.get("success"):
        # Check if retrain is warranted
        feedback_count = feedback_result.get("feedback_count", 0)
        last_training = _get_last_training_time()
        should_retrain = False

        if feedback_count >= MIN_SAMPLES_FOR_RETRAIN:
            if last_training is None:
                should_retrain = True
            else:
                hours_since = (datetime.now(timezone.utc) - last_training).total_seconds() / 3600
                if hours_since >= RETRAIN_INTERVAL_HOURS:
                    should_retrain = True

        if should_retrain:
            retrain_result = train_model(force=True)

    return {
        "feedback": feedback_result,
        "retrain": retrain_result,
        "pipeline_status": get_pipeline_status(),
    }

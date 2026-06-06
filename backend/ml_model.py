"""
ML module intentionally disabled for production safety.
No synthetic data generation. No random training. No active predictions.
"""

from typing import Any, Dict, List


ML_EXPERIMENTAL_ENABLED = False


def load_model(model_path: str = "model.pkl") -> None:
    _ = model_path
    return None


def train_and_save_model(model_path: str = "model.pkl") -> None:
    _ = model_path
    return None


def build_feature_vector(*args, **kwargs) -> List[float]:
    _ = args
    _ = kwargs
    return []


def ml_predict(model: Any, feature_vector: List[float]) -> Dict[str, Any]:
    _ = model
    _ = feature_vector
    return {
        "available": False,
        "experimental": True,
        "enabled": ML_EXPERIMENTAL_ENABLED,
        "ml_score": None,
        "ml_verdict": "Disabled",
        "note": "ML prediction disabled. Production decisioning uses deterministic rules + real threat intelligence.",
    }


def get_experimental_ml_status() -> Dict[str, Any]:
    return {
        "available": False,
        "experimental": True,
        "enabled": ML_EXPERIMENTAL_ENABLED,
        "note": "ML is disabled in production mode.",
    }

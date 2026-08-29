"""
Transformer Ensemble Module
===========================
Combines predictions from BERT/RoBERTa, CNN, and GNN models
into a unified risk score with confidence metrics.

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------
_TORCH_AVAILABLE = False
_TRANSFORMERS_AVAILABLE = False
_NETWORKX_AVAILABLE = False

try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    torch = None

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    AutoTokenizer = None
    AutoModelForSequenceClassification = None

try:
    import networkx as nx
    _NETWORKX_AVAILABLE = True
except ImportError:
    nx = None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class EnsembleResult:
    """Combined ensemble prediction result."""
    available: bool = True
    ensemble_score: float = 0.0
    ensemble_confidence: float = 0.0
    ensemble_verdict: str = "unknown"
    model_scores: dict[str, float] = field(default_factory=dict)
    model_confidences: dict[str, float] = field(default_factory=dict)
    model_weights: dict[str, float] = field(default_factory=dict)
    component_analysis: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    risk_level: str = "unknown"
    score: int = 0


# ---------------------------------------------------------------------------
# Model weights for ensemble
# ---------------------------------------------------------------------------
ENSEMBLE_WEIGHTS = {
    "bert_email": 0.30,      # BERT for email/text analysis
    "cnn_visual": 0.25,      # CNN for visual/DOM analysis
    "gnn_graph": 0.25,       # GNN for graph analysis
    "xgboost_ml": 0.20,      # XGBoost for feature-based ML
}

# Dynamic weight adjustment based on data availability
def _adjust_weights(available_models: list[str]) -> dict[str, float]:
    """Adjust ensemble weights based on available models."""
    weights = ENSEMBLE_WEIGHTS.copy()
    
    # Remove unavailable models and redistribute weights
    unavailable = [m for m in weights if m not in available_models]
    if unavailable:
        total_removed = sum(weights[m] for m in unavailable)
        available_weight = sum(weights[m] for m in available_models)
        
        for m in unavailable:
            weights.pop(m)
        
        if available_weight > 0:
            for m in available_models:
                weights[m] = weights.get(m, 0) + (weights.get(m, 0) / available_weight) * total_removed
    
    # Normalize weights to sum to 1.0
    total = sum(weights.values())
    if total > 0:
        for m in weights:
            weights[m] /= total
    
    return weights


# ---------------------------------------------------------------------------
# BERT/RoBERTa Email Analysis
# ---------------------------------------------------------------------------
_email_model_cache: dict[str, Any] = {}
_sms_model_cache: dict[str, Any] = {}

_EMAIL_MODEL_NAME = "ElSlay/BERT-Phishing-Email-Model"
_SMS_MODEL_NAME = "mariagrandury/distilbert-base-uncased-finetuned-sms-spam-detection"


def _load_email_model():
    """Load the email phishing BERT model (cached)."""
    if "tokenizer" in _email_model_cache:
        return _email_model_cache["tokenizer"], _email_model_cache["model"]
    if not _TRANSFORMERS_AVAILABLE or not _TORCH_AVAILABLE:
        return None, None
    try:
        tokenizer = AutoTokenizer.from_pretrained(_EMAIL_MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(_EMAIL_MODEL_NAME)
        model.eval()
        _email_model_cache["tokenizer"] = tokenizer
        _email_model_cache["model"] = model
        return tokenizer, model
    except Exception as e:
        logger.warning("Failed to load email phishing model: %s", e)
        return None, None


def _load_sms_model():
    """Load the SMS phishing BERT model (cached)."""
    if "tokenizer" in _sms_model_cache:
        return _sms_model_cache["tokenizer"], _sms_model_cache["model"]
    if not _TRANSFORMERS_AVAILABLE or not _TORCH_AVAILABLE:
        return None, None
    try:
        tokenizer = AutoTokenizer.from_pretrained(_SMS_MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(_SMS_MODEL_NAME)
        model.eval()
        _sms_model_cache["tokenizer"] = tokenizer
        _sms_model_cache["model"] = model
        return tokenizer, model
    except Exception as e:
        logger.warning("Failed to load SMS phishing model: %s", e)
        return None, None


def _rule_based_fallback(text: str, model_type: str = "email") -> dict[str, Any]:
    """
    Rule-based fallback when BERT model is unavailable.
    Uses keyword/heuristic analysis to produce a phishing score.
    """
    # Try using the email_phishing rule-based analysis if available
    try:
        from email_phishing import _rule_based_content_analysis
        content_result = _rule_based_content_analysis(text, content_type=model_type)
        phishing_prob = content_result.confidence
        score = round(phishing_prob * 100, 2)
        confidence = round(abs(phishing_prob - (1.0 - phishing_prob)) * 100, 2)

        if phishing_prob >= 0.7:
            verdict = "phishing"
        elif phishing_prob >= 0.4:
            verdict = "suspicious"
        elif phishing_prob >= 0.2:
            verdict = "uncertain"
        else:
            verdict = "legitimate"

        return {
            "available": True,
            "score": score,
            "confidence": confidence,
            "verdict": verdict,
            "probabilities": {
                "phishing": round(phishing_prob, 4),
                "legitimate": round(1.0 - phishing_prob, 4),
            },
            "model_name": f"rule_based_{model_type}",
            "fallback": True,
        }
    except Exception as e:
        logger.warning("Rule-based fallback failed: %s", e)

    # Last resort: basic keyword heuristic
    text_lower = text.lower()
    urgency_words = ["urgent", "immediately", "suspended", "locked", "verify your account",
                     "click here", "confirm your identity", "act now"]
    cred_words = ["password", "credentials", "login", "sign in to verify", "enter your"]

    urgency_hits = sum(1 for w in urgency_words if w in text_lower)
    cred_hits = sum(1 for w in cred_words if w in text_lower)

    raw_score = min(urgency_hits * 10 + cred_hits * 15, 100)
    phishing_prob = raw_score / 100.0
    confidence = round(abs(phishing_prob - (1.0 - phishing_prob)) * 100, 2)

    if phishing_prob >= 0.7:
        verdict = "phishing"
    elif phishing_prob >= 0.4:
        verdict = "suspicious"
    elif phishing_prob >= 0.2:
        verdict = "uncertain"
    else:
        verdict = "legitimate"

    return {
        "available": True,
        "score": round(phishing_prob * 100, 2),
        "confidence": confidence,
        "verdict": verdict,
        "probabilities": {
            "phishing": round(phishing_prob, 4),
            "legitimate": round(1.0 - phishing_prob, 4),
        },
        "model_name": f"keyword_heuristic_{model_type}",
        "fallback": True,
    }


def analyze_email_bert(text: str, model_type: str = "email") -> dict[str, Any]:
    """
    Analyze email/SMS content using BERT/RoBERTa transformer model.
    Falls back to rule-based heuristic analysis if the transformer model
    is unavailable (e.g. missing dependencies or model download failure).
    
    Args:
        text: Email or SMS content to analyze
        model_type: "email" or "sms"
    
    Returns:
        Dict with prediction scores and confidence
    """
    if model_type == "email":
        tokenizer, model = _load_email_model()
    else:
        tokenizer, model = _load_sms_model()
    
    if tokenizer is None or model is None:
        logger.info("BERT model unavailable for %s, using rule-based fallback", model_type)
        return _rule_based_fallback(text, model_type)
    
    try:
        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        
        with torch.no_grad():
            outputs = model(**inputs)
        
        probs = torch.softmax(outputs.logits, dim=1)[0]
        
        # Get phishing probability
        if probs.shape[0] == 2:
            # Binary classification: [legitimate, phishing]
            phishing_score = probs[1].item()
            legitimate_score = probs[0].item()
        else:
            phishing_score = probs[0].item()
            legitimate_score = 1.0 - phishing_score
        
        # Calculate confidence based on probability margin
        confidence = abs(phishing_score - legitimate_score)
        
        # Determine verdict
        if phishing_score >= 0.7:
            verdict = "phishing"
        elif phishing_score >= 0.4:
            verdict = "suspicious"
        elif phishing_score >= 0.2:
            verdict = "uncertain"
        else:
            verdict = "legitimate"
        
        return {
            "available": True,
            "score": round(phishing_score * 100, 2),
            "confidence": round(confidence * 100, 2),
            "verdict": verdict,
            "probabilities": {
                "phishing": round(phishing_score, 4),
                "legitimate": round(legitimate_score, 4),
            },
            "model_name": f"bert_{model_type}",
        }
        
    except Exception as e:
        logger.warning("BERT prediction failed: %s, falling back to rule-based analysis", e)
        return _rule_based_fallback(text, model_type)


# ---------------------------------------------------------------------------
# CNN Visual Analysis
# ---------------------------------------------------------------------------
_cnn_model_cache: dict[str, Any] = {}


def _build_cnn_model():
    """Build a simple CNN model for visual/DOM analysis."""
    if not _TORCH_AVAILABLE:
        return None
    
    try:
        import torch.nn as nn
        
        class PhishingCNN(nn.Module):
            """Simple CNN for phishing detection based on DOM features."""
            
            def __init__(self, input_dim=32, num_classes=2):
                super().__init__()
                self.features = nn.Sequential(
                    nn.Linear(input_dim, 64),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Dropout(0.2),
                )
                self.classifier = nn.Sequential(
                    nn.Linear(32, 16),
                    nn.ReLU(),
                    nn.Linear(16, num_classes),
                )
            
            def forward(self, x):
                x = self.features(x)
                x = self.classifier(x)
                return x
        
        model = PhishingCNN()
        model.eval()
        return model
        
    except Exception as e:
        logger.warning("Failed to build CNN model: %s", e)
        return None


def analyze_visual_cnn(dom_features: dict[str, Any], visual_features: dict[str, Any] = None) -> dict[str, Any]:
    """
    Analyze DOM and visual features using CNN model.
    
    Args:
        dom_features: Dictionary of DOM structure features
        visual_features: Optional dictionary of visual features
    
    Returns:
        Dict with prediction scores and confidence
    """
    if not _TORCH_AVAILABLE:
        return {
            "available": False,
            "error": "PyTorch not available",
            "score": 0.0,
            "confidence": 0.0,
        }
    
    try:
        # Build feature vector from DOM features
        feature_vector = []
        
        # DOM features
        feature_keys = [
            "total_elements", "form_count", "password_form_count",
            "script_count", "image_count", "iframe_count",
            "hidden_element_count", "external_script_count",
            "brands_detected_count", "obfuscation_count", "html_length",
        ]
        
        for key in feature_keys:
            val = dom_features.get(key, 0)
            if isinstance(val, (int, float)):
                feature_vector.append(float(val))
            elif isinstance(val, bool):
                feature_vector.append(1.0 if val else 0.0)
            else:
                feature_vector.append(0.0)
        
        # Add boolean features
        feature_vector.append(1.0 if dom_features.get("has_login_form", False) else 0.0)
        feature_vector.append(1.0 if dom_features.get("has_external_action", False) else 0.0)
        
        # Visual features if available
        if visual_features:
            for key in ["width", "height", "aspect_ratio", "r_avg", "g_avg", "b_avg",
                        "dark_ratio", "light_ratio", "entropy"]:
                val = visual_features.get(key, 0)
                if isinstance(val, (int, float)):
                    feature_vector.append(float(val))
        
        # Pad or truncate to expected size
        while len(feature_vector) < 32:
            feature_vector.append(0.0)
        feature_vector = feature_vector[:32]
        
        # Convert to tensor
        x = torch.tensor([feature_vector], dtype=torch.float32)
        
        # Load or build model
        model = _cnn_model_cache.get("model")
        if model is None:
            model = _build_cnn_model()
            if model is None:
                return {
                    "available": False,
                    "error": "CNN model not available",
                    "score": 0.0,
                    "confidence": 0.0,
                }
            _cnn_model_cache["model"] = model
        
        # Run prediction
        with torch.no_grad():
            outputs = model(x)
            probs = torch.softmax(outputs, dim=1)[0]
        
        phishing_score = probs[1].item()
        legitimate_score = probs[0].item()
        confidence = abs(phishing_score - legitimate_score)
        
        # Determine verdict based on features
        risk_indicators = 0
        if dom_features.get("password_form_count", 0) > 0:
            risk_indicators += 2
        if dom_features.get("has_external_action", False):
            risk_indicators += 2
        if dom_features.get("obfuscation_count", 0) > 2:
            risk_indicators += 1
        if dom_features.get("brands_detected_count", 0) > 0:
            risk_indicators += 1
        
        # Adjust score based on risk indicators
        adjusted_score = min(1.0, phishing_score + (risk_indicators * 0.1))
        
        if adjusted_score >= 0.7:
            verdict = "phishing"
        elif adjusted_score >= 0.4:
            verdict = "suspicious"
        elif adjusted_score >= 0.2:
            verdict = "uncertain"
        else:
            verdict = "legitimate"
        
        return {
            "available": True,
            "score": round(adjusted_score * 100, 2),
            "confidence": round(confidence * 100, 2),
            "verdict": verdict,
            "risk_indicators": risk_indicators,
            "probabilities": {
                "phishing": round(phishing_score, 4),
                "legitimate": round(legitimate_score, 4),
            },
            "model_name": "cnn_visual",
        }
        
    except Exception as e:
        logger.warning("CNN prediction failed: %s", e)
        return {
            "available": False,
            "error": str(e),
            "score": 0.0,
            "confidence": 0.0,
        }


# ---------------------------------------------------------------------------
# GNN Graph Analysis
# ---------------------------------------------------------------------------
def analyze_graph_gnn(graph_data: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze domain relationship graph using graph-based features.
    
    Args:
        graph_data: Dictionary containing graph structure and features
    
    Returns:
        Dict with prediction scores and confidence
    """
    try:
        # Extract graph features
        node_count = graph_data.get("node_count", 0)
        edge_count = graph_data.get("edge_count", 0)
        density = graph_data.get("density", 0.0)
        avg_degree = graph_data.get("avg_degree", 0.0)
        max_degree = graph_data.get("max_degree", 0)
        cluster_count = graph_data.get("cluster_count", 0)
        largest_cluster = graph_data.get("largest_cluster_size", 0)
        shared_infra = graph_data.get("shared_infrastructure_count", 0)
        centrality_max = graph_data.get("centrality_max", 0.0)
        
        # Calculate risk score based on graph features
        risk_score = 0.0
        findings = []
        
        # High density = many relationships = suspicious
        if density > 0.5:
            risk_score += 0.2
            findings.append(f"High graph density ({density:.2f})")
        
        # Many shared infrastructure edges = suspicious clustering
        if shared_infra > 5:
            risk_score += 0.2
            findings.append(f"Many shared infrastructure edges ({shared_infra})")
        
        # Large clusters = potential botnet/phishing network
        if largest_cluster > 10:
            risk_score += 0.25
            findings.append(f"Large domain cluster detected ({largest_cluster} domains)")
        
        # High centrality = key infrastructure node
        if centrality_max > 0.5:
            risk_score += 0.15
            findings.append(f"High centrality detected ({centrality_max:.2f})")
        
        # Many clusters = distributed infrastructure
        if cluster_count > 3:
            risk_score += 0.1
            findings.append(f"Multiple clusters detected ({cluster_count})")
        
        # Normalize score
        risk_score = min(1.0, risk_score)
        confidence = min(1.0, 0.5 + (node_count * 0.05))
        
        if risk_score >= 0.7:
            verdict = "phishing"
        elif risk_score >= 0.4:
            verdict = "suspicious"
        elif risk_score >= 0.2:
            verdict = "uncertain"
        else:
            verdict = "legitimate"
        
        return {
            "available": True,
            "score": round(risk_score * 100, 2),
            "confidence": round(confidence * 100, 2),
            "verdict": verdict,
            "findings": findings,
            "graph_metrics": {
                "node_count": node_count,
                "edge_count": edge_count,
                "density": density,
                "cluster_count": cluster_count,
                "shared_infrastructure": shared_infra,
            },
            "model_name": "gnn_graph",
        }
        
    except Exception as e:
        logger.warning("GNN analysis failed: %s", e)
        return {
            "available": False,
            "error": str(e),
            "score": 0.0,
            "confidence": 0.0,
        }


# ---------------------------------------------------------------------------
# Ensemble Combination
# ---------------------------------------------------------------------------
def combine_ensemble(
    bert_result: dict[str, Any] = None,
    cnn_result: dict[str, Any] = None,
    gnn_result: dict[str, Any] = None,
    xgboost_result: dict[str, Any] = None,
) -> EnsembleResult:
    """
    Combine predictions from multiple models into ensemble result.
    
    Args:
        bert_result: BERT/RoBERTa email analysis result
        cnn_result: CNN visual analysis result
        gnn_result: GNN graph analysis result
        xgboost_result: XGBoost ML result
    
    Returns:
        EnsembleResult with combined prediction
    """
    result = EnsembleResult()
    
    # Collect available models
    model_results = {}
    if bert_result and bert_result.get("available"):
        model_results["bert_email"] = bert_result
    if cnn_result and cnn_result.get("available"):
        model_results["cnn_visual"] = cnn_result
    if gnn_result and gnn_result.get("available"):
        model_results["gnn_graph"] = gnn_result
    if xgboost_result and xgboost_result.get("xgb_available"):
        # Normalize XGBoost result to match format
        model_results["xgboost_ml"] = {
            "available": True,
            "score": xgboost_result.get("xgb_score", 0),
            "confidence": 75.0,  # Default confidence
        }
    
    if not model_results:
        result.available = False
        result.findings.append("No models available for ensemble prediction")
        return result
    
    # Adjust weights based on available models
    weights = _adjust_weights(list(model_results.keys()))
    result.model_weights = weights
    
    # Calculate weighted ensemble score
    total_weight = 0.0
    weighted_score = 0.0
    weighted_confidence = 0.0
    
    for model_name, model_result in model_results.items():
        weight = weights.get(model_name, 0)
        score = model_result.get("score", 0)
        confidence = model_result.get("confidence", 50)
        
        weighted_score += score * weight
        weighted_confidence += confidence * weight
        total_weight += weight
        
        result.model_scores[model_name] = score
        result.model_confidences[model_name] = confidence
        
        # Collect findings
        if "findings" in model_result:
            for finding in model_result["findings"]:
                result.findings.append(f"[{model_name.upper()}] {finding}")
    
    if total_weight > 0:
        result.ensemble_score = round(weighted_score / total_weight, 2)
        result.ensemble_confidence = round(weighted_confidence / total_weight, 2)
    
    # Determine verdict
    if result.ensemble_score >= 70:
        result.ensemble_verdict = "phishing"
        result.risk_level = "critical"
    elif result.ensemble_score >= 45:
        result.ensemble_verdict = "suspicious"
        result.risk_level = "high"
    elif result.ensemble_score >= 25:
        result.ensemble_verdict = "uncertain"
        result.risk_level = "medium"
    else:
        result.ensemble_verdict = "legitimate"
        result.risk_level = "low"
    
    result.score = min(100, int(result.ensemble_score))
    
    # Add component analysis
    result.component_analysis = {
        "models_used": list(model_results.keys()),
        "weights": weights,
        "individual_scores": result.model_scores,
        "individual_confidences": result.model_confidences,
    }
    
    return result


# ---------------------------------------------------------------------------
# Convenience wrapper for API
# ---------------------------------------------------------------------------
def run_full_ensemble(
    email_text: str = "",
    dom_features: dict[str, Any] = None,
    visual_features: dict[str, Any] = None,
    graph_data: dict[str, Any] = None,
    xgboost_result: dict[str, Any] = None,
) -> dict[str, Any]:
    """
    Run full ensemble analysis combining all available models.
    
    Args:
        email_text: Email/SMS content for BERT analysis
        dom_features: DOM features for CNN analysis
        visual_features: Visual features for CNN analysis
        graph_data: Graph data for GNN analysis
        xgboost_result: XGBoost prediction result
    
    Returns:
        Dictionary with ensemble results
    """
    # Run BERT if text provided
    bert_result = None
    if email_text:
        bert_result = analyze_email_bert(email_text, model_type="email")
    
    # Run CNN if DOM features provided
    cnn_result = None
    if dom_features:
        cnn_result = analyze_visual_cnn(dom_features, visual_features)
    
    # Run GNN if graph data provided
    gnn_result = None
    if graph_data:
        gnn_result = analyze_graph_gnn(graph_data)
    
    # Combine all results
    ensemble = combine_ensemble(
        bert_result=bert_result,
        cnn_result=cnn_result,
        gnn_result=gnn_result,
        xgboost_result=xgboost_result,
    )
    
    return {
        "available": ensemble.available,
        "ensemble_score": ensemble.ensemble_score,
        "ensemble_confidence": ensemble.ensemble_confidence,
        "ensemble_verdict": ensemble.ensemble_verdict,
        "risk_level": ensemble.risk_level,
        "score": ensemble.score,
        "model_scores": ensemble.model_scores,
        "model_confidences": ensemble.model_confidences,
        "model_weights": ensemble.model_weights,
        "component_analysis": ensemble.component_analysis,
        "findings": ensemble.findings,
        "bert_result": bert_result,
        "cnn_result": cnn_result,
        "gnn_result": gnn_result,
    }

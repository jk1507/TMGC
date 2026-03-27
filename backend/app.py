
"""
app.py — Flask backend for Suspicious Domain Detection System
Endpoints: POST /analyze-domain, GET /health, GET /examples
INTEGRATION: XGB Hook included for enhanced feature tracking.
"""
from external_hooks import run_external_scans
import os
import sys
from datetime import datetime
from flask import Flask, request, jsonify


# XGB Integration Hook
from xgb_hook import run_xgb


# Local modules
from utils import (
    validate_domain, sanitize_domain,
    detect_typosquatting, detect_homoglyphs,
    detect_combosquatting, extract_features,
    analyze_whois_mock, compute_risk_score,
    normalize_homoglyphs
)
from ml_model import (
    load_model, ml_predict, build_feature_vector, train_and_save_model
)


# ──────────────────────────────────────────────────────────────────────────────
# FLASK APP SETUP
# ──────────────────────────────────────────────────────────────────────────────


app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    """Manual CORS — allows all origins (dev mode)"""
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/<path:path>", methods=["OPTIONS"])
@app.route("/", methods=["OPTIONS"])
def handle_options(path=""):
    """Handle CORS pre-flight requests."""
    from flask import Response
    r = Response()
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r, 204


# ──────────────────────────────────────────────────────────────────────────────
# ML MODEL INITIALIZATION
# ──────────────────────────────────────────────────────────────────────────────


MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
_model = None


def get_model():
    """Lazy-load model; train if not found."""
    global _model
    if _model is None:
        _model = load_model(MODEL_PATH)
        if _model is None:
            print("[INFO] model.pkl not found. Training now...")
            try:
                _model = train_and_save_model(MODEL_PATH)
                print("[INFO] Model trained successfully.")
            except Exception as e:
                print(f"[WARN] Could not train model: {e}")
                _model = None
    return _model


# ──────────────────────────────────────────────────────────────────────────────
# ANALYSIS PIPELINE
# ──────────────────────────────────────────────────────────────────────────────


def run_analysis(domain: str) -> dict:
    """
    Full analysis pipeline for a given domain.
    Returns comprehensive result dict and triggers XGB hook.
    """
    # 1. Sanitize input
    domain = sanitize_domain(domain)


    # 2. Extract domain name (without TLD) for string comparisons
    parts = domain.lower().split('.')
    domain_name = parts[-2] if len(parts) >= 2 else domain


    # 3. Normalize homoglyphs for secondary analysis
    normalized = normalize_homoglyphs(domain_name)


    # 4. Run all detectors
    homoglyph_result = detect_homoglyphs(domain)
    typo_result = detect_typosquatting(normalized)


    # Check raw domain for typosquatting (catches digit subs like g00gle)
    typo_result_raw = detect_typosquatting(domain_name)
    if typo_result_raw.get("jaro_winkler_score", 0) > typo_result.get("jaro_winkler_score", 0):
        typo_result = typo_result_raw


    combo_result = detect_combosquatting(domain)
    features = extract_features(domain)
    whois_result = analyze_whois_mock(domain)


    # 5. Risk scoring (Rule-based)
    risk = compute_risk_score(features, typo_result, homoglyph_result, combo_result, whois_result)


    # 6. ML classification
    model = get_model()
    fv = build_feature_vector(features, typo_result, homoglyph_result, combo_result, whois_result)
    ml_result = ml_predict(model, fv)


    # 7. Blend ML score into final score if available
    final_score = risk["score"]
    if ml_result["available"] and ml_result["ml_score"] is not None:
        # Weighted blend: 70% rule-based + 30% ML
        final_score = round(risk["score"] * 0.7 + ml_result["ml_score"] * 0.3, 1)
        if final_score >= 70:
            final_risk_level = "High"
        elif final_score >= 40:
            final_risk_level = "Medium"
        else:
            final_risk_level = "Low"
    else:
        final_risk_level = risk["risk_level"]


    # 8. Construct response object
    result = {
        "domain": domain,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "similarity_score": round(final_score / 100, 4),
        "risk_score": final_score,
        "risk_level": final_risk_level,
        "attack_type": risk["attack_type"],
        "domain_age": whois_result["age_str"],
        "domain_age_days": whois_result["age_days"],
        "creation_date": whois_result["creation_date"],
        "registrar": whois_result["registrar"],
        "whois_flag": whois_result["whois_flag"],
        "privacy_protected": whois_result["privacy_protected"],
        "typosquatting": {
            "detected": typo_result["detected"],
            "closest_brand": typo_result["closest_brand"],
            "jaro_winkler_score": typo_result["jaro_winkler_score"],
            "levenshtein_score": typo_result["levenshtein_score"],
            "edit_distance": typo_result["edit_distance"],
        },
        "homoglyph": {
            "detected": homoglyph_result["detected"],
            "count": homoglyph_result["count"],
            "suspicious_chars": homoglyph_result["suspicious_chars"][:5],
            "has_digit_substitution": homoglyph_result["has_digit_substitution"],
            "normalized_domain": homoglyph_result["normalized_domain"],
        },
        "combosquatting": {
            "detected": combo_result["detected"],
            "matched_brands": combo_result["matched_brands"],
            "matched_keywords": combo_result["matched_keywords"],
        },
        "features": {
            "length": features["length"],
            "digit_count": features["digit_count"],
            "digit_ratio": features["digit_ratio"],
            "hyphen_count": features["hyphen_count"],
            "subdomain_count": features["subdomain_count"],
            "suspicious_tld": features["suspicious_tld"],
            "tld": features["tld"],
            "has_suspicious_keywords": features["has_suspicious_keywords"],
            "matched_keywords": features["matched_keywords"],
            "entropy": features["entropy"],
            "is_ip_like": features["is_ip_like"],
        },
        "ml_classification": ml_result,
        "score_breakdown": risk["breakdown"],
    }


    # STEP 3 Integration: Trigger XGB Hook
    run_xgb(build_feature_vector(
        result["features"],
        result["typosquatting"],
        result["homoglyph"],
        result["combosquatting"],
        {
            "age_days": result["domain_age_days"],
            "privacy_protected": result["privacy_protected"],
            "suspicious_registrar": False
        }
    ), result)


    run_external_scans(domain, result)
    return result

# ──────────────────────────────────────────────────────────────────────────────
# API ROUTES
# ──────────────────────────────────────────────────────────────────────────────


@app.route("/", methods=["GET"])
def index():
    """Root endpoint — API info."""
    return jsonify({
        "service": "Suspicious Domain Detection System API",
        "version": "1.0.0",
        "endpoints": {
            "POST /analyze-domain": "Analyze a single domain",
            "POST /analyze-batch":  "Analyze up to 20 domains",
            "GET  /examples":       "Example test domains",
            "GET  /health":         "Service health check",
        }
    })


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    model = get_model()
    return jsonify({
        "status": "ok",
        "service": "Suspicious Domain Detection System",
        "version": "1.0.0",
        "ml_model": "loaded" if model is not None else "unavailable",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@app.route("/analyze-domain", methods=["POST"])
def analyze_domain():
    """Main analysis endpoint for single domains."""

    try:
        # Get request data
        data = request.get_json(silent=True)
        if not data:
            return jsonify({
                "error": "Request body must be JSON."
            }), 400


        # Extract domain
        domain = data.get("domain", "").strip()


        # Validate domain
        is_valid, error_msg = validate_domain(domain)
        if not is_valid:
            return jsonify({
                "error": error_msg
            }), 400


        # Run analysis
        result = run_analysis(domain)


        # 🔥 SAFETY FIX (IMPORTANT)
        # Convert any numpy values to native Python types
        # (handles nested dicts, lists, and float32/int32)
        def convert(obj):
            import numpy as np

            if isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}

            elif isinstance(obj, list):
                return [convert(i) for i in obj]

            elif isinstance(obj, (np.float32, np.float64)):
                return float(obj)

            elif isinstance(obj, (np.int32, np.int64)):
                return int(obj)

            return obj


        result = {k: convert(v) for k, v in result.items()}


        return jsonify(result), 200


    except Exception as e:
        app.logger.error(f"Analysis error for '{domain}': {e}", exc_info=True)

        return jsonify({
            "error": "Internal analysis error. Please try again.",
            "detail": str(e)
        }), 500


@app.route("/analyze-batch", methods=["POST"])
def analyze_batch():
    """Analyze multiple domains (Max 20)."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400


    domains = data.get("domains", [])
    if not isinstance(domains, list) or len(domains) == 0:
        return jsonify({"error": "Provide a non-empty list under 'domains'."}), 400


    if len(domains) > 20:
        return jsonify({"error": "Maximum 20 domains per batch."}), 400


    results = []
    for domain in domains:
        is_valid, err = validate_domain(domain)
        if not is_valid:
            results.append({"domain": domain, "error": err})
            continue
        try:
            results.append(run_analysis(domain))
        except Exception as e:
            results.append({"domain": domain, "error": str(e)})


    return jsonify({"results": results, "count": len(results)}), 200


@app.route("/examples", methods=["GET"])
def examples():
    """Return a list of example domains for testing."""
    return jsonify({
        "examples": [
            {"domain": "paypa1.com",        "expected": "Typosquatting / Homoglyph"},
            {"domain": "gooogle.com",       "expected": "Typosquatting"},
            {"domain": "paypal-login.com",  "expected": "Combo-Squatting"},
            {"domain": "амazon.com",        "expected": "Homoglyph (Cyrillic а)"},
            {"domain": "secure-netflix-verify.xyz", "expected": "Combo-Squatting + Suspicious TLD"},
            {"domain": "faceboook.com",     "expected": "Typosquatting"},
            {"domain": "microsoft-support.tk", "expected": "Combo-Squatting + Suspicious TLD"},
            {"domain": "g00gle.com",        "expected": "Homoglyph (digit substitution)"},
            {"domain": "amazon.com",        "expected": "Legitimate (baseline)"},
            {"domain": "github.com",        "expected": "Legitimate (baseline)"},
        ]
    })


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    print("=" * 60)
    print("  Suspicious Domain Detection System — Backend")
    print("=" * 60)


    # Pre-load or train the ML model on startup
    print("[INIT] Loading ML model...")
    model = get_model()
    if model:
        print("[INIT] ML model ready.")
    else:
        print("[INIT] Running in rule-based mode (no ML).")


    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"

    print(f"[INIT] Starting Flask on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)

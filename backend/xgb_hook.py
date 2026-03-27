from ml_xgboost import load_xgb, predict_xgb

_model = load_xgb()

def run_xgb(feature_vector, result):
    try:
        xgb_result = predict_xgb(_model, feature_vector)

        # Attach XGBoost result
        result["xgb"] = xgb_result

        # ✅ COMBINE SCORES HERE
        if xgb_result.get("xgb_available") and "risk_score" in result:
            rf_score = result["risk_score"]
            xgb_score = xgb_result.get("xgb_score", 0)

            combined_score = round((rf_score * 0.6) + (xgb_score * 0.4), 1)

            result["hybrid_score"] = combined_score

            if combined_score >= 70:
                result["hybrid_risk_level"] = "High"
            elif combined_score >= 40:
                result["hybrid_risk_level"] = "Medium"
            else:
                result["hybrid_risk_level"] = "Low"

        # ✅ DEBUG PRINTS (INSIDE FUNCTION)
        print("XGB RESULT:", xgb_result)
        print("HYBRID SCORE:", result.get("hybrid_score"))

    except Exception as e:
        print("XGB error:", e)
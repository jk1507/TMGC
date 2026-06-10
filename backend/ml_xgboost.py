import os
import pickle
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xgb_model.pkl")

def load_xgb():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return None


def train_xgb(X, y):
    from xgboost import XGBClassifier
    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        eval_metric='logloss'
    )

    model.fit(X_train, y_train)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print("XGBoost trained and saved")
    return model


def predict_xgb(model, feature_vector):
    if model is None:
        return {"xgb_available": False}

    vec = np.array(feature_vector).reshape(1, -1)
    proba = float(model.predict_proba(vec)[0][1])

    return {
        "xgb_available": True,
        "xgb_score": round(proba * 100, 1),
        "xgb_verdict": "Phishing" if proba >= 0.5 else "Legitimate"
    }

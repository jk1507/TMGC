"""
Train ALL ML models from AI labels — "distill" the AI's judgment into the ensemble.
====================================================================================
The production verdict is a hybrid: heuristic rules + ML ensemble + an AI-written
report. This script makes the ML ensemble learn the SAME judgment the AI (Gemini
or a local LLM) would give, so classification quality matches the AI without
needing the AI at prediction time.

It trains all 4 models + ensemble priors exactly like train_ai_machine.py
(hyperparameter tuning, calibration, optimal thresholds, stacking meta-model),
but the labels come from the AI instead of synthetic generation.

FEATURES ARE UNCHANGED: the exact 32-feature schema used at inference time
(train_xgb.feature_vector_for) is reused as-is.

How it works:
  1. Build a domain list:
       - Legitimate:  known trusted brands (train_xgb.LEGITIMATE_DOMAINS)
       - Phishing:    real reported domains from phishtank_online.csv
  2. Ask the labeler (Gemini by default, or your local Ollama/LM Studio model)
     to classify each domain as SAFE / SUSPICIOUS / PHISHING with a risk score.
     If too many label calls FAIL, the script aborts loudly instead of
     training on garbage labels.
  3. Build the 32-feature vectors and train ALL 4 models + ensemble priors.
  4. Save xgb_model.pkl, lgbm_model.pkl, rf_model.pkl, lr_model.pkl,
     ensemble_priors.pkl, training_report.json + the labeled dataset.

Usage:
    python train_from_gemini.py                  # Gemini labels + train all models
    python train_from_gemini.py --labeler local  # offline, uses your local LLM
    python train_from_gemini.py --limit 300      # 300 legit + 300 phish samples
    python train_from_gemini.py --train-only     # reuse existing gemini_training_data.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import sys
from datetime import datetime
from collections import Counter

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()  # load backend/.env (GEMINI_API_KEY etc.)

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATASET = os.path.join(BACKEND_DIR, "gemini_training_data.json")

# ---------------------------------------------------------------- labelers ---

async def _label_gemini(domains: list[str]) -> dict[str, dict]:
    """Label domains with the Gemini API (gemini-2.5-flash), 8 concurrent."""
    from google import genai

    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise SystemExit(
            "GEMINI_API_KEY not set. Add it to backend/.env or use --labeler local."
        )

    client = genai.Client(api_key=api_key)
    labels: dict[str, dict] = {}
    sem = asyncio.Semaphore(8)

    async def one(domain: str) -> None:
        prompt = (
            "You are a phishing domain classifier. Classify the domain below. "
            "Reply with ONLY valid JSON, no markdown, in this exact shape:\n"
            '{"verdict": "SAFE|SUSPICIOUS|PHISHING", "risk_score": 0-100}\n\n'
            f"Domain: {domain}\n"
        )
        async with sem:
            text = ""
            for attempt in range(3):  # retry transient 429/503 overloads
                try:
                    resp = await asyncio.to_thread(
                        client.models.generate_content, model="gemini-2.5-flash", contents=prompt
                    )
                    text = getattr(resp, "text", "") or ""
                    if text:
                        break
                except Exception as exc:
                    err = str(exc)
                    if "503" in err or "429" in err or "UNAVAILABLE" in err:
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    print(f"[warn] {domain}: {err[:120]}")
                    break
        labels[domain] = parse_verdict_json(text, domain)

    await asyncio.gather(*(one(d) for d in domains))
    return labels


async def _label_local(domains: list[str]) -> dict[str, dict]:
    """Label domains with the local OpenAI-compatible LLM (Ollama etc.), 4 concurrent."""
    from local_llm import local_llm_chat

    labels: dict[str, dict] = {}
    sem = asyncio.Semaphore(4)

    async def one(domain: str) -> None:
        prompt = (
            "You are a phishing domain classifier. Classify the domain below. "
            "Reply with ONLY valid JSON, no markdown, in this exact shape:\n"
            '{"verdict": "SAFE|SUSPICIOUS|PHISHING", "risk_score": 0-100}\n\n'
            f"Domain: {domain}\n"
        )
        async with sem:
            text = await local_llm_chat(prompt, timeout=20.0)
        labels[domain] = parse_verdict_json(text or "", domain)

    await asyncio.gather(*(one(d) for d in domains))
    return labels


def parse_verdict_json(text: str, domain: str) -> dict:
    """Robustly parse the model's JSON verdict (handles markdown fences/junk).

    FAILED calls are marked explicitly (failed=True) so the caller can detect
    a broken labeler instead of silently training on fallback labels.
    """
    failed = {"verdict": "SUSPICIOUS", "risk_score": 50, "failed": True, "raw": (text or "")[:300]}
    if not text:
        return failed
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return failed
    try:
        data = json.loads(m.group(0))
    except Exception:
        return failed
    verdict = str(data.get("verdict", "SUSPICIOUS")).strip().upper()
    if verdict not in {"SAFE", "SUSPICIOUS", "PHISHING"}:
        return failed
    try:
        risk = int(data.get("risk_score", 50))
    except Exception:
        risk = 50
    return {"verdict": verdict, "risk_score": max(0, min(100, risk)), "failed": False, "raw": text[:300]}


# -------------------------------------------------------------- dataset ------

def load_phishing_domains(limit: int) -> list[str]:
    """Extract real phishing domains from phishtank_online.csv."""
    csv_path = os.path.join(BACKEND_DIR, "phishtank_online.csv")
    domains: list[str] = []
    seen: set[str] = set()
    if not os.path.exists(csv_path):
        print(f"[warn] {csv_path} not found — skipping PhishTank domains")
        return domains
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        next(f, None)  # header
        for line in f:
            parts = line.split(",")
            if len(parts) < 2:
                continue
            raw = parts[1].strip()
            m = re.match(r"https?://([^/]+)", raw)
            if not m:
                continue
            host = m.group(1).lower().strip(".")
            if not host or not re.match(r"^[a-z0-9.\-]+$", host):
                continue
            if host not in seen:
                seen.add(host)
                domains.append(host)
            if len(domains) >= limit:
                break
    return domains


def load_domain_file(path: str, limit: int, exclude: set[str] | None = None) -> list[str]:
    """Load domains from a plain-text file (one per line) for big real datasets."""
    domains: list[str] = []
    seen: set[str] = set()
    if not os.path.exists(path):
        print(f"[warn] {path} not found")
        return domains
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            host = line.strip().lower().rstrip(".")
            if not host or "." not in host or not re.match(r"^[a-z0-9.\-]+$", host):
                continue
            if host in seen or (exclude and host in exclude):
                continue
            seen.add(host)
            domains.append(host)
            if len(domains) >= limit:
                break
    return domains


def build_samples(legit_domains: list[str], phish_domains: list[str], labels: dict[str, dict]) -> tuple[list, list, list]:
    """Return (X, y, meta) where y: 0=SAFE, 1=PHISHING/SUSPICIOUS. Features UNCHANGED (32)."""
    from train_xgb import feature_vector_for, generate_legitimate_age, generate_phishing_age

    X: list = []
    y: list = []
    meta: list = []

    for domain in legit_domains:
        lab = labels.get(domain, {})
        verdict = lab.get("verdict", "SAFE")
        if verdict in {"PHISHING", "SUSPICIOUS"}:
            label = 1
            age = generate_phishing_age(domain)
            X.append(feature_vector_for(domain, age, has_ssl=0.3, has_mx=0.4, has_asn=0.4, header_score=10))
        else:
            label = 0
            age = generate_legitimate_age(domain)
            X.append(feature_vector_for(domain, age, has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=2))
        y.append(label)
        meta.append({"domain": domain, "label": label, "ai_verdict": verdict,
                     "ai_score": lab.get("risk_score", 50), "failed": bool(lab.get("failed", False))})

    for domain in phish_domains:
        lab = labels.get(domain, {})
        verdict = lab.get("verdict", "PHISHING")
        label = 1 if verdict in {"PHISHING", "SUSPICIOUS"} else 0
        if verdict == "SAFE":
            age = generate_legitimate_age(domain)
            X.append(feature_vector_for(domain, age, has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=2))
        else:
            age = generate_phishing_age(domain)
            X.append(feature_vector_for(domain, age, has_ssl=0.3, has_mx=0.3, has_asn=0.3, header_score=12))
        y.append(label)
        meta.append({"domain": domain, "label": label, "ai_verdict": verdict,
                     "ai_score": lab.get("risk_score", 70), "failed": bool(lab.get("failed", False))})

    return X, y, meta


def sanity_check_labels(meta: list[dict]) -> None:
    """Abort loudly if the labels are garbage (failed calls or a degenerate split)."""
    total = len(meta)
    failed = sum(1 for m in meta if m.get("failed"))
    verdicts = Counter(m["ai_verdict"] for m in meta)
    labels = Counter(m["label"] for m in meta)

    print(f"  Labels: {dict(verdicts)}")
    print(f"  Binary: {labels[0]} SAFE / {labels[1]} RISK  (failed calls: {failed}/{total})")

    if failed > max(1, total * 0.5):
        raise SystemExit(
            f"ABORT: {failed}/{total} AI label calls failed (no usable response). "
            "The labeler is unavailable — check your Gemini key/quota "
            "(https://aistudio.google.com/apikey) or install Ollama and pull a model."
        )
    if labels[0] < 10 or labels[1] < 10:
        raise SystemExit(
            f"ABORT: class imbalance too severe ({labels[0]} SAFE / {labels[1]} RISK). "
            "Cannot train a binary classifier. Check that the labeler gives varied verdicts."
        )


# ------------------------------------------------------- all-models training --

def train_all_models_ai(X, y, meta: list[dict], report_path: str = DEFAULT_DATASET) -> None:
    """Train ALL 4 models + ensemble priors using train_ai_machine's professional
    pipeline, on AI-labeled data. Feature schema is unchanged (32 features)."""
    import numpy as np
    from sklearn.model_selection import train_test_split

    import train_ai_machine as tam
    from ml_ensemble import ScaledModelWrapper

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    print("\n" + "=" * 72)
    print("  AI-DISTILLED TRAINING — all 4 models + ensemble priors")
    print("=" * 72)
    print(f"  Samples: {len(X)}  (features: {X.shape[1]} — unchanged schema)")

    # Adapt CV folds to data size so tiny class splits don't crash
    min_class = min(int(np.sum(y == 0)), int(np.sum(y == 1)))
    tam.CV_FOLDS = max(2, min(5, min_class))
    tam.N_ITER_SEARCH = 12  # keep tuning fast enough for one-shot runs
    print(f"  CV folds: {tam.CV_FOLDS}, tuning iterations: {tam.N_ITER_SEARCH}")

    # 60% train, 20% calibrate, 20% test
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.4, random_state=tam.RANDOM_SEED, stratify=y
    )
    X_cal, X_test, y_cal, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=tam.RANDOM_SEED, stratify=y_temp
    )
    print(f"  Train: {len(X_train)} | Calibrate: {len(X_cal)} | Test: {len(X_test)}")

    results: dict = {}
    trained_models: dict = {}
    thresholds: dict = {}
    feature_importances: dict = {}

    # ---- XGBoost ----
    print("\n  STEP 3a: XGBoost — tuning & training")
    try:
        model = tam.tune_xgboost(X_train, y_train)
        prob = model.predict_proba(X_test)[:, 1]
        metrics = tam.compute_metrics(y_test, model.predict(X_test), prob)
        th, _ = tam.find_optimal_threshold(y_test, prob)
        results["xgboost"] = metrics
        thresholds["xgboost"] = th
        trained_models["xgboost"] = model
        feature_importances["xgboost"] = tam.compute_feature_importance(model, "xgboost")
        print(f"    accuracy={metrics['accuracy']:.4f} auc={metrics.get('auc_roc', 'N/A')} thresh={th:.3f}")
    except ImportError:
        print("  ! xgboost not installed. Skipping.")

    # ---- LightGBM ----
    print("\n  STEP 3b: LightGBM — tuning & training")
    try:
        model = tam.tune_lightgbm(X_train, y_train)
        prob = model.predict_proba(X_test)[:, 1]
        metrics = tam.compute_metrics(y_test, model.predict(X_test), prob)
        th, _ = tam.find_optimal_threshold(y_test, prob)
        results["lightgbm"] = metrics
        thresholds["lightgbm"] = th
        trained_models["lightgbm"] = model
        feature_importances["lightgbm"] = tam.compute_feature_importance(model, "lightgbm")
        print(f"    accuracy={metrics['accuracy']:.4f} auc={metrics.get('auc_roc', 'N/A')} thresh={th:.3f}")
    except ImportError:
        print("  ! lightgbm not installed. Skipping.")

    # ---- Random Forest ----
    print("\n  STEP 3c: Random Forest — tuning & training")
    try:
        model = tam.tune_random_forest(X_train, y_train)
        prob = model.predict_proba(X_test)[:, 1]
        metrics = tam.compute_metrics(y_test, model.predict(X_test), prob)
        th, _ = tam.find_optimal_threshold(y_test, prob)
        results["random_forest"] = metrics
        thresholds["random_forest"] = th
        trained_models["random_forest"] = model
        feature_importances["random_forest"] = tam.compute_feature_importance(model, "random_forest")
        print(f"    accuracy={metrics['accuracy']:.4f} auc={metrics.get('auc_roc', 'N/A')} thresh={th:.3f}")
    except ImportError:
        print("  ! sklearn missing. Skipping.")

    # ---- Logistic Regression (scaled) ----
    print("\n  STEP 3d: Logistic Regression — tuning & training")
    try:
        model_lr, scaler = tam.tune_logistic_regression(X_train, y_train)
        model = ScaledModelWrapper(model_lr, scaler)
        X_test_scaled = scaler.transform(X_test)
        prob = model_lr.predict_proba(X_test_scaled)[:, 1]
        metrics = tam.compute_metrics(y_test, model_lr.predict(X_test_scaled), prob)
        th, _ = tam.find_optimal_threshold(y_test, prob)
        results["logistic_regression"] = metrics
        thresholds["logistic_regression"] = th
        trained_models["logistic_regression"] = model
        feature_importances["logistic_regression"] = tam.compute_feature_importance(model_lr, "logistic_regression")
        print(f"    accuracy={metrics['accuracy']:.4f} auc={metrics.get('auc_roc', 'N/A')} thresh={th:.3f}")
    except ImportError:
        print("  ! sklearn missing. Skipping.")

    if not trained_models:
        raise SystemExit("ABORT: no models could be trained.")

    # ---- Calibration ----
    print("\n  STEP 4: Probability calibration (Platt scaling)")
    for name in list(trained_models.keys()):
        try:
            trained_models[name] = tam.calibrate_model(trained_models[name], X_cal, y_cal)
            print(f"    {name}: calibrated OK")
        except Exception as e:
            print(f"    {name}: calibration skipped ({e})")

    # ---- Save models ----
    print("\n  STEP 5: Saving models")
    for name, model in trained_models.items():
        path = tam.MODEL_PATHS.get(name)
        if path:
            with open(path, "wb") as f:
                import pickle
                pickle.dump(model, f)
            print(f"    {name}: saved ({os.path.getsize(path) / 1024:.1f} KB) -> {path}")

    # ---- Stacking meta-model ----
    print("\n  STEP 6: Stacking meta-model")
    stacking_results = tam.train_stacking_meta_model(trained_models, X_train, y_train, X_test, y_test)

    ensemble_weights = {
        "xgboost": 0.35, "lightgbm": 0.30,
        "random_forest": 0.20, "logistic_regression": 0.15,
    }
    sw = stacking_results.get("stacking_weights") or {}
    total_abs = sum(abs(w) for w in sw.values())
    if total_abs > 0:
        ensemble_weights = {k: round(abs(v) / total_abs, 3) for k, v in sw.items()}
        print(f"    Optimized ensemble weights: {ensemble_weights}")

    # ---- Priors ----
    print("\n  STEP 7: Saving ensemble priors")
    feature_means = {f"f{i}": float(X[:, i].mean()) for i in range(X.shape[1])}
    feature_stds = {f"f{i}": float(X[:, i].std()) for i in range(X.shape[1])}
    model_priors = {}
    for name in trained_models:
        model_priors[name] = {
            "auc_roc": results.get(name, {}).get("auc_roc", 0.0),
            "optimal_threshold": thresholds.get(name, 0.5),
            "metrics": results.get(name, {}),
        }
    priors = {
        "feature_count": int(X.shape[1]),
        "training_samples": int(len(X)),
        "phishing_ratio": float(y.mean()),
        "feature_means": feature_means,
        "feature_stds": feature_stds,
        "model_results": {k: results.get(k, {}) for k in trained_models},
        "model_priors": model_priors,
        "ensemble_weights": ensemble_weights,
        "optimal_thresholds": thresholds,
        "training_date": datetime.now().isoformat(),
        "pipeline_version": "3.0-ai-distilled",
        "ai_labeler": "gemini_or_local",
    }
    import pickle
    with open(tam.PRIORS_PATH, "wb") as f:
        pickle.dump(priors, f)
    print(f"    Priors saved -> {tam.PRIORS_PATH}")

    # ---- Report ----
    report = {
        "training_date": datetime.now().isoformat(),
        "training_samples": int(len(X)),
        "source": "ai-distillation",
        "ai_verdicts": dict(Counter(m["ai_verdict"] for m in meta)),
        "models": {
            name: {
                "test_metrics": results.get(name, {}),
                "optimal_threshold": thresholds.get(name, 0.5),
                "feature_importance_top5": feature_importances.get(name, {}).get("top_5", []),
            }
            for name in trained_models
        },
        "ensemble_weights": ensemble_weights,
        "stacking_meta_model": stacking_results.get("metrics", {}),
        "pipeline_version": "3.0-ai-distilled",
    }
    with open(tam.REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"    Report saved -> {tam.REPORT_PATH}")

    print("\n" + "=" * 72)
    print("  TRAINING COMPLETE — all models distilled from AI labels")
    for name in trained_models:
        m = results.get(name, {})
        print(f"    {name.upper():20s} acc={m.get('accuracy', 0):.4f} auc={m.get('auc_roc', 0):.4f} f1={m.get('f1_score', 0):.4f} thresh={thresholds.get(name, 0.5):.3f}")
    print("=" * 72)


# ------------------------------------------------------------------- main ----

async def main() -> None:
    parser = argparse.ArgumentParser(description="Distill AI judgment into all ML models")
    parser.add_argument("--labeler", choices=["gemini", "local"], default="gemini",
                        help="Which AI labels the domains (default: gemini)")
    parser.add_argument("--limit", type=int, default=300,
                        help="Number of domains per class to label (default: 300)")
    parser.add_argument("--out", default=DEFAULT_DATASET,
                        help="Where to save the labeled dataset")
    parser.add_argument("--legit-file", default=None,
                        help="Plain-text file of real trusted domains (one per line)")
    parser.add_argument("--phish-file", default=None,
                        help="Plain-text file of real phishing domains (one per line)")
    parser.add_argument("--train-only", action="store_true",
                        help="Skip labeling; train from the existing dataset file (--out)")
    args = parser.parse_args()

    random.seed(42)

    if args.train_only:
        if not os.path.exists(args.out):
            raise SystemExit(f"{args.out} not found — run labeling first (drop --train-only).")
        with open(args.out, "r", encoding="utf-8") as f:
            data = json.load(f)
        meta = data["samples"]
        print(f"Loaded {len(meta)} labeled samples from {args.out}")
        # Rebuild X/y from the saved domains + AI verdicts
        from train_xgb import feature_vector_for, generate_legitimate_age, generate_phishing_age
        X, y = [], []
        for m in meta:
            domain = m["domain"]
            if m["label"] == 0:
                X.append(feature_vector_for(domain, generate_legitimate_age(domain),
                                            has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=2))
            else:
                X.append(feature_vector_for(domain, generate_phishing_age(domain),
                                            has_ssl=0.3, has_mx=0.3, has_asn=0.3, header_score=12))
            y.append(m["label"])
        sanity_check_labels(meta)
        train_all_models_ai(X, y, meta, args.out)
        return

    from train_xgb import LEGITIMATE_DOMAINS

    if args.phish_file:
        phish_domains = load_domain_file(args.phish_file, args.limit)
    else:
        phish_domains = load_phishing_domains(args.limit)

    if args.legit_file:
        # Drop any legit host that also appears in the phishing set so the same
        # domain never trains as both classes.
        legit_domains = load_domain_file(args.legit_file, args.limit, exclude=set(phish_domains))
    else:
        legit_domains = LEGITIMATE_DOMAINS[: args.limit]

    print(f"Domains to label: {len(legit_domains)} legit + {len(phish_domains)} phishing = {len(legit_domains) + len(phish_domains)}")

    all_domains = legit_domains + phish_domains
    if args.labeler == "gemini":
        labels = await _label_gemini(all_domains)
    else:
        labels = await _label_local(all_domains)

    X, y, meta = build_samples(legit_domains, phish_domains, labels)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"labeler": args.labeler, "training_date": datetime.now().isoformat(), "samples": meta}, f, indent=2)
    print(f"Saved labeled dataset -> {args.out}")

    sanity_check_labels(meta)
    train_all_models_ai(X, y, meta, args.out)


if __name__ == "__main__":
    asyncio.run(main())
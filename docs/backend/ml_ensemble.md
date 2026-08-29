# backend/ml_ensemble.py - Ensemble ML Module

Combines predictions from multiple ML models for robust threat classification.

## Models Used
- **XGBoost**: Primary gradient-boosted tree (weight: 0.35)
- **LightGBM**: Fast gradient-boosted tree (weight: 0.30)
- **Random Forest**: Ensemble of decision trees (weight: 0.20)
- **Logistic Regression**: Linear baseline (weight: 0.15)

## Classes

### `ScaledModelWrapper`
Wraps a model with StandardScaler for transparent inference.
- Used by Logistic Regression which requires feature scaling

## Functions

### `ensemble_predict(feature_vector, models=None, weights=None)`
Run ensemble prediction using all available models.

**Args:**
- `feature_vector`: 32-element feature vector
- `models`: Optional pre-loaded models dict
- `weights`: Optional custom model weights

**Returns dict with:**
- `ensemble_verdict`: phishing/suspicious/uncertain/legitimate
- `ensemble_score`: 0-100 weighted score
- `model_count`: Number of available models
- `available_models`: List of model names
- `model_predictions`: Per-model scores
- `model_agreement`: Percentage of models within 0.15 of mean
- `confidence`: 50-98 based on entropy
- `entropy`: Shannon entropy metrics
- `kl_divergence`: KL divergence between models
- `beta_interval`: Bayesian credible interval
- `cohens_kappa`: Inter-model agreement
- `bma`: Bayesian Model Averaging results

### `_compute_entropy(probabilities)`
Shannon entropy of prediction probabilities (0 bits = certain, 1 bit = max uncertainty).

### `_compute_kl_divergence(p, q)`
KL divergence between two probability distributions.

### `_compute_beta_interval(successes, trials, ...)`
Bayesian credible interval using Beta distribution.

### `_compute_cohens_kappa(p1, p2, threshold=0.5)`
Inter-model agreement coefficient.

### `_compute_bayes_factor(best_proba, worst_proba)`
Bayes factor comparing best vs worst model predictions.

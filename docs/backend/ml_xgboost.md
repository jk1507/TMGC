# backend/ml_xgboost.py - XGBoost ML Model

XGBoost-based phishing detection model with 32 engineered features.

## Functions

### `load_xgb()`
Load trained XGBoost model from pickle file.
- Returns: Trained model or None if not found

### `_load_xgb_threshold(default=0.70)`
Load optimal prediction threshold from ensemble priors.
- Returns: Threshold float (default 0.70)

### `train_xgb(X, y)`
Train XGBoost classifier with optimized hyperparameters.
- Features: 400 trees, max_depth=6, learning_rate=0.06
- Includes probability calibration
- Saves model to xgb_model.pkl

### `predict_xgb(model, feature_vector)`
Run prediction on 32-element feature vector.
- Returns dict with:
  - `xgb_available`: bool
  - `xgb_score`: 0-100 phishing probability
  - `xgb_verdict`: Phishing/Suspicious/Uncertain/Legitimate
  - `thresholds`: dict of classification thresholds

## Feature Vector (32 elements)

| Index | Feature | Description |
|-------|---------|-------------|
| 0 | length | Normalized domain length |
| 1 | digit_ratio | Ratio of digits in domain |
| 2 | hyphen_count | Normalized hyphen count |
| 3 | subdomain_count | Subdomain depth |
| 4 | entropy | Shannon entropy |
| 5 | consonant_ratio | Consonant-to-letter ratio |
| 6 | suspicious_tld | Suspicious TLD flag |
| 7 | has_keywords | Brand keyword presence |
| 8 | is_ip_like | IP address pattern |
| 9 | excessive_hyphens | 3+ hyphens flag |
| 10 | jaro_winkler | Jaro-Winkler similarity |
| 11 | levenshtein | Levenshtein similarity |
| 12 | edit_distance | Normalized edit distance |
| 13 | typosquatting | Typosquatting detected |
| 14 | homoglyph | Homoglyph detected |
| 15 | homoglyph_count | Number of homoglyphs |
| 16 | digit_substitution | Digit-for-letter substitution |
| 17 | combosquatting | Combosquatting detected |
| 18 | brand_only | Brand without keywords |
| 19 | keyword_count | Phishing keyword count |
| 20 | age_log | Log-normalized domain age |
| 21 | privacy | WHOIS privacy detected |
| 22 | suspicious_reg | Suspicious registrar |
| 23 | jaro_raw | Jaro-Winkler (unnormalized) |
| 24 | label_changed | Normalization changed label |
| 25 | consecutive_digits | Max consecutive digits |
| 26 | tld_score | TLD risk score (0-1) |
| 27 | unique_tokens | Unique tokens in label |
| 28 | has_valid_ssl | SSL certificate valid |
| 29 | has_mx | MX records present |
| 30 | has_asn | ASN data available |
| 31 | header_score_norm | Security header deficit |

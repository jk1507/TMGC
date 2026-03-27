# Suspicious Domain Detection System (SDDS)

A production-ready phishing and malicious domain detection engine combining
rule-based heuristics with machine learning.

---

## Project Structure

```
project/
├── backend/
│   ├── app.py          — Flask API server
│   ├── utils.py        — Core detection logic
│   ├── ml_model.py     — ML classifier (RandomForest)
│   ├── model.pkl       — Trained model (auto-generated on first run)
│   └── requirements.txt
├── frontend/
│   ├── index.html      — Main UI
│   ├── styles.css      — Dark terminal aesthetic
│   └── script.js       — API integration + rendering
└── README.md
```

---

## Features

| Feature | Implementation |
|---|---|
| Typosquatting | Levenshtein distance + Jaro-Winkler similarity |
| Homoglyph attack | Unicode confusable character map |
| Combo-squatting | Brand + keyword pattern matching |
| Domain features | Entropy, digit ratio, TLD, hyphens, subdomains |
| WHOIS analysis | Domain age estimation, registrar flagging |
| ML classification | RandomForest (23 features, scikit-learn) |
| Risk scoring | Weighted multi-signal scoring (0–100) |
| Real-time monitor | Background monitoring simulation |
| Alert system | Console + UI banner for High-risk domains |

---

## Installation

### 1. Clone and navigate

```bash
cd project/backend
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Backend

```bash
cd project/backend
python app.py
```

The server starts at `http://localhost:5000`.

On first run it will automatically train and save `model.pkl`.

To retrain the model manually:

```bash
python ml_model.py
```

---

## Running the Frontend

Open `project/frontend/index.html` in any modern browser.

> **CORS note**: The Flask app allows all origins by default.
> For production, restrict CORS to your actual domain.

If you want to serve via a local HTTP server:

```bash
cd project/frontend
python -m http.server 8080
# then open http://localhost:8080
```

---

## API Reference

### POST /analyze-domain

```bash
curl -X POST http://localhost:5000/analyze-domain \
  -H "Content-Type: application/json" \
  -d '{"domain": "paypa1.com"}'
```

Response:

```json
{
  "domain": "paypa1.com",
  "similarity_score": 0.92,
  "risk_score": 87.4,
  "risk_level": "High",
  "attack_type": "Homoglyph Attack",
  "domain_age": "12 days",
  "whois_flag": "Suspicious",
  "typosquatting": { "detected": true, "closest_brand": "paypal", "jaro_winkler_score": 0.93 },
  "homoglyph": { "detected": true, "count": 1, "has_digit_substitution": true },
  "combosquatting": { "detected": false },
  "ml_classification": { "available": true, "ml_score": 91.2, "ml_verdict": "Phishing" }
}
```

### POST /analyze-batch

```bash
curl -X POST http://localhost:5000/analyze-batch \
  -H "Content-Type: application/json" \
  -d '{"domains": ["paypa1.com", "amazon.com", "gooogle.com"]}'
```

### GET /examples

```bash
curl http://localhost:5000/examples
```

### GET /health

```bash
curl http://localhost:5000/health
```

---

## Test Domains

| Domain | Expected Detection |
|---|---|
| `paypa1.com` | Homoglyph + Typosquatting |
| `gooogle.com` | Typosquatting |
| `paypal-login.com` | Combo-Squatting |
| `g00gle.com` | Digit Substitution |
| `secure-netflix-verify.xyz` | Combo-Squatting + Suspicious TLD |
| `faceboook.com` | Typosquatting |
| `microsoft-support.tk` | Combo-Squatting + Suspicious TLD |
| `amazon.com` | Legitimate (baseline) |

---

## Architecture

```
Frontend (HTML/CSS/JS)
       │  fetch() POST /analyze-domain
       ▼
Flask API (app.py)
       │
       ├── utils.py
       │    ├── validate_domain()
       │    ├── detect_typosquatting()    ← Levenshtein + Jaro-Winkler
       │    ├── detect_homoglyphs()       ← Unicode confusable map
       │    ├── detect_combosquatting()   ← Brand × keyword matching
       │    ├── extract_features()        ← Entropy, length, TLD, etc.
       │    ├── analyze_whois_mock()      ← Domain age + registrar
       │    └── compute_risk_score()      ← Weighted combination
       │
       └── ml_model.py
            ├── build_feature_vector()   ← 23 numeric features
            └── ml_predict()             ← RandomForest classifier
```

---

## Notes

- **WHOIS data is simulated** for portability. Replace `analyze_whois_mock()` in `utils.py` with
  `python-whois` for live data: `pip install python-whois`
- The ML model trains on **synthetic data** that mirrors real phishing patterns.
  For production, use the UCI Phishing Dataset or a labeled live dataset.
- All frontend/backend communication is over **localhost** in development mode.
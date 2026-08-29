# RETRO_INTEL — How It Works

## What Is This Project?

**RETRO_INTEL** is a phishing and malicious domain detection system. You give it a website address (domain name), and it tells you whether that domain is **safe**, **suspicious**, or a **phishing scam**.

Think of it like a security scanner for website addresses — it checks dozens of signals to figure out if a domain is trying to trick you.

---

## Simple Example

```
You type:    paypa1.com
System says: ⚠️ RISK SCORE: 100/100 — PHISHING
Reason:      Looks like "paypal.com" but uses the number 1 instead of the letter l.
```

---

## How Does It Work? (Step by Step)

When you enter a domain, the system runs **7 major checks** in parallel:

```
You enter: paypa1.com
         │
         ▼
┌─────────────────────────────────────────────────────┐
│           STEP 1: DOMAIN NAME ANALYSIS              │
│  (Runs instantly — no network needed)                │
│                                                     │
│  • Is it trying to look like a famous brand?        │
│  • Are there weird characters (homoglyphs)?         │
│  • Is the TLD suspicious (.xyz, .top, .tk)?         │
│  • Is the domain too long or has too many hyphens?  │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           STEP 2: DNS & NETWORK LOOKUPS             │
│  (Takes 1-3 seconds)                                │
│                                                     │
│  • What IP address does this domain point to?       │
│  • Does it have email (MX) records?                 │
│  • Who owns the IP? (hosting provider, country)     │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           STEP 3: WHOIS & DOMAIN AGE                │
│  (Takes 1-2 seconds)                                │
│                                                     │
│  • When was this domain registered?                 │
│  • Is it brand new? (phishing domains are new)      │
│  • Who is the registrar? (suspicious ones exist)    │
│  • Is WHOIS privacy enabled? (red flag)             │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           STEP 4: SSL CERTIFICATE CHECK             │
│  (Takes 1-2 seconds)                                │
│                                                     │
│  • Does the site have a valid SSL certificate?      │
│  • Is the certificate expired or self-signed?       │
│  • Who issued it? (free CAs are often abused)       │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           STEP 5: HTTP SECURITY HEADERS             │
│  (Takes 1-2 seconds)                                │
│                                                     │
│  • Does it have security headers like HSTS, CSP?    │
│  • Missing headers = suspicious (phishers don't     │
│    bother setting them up)                          │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           STEP 6: ML & AI ANALYSIS                  │
│  (Runs in background)                               │
│                                                     │
│  • XGBoost ML model scores 32 features              │
│  • Ensemble of 4 ML models vote together            │
│  • Google Gemini AI writes a detailed report        │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           STEP 7: SCORING & VERDICT                 │
│  (Instant)                                          │
│                                                     │
│  • Combines ALL signals into one final score        │
│  • Produces: SAFE / SUSPICIOUS / PHISHING           │
│  • Generates detailed findings list                 │
└─────────────────────────────────────────────────────┘
```

---

## Technologies Used

### Backend (Python)

| Technology | What It Does | Why It's Used |
|---|---|---|
| **FastAPI** | Web server framework | Fast, modern API server for handling requests |
| **uvicorn** | ASGI server | Runs the FastAPI app on your machine |
| **XGBoost** | Machine Learning model | Trained on phishing data to classify domains |
| **scikit-learn** | ML utilities | Probability calibration, cross-validation |
| **numpy** | Number crunching | Fast math operations for feature vectors |
| **python-whois** | Domain registration lookup | Gets domain age, registrar, nameservers |
| **dnspython** | DNS queries | Resolves domain to IP, finds MX records |
| **cryptography** | SSL/TLS parsing | Reads SSL certificate details |
| **google-genai** | Google Gemini AI | Writes human-readable security reports |
| **Playwright** (optional) | Browser automation | Visits the actual website to detect phishing forms |
| **rapidfuzz** | Text matching | Compares domain names to known brands |
| **imagehash** | Image analysis | Compares website screenshots to brand logos |
| **networkx** | Graph analysis | Maps relationships between domains |

### Frontend (React)

| Technology | What It Does |
|---|---|
| **React 19** | User interface framework |
| **Vite** | Fast build tool and dev server |
| **xlsx** | Export results to Excel |
| **jspdf** | Export reports as PDF |

---

## What Each Detection Module Does

### 1. Typosquatting Detection
**File:** `utils.py` → `detect_typosquatting()`

Catches domains that are slight misspellings of real brands.

```
Technique: Jaro-Winkler similarity + Levenshtein distance
Example:   faceboook.com → detects "facebook" with edit distance 1
```

### 2. Homoglyph Attack Detection
**File:** `utils.py` → `detect_homoglyphs()`

Catches domains using Unicode look-alike characters.

```
Technique: Unicode confusable character mapping
Example:   gооgle.com (Cyrillic "о" instead of Latin "o")
           paypa1.com (digit "1" instead of letter "l")
```

### 3. Combo-Squatting Detection
**File:** `utils.py` → `detect_combosquatting()`

Catches domains that combine a real brand name with suspicious keywords.

```
Technique: Brand name + phishing keyword matching
Example:   paypal-login.com (brand "paypal" + keyword "login")
           amazon-verify-account.xyz (brand + "verify" + "account")
```

### 4. SSL/TLS Analysis
**File:** `utils.py` → `analyze_ssl_signals()`

Checks the domain's security certificate.

```
Checks: Expired? Self-signed? Hostname mismatch?
        Weak protocol (TLS 1.0)? Weak cipher?
```

### 5. Redirect Chain Analysis
**File:** `utils.py` → `analyze_redirect_chain()`

Follows redirects to see where the domain actually sends you.

```
Example:   login.paypa1.com → → → → some-random-server.com
           (4 redirects = suspicious)
```

### 6. Certificate Transparency Logs
**File:** `utils.py` → `analyze_certificate_transparency()`

Checks public certificate records for suspicious patterns.

```
Checks: How many subdomains? Recent rapid certificate issuance?
        Suspicious Certificate Authorities?
```

### 7. DNS Record Analysis
**File:** `utils.py` → `analyze_dns_records()`

Deep analysis of all DNS records.

```
Checks: SPF? DKIM? DMARC? (email security)
        Wildcard DNS? (any subdomain resolves = risky)
        DNSSEC? (DNS authentication)
```

### 8. Brand Impersonation Detection
**File:** `brand_impersonation.py`

Detects if a domain is pretending to be a known brand.

```
Checks: Domain name similarity to brands
        SSL issuer mismatch (bank SSL on non-bank domain)
        Login form harvesting detection
        Social profile cross-referencing
```

### 9. Entity Attribution
**File:** `owner_image_detection.py`

Tries to figure out who actually owns the domain.

```
Technique: WHOIS email → Gravatar lookup
           Username → GitHub profile lookup
           Social media presence detection
```

### 10. Fast-Flux & DGA Detection
**File:** `fast_flux_dga.py`

Detects advanced evasion techniques.

```
Fast-Flux: Domain rapidly changes IP addresses (botnet pattern)
DGA:       Domain name looks randomly generated (Domain Generation Algorithm)
```

### 11. Threat Intelligence Feeds
**File:** `threat_intel.py`

Checks the domain against known threat databases.

```
Sources:  URLhaus (abuse.ch)
          Google Safe Browsing
          PhishTank
          VirusTotal
          AbuseIPDB
          URLScan
```

### 12. Ensemble ML (4 Models Vote)
**File:** `ml_ensemble.py`

Combines predictions from multiple ML models.

```
Models:   XGBoost + LightGBM + Random Forest + Logistic Regression
Method:   Weighted voting based on each model's accuracy
Output:   Final phishing probability score
```

---

## The 32 ML Features

The XGBoost model uses 32 numeric features to make its prediction:

```
 #  Feature                    Example
 0  Domain length              50.0 (normalized)
 1  Digit ratio                0.14 (14% are numbers)
 2  Hyphen count               0.20 (1 hyphen / 5)
 3  Subdomain depth            0.00 (no subdomains)
 4  Shannon entropy            0.60 (how random it looks)
 5  Consonant ratio            0.75 (75% consonants)
 6  Suspicious TLD             1.00 (.xyz, .top, etc.)
 7  Has brand keywords         1.00 (contains "paypal")
 8  Is IP-like domain          0.00 (not an IP address)
 9  Excessive hyphens          0.00 (less than 3)
10  Jaro-Winkler similarity    0.88 (close to "paypal")
11  Levenshtein score          0.91 (edit distance = 1)
12  Edit distance              0.10 (normalized)
13  Typosquatting detected     1.00 (yes)
14  Homoglyph detected         0.00 (no)
15  Homoglyph count            0.00
16  Digit substitution         1.00 (1 → l)
17  Combo-squatting detected   0.00
18  Brand only                 0.00
19  Keyword count              0.00
20  Domain age (log)           0.15 (very new)
21  WHOIS privacy              1.00 (hidden owner)
22  Suspicious registrar       0.00
23  Jaro raw vs brand          0.85
24  Normalization changed      1.00
25  Consecutive digits         0.20
26  TLD risk score             0.80
27  Unique tokens              0.20
28  SSL certificate valid      0.00 (no SSL)
29  MX records present         0.00 (no email)
30  ASN available              0.00 (no hosting info)
31  Security header deficit    0.73 (missing headers)
```

---

## How Scoring Works

The system combines multiple scores into one final risk score (0-100):

```
Final Score = Heuristic Score + ML Score + AI Score + Threat Feed Score

Where:
  • Heuristic Score:  Rule-based detections (typosquatting, homoglyphs, etc.)
  • ML Score:         XGBoost model prediction (0-100)
  • AI Score:         Google Gemini AI assessment (if configured)
  • Threat Feed:      Matches in threat intelligence databases
```

### Score Ranges

| Score | Classification | What It Means |
|---|---|---|
| 0-25 | **SAFE** | Domain looks legitimate |
| 26-50 | **SUSPICIOUS** | Some concerning signals, investigate further |
| 51-75 | **HIGH RISK** | Strong indicators of phishing |
| 76-100 | **CRITICAL** | Almost certainly malicious |

---

## Scan Modes

### Fast Scan (Default)
- **Time:** ~3-5 seconds
- **Does:** Domain name analysis only (no network calls)
- **Good for:** Quick checks, bulk scanning

### Deep Scan
- **Time:** ~15-47 seconds
- **Does:** Everything in Fast Scan + live DNS, WHOIS, SSL, HTTP headers, port scanning, threat feeds
- **Good for:** Thorough investigation of suspicious domains

---

## Project File Structure

```
TMGC - Copy/
├── backend/
│   ├── main.py                    # Main server — API endpoints & analysis pipeline
│   ├── utils.py                   # Core detection logic (15+ analysis functions)
│   ├── scoring.py                 # Hybrid scoring engine (combines all signals)
│   ├── ml_xgboost.py             # XGBoost ML model (train + predict)
│   ├── ml_ensemble.py            # Ensemble of 4 ML models
│   ├── ml_model.py               # Old RandomForest model
│   ├── threat_intel.py           # Threat intelligence feed checks
│   ├── fast_flux_dga.py          # Fast-flux & DGA detection
│   ├── brand_impersonation.py    # Brand impersonation detection
│   ├── owner_image_detection.py  # Entity attribution (Gravatar, GitHub)
│   ├── browser_automation.py     # Playwright browser analysis
│   ├── dom_visual_analysis.py    # DOM structure & visual analysis
│   ├── sandbox_analysis.py       # URL behavior analysis
│   ├── adversarial_detection.py  # Adversarial content detection
│   ├── continuous_learning.py    # Feedback loop & model retraining
│   ├── email_phishing.py         # Email/SMS phishing analysis
│   ├── graph_analysis.py         # Domain relationship graph
│   ├── misp_otx.py              # MISP/OTX threat intel
│   ├── stealth.py                # Browser-like request headers
│   ├── reputation_timeline.py    # Domain reputation over time
│   ├── requirements.txt          # Python dependencies
│   ├── xgb_model.pkl            # Pre-trained XGBoost model
│   ├── lgbm_model.pkl           # Pre-trained LightGBM model
│   ├── rf_model.pkl             # Pre-trained Random Forest model
│   ├── lr_model.pkl             # Pre-trained Logistic Regression model
│   └── ensemble_priors.pkl      # Model calibration thresholds
│
├── front_end/
│   ├── src/
│   │   ├── App.jsx               # Main React app
│   │   └── PremiumDashboard.jsx  # Analysis dashboard UI
│   ├── package.json              # Node.js dependencies
│   └── vite.config.js            # Vite build configuration
│
├── browser_extension/            # Chrome extension (optional)
├── readme.md                     # Project overview
└── HOW_IT_WORKS.md              # This file
```

---

## Sample Output

When you analyze `paypa1.com`, you get:

```json
{
  "domain": "paypa1.com",
  "risk_score": 100,
  "ai_verdict": "PHISHING — Domain impersonates PayPal using digit substitution",
  "findings": [
    "HIGH RISK: Potential typosquatting / impersonation detected",
    "ENTITY ATTRIBUTION: No Ownership Evidence",
    "ML ANALYSIS: XGBoost flags domain as PHISHING (score: 95/100)",
    "ENSEMBLE ML: 4 models voted — Score: 92/100, Verdict: PHISHING"
  ],
  "ml_result": {
    "xgb_available": true,
    "xgb_score": 95.0,
    "xgb_verdict": "Phishing"
  },
  "security_headers": {
    "Strict-Transport-Security": false,
    "Content-Security-Policy": false,
    "X-Frame-Options": false
  }
}
```

---

## API Endpoints

| Endpoint | Method | What It Does |
|---|---|---|
| `/health` | GET | Check if server is running |
| `/api/v1/analyze` | POST | Analyze a domain (main endpoint) |
| `/api/v1/analyze` | GET | Analyze a domain via query parameter |
| `/api/v1/ai-analysis` | POST | Get AI-generated detailed report |
| `/api/v1/features` | GET | Check which features are enabled |
| `/docs` | GET | Interactive API documentation (Swagger) |

---

## Quick Start

```bash
# 1. Start Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000

# 2. Start Frontend (new terminal)
cd front_end
npm install
npm run dev

# 3. Open browser
# Go to http://localhost:5173
```

---

## Testing

### Test Domains

| Domain | Expected Result | Why |
|---|---|---|
| `paypa1.com` | 🔴 PHISHING | Digit substitution (1→l) impersonating PayPal |
| `gooogle.com` | 🟡 SUSPICIOUS | Extra letter "o" — typosquatting Google |
| `faceboook.com` | 🟡 SUSPICIOUS | Extra letter "o" — typosquatting Facebook |
| `g00gle.com` | 🔴 PHISHING | Digit substitution (0→o) impersonating Google |
| `paypal-login.com` | 🟡 SUSPICIOUS | Brand + keyword combo-squatting |
| `amazon.com` | 🟢 SAFE | Legitimate domain, verified organization |
| `google.com` | 🟢 SAFE | Legitimate domain |
| `microsoft-support.tk` | 🔴 CRITICAL | Brand + keyword + suspicious TLD (.tk) |
| `secure-netflix-verify.xyz` | 🔴 CRITICAL | Multiple keywords + suspicious TLD (.xyz) |

### curl Examples

```bash
# Quick scan
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "paypa1.com"}'

# Deep scan
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "paypa1.com", "deep_scan": true}'

# GET request
curl "http://localhost:8000/api/v1/analyze?target=amazon.com"
```

---

## Summary

RETRO_INTEL is a **multi-layered phishing detection system** that combines:

1. **Rule-based analysis** — 15+ detection algorithms checking domain patterns
2. **Machine Learning** — 4 trained models voting together (XGBoost, LightGBM, RandomForest, LogisticRegression)
3. **AI Analysis** — Google Gemini writes human-readable security reports
4. **Threat Intelligence** — Cross-references 6+ threat databases
5. **Network Probing** — Live DNS, WHOIS, SSL, HTTP, and port scanning

All signals are combined into a single **risk score (0-100)** with a clear verdict: **SAFE**, **SUSPICIOUS**, **HIGH RISK**, or **CRITICAL**.

# TMGC / RETRO_INTEL — COMPLETE PROJECT ARCHITECTURE EXPLAINED

This document explains what each file in the project does, how files connect, and what role every component plays.

---

# PROJECT OVERVIEW

Project Name:

RETRO_INTEL / TMGC  
(OSINT Domain Threat Analyzer)

Purpose:

A cybersecurity web application that analyzes suspicious domains/websites and detects:

- Phishing
- Typosquatting
- Homoglyph attacks
- Combo-squatting
- Suspicious SSL/DNS/WHOIS
- Threat intelligence feed matches
- Website cloning
- Infrastructure risks

The system uses:

1. React Frontend
2. FastAPI Backend
3. Machine Learning (XGBoost)
4. Gemini AI Analysis
5. OSINT / Threat Intelligence APIs

---

# PROJECT FLOW

User enters URL
↓
React Frontend
↓
FastAPI Backend
↓
Threat Analysis Engine
↓
ML + Threat Feeds + Website Inspection
↓
Risk Score
↓
Gemini AI Analysis
↓
Frontend Dashboard + Reports

---

# FRONTEND FILES

====================================
1. App.jsx
====================================

Purpose:
Main frontend brain of the application.

This file controls:

- UI rendering
- user authentication
- API calls
- analysis logic
- AI analysis
- logs
- report exports

Major Features:

1. Analyze domain button
2. AI analysis button
3. Terminal logs
4. Risk score display
5. Threat intelligence display
6. WHOIS section
7. Website inspection section
8. Security headers section
9. PDF export
10. Markdown export
11. JSON export
12. TXT export

Main APIs used:

POST /api/v1/analyze
POST /api/v1/ai-analysis

Important functions:

analyze()
→ Calls backend domain analysis.

runAIAnalysis()
→ Calls Gemini AI reasoning.

exportPdf()
→ Creates forensic PDF.

exportMarkdown()
→ Creates markdown report.

exportJson()
→ Downloads JSON result.

exportRawTxt()
→ Downloads raw evidence logs.

Status:

MAIN ACTIVE FILE

------------------------------------

====================================
2. main.jsx
====================================

Purpose:
Starts React application.

What it does:

Loads App.jsx into root div.

Code Flow:

index.html
↓
main.jsx
↓
App.jsx

Status:

Required startup file.

------------------------------------

====================================
3. index.html
====================================

Purpose:
React entry point.

What it does:

Contains:

<div id="root"></div>

React injects UI here.

Also loads Tailwind CSS.

Status:

Required.

------------------------------------

====================================
4. package.json
====================================

Purpose:
Frontend dependency manager.

Controls:

Installed packages.

Dependencies:

React
ReactDOM
Vite
jsPDF

Scripts:

npm run dev
→ start development server

npm run build
→ production build

npm run preview
→ preview production build

Status:

Required.

------------------------------------

====================================
5. dashboard.html
====================================

Purpose:
OLD dashboard page.

What it does:

Displays user info from localStorage.

Seems to be old version before React migration.

Status:

Legacy file.
Not used anymore.

------------------------------------

====================================
6. login.html
====================================

Purpose:
Old login screen.

Used with:

auth.js

Allows:

- email login
- password login

Status:

Legacy file.

------------------------------------

====================================
7. signup.html
====================================

Purpose:
Old signup page.

Allows:

- name
- email
- mobile
- password registration

Uses:

auth.js

Status:

Legacy file.

------------------------------------

====================================
8. script.js
====================================

Purpose:
Old frontend logic.

Controls:

- API requests
- UI updates
- examples
- loader
- results rendering

Important functions:

analyzeDomain()
→ sends domain to backend.

renderResults()
→ shows backend result.

renderWhois()
→ WHOIS UI.

renderDetection()
→ phishing detection UI.

renderWebsiteInspection()
→ website signals UI.

Status:

Legacy file.
Partially replaced by React App.jsx.

------------------------------------

====================================
9. style.css
====================================

Purpose:
Main CSS for old frontend.

Contains:

- cyberpunk UI
- animations
- scanlines
- cards
- dashboard design
- colors
- typography

Status:

Legacy styling file.

---

# BACKEND FILES

====================================
10. main.py
====================================

Purpose:
MAIN BACKEND SERVER.

Framework:

FastAPI

Responsibilities:

1. API server
2. Domain analysis
3. DNS checks
4. WHOIS checks
5. SSL checks
6. Port scanning
7. ML prediction
8. AI analysis
9. Report generation

Endpoints:

GET /health

POST /api/v1/analyze

POST /api/v1/ai-analysis

Main Job:

Coordinates everything.

Think of this as:

"Backend Brain"

Status:

MOST IMPORTANT FILE

------------------------------------

====================================
11. utils.py
====================================

Purpose:
Threat analysis engine.

This file contains actual cybersecurity logic.

Features:

1. Domain sanitization
2. URL validation
3. Typosquatting detection
4. Homoglyph detection
5. Combo-squatting detection
6. Website inspection
7. SSL analysis
8. DNS analysis
9. VirusTotal analysis
10. URLHaus analysis
11. URLScan analysis
12. Safe Browsing analysis
13. Risk scoring

Examples:

paypa1.com
→ typosquatting detection

gοogle.com
→ homoglyph detection

amazon-login.xyz
→ combo-squatting

Status:

CORE DETECTION ENGINE

------------------------------------

====================================
12. app.py
====================================

Purpose:
Old Flask backend.

What it does:

Domain phishing analysis.

Likely older version before FastAPI migration.

Framework:

Flask

Status:

Secondary / legacy backend.

Can probably be removed later.

------------------------------------

====================================
13. ml_xgboost.py
====================================

Purpose:
Machine learning engine.

What it does:

Loads XGBoost model.

Predicts:

Legitimate
OR
Phishing

Functions:

load_xgb()

train_xgb()

predict_xgb()

Status:

ACTIVE

------------------------------------

====================================
14. train_xgb.py
====================================

Purpose:
Train ML model.

What it does:

Creates phishing dataset.

Trains XGBoost.

Saves:

xgb_model.pkl

Run when retraining model.

Status:

Training utility.

------------------------------------

====================================
15. xgb_hook.py
====================================

Purpose:
Hybrid scoring.

Combines:

Rule score (60%)

+

ML score (40%)

Produces:

hybrid_score

hybrid_risk_level

Status:

ACTIVE

------------------------------------

====================================
16. ml_model.py
====================================

Purpose:
Disabled ML placeholder.

Currently:

ML disabled.

Returns:

"ML disabled in production"

Status:

Mostly unused.

------------------------------------

====================================
17. phishtank_hook.py
====================================

Purpose:
PhishTank integration.

Checks:

Whether domain exists in phishing database.

Currently:

Mock implementation.

Status:

Needs improvement.

------------------------------------

====================================
18. external_hooks.py
====================================

Purpose:
External integrations.

Currently:

Runs PhishTank scan.

Can later include:

- VirusTotal
- URLHaus
- AbuseIPDB
- Shodan

Status:

Expandable.

------------------------------------

====================================
19. config.py
====================================

Purpose:
Backend configuration file.

Stores:

PORT
HOST
DATABASE
DEBUG
RISK THRESHOLDS

Like:

LOW_RISK_MAX
MEDIUM_RISK_MAX
HIGH_RISK_MAX

Status:

Required config file.

------------------------------------

====================================
20. requirements.txt
====================================

Purpose:
Python dependencies.

Used by:

pip install -r requirements.txt

Installs:

FastAPI
Flask
xgboost
numpy
scikit-learn
google-genai
whois
dnspython

Status:

Required.

------------------------------------

====================================
21. scanner.db
====================================

Purpose:
SQLite database.

Probably stores:

scan data
results
history

Status:

Database file.

------------------------------------

====================================
22. test_100_domains.py
====================================

Purpose:
Testing script.

Runs:

100 domains automatically.

Checks:

Backend accuracy.

Used for:

benchmarking.

Status:

Testing utility.

------------------------------------

====================================
23. xgb_model.pkl
====================================

Purpose:
Saved ML model.

Used by:

ml_xgboost.py

Contains:

trained XGBoost phishing classifier.

Status:

Required for ML.

---

# HOW FILES CONNECT

FRONTEND

index.html
↓
main.jsx
↓
App.jsx
↓
FastAPI API Calls

-----------------------

BACKEND

main.py
↓
utils.py
↓
Threat Intelligence
↓
ML
↓
Risk Score
↓
JSON Response

---

# API FLOW

1. DOMAIN ANALYSIS

Frontend:

App.jsx

↓

POST /api/v1/analyze

↓

main.py

↓

utils.py

↓

ML + Threat Feeds

↓

Result JSON

↓

Frontend Dashboard

---

2. AI ANALYSIS

Frontend:

App.jsx

↓

POST /api/v1/ai-analysis

↓

main.py

↓

Gemini AI

↓

SOC Report

↓

Frontend Display

---

# CURRENT PROJECT STATUS

Architecture Level:

Intermediate → Advanced

Strengths:

✓ Strong UI
✓ Threat analysis
✓ ML integration
✓ AI integration
✓ PDF export
✓ SOC-style dashboard

Weaknesses:

✗ Mixed old + new frontend
✗ App.jsx too large
✗ Old Flask backend still present
✗ Authentication insecure
✗ Folder structure not modular

Recommended Future Refactor:

frontend/
components/
services/
hooks/
pages/

backend/
routes/
services/
models/
security/
ml/
intel/
utils/



#┌─────────────────────┐
│    React Frontend   │
│  (Dashboard / UI)   │
└──────────┬──────────┘
           │ REST API
           ▼
┌─────────────────────┐
│   FastAPI Backend   │
│   Analysis Engine   │
└──────────┬──────────┘
           │
 ┌─────────┼─────────┐
 ▼         ▼         ▼
ML       OSINT      AI
Engine   Feeds    Analysis
(XGB)  (VT, DNS)  (Gemini)
 └─────────┬─────────┘
           ▼
┌─────────────────────┐
│ Threat Score Engine │
│  Risk Classification│
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ SOC Dashboard       │
│ PDF / Reports       │
└─────────────────────┘


## 🧪 `test_100_domains.py`

### Overview

`test_100_domains.py` is an automated benchmarking and validation utility used to evaluate the effectiveness of the TMGC threat detection engine across a large dataset of domains.

This script performs bulk testing on **100+ domains** to verify the consistency, accuracy, and reliability of the phishing detection pipeline.

---

### Purpose

The primary objective of this file is to test and benchmark TMGC after:

* Machine learning retraining
* Threat scoring updates
* Rule-engine modifications
* New phishing detection improvements
* Backend security logic changes

It helps ensure that new updates do not negatively affect detection quality.

---

### What It Tests

The script automatically evaluates multiple domain categories, including:

✅ Legitimate domains
🚨 Phishing domains
⚠️ Suspicious domains
🔍 Typosquatting attacks
🌍 Homoglyph attacks
🎭 Combo-squatting domains

Examples:

```txt
google.com → Legitimate
paypa1.com → Typosquatting
gοogle.com → Homoglyph Attack
amazon-login.xyz → Suspicious
```

---

### Detection Pipeline

The testing workflow follows the complete TMGC detection architecture:

```txt
Domain Dataset
       ↓
Threat Analysis Engine
       ↓
Rule-Based Detection
       ↓
Machine Learning (XGBoost)
       ↓
Threat Intelligence Checks
       ↓
Hybrid Risk Scoring
       ↓
Final Classification
```

---

### Metrics Evaluated

The script helps measure:

* **Detection Accuracy**
* **Precision**
* **Recall**
* **F1 Score**
* **False Positive Rate**
* **False Negative Rate**
* **Risk Score Consistency**

These metrics help validate the real-world performance of TMGC.

---

### Usage

Run the benchmark test using:

```bash
python test_100_domains.py
```

---

### Status

**Active Testing / Benchmarking Utility**

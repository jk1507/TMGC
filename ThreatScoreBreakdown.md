# 🛡️ TMGC Threat Score Breakdown

## Overview

The TMGC (Threat Monitoring and Guard Console) uses a **hybrid scoring engine** that combines multiple independent analysis signals into a single 0-100 risk score. The system is designed to be **explainable, false-positive resistant, and ML-supported**.

## Scoring Architecture

### Signal Sources

| Signal | Weight | Type | Description |
|--------|--------|------|-------------|
| Heuristic Analysis | 35% | PRIMARY | Domain pattern, WHOIS, DNS, SSL signals |
| Security Headers | 20% | SUPPORTING | HTTP security header posture |
| XGBoost ML | 20% | SUPPORTING | Gradient-boosted tree model prediction |
| Domain Reputation | 15% | SUPPORTING | Age, registrar, ASN, infrastructure |
| AI Analysis | 10% | CONFIDENCE BOOST | LLM-based contextual reasoning |

### Threat Levels

| Score Range | Label | Severity |
|-------------|-------|----------|
| 0-10 | SAFE VERIFIED | safe |
| 11-25 | LOW RISK | low |
| 26-45 | SUSPICIOUS | suspicious |
| 46-70 | HIGH RISK | high |
| 71-100 | MALICIOUS / PHISHING | critical |

## Scoring Components

### 1. Heuristic Analysis (0-100)
- Domain length, digit ratio, entropy
- Typosquatting detection (Jaro-Winkler, Levenshtein)
- Homoglyph/confusable character detection
- Combo-squatting (brand + keyword)
- WHOIS signals (age, privacy, registrar)
- DNS signals (MX, SPF, DKIM, DMARC)
- SSL/TLS analysis (expired, self-signed, revoked)
- Open port exposure
- Website inspection (password forms, external actions)

### 2. Security Headers (0-50+)
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

### 3. XGBoost ML (0-100)
- 32-feature vector analysis
- Trained on 10,000+ known phishing/legitimate domains
- Lexical, WHOIS, and infrastructure features
- Inference-time features (SSL validity, MX presence, ASN, headers)

### 4. Trust Bonuses (0-100 reduction)
- Domain age (>5 years: -5, >10 years: -10, >20 years: -15)
- Major global brand (-10 to -20, eliminated when impersonation detected)
- Trusted registrar (-10)
- Trusted ASN (-10)
- Valid SSL (-5)
- DNSSEC (-5)
- Government/education domain (-20)
- Verified organization (-50)

### 5. Phishing Penalties (0-100 increase)
- Typosquatting: +40
- Homoglyph: +20 + (count * 8)
- Digit substitution: +15
- Combo-squatting: +35
- Suspicious TLD: +20
- Dark web TLD: +55
- Very new domain (<7 days): +30
- WHOIS privacy: +10
- IP masquerading: +25
- Excessive subdomains: +20
- Password form: +12
- External form action: +18
- Multiple indicators exponential: +35%

## False Positive Protection

### Hard-Protected Domains
Globally recognized, verified organizations on TMGC's trusted domain list receive a -50 trust bonus. These domains are NEVER flagged as suspicious.

### AI Override Guard
When ML says "Legitimate" with low heuristic evidence, AI influence is capped to 5% to prevent hallucinated AI assessments from distorting the verdict.

### Security Floor
Domains with confirmed poor security posture (missing SSL, missing headers) never reach 0/100. A minimum floor ensures security posture is never fully suppressed.

### Government/Education Cap
Government (.gov, .gov.*) and education (.edu, .mil) domains are capped at LOW RISK (18) when they have confirming infrastructure.

## Dynamic Confidence

The system computes a dynamic confidence percentage based on:
- Signal agreement (multiple engines pointing same direction)
- Signal strength (strong evidence = high confidence)
- Threat feed validation
- Ensemble ML agreement
- Mathematical metrics (entropy, KL divergence, Cohen's kappa)

## Ensemble ML (v3.0)

Combines predictions from 4 ML models:
- XGBoost (primary)
- LightGBM
- Random Forest
- Logistic Regression

Returns weighted ensemble score with entropy-based confidence metrics, Bayesian credible intervals, and inter-model agreement analysis.

## Threat Intelligence Feeds (v3.0)

External validation from:
- URLhaus (abuse.ch) — free
- VirusTotal — API key required
- AbuseIPDB — API key required
- urlscan.io — optional API key
- Google Safe Browsing — API key required
- PhishTank — API key required

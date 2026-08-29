# RETRO_INTEL Documentation

This folder contains function-level documentation for all files in the project.

## Project Overview

RETRO_INTEL is an OSINT Domain Threat Analyzer that combines multiple analysis techniques to detect phishing and malicious domains.

## Structure

```
docs/
├── README.md                    # This file
├── backend/                     # Backend Python modules
│   ├── main.md                  # Main API application
│   ├── scoring.md               # Hybrid scoring engine
│   ├── ml_xgboost.md            # XGBoost ML model
│   ├── ml_ensemble.md           # Ensemble ML predictions
│   ├── threat_intel.md          # Threat intelligence feeds
│   ├── brand_impersonation.md   # Brand impersonation detection
│   ├── continuous_learning.md   # Online learning pipeline
│   ├── adversarial_detection.md # Adversarial content detection
│   ├── email_phishing.md        # Email/SMS phishing detection
│   ├── graph_analysis.md        # Domain relationship graphs
│   ├── sandbox_analysis.md      # URL/attachment sandbox analysis
│   ├── dom_visual_analysis.md   # DOM & visual analysis
│   ├── misp_otx.md              # MISP & OTX integration
│   ├── utils.md                 # Core utility functions
│   ├── stealth.md               # Stealth HTTP module
│   ├── fast_flux_dga.md         # Fast-flux & DGA detection
│   ├── reputation_timeline.md   # Reputation tracking
│   ├── owner_image_detection.md # Owner attribution
│   ├── browser_automation.md    # Playwright browser analysis
│   ├── config.md                # Configuration
│   ├── content_similarity.md    # Content similarity comparison
│   ├── screenshot_similarity.md # Screenshot comparison
│   ├── external_hooks.md        # External hook integrations
│   └── phishtank_hook.md        # PhishTank integration
├── frontend/                    # Frontend React components
│   └── App.md                   # Main React application
└── browser_extension/           # Browser extension
    └── manifest.md              # Extension manifest
```

## Quick Reference

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI application, API endpoints, request handling |
| `scoring.py` | Hybrid risk scoring with trust bonuses and penalties |
| `ml_xgboost.py` | XGBoost model training and prediction |
| `ml_ensemble.py` | Multi-model ensemble predictions |
| `threat_intel.py` | URLhaus, VirusTotal, AbuseIPDB, urlscan.io |
| `brand_impersonation.py` | Brand similarity and login harvesting detection |
| `utils.py` | Domain validation, homoglyph detection, SSL analysis |
| `stealth.py` | Proxy support, rate limiting, rotating user agents |

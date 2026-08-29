# backend/main.py - Main API Application

FastAPI application that serves the RETRO_INTEL threat analysis API.

## Classes

### AnalyzeRequest
Pydantic model for incoming analysis requests.
- `url`: Target URL/domain (3-2048 chars)
- `deep_scan`: Enable deep analysis (default: False)

### AnalyzeResponse
Pydantic model for analysis response containing all threat data.
- Domain info, IP, WHOIS, DNS, SSL, ports, headers
- ML predictions, threat intel, brand impersonation
- AI verdict, risk score, findings

### CommandResult
Result of a command execution (stdout, stderr, status).

### HeaderStatus
Security header analysis result with strength评估.

### RateLimiter
In-memory rate limiter with minute/hour buckets.

## Functions

### `safe_iso_date(year, month, day)`
Safely create ISO date string, returns None on invalid dates.

### `levenshtein_distance(left, right)`
Compute edit distance between two strings.

### `fallback_dns(domain, rtype)`
DNS resolution fallback using dnspython or socket.

### `fallback_whois(query)`
WHOIS lookup fallback using python-whois library.

### `fallback_ip_whois(ip)`
IP WHOIS with RDAP, PTR, and CDN heuristics.

### `fallback_ssl_probe(domain)`
SSL certificate probe using native Python ssl module.

### `fallback_port_scan(domain, ports)`
Async port scanner using native sockets.

### `fallback_curl(domain)`
HTTP headers check with redirect tracking.

### `get_ml_prediction(domain, parsed_domain, whois_raw, ...)`
Extract features and run XGBoost prediction.

### `run_analysis(url, deep_scan)`
Main analysis pipeline - orchestrates all modules.

### `compute_security_headers(raw_headers)`
Parse and score security headers.

### `domain_age_days(created_date)`
Calculate domain age in days.

## API Endpoints

### POST `/api/v1/analyze`
Analyze a domain for phishing/threat indicators.

### POST `/api/v1/ai-analysis`
Generate AI-powered threat analysis report.

### GET `/api/v1/health`
Health check endpoint.

### POST `/api/v1/feedback`
Submit user feedback for continuous learning.

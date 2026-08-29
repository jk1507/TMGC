# backend/scoring.py - Hybrid Scoring Engine

Domain-aware, explainable, false-positive resistant scoring system.

## Design Philosophy
- ML is a SUPPORTING signal, never the dominant factor
- Trust bonuses reduce risk for legitimate domains
- Hard-protected domains are NEVER flagged as suspicious

## Constants

### `HARD_PROTECT_DOMAINS`
Globally trusted domains (google.com, microsoft.com, etc.) - never flagged.

### `SUSPICIOUS_NAME_PATTERNS`
Domain labels suggesting malicious intent (exploitkit, malware, phishing, etc.)

### `THREAT_LEVELS`
Score ranges: SAFE (0-10), LOW RISK (11-25), SUSPICIOUS (26-45), HIGH RISK (46-70), CRITICAL (71-100).

## Functions

### `clamp_score(score)`
Clamp score to 0-100 range.

### `get_threat_level(score)`
Return (label, severity) tuple for a score.

### `classify_score(score)`
Legacy classification (CRITICAL, HIGH RISK, SUSPICIOUS, LOW RISK, SAFE).

### `is_hard_protected(domain)`
Check if domain is in the hard-protected list.

### `compute_domain_age_days(created_iso)`
Compute domain age in days from ISO string.

### `get_major_brand(domain)`
Extract major brand name from domain, if any.

### `compute_trust_bonuses(domain, parsed_domain, ssl_valid, ...)`
Calculate trust bonuses for legitimate indicators:
- Domain age bonus (older = more trusted)
- Trusted registrar bonus
- Trusted ASN/hosting bonus
- SSL certificate bonus
- Hard-protected domain override

### `compute_phishing_penalties(domain, findings, ml_result, ...)`
Calculate penalties for phishing indicators:
- Suspicious name patterns
- Brand impersonation penalties
- ML prediction penalties
- Threat intel penalties

### `compute_hybrid_score(heuristics_score, header_score, xgb_score, ...)`
Combine all signals into final hybrid score with dynamic weighting.

### `compute_data_completeness(result_data)`
Track data quality/completeness for confidence assessment.

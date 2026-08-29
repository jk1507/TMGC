# backend/utils.py - Core Utility Functions

Production phishing domain detection utilities with deterministic scoring.

## Features
- Domain validation and sanitization
- Homoglyph/combosquatting detection
- Typosquatting detection with keyboard proximity
- SSL/TLS certificate analysis
- Abused infrastructure detection
- Redirect chain analysis
- Circuit breaker for external APIs

## Classes

### `CircuitBreakerState`
Track circuit breaker state for external services.
- failures, last_failure, state, success_count

### `DomainConfig`
Configuration for brands, keywords, and TLDs.

## Domain Functions

### `sanitize_domain(raw)`
Clean domain input (remove protocol, ports, paths).

### `validate_domain(domain)`
Validate domain format and return (bool, error_msg).

### `sanitize_url(raw)`
Clean URL input and normalize.

### `validate_url(url)`
Validate URL format and safety.

## Detection Functions

### `detect_typosquatting(domain_name)`
Enhanced typosquatting detection with keyboard proximity.
- Returns: brand match, edit distance, Jaro-Winkler score

### `detect_homoglyphs(label)`
Unicode character analysis for homoglyph detection.
- Returns: suspicious chars, digit substitutions

### `detect_combosquatting(domain)`
Detect brand + keyword combinations.
- Returns: matched brands, keywords

### `detect_abused_infrastructure(domain)`
Check for abused legitimate services (ngrok, duckdns, etc.)

### `detect_subdomain_phishing(domain)`
Detect brand impersonation via subdomains.

### `detect_url_path_signals(url)`
Check for suspicious keywords in URL paths.

### `detect_punycode_homograph(domain)`
Detect punycode/IDN homograph attacks.

## Analysis Functions

### `inspect_website(url, timeout=2.5)`
Fetch website and extract HTML signals.

### `compare_website_to_reference(suspect_url, reference_url)`
Compare two websites for cloning detection.

### `analyze_ssl_signals(domain)`
Analyze SSL certificate for trust indicators.

### `analyze_redirect_chain(url)`
Follow and analyze redirect chain.

### `analyze_certificate_transparency(domain)`
Query CT logs for certificate history.

### `analyze_dns_records(domain)`
Comprehensive DNS record analysis.

### `enumerate_subdomains(domain)`
Subdomain enumeration via DNS.

### `extract_features(domain)`
Extract 28+ features for ML model.

## SSL Error Detection

### `is_ssl_expired_error(error_str)`
### `is_ssl_self_signed_error(error_str)`
### `is_ssl_hostname_mismatch_error(error_str)`
### `is_ssl_revoked_error(error_str)`
### `is_ssl_untrusted_root_error(error_str)`

## String Similarity

### `normalize_homoglyphs(text)`
Normalize confusable characters.

### `levenshtein_distance(a, b)`
Compute edit distance.

### `jaro_similarity(s1, s2)`
Compute Jaro similarity.

### `jaro_winkler_similarity(s1, s2, p=0.1)`
Compute Jaro-Winkler similarity.

### `calculate_keyboard_distance(char1, char2)`
QWERTY keyboard distance between characters.

## Retry Logic

### `with_retry(func, *args, max_retries=3, ...)`
Async retry with exponential backoff and circuit breaker.

### `with_retry_sync(func, *args, ...)`
Synchronous retry version.

## Constants

### `SUSPICIOUS_TLDS`
Suspicious top-level domains (xyz, top, club, etc.)

### `HIGH_RISK_TLDS`
High-risk TLDs (xyz, top, tk, ml, etc.)

### `DARK_WEB_TLDS`
Dark web TLDs (onion, i2p, bit)

### `ABUSED_INFRA_DOMAINS`
Legitimate services frequently abused for phishing.

### `SUSPICIOUS_PATH_KEYWORDS`
Suspicious keywords in URL paths.

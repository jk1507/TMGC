# backend/brand_impersonation.py - Brand Impersonation Detection

Advanced detection of brand impersonation, similarity, and login harvesting.

## Features
- Brand similarity scoring (Levenshtein, Jaro-Winkler)
- Login page harvesting detection
- Multi-brand campaign detection
- Brand + subdomain impersonation

## Functions

### `analyze_brand_impersonation(domain, website_content="", whois_text="")`
Comprehensive brand impersonation analysis.

**Detects:**
- Domain similarity to known brands
- Brand keywords + phishing keyword combinations
- Login page credential collection patterns
- Brand + subdomain impersonation

**Returns dict with:**
- `impersonation_detected`: bool
- `impersonated_brands`: List of matched brands
- `similarity_scores`: Per-brand scores
- `phishing_keywords_found`: Matched keywords
- `login_harvesting`: bool
- `overall_risk`: 0-100 score

### `detect_brand_similarity(domain)`
Quick brand similarity check using Levenshtein distance.

**Returns dict with:**
- `closest_brand`: Brand name
- `similarity_score`: 0-1 float
- `matched_keyword`: Best matching keyword

### `detect_login_harvesting(website_content)`
Detect login credential harvesting pages.

**Analyzes:**
- Credential-related keywords
- Password field indicators
- Suspicious form actions
- Multiple credential collection indicators

**Returns dict with:**
- `is_login_page`: bool
- `confidence`: 0-1 float
- `indicators_found`: List of findings

### `_levenshtein(a, b)`
Compute Levenshtein edit distance between strings.

### `_load_brand_db()`
Load brand database from JSON file (cached).

### `_get_default_brand_db()`
Return default brand database with 20+ brands.

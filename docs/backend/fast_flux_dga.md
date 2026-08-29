# backend/fast_flux_dga.py - Fast-Flux & DGA Detection

Detects fast-flux DNS techniques and Domain Generation Algorithm patterns.

## Fast-Flux Detection
- Multiple A record resolution over time
- Short TTL values (< 5 minutes)
- ASN diversity in resolved IPs
- Geographic dispersion

## DGA Detection
- Character entropy analysis
- Consonant/vowel ratio
- N-gram frequency analysis
- Dictionary word composition
- Length and randomness scoring

## Functions

### `detect_fast_flux(domain)`
Detect fast-flux DNS patterns.

**Analyzes:**
- Number of A records (multiple IPs = suspect)
- TTL values (very short = fast-flux)
- NS record patterns (generic names)
- IP diversity and geographic spread

**Returns dict with:**
- `detected`: bool
- `confidence`: 0-100
- `indicators`: List of findings
- `ip_addresses`: Resolved IPs
- `ttl`: Current TTL value
- `warning`: Human-readable warning

### `detect_dga(domain)`
Detect Domain Generation Algorithm patterns.

**Features analyzed:**
- Shannon entropy (high for DGA)
- Consonant/vowel ratio
- Digit ratio
- Bigram frequency (English-likeness)
- Length-based scoring
- Repeated characters
- Vowel gaps

**Returns dict with:**
- `detected`: bool
- `dga_score`: 0-100
- `features`: Individual feature scores
- `label`: Domain label analyzed
- `warning`: Human-readable warning

## Helper Functions

### `_entropy(s)`
Compute Shannon entropy of a string.

### `_consonant_ratio(s)`
Compute consonant-to-letter ratio.

### `_vowel_ratio(s)`
Compute vowel-to-letter ratio.

### `_digit_ratio(s)`
Compute digit-to-length ratio.

### `_bigram_score(s)`
Compute proportion of English-like bigrams.

### `_resolve_all_a_records(domain)`
Resolve all A records for a domain.

### `_get_ttl(domain)`
Get TTL for domain's A record.

## Constants

### `DGA_TLDS`
Common TLDs for DGA domains.

### `ENGLISH_BIGRAMS`
High-frequency English letter pairs.

### `FAST_FLUX_TTL_THRESHOLD`
300 seconds (5 minutes).

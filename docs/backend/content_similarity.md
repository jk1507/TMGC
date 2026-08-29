# backend/content_similarity.py - Content Similarity Analysis

Compares website content against known legitimate sites to detect phishing clones.

## Features
- Phishing page detection via content comparison
- Content scraping/mirroring detection
- Brand impersonation via page structure similarity

## Functions

### `compare_content(suspect_url, reference_url, timeout=4.0)`
Compare content of two URLs for similarity analysis.

**Returns dict with:**
- `available`: bool
- `similarity`: 0.0-1.0 similarity score
- `likely_clone`: True if similarity >= 0.72
- `suspect_url`: Original suspect URL
- `reference_url`: Reference URL
- `suspect_text_length`: Text length from suspect
- `reference_text_length`: Text length from reference

### `_fetch_text(url, timeout)`
Fetch text content from a URL.
- Returns: Cleaned text or None

### `_html_to_text(html)`
Convert HTML to plain text.
- Removes scripts, styles, noscript tags
- Strips HTML tags
- Normalizes whitespace

### `_clean_text(text)`
Clean text for comparison.
- Lowercase
- Remove non-alphanumeric characters
- Normalize whitespace
- Truncate to 5000 chars

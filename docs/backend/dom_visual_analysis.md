# backend/dom_visual_analysis.py - DOM & Visual Analysis

Multi-modal webpage analysis with CNN-ready pipeline.

## Features
- DOM structure analysis for phishing patterns
- Visual similarity scoring (CNN feature extraction ready)
- Brand impersonation markers detection
- Rendering pattern analysis
- Layout fingerprinting

## Data Classes

### `DOMAnalysisResult`
DOM structure analysis result.
- brands_detected, phishing_markers
- layout_analysis, form_analysis
- script_analysis, meta_analysis

### `VisualAnalysisResult`
Visual/screenshot analysis result.
- similar_to_known_brand, matched_brand
- similarity_score, visual_features

## Brand DOM Signatures

Pre-configured signatures for: PayPal, Microsoft, Google, Apple, Amazon.

Each includes:
- meta_keywords
- css_classes
- form_actions
- js_globals
- favicon_patterns

## Functions

### `analyze_dom_structure(html, url="")`
Analyze DOM structure for phishing indicators.

**Checks:**
- Brand impersonation via CSS classes, meta tags, JS globals
- Credential harvesting forms
- Suspicious script patterns
- Layout mimicking
- Hidden elements

**Returns dict with:**
- `brands_detected`: List of matched brands
- `phishing_markers`: Suspicious findings
- `form_analysis`: Form statistics
- `script_analysis`: Script statistics
- `score`: 0-100 risk score

### `analyze_webpage_visual(url, timeout=10.0)`
Visual analysis of webpage (requires Playwright).

### `compare_visual_similarity(suspect_url, reference_url)`
Compare visual similarity between two URLs.

### `extract_cnn_features(image_data)`
Extract CNN features for visual similarity (requires PIL).

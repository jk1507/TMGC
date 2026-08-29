# backend/email_phishing.py - Email & SMS Phishing Detection

Multi-modal NLP-based phishing detection for email and SMS content.

## Features
- Email content analysis (body, subject, sender)
- SMS/instant messaging analysis
- Email header analysis (SPF, DKIM, DMARC, routing)
- Transformer-based models (BERT/RoBERTa) when available
- Rule-based fallback when ML libs unavailable

## Data Classes

### `EmailHeaderAnalysis`
Parsed email header inspection results.
- SPF/DKIM/DMARC results
- Reply-To/From domain mismatch
- Suspicious X-Mailer detection

### `ContentPhishingResult`
NLP + heuristic content analysis result.
- ML score and heuristic score
- Attack type classification
- Urgency level assessment
- Brand impersonation detection

### `EmailPhishingResult`
Complete email phishing analysis combining headers and content.

### `SMSPhishingResult`
SMS/instant messaging phishing result.

## Functions

### `analyze_email_phishing(subject="", body="", sender="", raw_headers="")`
Complete email phishing analysis combining:
1. Header analysis (SPF/DKIM/DMARC anomalies)
2. Content NLP analysis (BERT + rule-based)
3. URL extraction & obfuscation detection
4. Brand impersonation detection

**Returns:** EmailPhishingResult with overall_score 0-100

### `analyze_sms_phishing(message, sender="")`
SMS phishing analysis with SMS-specific heuristics:
- Short message urgency patterns
- URL obfuscation in SMS
- Premium rate number patterns

### `analyze_email_headers(raw_headers)`
Parse raw email headers and detect anomalies.

**Checks:**
- SPF/DKIM/DMARC results
- Reply-To vs From domain mismatch
- Return-Path anomalies
- Suspicious X-Mailer
- Received chain depth

### `_rule_based_content_analysis(content, content_type="email")`
Rule-based + statistical NLP content analysis.

**Analyzes:**
- Urgency detection (keywords)
- Credential harvesting phrases
- Financial phishing phrases
- Brand impersonation patterns
- URL obfuscation
- Grammar/spelling anomalies

### `_extract_urls(text)`
Extract all URLs from email/SMS text.

### `_detect_url_obfuscation(url)`
Detect URL obfuscation techniques:
- Hex encoding
- IP address as hostname
- Excessive subdomains
- Data URIs
- Homograph characters
- URL shorteners

### `_check_brand_impersonation(text)`
Check if text impersonates known brands.

## Keywords

### `URGENCY_KEYWORDS`
Phrases creating urgency (urgent, immediately, act now, etc.)

### `CREDENTIAL_HARVESTING_PHRASES`
Phrases requesting credentials (confirm password, verify login, etc.)

### `FINANCIAL_PHISHING_PHRASES`
Financial fraud phrases (wire transfer, bank account, etc.)

### `BRAND_IMPERSONATION_PATTERNS`
Brand-specific patterns for 10+ major brands.

# backend/owner_image_detection.py - Owner Image Detection

Evidence-based entity attribution for domain ownership.

## Methods
- WHOIS email extraction → Gravatar lookup
- WHOIS text pattern matching (org names, social links)
- Website content scanning (social media links, emails)
- GitHub profile search
- Social media platform detection

## Important
All attribution is evidence-based. NEVER infers ownership from keyword matches alone.

## Functions

### `analyze_owner_images(domain, whois_text="", website_text="", timeout=1.5)`
Analyze owner images and entity attribution.

**Steps:**
1. Extract emails from WHOIS
2. Look up Gravatar profiles for emails
3. Detect social media links
4. Attempt GitHub profile lookup
5. Score attribution confidence

**Returns dict with:**
- `attribution_level`: Verified/Probable/Possible/None
- `attribution_score`: 0-100
- `attribution_severity`: verified/probable/possible/none
- `display_owner`: bool
- `attribution_evidence`: List of findings
- `emails_found`: Extracted emails
- `gravatar_profiles`: Matched Gravatar profiles
- `github_profile`: GitHub profile data
- `social_media`: Detected social links
- `org_names`: Organization names from WHOIS

### `_extract_emails(text)`
Extract all email addresses from text.

### `_extract_org_names(text)`
Extract organization names from WHOIS text.

### `_gravatar_hash(email)`
Compute Gravatar hash from email address.

### `_lookup_gravatar(email, timeout=2.0)`
Look up Gravatar profile for an email.

### `_lookup_github(username, timeout=2.0)`
Look up GitHub profile by username.

### `_detect_social_links(text)`
Detect social media profile links in text.

## Social Platforms Detected
- LinkedIn, Twitter/X, GitHub, Facebook
- Instagram, YouTube, TikTok, Medium
- Reddit, Discord, Telegram, Signal

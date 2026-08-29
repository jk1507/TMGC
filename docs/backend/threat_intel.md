# backend/threat_intel.py - Threat Intelligence Feeds

Aggregates multiple threat intelligence sources for domain/IP reputation.

## Sources

| Provider | API Key Required | Cost |
|----------|------------------|------|
| URLhaus (abuse.ch) | No | Free |
| Google Safe Browsing | Yes | Free tier |
| PhishTank | Yes | Free tier |
| VirusTotal | Yes | Free tier |
| AbuseIPDB | Yes | Free tier |
| urlscan.io | Optional | Free tier |

## Functions

### `check_urlhaus(domain, url="")`
URLhaus check (free, no API key).
- Checks both URL and host endpoints
- Returns flagged status and match details

### `check_google_safe_browsing(url, api_key="")`
Google Safe Browsing v4 lookup.
- Requires GOOGLE_SAFE_BROWSING_API_KEY env var
- Checks for malware, social engineering, unwanted software

### `check_phishtank(url, api_key="")`
PhishTank URL verification.
- Requires PHISHTANK_API_KEY env var
- Returns in_database, verified, valid status

### `check_virustotal(domain, api_key="")`
VirusTotal domain reputation.
- Requires VIRUSTOTAL_API_KEY env var
- Returns malicious/suspicious/harmless/undetected counts

### `check_abuseipdb(ip, api_key="")`
AbuseIPDB IP reputation check.
- Requires ABUSEIPDB_API_KEY env var
- Returns abuse confidence score and report count

### `check_urlscan(domain, api_key="")`
urlscan.io domain search.
- API key optional for basic search
- Returns recent scan results and metadata

### `run_all_feeds(domain, ip="", website_url="")`
Run all available threat intel feeds.
- Returns aggregated results with overall_score (0-100)
- Counts total feeds checked and flagged

## Helper Functions

### `_form_post(url, form, headers=None, timeout=4.0)`
Make form-encoded POST request.

### `_json_post(url, payload, headers=None, timeout=4.0)`
Make JSON POST request.

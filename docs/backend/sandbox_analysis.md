# backend/sandbox_analysis.py - Sandbox & Behavioral Analysis

Dynamic analysis of URLs and attachments in sandboxed environments.

## Features
- URL behavioral analysis (redirects, JS execution, DOM changes)
- Attachment static analysis (entropy, imports, sections)
- HTTP traffic capture and inspection
- Cookie/credential exfiltration detection
- Drive-by download detection

## Data Classes

### `BehavioralIndicator`
Single behavioral indicator from sandbox analysis.
- category: redirect, script, network, cookie, form, download
- severity: info, low, medium, high, critical

### `SandboxResult`
Complete sandbox analysis result.

## Functions

### `analyze_url_behavior(url, timeout=10.0, follow_redirects=True, max_redirects=10)`
Analyze URL behavior via HTTP request inspection.

**Checks:**
- Redirect chain analysis
- Response header anomalies
- JavaScript-based redirects
- Form action targets
- External resource loading
- Cookie behavior
- Content obfuscation

**Returns dict with:**
- `redirect_chain`: List of redirect URLs
- `http_traffic`: Request/response details
- `scripts_detected`: JS redirects found
- `forms_detected`: Forms with password fields
- `cookies_set`: Authentication cookies
- `external_requests`: External domains loaded
- `overall_score`: 0-100 risk score
- `risk_level`: critical/high/medium/low/clean

### `analyze_attachment(filename, content)`
Static analysis of file attachment.

**Checks:**
- File entropy (packed/encrypted detection)
- Magic byte detection
- PE header analysis
- Suspicious strings extraction
- Hash computation (MD5, SHA256)

**Returns dict with:**
- `file_type`: Detected file type
- `entropy`: Shannon entropy value
- `is_packed`: bool
- `is_executable`: bool
- `suspicious_strings`: List of findings
- `overall_score`: 0-100 risk score

### `analyze_sandbox(url="", filename="", content=b"")`
Unified sandbox analysis API.
- For URLs: behavioral analysis
- For files: static analysis

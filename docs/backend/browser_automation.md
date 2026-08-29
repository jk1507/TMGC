# backend/browser_automation.py - Browser Automation

Playwright-based dynamic content analysis for sophisticated phishing detection.

## Capabilities
- Full page rendering with JavaScript execution
- Form detection and analysis
- Network request capture (XHR, fetch, WebSocket)
- Console log capture
- Storage inspection (localStorage, sessionStorage, cookies)
- Stealth mode (avoid bot detection)

## Prerequisites
```bash
pip install playwright
playwright install chromium
```

## Functions

### `is_playwright_installed()`
Check if Playwright is installed and available.
- Returns: bool

### `analyze_dynamic_content(url, timeout=10.0, capture_network=True, ...)`
Analyze a website using Playwright browser automation.

**Args:**
- `url`: The URL to visit
- `timeout`: Maximum wait time for page load
- `capture_network`: Capture network requests
- `capture_console`: Capture console messages
- `capture_storage`: Inspect browser storage
- `network_capture_ms`: Network capture duration after load
- `stealth`: Use stealth mode

**Returns dict with:**
- `available`: bool
- `page_title`: Page title
- `final_url`: Final URL after redirects
- `http_status`: HTTP status code
- `forms`: Detected forms with fields
- `external_endpoints`: External URLs communicated with
- `login_form`: Whether login form detected
- `suspicious_patterns`: Any suspicious patterns found
- `console_logs`: Captured console messages
- `local_storage`: localStorage contents
- `cookies`: Browser cookies

## Stealth Mode Features
- Disables webdriver detection
- Mocks browser plugins
- Sets realistic locale and timezone
- Disables automation-controlled blink features

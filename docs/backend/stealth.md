# backend/stealth.py - Stealth HTTP Module

Proxy, rate limiting, and rotating User-Agent for realistic browser requests.

## Features
- Rotating User-Agent strings (realistic browser list)
- HTTP/HTTPS/SOCKS proxy support
- Rate limiting with configurable delay and jitter
- Burst request support
- Full browser header set

## Configuration

```python
HTTP_PROXY = os.environ.get("HTTP_PROXY")
HTTPS_PROXY = os.environ.get("HTTPS_PROXY")
SOCKS_PROXY = os.environ.get("SOCKS_PROXY")

STEALTH_RATE_LIMIT = 2.0       # Max requests per second
STEALTH_BURST_SIZE = 5         # Max burst requests
STEALTH_DELAY_MS = 300         # Base delay (ms)
STEALTH_JITTER_MS = 200        # Random jitter (ms)
```

## User Agents

Realistic rotating browser strings:
- Chrome 120+ (Windows, macOS)
- Firefox 121+ (Windows)
- Edge 120+ (Windows)
- Safari 17.2 (macOS)
- Mobile Safari (iPhone)

## Functions

### `setup_stealth()`
Initialize stealth module at app startup.
- Reads proxy settings from env vars
- Resets rate limiter state
- Configures proxy handlers

### `stealth_build_request(url, headers=None, data=None, method=None)`
Build urllib Request with stealth browser headers.

**Headers included:**
- User-Agent (rotated)
- Accept (full browser set)
- Accept-Language (en-US)
- DNT: 1
- Upgrade-Insecure-Requests: 1
- Connection: keep-alive

### `build_stealth_opener(*handlers)`
Build urllib opener with proxy support and custom handlers.

### `_apply_rate_limit()`
Apply rate limiting delay before requests.
- Burst detection
- Per-second rate limiting
- Random jitter

### `_get_random_user_agent()`
Return random User-Agent from realistic list.

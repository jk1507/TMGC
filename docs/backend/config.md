# backend/config.py - Configuration

Application configuration for RETRO_INTEL.

## Class: Config

### Server Settings
```python
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000
DB_PATH = "scanner.db"
CACHE_TTL_HOURS = 24
```

### Feature Flags
```python
ENABLE_LIVE_WHOIS = True
ENABLE_DNS_CHECKS = True
ENABLE_SSL_CHECKS = True
ENABLE_WATCHLIST = True
```

### Risk Thresholds
```python
LOW_RISK_MAX = 29
MEDIUM_RISK_MAX = 59
HIGH_RISK_MAX = 79
```

### Stealth/Proxy Configuration
```python
HTTP_PROXY = None
HTTPS_PROXY = None
SOCKS_PROXY = None

STEALTH_RATE_LIMIT = 2.0
STEALTH_BURST_SIZE = 5
STEALTH_DELAY_MS = 300
STEALTH_JITTER_MS = 200
STEALTH_USER_AGENT = None
```

## Instance
```python
config = Config()
```

## Usage
Import and use throughout the application:
```python
from config import config
print(config.PORT)
```

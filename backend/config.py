import os

class Config:
    DEBUG = True

    HOST = "0.0.0.0"
    PORT = 5000

    DB_PATH = "scanner.db"

    CACHE_TTL_HOURS = 24

    ENABLE_LIVE_WHOIS = True
    ENABLE_DNS_CHECKS = True
    ENABLE_SSL_CHECKS = True
    ENABLE_WATCHLIST = True

    MAX_URL_LENGTH = 2048

    LOW_RISK_MAX = 29
    MEDIUM_RISK_MAX = 59
    HIGH_RISK_MAX = 79

    # ========================================================================
    # STEALTH / PROXY CONFIGURATION
    # ========================================================================
    # Proxy settings (also read from HTTP_PROXY / HTTPS_PROXY env vars)
    HTTP_PROXY: str | None = None
    HTTPS_PROXY: str | None = None
    SOCKS_PROXY: str | None = None

    # Rate limiting
    STEALTH_RATE_LIMIT: float = 2.0       # Max requests per second
    STEALTH_BURST_SIZE: int = 5           # Max burst requests
    STEALTH_DELAY_MS: int = 300           # Base delay between requests (ms)
    STEALTH_JITTER_MS: int = 200          # Random jitter (ms)

    # Custom User-Agent (optional — rotates through realistic list by default)
    STEALTH_USER_AGENT: str | None = None


# THIS LINE IS VERY IMPORTANT
config = Config()
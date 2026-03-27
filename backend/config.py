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

# THIS LINE IS VERY IMPORTANT
config = Config()
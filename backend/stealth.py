"""
Stealth HTTP Module — Proxy, Rate Limiting & Rotating User-Agent
=================================================================
Provides realistic browser-like HTTP requests to avoid CDN edge server
blocking and to retrieve full security headers.

Features:
  - Rotating User-Agent strings (realistic browser list)
  - HTTP/HTTPS/SOCKS proxy support (via environment variables or config)
  - Rate limiting with configurable delay and jitter
  - Burst request support
  - Full browser header set (Accept, Accept-Language, DNT, etc.)

Usage:
    from stealth import setup_stealth, build_stealth_opener, stealth_build_request

    setup_stealth()                     # Call once at app startup
    req = stealth_build_request(url, headers=extra_headers)
    opener = build_stealth_opener(handler)
    with opener.open(req, timeout=5) as resp:
        ...
"""

from __future__ import annotations

import os
import random
import time
import urllib.request
from typing import Any

# ==============================================================================
# CONFIGURATION (can be overridden via config or env vars)
# ==============================================================================

# Proxy settings (read from env vars or config)
HTTP_PROXY: str | None = os.environ.get("HTTP_PROXY")
HTTPS_PROXY: str | None = os.environ.get("HTTPS_PROXY")
SOCKS_PROXY: str | None = os.environ.get("SOCKS_PROXY")

# Rate limiting
STEALTH_RATE_LIMIT: float = 2.0       # Max requests per second
STEALTH_BURST_SIZE: int = 5           # Max burst requests
STEALTH_DELAY_MS: int = 300           # Base delay between requests (ms)
STEALTH_JITTER_MS: int = 200          # Random jitter (ms)

# ==============================================================================
# REALISTIC USER-AGENT LIST (browser-like rotating agents)
# ==============================================================================

USER_AGENTS: list[str] = [
    # Chrome 120+ Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Generic mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

_last_request_time: float = 0.0
_burst_count: int = 0
_burst_window_start: float = 0.0


# ==============================================================================
# PUBLIC API
# ==============================================================================


def setup_stealth() -> None:
    """
    Initialize the stealth module.

    Call this once at application startup.
    Reads proxy settings from environment variables and config.
    Resets rate limiter state.
    """
    global _last_request_time, _burst_count, _burst_window_start
    global HTTP_PROXY, HTTPS_PROXY, SOCKS_PROXY

    HTTP_PROXY = os.environ.get("HTTP_PROXY") or HTTP_PROXY
    HTTPS_PROXY = os.environ.get("HTTPS_PROXY") or HTTPS_PROXY
    SOCKS_PROXY = os.environ.get("SOCKS_PROXY") or SOCKS_PROXY

    _last_request_time = 0.0
    _burst_count = 0
    _burst_window_start = time.monotonic()

    # Configure proxy handlers if set
    if HTTP_PROXY or HTTPS_PROXY:
        proxy_support = urllib.request.ProxyHandler({
            "http": HTTP_PROXY or "",
            "https": HTTPS_PROXY or HTTP_PROXY or "",
        })
        urllib.request.install_opener(urllib.request.build_opener(proxy_support))


def _apply_rate_limit() -> None:
    """Apply rate limiting delay before making a request."""
    global _last_request_time, _burst_count, _burst_window_start

    now = time.monotonic()

    # Reset burst counter every second
    if now - _burst_window_start >= 1.0:
        _burst_count = 0
        _burst_window_start = now

    # If we've exceeded burst limit, apply base delay
    if _burst_count >= STEALTH_BURST_SIZE:
        delay_ms = STEALTH_DELAY_MS + random.randint(0, STEALTH_JITTER_MS)
        time.sleep(delay_ms / 1000.0)
        _burst_count = 0
    elif _last_request_time > 0:
        # Rate limit per-second
        elapsed = now - _last_request_time
        min_interval = 1.0 / STEALTH_RATE_LIMIT
        if elapsed < min_interval:
            jitter = random.uniform(0, STEALTH_JITTER_MS / 1000.0)
            time.sleep(min_interval - elapsed + jitter)

    _burst_count += 1
    _last_request_time = time.monotonic()


def _get_random_user_agent() -> str:
    """Return a random User-Agent string from the realistic list."""
    return random.choice(USER_AGENTS)


def stealth_build_request(
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    method: str | None = None,
) -> urllib.request.Request:
    """
    Build a urllib Request with stealth browser headers.

    Args:
        url: The URL to request.
        headers: Additional headers to include (will override defaults).
        data: Optional request body bytes.
        method: HTTP method (GET, POST, etc.).

    Returns:
        A configured urllib.request.Request with realistic browser headers.
    """
    _apply_rate_limit()

    default_headers: dict[str, str] = {
        "User-Agent": _get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

    if headers:
        default_headers.update(headers)

    req = urllib.request.Request(
        url,
        data=data,
        headers=default_headers,
        method=method,
    )
    return req


def build_stealth_opener(
    *handlers: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    """
    Build a urllib opener with stealth proxy support and custom handlers.

    Args:
        *handlers: Custom handlers to include (e.g., HTTPRedirectHandler).

    Returns:
        An OpenerDirector configured with proxy support (if enabled).
    """
    handler_list = list(handlers)

    # Add proxy handler if proxies are configured
    if HTTP_PROXY or HTTPS_PROXY:
        proxy_handler = urllib.request.ProxyHandler({
            "http": HTTP_PROXY or "",
            "https": HTTPS_PROXY or HTTP_PROXY or "",
        })
        handler_list.append(proxy_handler)

    return urllib.request.build_opener(*handler_list)

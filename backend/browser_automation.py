"""
Browser Automation Module (v3.0)
==================================
Playwright-based dynamic content analysis for sophisticated phishing detection.

Capabilities:
  - Full page rendering with JavaScript execution
  - Form detection and analysis
  - Network request capture (XHR, fetch, WebSocket endpoints)
  - Console log capture (errors, warnings)
  - Storage inspection (localStorage, sessionStorage, cookies)
  - Stealth mode (avoid bot detection)

Gracefully degrades when Playwright is not installed.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

# Check if Playwright is available
PLAYWRIGHT_AVAILABLE = False
try:
    import playwright  # type: ignore # noqa: F401
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


def is_playwright_installed() -> bool:
    """Check if Playwright is installed and available."""
    return PLAYWRIGHT_AVAILABLE


def analyze_dynamic_content(
    url: str,
    timeout: float = 10.0,
    capture_network: bool = True,
    capture_console: bool = False,
    capture_storage: bool = False,
    network_capture_ms: int = 2000,
    stealth: bool = True,
) -> dict[str, Any]:
    """
    Analyze a website using Playwright browser automation.

    Args:
        url: The URL to visit.
        timeout: Maximum time to wait for page load.
        capture_network: Whether to capture network requests.
        capture_console: Whether to capture console messages.
        capture_storage: Whether to inspect browser storage.
        network_capture_ms: How long to capture network traffic after load.
        stealth: Whether to use stealth mode to avoid bot detection.

    Returns:
        Dict with analysis results including:
          - page_title: The page title
          - forms: Detected forms with action URLs and field counts
          - external_endpoints: External URLs the page communicates with
          - console_logs: Captured console messages (if enabled)
          - storage: Browser storage contents (if enabled)
          - login_form: Whether a login form was detected
          - suspicious_patterns: Any suspicious patterns detected
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            "available": False,
            "source": "unavailable",
            "reason": "Playwright is not installed. Install with: pip install playwright && playwright install chromium",
        }

    result: dict[str, Any] = {
        "available": True,
        "source": "playwright",
        "url": url,
        "page_title": None,
        "final_url": None,
        "http_status": None,
        "forms": [],
        "external_endpoints": [],
        "login_form": False,
        "suspicious_patterns": [],
        "error": None,
    }

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return {
            "available": False,
            "source": "import_error",
            "reason": "Playwright sync_api not available.",
        }

    try:
        with sync_playwright() as p:
            browser_type = p.chromium

            launch_options = {
                "headless": True,
                "args": [
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            }

            if stealth:
                launch_options["args"].extend([
                    "--disable-blink-features=AutomationControlled",
                ])

            browser = browser_type.launch(**launch_options)
            context_options = {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "viewport": {"width": 1920, "height": 1080},
            }

            if stealth:
                context_options["locale"] = "en-US"
                context_options["timezone_id"] = "America/New_York"

            context = browser.new_context(**context_options)

            if stealth:
                # Add stealth scripts
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                    window.chrome = { runtime: {} };
                """)

            page = context.new_page()

            # Network capture
            network_requests: list[dict[str, Any]] = []
            if capture_network:
                def handle_request(request: Any) -> None:
                    network_requests.append({
                        "url": request.url,
                        "method": request.method,
                        "headers": dict(request.headers),
                        "resource_type": request.resource_type,
                    })

                page.on("request", handle_request)

            # Console capture
            console_messages: list[str] = []
            if capture_console:
                def handle_console(msg: Any) -> None:
                    console_messages.append(f"[{msg.type}] {msg.text}")

                page.on("console", handle_console)

            # Navigate
            response = page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))

            if response:
                result["http_status"] = response.status
                result["final_url"] = response.url

            result["page_title"] = page.title()

            # Extract forms
            forms = page.query_selector_all("form")
            for form in forms:
                action = form.get_attribute("action") or ""
                method = (form.get_attribute("method") or "get").upper()
                inputs = form.query_selector_all("input")
                buttons = form.query_selector_all("button, input[type=submit]")

                field_types = []
                for inp in inputs:
                    inp_type = inp.get_attribute("type") or "text"
                    inp_name = inp.get_attribute("name") or ""
                    field_types.append({"type": inp_type, "name": inp_name})

                form_info = {
                    "action": action,
                    "method": method,
                    "field_count": len(inputs),
                    "button_count": len(buttons),
                    "fields": field_types,
                    "has_password": any(f["type"] == "password" for f in field_types),
                    "has_email": any("email" in f["type"] or "email" in f["name"].lower() for f in field_types),
                }
                result["forms"].append(form_info)

                if form_info["has_password"]:
                    result["login_form"] = True

            # Wait for network traffic
            if capture_network and network_capture_ms > 0:
                page.wait_for_timeout(network_capture_ms)

            # External endpoints
            if network_requests:
                base_domain = urlparse(url).hostname or ""
                external = [
                    req for req in network_requests
                    if urlparse(req["url"]).hostname and
                    urlparse(req["url"]).hostname != base_domain and
                    not urlparse(req["url"]).hostname.endswith("." + base_domain)
                ]
                # Deduplicate by URL
                seen = set()
                for req in external:
                    if req["url"] not in seen:
                        seen.add(req["url"])
                        result["external_endpoints"].append({
                            "url": req["url"],
                            "method": req["method"],
                            "resource_type": req.get("resource_type", "unknown"),
                        })

            # Storage capture
            if capture_storage:
                try:
                    result["local_storage"] = page.evaluate("JSON.stringify(window.localStorage)")
                except Exception:
                    result["local_storage"] = None

                try:
                    result["cookies"] = context.cookies()
                except Exception:
                    result["cookies"] = []

            # Console logs
            if console_messages:
                result["console_logs"] = console_messages[:50]

            # Suspicious pattern detection
            suspicious: list[str] = []
            page_text = page.content().lower() if page.content() else ""

            if "data:" in page_text and "base64" in page_text:
                suspicious.append("Page contains base64 data URIs — possible obfuscation")

            # Check for external form submissions
            for form in result["forms"]:
                action = form.get("action", "").lower()
                if action and not action.startswith("#") and not action.startswith("/") and not action.startswith("javascript:"):
                    suspicious.append(f"Form submits to external URL: {action}")

            if result["login_form"]:
                suspicious.append("Login form detected — credential harvesting risk")

            result["suspicious_patterns"] = suspicious[:10]

            # Cleanup
            context.close()
            browser.close()

    except Exception as exc:
        result["available"] = False
        result["source"] = "error"
        result["error"] = str(exc)
        # Cleanup on error
        try:
            context.close()
        except Exception:
            pass
        try:
            browser.close()
        except Exception:
            pass

    return result

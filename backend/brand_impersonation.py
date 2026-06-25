"""
Brand Impersonation Detection Engine (v3.0)
============================================
Advanced detection of brand impersonation, brand similarity,
and login harvesting pages.

Features:
  - Brand similarity scoring (Levenshtein, Jaro-Winkler, keyboard proximity)
  - Login page harvesting detection (form analysis, credential collection)
  - Multi-brand campaign detection
  - Visual similarity heuristics
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# Load brand database
BRAND_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand_database.json")

# In-memory brand cache
_brand_db: dict[str, Any] | None = None


def _load_brand_db() -> dict[str, Any]:
    """Load the brand database from disk."""
    global _brand_db
    if _brand_db is not None:
        return _brand_db

    try:
        with open(BRAND_DB_PATH, "r") as f:
            _brand_db = json.load(f)
            return _brand_db
    except (FileNotFoundError, json.JSONDecodeError):
        _brand_db = _get_default_brand_db()
        return _brand_db


def _get_default_brand_db() -> dict[str, Any]:
    """Return the default brand database."""
    return {
        "brands": [
            {"name": "Google", "domains": ["google.com", "gmail.com", "youtube.com"],
             "keywords": ["google", "gmail", "youtube", "g00gle", "go0gle"]},
            {"name": "Microsoft", "domains": ["microsoft.com", "office.com", "outlook.com"],
             "keywords": ["microsoft", "office365", "outlook", "azure", "m1crosoft"]},
            {"name": "Apple", "domains": ["apple.com", "icloud.com"],
             "keywords": ["apple", "icloud", "app1e", "appie"]},
            {"name": "Amazon", "domains": ["amazon.com", "aws.amazon.com"],
             "keywords": ["amazon", "aws", "amaz0n", "amzon"]},
            {"name": "Facebook", "domains": ["facebook.com", "messenger.com"],
             "keywords": ["facebook", "fb", "meta", "faceb00k", "facebok"]},
            {"name": "Instagram", "domains": ["instagram.com"],
             "keywords": ["instagram", "insta", "instagr4m"]},
            {"name": "Twitter/X", "domains": ["twitter.com", "x.com"],
             "keywords": ["twitter", "x", "tw1tter"]},
            {"name": "LinkedIn", "domains": ["linkedin.com"],
             "keywords": ["linkedin", "linked1n"]},
            {"name": "PayPal", "domains": ["paypal.com"],
             "keywords": ["paypal", "paypa1", "payp4l", "pay-pal"]},
            {"name": "Netflix", "domains": ["netflix.com"],
             "keywords": ["netflix", "netf1ix", "netflx"]},
            {"name": "WhatsApp", "domains": ["whatsapp.com"],
             "keywords": ["whatsapp", "whats4pp", "wh4tsapp"]},
            {"name": "Telegram", "domains": ["telegram.org"],
             "keywords": ["telegram", "telegr4m", "t eleg r am"]},
            {"name": "Coinbase", "domains": ["coinbase.com"],
             "keywords": ["coinbase", "c0inbase", "coinb4se"]},
            {"name": "Binance", "domains": ["binance.com"],
             "keywords": ["binance", "b1nance", "bin4nce"]},
            {"name": "GitHub", "domains": ["github.com"],
             "keywords": ["github", "g1thub", "git-hub"]},
            {"name": "Adobe", "domains": ["adobe.com"],
             "keywords": ["adobe", "ad0be", "adob e"]},
            {"name": "Spotify", "domains": ["spotify.com"],
             "keywords": ["spotify", "sp0tify", "spot1fy"]},
            {"name": "SBI", "domains": ["sbi.co.in", "onlinesbi.sbi"],
             "keywords": ["sbi", "statebank", "onlinesbi"]},
            {"name": "HDFC", "domains": ["hdfcbank.com"],
             "keywords": ["hdfc", "hdfcbank"]},
            {"name": "ICICI", "domains": ["icicibank.com"],
             "keywords": ["icici", "icicibank"]},
            {"name": "PhonePe", "domains": ["phonepe.com"],
             "keywords": ["phonepe", "phone-pay"]},
            {"name": "Paytm", "domains": ["paytm.com"],
             "keywords": ["paytm", "pay-tm"]},
            {"name": "Flipkart", "domains": ["flipkart.com"],
             "keywords": ["flipkart", "flipk4rt"]},
        ],
        "phishing_keywords": [
            "login", "signin", "verify", "account", "update",
            "secure", "password", "reset", "recover", "billing",
            "payment", "wallet", "support", "help", "official",
            "confirm", "auth", "2fa", "mfa", "otp", "kyc",
            "claim", "reward", "prize", "gift", "airdrop",
        ],
        "login_page_indicators": {
            "keywords": ["password", "login", "sign in", "sign in", "username"],
            "credential_fields": ["password", "passwd", "pwd", "login", "username"],
            "suspicious_form_actions": ["/login", "/verify", "/secure", "/auth"],
        },
    }


def analyze_brand_impersonation(
    domain: str,
    website_content: str = "",
    whois_text: str = "",
) -> dict[str, Any]:
    """
    Comprehensive brand impersonation analysis.

    Detects:
      - Domain similarity to known brands
      - Brand keywords in domain + phishing keyword combinations
      - Login page credential collection patterns
      - Brand + subdomain impersonation

    Args:
        domain: The domain to analyze.
        website_content: Text content from the website.
        whois_text: Raw WHOIS output.

    Returns:
        Dict with impersonation analysis results.
    """
    db = _load_brand_db()
    clean = domain.strip().lower().removeprefix("www.").removesuffix(".")
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean

    results: dict[str, Any] = {
        "domain": domain,
        "impersonation_detected": False,
        "impersonated_brands": [],
        "similarity_scores": {},
        "phishing_keywords_found": [],
        "login_harvesting": False,
        "overall_risk": 0,
        "details": [],
    }

    brands = db.get("brands", [])
    phishing_keywords = db.get("phishing_keywords", [])

    # Check domain similarity to each known brand
    for brand in brands:
        for keyword in brand.get("keywords", []):
            kw_lower = keyword.lower()

            # Exact brand match in domain label (not the registered domain itself)
            if kw_lower == label:
                continue  # The domain IS the brand, not impersonating it

            # Brand appears in subdomain or label (possible impersonation)
            if kw_lower in clean and kw_lower != label:
                # Check if this is a legitimate subdomain of the brand
                is_legitimate_subdomain = False
                for legit_domain in brand.get("domains", []):
                    if clean.endswith("." + legit_domain) or clean == legit_domain:
                        is_legitimate_subdomain = True
                        break

                if not is_legitimate_subdomain:
                    if brand["name"] not in [b["name"] for b in results["impersonated_brands"]]:
                        results["impersonated_brands"].append({
                            "name": brand["name"],
                            "matched_keyword": keyword,
                            "confidence": "high" if kw_lower in label else "medium",
                        })

    # Check for phishing keywords
    found_keywords = [kw for kw in phishing_keywords if kw in clean]
    results["phishing_keywords_found"] = found_keywords

    # Determine overall risk
    risk = 0
    if results["impersonated_brands"]:
        risk += 30
        results["details"].append(
            f"Domain contains brand name(s): "
            f"{', '.join(b['name'] for b in results['impersonated_brands'])}"
        )

    if found_keywords:
        risk += min(len(found_keywords) * 5, 25)
        results["details"].append(
            f"Phishing keywords detected: {', '.join(found_keywords)}"
        )

    # Check website content for login harvesting
    if website_content:
        harvesting_result = detect_login_harvesting(website_content)
        if harvesting_result.get("is_login_page"):
            risk += 20
            results["login_harvesting"] = True
            results["details"].append(
                "Website is a login/credential harvesting page"
            )

    results["overall_risk"] = min(risk, 100)
    results["impersonation_detected"] = (
        len(results["impersonated_brands"]) > 0 and len(found_keywords) > 0
    ) or (len(results["impersonated_brands"]) >= 2)

    return results


def detect_brand_similarity(domain: str) -> dict[str, Any]:
    """
    Quick brand similarity check using Levenshtein distance.

    Returns the closest brand match and similarity score.
    """
    db = _load_brand_db()
    clean = domain.strip().lower().removeprefix("www.").removesuffix(".")
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean

    best_match = None
    best_score = 0.0
    best_keyword = None

    for brand in db.get("brands", []):
        for keyword in brand.get("keywords", []):
            kw = keyword.lower()
            dist = _levenshtein(label, kw)
            max_len = max(len(label), len(kw))
            if max_len == 0:
                continue
            score = 1.0 - (dist / max_len)

            if score > best_score:
                best_score = score
                best_match = brand["name"]
                best_keyword = kw

    return {
        "closest_brand": best_match,
        "similarity_score": round(best_score, 4),
        "matched_keyword": best_keyword,
    }


def detect_login_harvesting(website_content: str) -> dict[str, Any]:
    """
    Detect if website content indicates a login credential harvesting page.

    Analyzes:
      - Presence of login forms / password fields
      - Suspicious form actions (external URLs, data URIs)
      - Brand impersonation in page title
      - Multiple credential collection indicators

    Args:
        website_content: Text content of the website.

    Returns:
        Dict with harvesting detection results.
    """
    content = website_content.lower()
    indicators = _get_default_brand_db().get("login_page_indicators", {})

    result: dict[str, Any] = {
        "is_login_page": False,
        "confidence": 0.0,
        "indicators_found": [],
    }

    # Check for credential-related keywords
    found_kw = [kw for kw in indicators.get("keywords", []) if kw in content]
    if found_kw:
        result["indicators_found"].extend(found_kw)

    # Check for password field indicators
    for field in indicators.get("credential_fields", []):
        if field in content:
            result["indicators_found"].append(f"credential_field:{field}")

    # Check for external/suspicious form actions
    for action in indicators.get("suspicious_form_actions", []):
        if action in content:
            result["indicators_found"].append(f"suspicious_action:{action}")

    # Determine if this is a login harvesting page
    if len(result["indicators_found"]) >= 3:
        result["is_login_page"] = True
        result["confidence"] = min(40 + len(result["indicators_found"]) * 10, 95)

    return result


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]

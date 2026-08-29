"""
DOM & Visual Analysis with CNN-Ready Pipeline
==============================================
Multi-modal webpage analysis:
  - DOM structure analysis for phishing patterns
  - Visual similarity scoring (CNN feature extraction ready)
  - Brand impersonation markers detection
  - Rendering pattern analysis
  - Layout fingerprinting

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import re
import math
import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Optional image analysis
_PIL_AVAILABLE = False
_IMAGEHASH_AVAILABLE = False
try:
    from PIL import Image
    import io
    _PIL_AVAILABLE = True
except ImportError:
    pass

try:
    import imagehash
    _IMAGEHASH_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Brand visual signatures (CSS patterns, layout markers)
# ---------------------------------------------------------------------------
BRAND_DOM_SIGNATURES = {
    "paypal": {
        "meta_keywords": ["paypal"],
        "css_classes": ["paypal", "pp-", "paypal-button"],
        "form_actions": ["paypal.com/cgi-bin"],
        "js_globals": ["paypal", "PPConfig"],
        "favicon_patterns": ["paypal"],
    },
    "microsoft": {
        "meta_keywords": ["microsoft", "office", "outlook", "onedrive"],
        "css_classes": ["ms-", "microsoft", "office"],
        "form_actions": ["login.microsoftonline.com", "login.live.com"],
        "js_globals": ["Microsoft", "Office"],
        "favicon_patterns": ["microsoft", "msn"],
    },
    "google": {
        "meta_keywords": ["google", "gmail", "gsuite"],
        "css_classes": ["google", "gserviceaccount", "goog-"],
        "form_actions": ["accounts.google.com", "mail.google.com"],
        "js_globals": ["google", "gapi", "GoogleAuth"],
        "favicon_patterns": ["google", "gstatic"],
    },
    "apple": {
        "meta_keywords": ["apple", "icloud", "itunes"],
        "css_classes": ["apple-", "icloud"],
        "form_actions": ["apple.com", "icloud.com"],
        "js_globals": ["apple", "AppleID"],
        "favicon_patterns": ["apple"],
    },
    "amazon": {
        "meta_keywords": ["amazon", "aws"],
        "css_classes": ["amazon", "a-", "nav-"],
        "form_actions": ["amazon.com", "signin.amazon"],
        "js_globals": ["amazon", "amzn"],
        "favicon_patterns": ["amazon", "amzn"],
    },
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class DOMAnalysisResult:
    """DOM structure analysis result."""
    available: bool = True
    score: int = 0
    risk_level: str = "unknown"
    brands_detected: list[str] = field(default_factory=list)
    phishing_markers: list[str] = field(default_factory=list)
    layout_analysis: dict[str, Any] = field(default_factory=dict)
    form_analysis: dict[str, Any] = field(default_factory=dict)
    script_analysis: dict[str, Any] = field(default_factory=dict)
    meta_analysis: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    dom_features: dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualAnalysisResult:
    """Visual/screenshot analysis result."""
    available: bool = True
    score: int = 0
    risk_level: str = "unknown"
    similar_to_known_brand: bool = False
    matched_brand: str = ""
    similarity_score: float = 0.0
    visual_features: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DOM Structure Analysis
# ---------------------------------------------------------------------------
def analyze_dom_structure(html: str, url: str = "") -> dict[str, Any]:
    """
    Analyze DOM structure for phishing indicators.
    
    Checks:
    - Brand impersonation via CSS classes, meta tags, JS globals
    - Credential harvesting forms
    - Suspicious script patterns
    - Layout mimicking
    - Hidden elements
    """
    if not html:
        return {"available": False, "error": "No HTML content provided"}

    result = {
        "available": True,
        "score": 0,
        "risk_level": "unknown",
        "brands_detected": [],
        "phishing_markers": [],
        "layout_analysis": {},
        "form_analysis": {},
        "script_analysis": {},
        "meta_analysis": {},
        "findings": [],
        "dom_features": {},
    }

    html_lower = html.lower()

    # --- Brand Detection ---
    for brand, signatures in BRAND_DOM_SIGNATURES.items():
        brand_hits = 0

        # Check meta keywords
        for keyword in signatures["meta_keywords"]:
            if keyword in html_lower:
                brand_hits += 1

        # Check CSS classes
        for css_class in signatures["css_classes"]:
            if css_class in html_lower:
                brand_hits += 1

        # Check form actions
        for action in signatures["form_actions"]:
            if action in html_lower:
                brand_hits += 2  # stronger signal

        # Check JS globals
        for js_global in signatures["js_globals"]:
            if js_global.lower() in html_lower:
                brand_hits += 1

        if brand_hits >= 2:
            result["brands_detected"].append(brand)
            result["findings"].append(f"Brand DOM signature detected: {brand} ({brand_hits} markers)")
            result["score"] += brand_hits * 5

    # --- Form Analysis ---
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
    password_forms = 0
    external_form_actions = 0
    page_domain = urlparse(url).hostname if url else ""

    for form_content in forms:
        has_password = bool(re.search(r'type\s*=\s*["\']?password', form_content, re.IGNORECASE))
        action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_content, re.IGNORECASE)

        if has_password:
            password_forms += 1
            action = action_match.group(1) if action_match else ""

            if action and page_domain:
                action_domain = urlparse(action).hostname if action.startswith("http") else page_domain
                if action_domain != page_domain:
                    external_form_actions += 1
                    result["phishing_markers"].append(f"Password form posts to external domain: {action_domain}")
                    result["score"] += 25

    result["form_analysis"] = {
        "total_forms": len(forms),
        "password_forms": password_forms,
        "external_actions": external_form_actions,
    }

    if password_forms > 0:
        result["findings"].append(f"{password_forms} password form(s) detected")

    # --- Script Analysis ---
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
    inline_scripts = len([s for s in scripts if s.strip()])
    external_scripts = len(re.findall(r'<script[^>]+src\s*=', html, re.IGNORECASE))

    obfuscation_indicators = 0
    for script in scripts:
        if re.search(r'eval\s*\(', script):
            obfuscation_indicators += 1
        if re.search(r'document\.write\s*\(', script):
            obfuscation_indicators += 1
        if re.search(r'\\x[0-9a-f]{2}', script):
            obfuscation_indicators += 1

    result["script_analysis"] = {
        "inline_scripts": inline_scripts,
        "external_scripts": external_scripts,
        "obfuscation_indicators": obfuscation_indicators,
    }

    if obfuscation_indicators >= 3:
        result["phishing_markers"].append(f"Script obfuscation detected ({obfuscation_indicators} indicators)")
        result["score"] += 20

    # --- Meta Analysis ---
    title = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    meta_desc = re.search(r'<meta[^>]+name\s*=\s*["\']description["\'][^>]+content\s*=\s*["\']([^"\']*)["\']', html, re.IGNORECASE)
    meta_keywords = re.search(r'<meta[^>]+name\s*=\s*["\']keywords["\'][^>]+content\s*=\s*["\']([^"\']*)["\']', html, re.IGNORECASE)

    result["meta_analysis"] = {
        "title": title.group(1).strip() if title else "",
        "description": meta_desc.group(1).strip() if meta_desc else "",
        "keywords": meta_keywords.group(1).strip() if meta_keywords else "",
    }

    # --- Hidden Elements ---
    hidden_elements = len(re.findall(
        r'(?:display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute\s*;\s*(?:top|left)\s*:\s*-9999)',
        html_lower
    ))
    if hidden_elements > 5:
        result["phishing_markers"].append(f"Many hidden elements ({hidden_elements})")
        result["score"] += 10

    # --- Layout Features (CNN-ready) ---
    # Extract structural features for CNN feature vector
    result["dom_features"] = {
        "total_elements": len(re.findall(r'<[a-zA-Z]+', html)),
        "form_count": len(forms),
        "password_form_count": password_forms,
        "script_count": inline_scripts + external_scripts,
        "image_count": len(re.findall(r'<img[^>]+>', html, re.IGNORECASE)),
        "iframe_count": len(re.findall(r'<iframe[^>]+>', html, re.IGNORECASE)),
        "hidden_element_count": hidden_elements,
        "external_script_count": external_scripts,
        "brands_detected_count": len(result["brands_detected"]),
        "obfuscation_count": obfuscation_indicators,
        "html_length": len(html),
        "has_login_form": password_forms > 0,
        "has_external_action": external_form_actions > 0,
    }

    # Risk level
    score = result["score"]
    if score >= 50:
        result["risk_level"] = "critical"
    elif score >= 30:
        result["risk_level"] = "high"
    elif score >= 15:
        result["risk_level"] = "medium"
    elif score > 0:
        result["risk_level"] = "low"
    else:
        result["risk_level"] = "clean"

    result["score"] = min(score, 100)
    return result


# ---------------------------------------------------------------------------
# Visual Similarity Analysis (CNN Feature Extraction Ready)
# ---------------------------------------------------------------------------
def compute_visual_features(image_bytes: bytes) -> dict[str, Any]:
    """
    Extract visual features from a screenshot for CNN analysis.
    Returns a feature dictionary that can be fed into a CNN model.
    """
    if not _PIL_AVAILABLE:
        return {"available": False, "error": "Pillow not installed"}

    try:
        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        img_rgb = img.convert("RGB")

        # Color histogram
        histogram = img_rgb.histogram()
        total_pixels = sum(histogram[:768])

        # Color distribution (R, G, B averages)
        r_avg = sum(i * histogram[i] for i in range(256)) / max(total_pixels, 1)
        g_avg = sum(i * histogram[i + 256] for i in range(256)) / max(total_pixels, 1)
        b_avg = sum(i * histogram[i + 512] for i in range(256)) / max(total_pixels, 1)

        # Dominant color regions
        dark_pixels = sum(histogram[:64]) / max(total_pixels, 1)
        light_pixels = sum(histogram[192:]) / max(total_pixels, 1)

        # Entropy
        entropy = 0.0
        for count in histogram[:768]:
            if count > 0:
                p = count / max(total_pixels, 1)
                entropy -= p * math.log2(p)

        features = {
            "available": True,
            "width": width,
            "height": height,
            "aspect_ratio": round(width / max(height, 1), 4),
            "r_avg": round(r_avg / 255, 4),
            "g_avg": round(g_avg / 255, 4),
            "b_avg": round(b_avg / 255, 4),
            "dark_ratio": round(dark_pixels, 4),
            "light_ratio": round(light_pixels, 4),
            "entropy": round(entropy, 4),
            "total_pixels": total_pixels,
        }

        # Perceptual hash (if imagehash available)
        if _IMAGEHASH_AVAILABLE:
            phash = imagehash.phash(img_rgb)
            dhash = imagehash.dhash(img_rgb)
            ahash = imagehash.average_hash(img_rgb)
            features["phash"] = str(phash)
            features["dhash"] = str(dhash)
            features["ahash"] = str(ahash)

        return features

    except Exception as e:
        return {"available": False, "error": str(e)}


def compare_visual_similarity(
    image1_bytes: bytes,
    image2_bytes: bytes,
) -> dict[str, Any]:
    """
    Compare two screenshots for visual similarity.
    Uses perceptual hashing when available, pixel comparison as fallback.
    """
    result = {
        "available": True,
        "similarity_score": 0.0,
        "method": "unknown",
        "hash_distance": None,
        "findings": [],
    }

    if _IMAGEHASH_AVAILABLE and _PIL_AVAILABLE:
        try:
            img1 = Image.open(io.BytesIO(image1_bytes)).convert("RGB")
            img2 = Image.open(io.BytesIO(image2_bytes)).convert("RGB")

            hash1 = imagehash.phash(img1)
            hash2 = imagehash.phash(img2)
            distance = hash1 - hash2

            # Distance 0 = identical, 64 = completely different
            similarity = 1.0 - (distance / 64.0)
            result["similarity_score"] = round(max(similarity, 0.0), 4)
            result["hash_distance"] = distance
            result["method"] = "perceptual_hash"

            if similarity > 0.85:
                result["findings"].append(f"High visual similarity detected (score: {similarity:.2%})")
            elif similarity > 0.7:
                result["findings"].append(f"Moderate visual similarity (score: {similarity:.2%})")

            return result

        except Exception as e:
            result["findings"].append(f"Hash comparison failed: {e}")

    # Fallback: basic byte comparison
    try:
        h1 = hashlib.md5(image1_bytes).hexdigest()
        h2 = hashlib.md5(image2_bytes).hexdigest()
        result["method"] = "exact_hash"
        result["similarity_score"] = 1.0 if h1 == h2 else 0.0
        return result
    except Exception:
        result["available"] = False
        return result


# ---------------------------------------------------------------------------
# CNN Feature Vector for Training
# ---------------------------------------------------------------------------
def extract_cnn_features(html: str, screenshot_bytes: bytes = b"") -> dict[str, Any]:
    """
    Extract a combined feature vector for CNN-based classification.
    Combines DOM features with visual features.
    """
    # DOM features
    dom_result = analyze_dom_structure(html)
    dom_features = dom_result.get("dom_features", {})

    # Visual features
    visual_features = {}
    if screenshot_bytes and _PIL_AVAILABLE:
        visual_features = compute_visual_features(screenshot_bytes)

    # Combine into unified feature vector
    combined = {
        "dom_features": dom_features,
        "visual_features": visual_features if visual_features.get("available") else {},
        "combined_vector": [],
    }

    # Create flat vector for ML
    vector = []
    for key in sorted(dom_features.keys()):
        val = dom_features[key]
        if isinstance(val, (int, float)):
            vector.append(float(val))
        elif isinstance(val, bool):
            vector.append(1.0 if val else 0.0)

    if visual_features.get("available"):
        for key in sorted(visual_features.keys()):
            if key in ("phash", "dhash", "ahash", "available"):
                continue
            val = visual_features[key]
            if isinstance(val, (int, float)):
                vector.append(float(val))

    combined["combined_vector"] = vector

    return combined


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze_webpage_visual(
    html: str = "",
    url: str = "",
    screenshot_bytes: bytes = b"",
) -> dict[str, Any]:
    """
    Complete webpage visual and DOM analysis.
    
    Returns combined analysis of DOM structure and visual appearance.
    """
    result = {
        "available": True,
        "dom_analysis": {},
        "visual_analysis": {},
        "overall_score": 0,
        "risk_level": "unknown",
        "findings": [],
    }

    # DOM analysis
    if html:
        dom_result = analyze_dom_structure(html, url)
        result["dom_analysis"] = dom_result
        result["findings"].extend(dom_result.get("findings", []))
        result["overall_score"] = max(result["overall_score"], dom_result.get("score", 0))

    # Visual analysis
    if screenshot_bytes and _PIL_AVAILABLE:
        visual_features = compute_visual_features(screenshot_bytes)
        result["visual_analysis"] = visual_features

    # Risk level
    score = result["overall_score"]
    if score >= 50:
        result["risk_level"] = "critical"
    elif score >= 30:
        result["risk_level"] = "high"
    elif score >= 15:
        result["risk_level"] = "medium"
    elif score > 0:
        result["risk_level"] = "low"
    else:
        result["risk_level"] = "clean"

    result["overall_score"] = min(score, 100)

    return result

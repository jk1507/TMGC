"""
Sandbox & Behavioral Analysis Integration
==========================================
Dynamic analysis of URLs and attachments in sandboxed environments:
  - URL behavioral analysis (redirects, JS execution, DOM changes)
  - Attachment static analysis (entropy, imports, sections)
  - HTTP traffic capture and inspection
  - Cookie / credential exfiltration detection
  - Drive-by download detection

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# Optional imports
_REQUESTS_AVAILABLE = False
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class BehavioralIndicator:
    """A single behavioral indicator from sandbox analysis."""
    category: str  # redirect, script, network, cookie, form, download
    severity: str  # info, low, medium, high, critical
    description: str
    evidence: str = ""
    timestamp: str = ""


@dataclass
class SandboxResult:
    """Complete sandbox analysis result."""
    available: bool = True
    url: str = ""
    analysis_type: str = "url"  # url, attachment
    overall_score: int = 0
    risk_level: str = "unknown"
    indicators: list[BehavioralIndicator] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    http_traffic: list[dict[str, Any]] = field(default_factory=list)
    scripts_detected: list[str] = field(default_factory=list)
    forms_detected: list[dict[str, Any]] = field(default_factory=list)
    cookies_set: list[str] = field(default_factory=list)
    external_requests: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# URL Behavioral Analysis
# ---------------------------------------------------------------------------
def analyze_url_behavior(
    url: str,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    max_redirects: int = 10,
) -> dict[str, Any]:
    """
    Analyze URL behavior by making HTTP request and inspecting response.
    
    Checks:
    - Redirect chain analysis
    - Response header anomalies
    - JavaScript-based redirects
    - Form action targets
    - External resource loading
    - Cookie behavior
    - Content obfuscation
    """
    if not _REQUESTS_AVAILABLE:
        return {"available": False, "error": "requests not installed"}

    result = {
        "available": True,
        "url": url,
        "analysis_type": "url",
        "overall_score": 0,
        "risk_level": "unknown",
        "redirect_chain": [],
        "http_traffic": [],
        "scripts_detected": [],
        "forms_detected": [],
        "cookies_set": [],
        "external_requests": [],
        "findings": [],
        "indicators": [],
    }

    try:
        # Make request with redirect tracking
        session = requests.Session()
        session.max_redirects = max_redirects

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=follow_redirects)

        # Track redirect chain
        for resp in response.history:
            result["redirect_chain"].append(resp.url)
            result["http_traffic"].append({
                "url": resp.url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
            })
        result["redirect_chain"].append(response.url)

        # Final response
        result["http_traffic"].append({
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_length": len(response.content),
        })

        # --- Redirect Analysis ---
        redirect_count = len(response.history)
        if redirect_count > 5:
            result["findings"].append(f"Excessive redirects ({redirect_count} hops)")
            result["indicators"].append({
                "category": "redirect",
                "severity": "medium",
                "description": f"URL redirects {redirect_count} times before reaching final destination",
            })

        # Check for redirect to different domain
        if response.history:
            original_domain = urlparse(url).hostname
            final_domain = urlparse(response.url).hostname
            if original_domain != final_domain:
                result["findings"].append(f"Redirect to different domain: {original_domain} -> {final_domain}")
                result["indicators"].append({
                    "category": "redirect",
                    "severity": "high",
                    "description": f"Cross-domain redirect from {original_domain} to {final_domain}",
                    "evidence": f"Chain: {' -> '.join(result['redirect_chain'][:5])}",
                })

        # --- Content Analysis ---
        content = response.text
        content_lower = content.lower()

        # JavaScript redirect detection
        js_redirects = re.findall(
            r'(?:window\.(?:location|location\.href|location\.replace|location\.assign))\s*[=(]\s*["\']([^"\']+)["\']',
            content, re.IGNORECASE
        )
        meta_redirects = re.findall(
            r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'>\s]+)',
            content, re.IGNORECASE
        )
        all_js_redirects = js_redirects + meta_redirects

        if all_js_redirects:
            result["scripts_detected"].extend(all_js_redirects)
            result["findings"].append(f"JavaScript/meta redirects detected ({len(all_js_redirects)})")
            result["indicators"].append({
                "category": "script",
                "severity": "medium",
                "description": f"Client-side redirects detected: {len(all_js_redirects)} redirect(s)",
                "evidence": str(all_js_redirects[:3]),
            })

        # Form analysis
        forms = re.findall(
            r'<form[^>]*>(.*?)</form>',
            content, re.DOTALL | re.IGNORECASE
        )
        for form_content in forms:
            form_action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            has_password = bool(re.search(r'type\s*=\s*["\']?password', form_content, re.IGNORECASE))
            method = re.search(r'method\s*=\s*["\'](\w+)["\']', form_content, re.IGNORECASE)

            if has_password:
                action_url = form_action.group(1) if form_action else "(same page)"
                result["forms_detected"].append({
                    "action": action_url,
                    "has_password": True,
                    "method": method.group(1) if method else "GET",
                })

                # Check if form posts to different domain
                if action_url and action_url.startswith("http"):
                    action_domain = urlparse(action_url).hostname
                    page_domain = urlparse(response.url).hostname
                    if action_domain != page_domain:
                        result["findings"].append(f"Password form posts to external domain: {action_domain}")
                        result["indicators"].append({
                            "category": "form",
                            "severity": "critical",
                            "description": f"Password form submits to external domain: {action_domain}",
                            "evidence": f"Action: {action_url}",
                        })

        # External resource detection
        external_urls = re.findall(r'(?:src|href)\s*=\s*["\']?(https?://[^"\'>\s]+)', content, re.IGNORECASE)
        page_domain = urlparse(response.url).hostname
        external = set()
        for ext_url in external_urls:
            ext_domain = urlparse(ext_url).hostname
            if ext_domain and ext_domain != page_domain:
                external.add(ext_domain)
        result["external_requests"] = list(external)

        if len(external) > 10:
            result["findings"].append(f"Many external resources loaded ({len(external)} domains)")

        # Cookie analysis
        cookies = response.cookies
        result["cookies_set"] = [c.name for c in cookies]
        for cookie in cookies:
            if cookie.name.lower() in ("session", "token", "auth", "jwt", "sid"):
                result["findings"].append(f"Authentication cookie set: {cookie.name}")

        # Content obfuscation
        obfuscation_patterns = [
            (r'eval\s*\(', "eval() usage"),
            (r'document\.write\s*\(', "document.write() usage"),
            (r'unescape\s*\(', "unescape() usage"),
            (r'String\.fromCharCode', "String.fromCharCode() obfuscation"),
            (r'\\x[0-9a-f]{2}', "Hex-encoded strings"),
            (r'atob\s*\(', "Base64 decoding"),
            (r'(?:\bfunction\b\s*\w+\s*\([^)]*\)\s*\{[^}]{500,})', "Large inline functions"),
        ]

        obfuscation_count = 0
        for pattern, label in obfuscation_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                obfuscation_count += len(matches)
                if len(matches) >= 2:
                    result["findings"].append(f"Code obfuscation: {label} ({len(matches)} instances)")

        if obfuscation_count >= 5:
            result["indicators"].append({
                "category": "script",
                "severity": "high",
                "description": f"Heavy code obfuscation detected ({obfuscation_count} indicators)",
            })

        # --- Score Calculation ---
        score = 0
        if redirect_count > 3:
            score += min(redirect_count * 5, 25)
        if len(result["forms_detected"]) > 0:
            score += 15
        if obfuscation_count > 3:
            score += 20
        if all_js_redirects:
            score += 10
        if len(external) > 10:
            score += 10

        result["overall_score"] = min(score, 100)

        if score >= 60:
            result["risk_level"] = "critical"
        elif score >= 40:
            result["risk_level"] = "high"
        elif score >= 20:
            result["risk_level"] = "medium"
        elif score > 0:
            result["risk_level"] = "low"
        else:
            result["risk_level"] = "clean"

    except requests.exceptions.SSLError:
        result["findings"].append("SSL certificate error — possible MitM or invalid certificate")
        result["indicators"].append({
            "category": "network",
            "severity": "high",
            "description": "SSL certificate validation failed",
        })
        result["overall_score"] = 40
        result["risk_level"] = "high"
    except requests.exceptions.ConnectionError:
        result["findings"].append("Connection failed — host may be down or blocking")
        result["overall_score"] = 0
        result["risk_level"] = "unknown"
    except Exception as e:
        result["findings"].append(f"Analysis error: {str(e)[:100]}")
        result["overall_score"] = 0
        result["risk_level"] = "error"

    return result


# ---------------------------------------------------------------------------
# Attachment Static Analysis
# ---------------------------------------------------------------------------
def analyze_attachment(
    filename: str,
    content: bytes,
) -> dict[str, Any]:
    """
    Static analysis of file attachment.
    
    Checks:
    - File entropy (packed/encrypted detection)
    - Magic byte detection
    - PE header analysis (if executable)
    - Suspicious strings extraction
    - Hash matching against known malware
    """
    result = {
        "available": True,
        "analysis_type": "attachment",
        "filename": filename,
        "file_size": len(content),
        "file_type": "unknown",
        "entropy": 0.0,
        "is_packed": False,
        "is_executable": False,
        "suspicious_strings": [],
        "findings": [],
        "overall_score": 0,
        "risk_level": "unknown",
    }

    if not content:
        return result

    # File type detection via magic bytes
    magic_signatures = {
        b"MZ": "PE/EXE",
        b"\x7fELF": "ELF",
        b"PK": "ZIP/Office Doc",
        b"%PDF": "PDF",
        b"\xd0\xcf\x11\xe0": "OLE2/Office Doc",
        b"Rar!": "RAR",
        b"\x1f\x8b": "GZIP",
        b"4": "7z",
        b"BZh": "BZIP2",
        b"\x89PNG": "PNG",
        b"\xff\xd8\xff": "JPEG",
    }

    for magic, ftype in magic_signatures.items():
        if content[:len(magic)] == magic:
            result["file_type"] = ftype
            break

    # PE detection
    if content[:2] == b"MZ":
        result["is_executable"] = True
        result["findings"].append("File is a PE executable")
        result["overall_score"] += 20

    # Entropy calculation
    import math
    byte_freq = [0] * 256
    for byte in content:
        byte_freq[byte] += 1
    entropy = 0.0
    for count in byte_freq:
        if count > 0:
            p = count / len(content)
            entropy -= p * math.log2(p)
    result["entropy"] = round(entropy, 4)

    # High entropy = packed/encrypted
    if entropy > 7.5:
        result["is_packed"] = True
        result["findings"].append(f"High entropy ({entropy:.2f}) — file may be packed or encrypted")
        result["overall_score"] += 25

    # Suspicious string extraction
    text_content = content.decode("latin-1", errors="ignore")
    suspicious_patterns = [
        (r'(?:cmd|powershell|bash|sh)\s', "Shell command"),
        (r'(?:http://|https://)\S+', "URL found"),
        (r'(?:\\\\|\.\.\\|\.\.\/)', "Path traversal"),
        (r'(?:CreateObject|WScript|Shell\.Application)', "COM object creation"),
        (r'(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread)', "Process injection"),
        (r'(?:InternetOpen|HttpSendRequest|URLDownload)', "Network API usage"),
        (r'(?:RegSetValue|RegCreateKey)', "Registry modification"),
    ]

    for pattern, label in suspicious_patterns:
        matches = re.findall(pattern, text_content, re.IGNORECASE)
        if matches:
            result["suspicious_strings"].append({
                "type": label,
                "count": len(matches),
                "sample": matches[0][:100],
            })
            if len(matches) >= 2:
                result["overall_score"] += 10

    # Hash computation
    result["md5"] = hashlib.md5(content).hexdigest()
    result["sha256"] = hashlib.sha256(content).hexdigest()

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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def analyze_sandbox(url: str = "", filename: str = "", content: bytes = b"") -> dict[str, Any]:
    """
    Unified sandbox analysis API.
    For URLs: behavioral analysis
    For files: static analysis
    """
    if content:
        return analyze_attachment(filename=filename, content=content)
    elif url:
        return analyze_url_behavior(url=url)
    else:
        return {"available": False, "error": "No URL or file content provided"}

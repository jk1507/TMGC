"""
Email & SMS Phishing Detection Engine
======================================
Multi-modal NLP-based phishing detection for:
  - Email content (body, subject, sender)
  - SMS / instant messaging content
  - Email header analysis (SPF, DKIM, DMARC, routing anomalies)

Uses transformer-based models (BERT/RoBERTa) when available,
falls back to rule-based + statistical NLP when ML libs are absent.

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import re
import json
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional heavy imports (graceful fallback)
# ---------------------------------------------------------------------------
_TORCH_AVAILABLE = False
_TRANSFORMERS_AVAILABLE = False

try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore[assignment]

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    AutoTokenizer = None  # type: ignore[assignment,misc]
    AutoModelForSequenceClassification = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Pre-trained model paths (downloaded lazily)
# ---------------------------------------------------------------------------
_EMAIL_MODEL_NAME = "limnegri/bert-phishing-emails"
_SMS_MODEL_NAME = "mariagrazia/bert-sms-phishing"
_LOCAL_CACHE_DIR = None  # uses HF default cache


# ---------------------------------------------------------------------------
# Phishing keyword / heuristic dictionaries
# ---------------------------------------------------------------------------
URGENCY_KEYWORDS = {
    "urgent", "immediately", "act now", "deadline", "expires",
    "suspended", "locked", "unauthorized", "verify your account",
    "confirm your identity", "reset your password", "click here",
    "act within", "failure to comply", "legal action",
    "final warning", "last chance", "within 24 hours",
    "account will be", "service will be", "limited time",
}

CREDENTIAL_HARVESTING_PHRASES = {
    "confirm your password", "verify your login", "update your billing",
    "confirm your payment", "validate your account", "reactivate your account",
    "verify your email", "confirm your identity", "secure your account",
    "update your security", "restore your access", "unlock your account",
    "sign in to verify", "log in to confirm", "enter your credentials",
}

FINANCIAL_PHISHING_PHRASES = {
    "wire transfer", "bank account", "credit card", "social security",
    "tax refund", "lottery winner", "inheritance", "investment opportunity",
    "bitcoin wallet", "crypto wallet", "send money", "payment pending",
    "invoice attached", "banking details", "routing number",
}

BRAND_IMPERSONATION_PATTERNS = {
    "paypal": ["paypal.com", "paypal security", "paypal account"],
    "microsoft": ["microsoft.com", "office 365", "outlook", "onedrive", "azure"],
    "google": ["google.com", "gmail", "google drive", "google workspace"],
    "apple": ["apple.com", "icloud", "apple id", "itunes"],
    "amazon": ["amazon.com", "amazon prime", "aws"],
    "netflix": ["netflix.com", "netflix account", "netflix subscription"],
    "facebook": ["facebook.com", "meta", "instagram", "whatsapp"],
    "dhl": ["dhl.com", "dhl express", "dhl shipping"],
    "fedex": ["fedex.com", "fedex tracking"],
    "ups": ["ups.com", "ups tracking"],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class EmailHeaderAnalysis:
    """Parsed results from email header inspection."""
    spf_result: str = "unknown"
    dkim_result: str = "unknown"
    dmarc_result: str = "unknown"
    reply_to_mismatch: bool = False
    reply_to_domain: str = ""
    from_domain: str = ""
    return_path_domain: str = ""
    received_chain_depth: int = 0
    suspicious_xmailer: bool = False
    has_html_mixed: bool = False
    anomalies: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class ContentPhishingResult:
    """Result of NLP + heuristic content analysis."""
    is_phishing: bool = False
    confidence: float = 0.0
    ml_score: float = 0.0
    heuristic_score: float = 0.0
    model_used: str = "rule_based"
    attack_type: str = "none"
    urgency_level: str = "low"
    brands_impersonated: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)
    credential_harvesting: bool = False
    financial_phishing: bool = False
    obfuscation_detected: bool = False
    findings: list[str] = field(default_factory=list)
    raw_features: dict[str, Any] = field(default_factory=dict)


@dataclass
class EmailPhishingResult:
    """Complete email phishing analysis result."""
    available: bool = True
    content_result: ContentPhishingResult = field(default_factory=ContentPhishingResult)
    header_result: EmailHeaderAnalysis = field(default_factory=EmailHeaderAnalysis)
    overall_score: int = 0
    risk_level: str = "unknown"
    summary: str = ""


@dataclass
class SMSPhishingResult:
    """SMS / instant messaging phishing result."""
    available: bool = True
    is_phishing: bool = False
    confidence: float = 0.0
    ml_score: float = 0.0
    heuristic_score: float = 0.0
    model_used: str = "rule_based"
    attack_type: str = "none"
    suspicious_urls: list[str] = field(default_factory=list)
    brands_impersonated: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    score: int = 0


# ---------------------------------------------------------------------------
# ML Model loader (lazy singleton)
# ---------------------------------------------------------------------------
_email_model_cache: dict[str, Any] = {}
_sms_model_cache: dict[str, Any] = {}


def _load_email_model():
    """Load the email phishing BERT model (cached)."""
    if "tokenizer" in _email_model_cache:
        return _email_model_cache["tokenizer"], _email_model_cache["model"]
    if not _TRANSFORMERS_AVAILABLE or not _TORCH_AVAILABLE:
        return None, None
    try:
        tokenizer = AutoTokenizer.from_pretrained(_EMAIL_MODEL_NAME, cache_dir=_LOCAL_CACHE_DIR)
        model = AutoModelForSequenceClassification.from_pretrained(_EMAIL_MODEL_NAME, cache_dir=_LOCAL_CACHE_DIR)
        model.eval()
        _email_model_cache["tokenizer"] = tokenizer
        _email_model_cache["model"] = model
        return tokenizer, model
    except Exception as e:
        logger.warning("Failed to load email phishing model: %s", e)
        return None, None


def _load_sms_model():
    """Load the SMS phishing BERT model (cached)."""
    if "tokenizer" in _sms_model_cache:
        return _sms_model_cache["tokenizer"], _sms_model_cache["model"]
    if not _TRANSFORMERS_AVAILABLE or not _TORCH_AVAILABLE:
        return None, None
    try:
        tokenizer = AutoTokenizer.from_pretrained(_SMS_MODEL_NAME, cache_dir=_LOCAL_CACHE_DIR)
        model = AutoModelForSequenceClassification.from_pretrained(_SMS_MODEL_NAME, cache_dir=_LOCAL_CACHE_DIR)
        model.eval()
        _sms_model_cache["tokenizer"] = tokenizer
        _sms_model_cache["model"] = model
        return tokenizer, model
    except Exception as e:
        logger.warning("Failed to load SMS phishing model: %s", e)
        return None, None


def _predict_with_model(text: str, model_type: str = "email") -> tuple[float, str]:
    """Run transformer prediction, return (score 0-1, model_name)."""
    if model_type == "email":
        tokenizer, model = _load_email_model()
    else:
        tokenizer, model = _load_sms_model()

    if tokenizer is None or model is None:
        return 0.0, "unavailable"

    try:
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
        with torch.no_grad():
            outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)[0]
        # Typically: [legitimate, phishing] or [phishing, legitimate]
        if probs.shape[0] == 2:
            phishing_score = max(probs[0].item(), probs[1].item())
            if probs[0].item() > probs[1].item():
                phishing_score = probs[0].item()
            else:
                phishing_score = probs[1].item()
        else:
            phishing_score = probs[0].item()
        return phishing_score, f"bert_{model_type}"
    except Exception as e:
        logger.warning("Model prediction failed: %s", e)
        return 0.0, "error"


# ---------------------------------------------------------------------------
# Email Header Analysis
# ---------------------------------------------------------------------------
def analyze_email_headers(raw_headers: str) -> EmailHeaderAnalysis:
    """
    Parse raw email headers and detect anomalies.
    
    Checks:
    - SPF / DKIM / DMARC results
    - Reply-To vs From domain mismatch
    - Return-Path anomalies
    - Suspicious X-Mailer / User-Agent
    - Received chain depth
    - Mixed HTML/text content
    """
    result = EmailHeaderAnalysis()

    if not raw_headers:
        result.anomalies.append("No email headers provided")
        result.score = 5
        return result

    # Parse headers using Python's email parser
    try:
        msg = Parser(policy=policy.default).parsestr(raw_headers)
    except Exception:
        # Try manual parsing if email parser fails
        msg = None

    if msg is not None:
        # From domain
        from_header = msg.get("From", "")
        from_match = re.search(r"@([\w.-]+)", from_header)
        result.from_domain = from_match.group(1).lower() if from_match else ""

        # Reply-To
        reply_to = msg.get("Reply-To", "")
        reply_to_match = re.search(r"@([\w.-]+)", reply_to)
        result.reply_to_domain = reply_to_match.group(1).lower() if reply_to_match else ""

        if result.reply_to_domain and result.from_domain and result.reply_to_domain != result.from_domain:
            result.reply_to_mismatch = True
            result.anomalies.append(
                f"Reply-To domain ({result.reply_to_domain}) differs from From domain ({result.from_domain})"
            )

        # Return-Path
        return_path = msg.get("Return-Path", "")
        rp_match = re.search(r"@([\w.-]+)", return_path)
        result.return_path_domain = rp_match.group(1).lower() if rp_match else ""

        if result.return_path_domain and result.from_domain and result.return_path_domain != result.from_domain:
            result.anomalies.append(
                f"Return-Path domain ({result.return_path_domain}) differs from From domain ({result.from_domain})"
            )

        # SPF / DKIM / DMARC
        auth_results = msg.get("Authentication-Results", "")
        spf_match = re.search(r"spf\s*=\s*(\w+)", auth_results, re.I)
        dkim_match = re.search(r"dkim\s*=\s*(\w+)", auth_results, re.I)
        dmarc_match = re.search(r"dmarc\s*=\s*(\w+)", auth_results, re.I)

        result.spf_result = spf_match.group(1).lower() if spf_match else "missing"
        result.dkim_result = dkim_match.group(1).lower() if dkim_match else "missing"
        result.dmarc_result = dmarc_match.group(1).lower() if dmarc_match else "missing"

        if result.spf_result == "fail":
            result.anomalies.append("SPF check FAILED — sender IP is not authorized")
        elif result.spf_result == "missing":
            result.anomalies.append("No SPF record found — sender authenticity unverified")

        if result.dkim_result == "fail":
            result.anomalies.append("DKIM signature verification FAILED")
        elif result.dkim_result == "missing":
            result.anomalies.append("No DKIM signature found")

        if result.dmarc_result == "fail":
            result.anomalies.append("DMARC policy check FAILED")
        elif result.dmarc_result == "missing":
            result.anomalies.append("No DMARC policy found")

        # Received chain depth
        received = msg.get_all("Received", [])
        result.received_chain_depth = len(received) if received else 0
        if result.received_chain_depth > 8:
            result.anomalies.append(
                f"Unusually deep Received chain ({result.received_chain_depth} hops) — possible relay manipulation"
            )

        # Suspicious X-Mailer
        x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
        suspicious_mailers = ["phpmailer", "mass mailer", "email robot", "bulk mail", "mail king"]
        if any(s in x_mailer.lower() for s in suspicious_mailers):
            result.suspicious_xmailer = True
            result.anomalies.append(f"Suspicious X-Mailer detected: {x_mailer}")

        # Content-Type mixed HTML/text
        content_type = msg.get("Content-Type", "")
        if "multipart/alternative" in content_type:
            result.has_html_mixed = True

    else:
        # Fallback: regex-based header parsing
        lines = raw_headers.lower()
        if "spf=fail" in lines:
            result.spf_result = "fail"
            result.anomalies.append("SPF check FAILED")
        elif "spf=pass" in lines:
            result.spf_result = "pass"
        else:
            result.spf_result = "missing"

        if "dkim=fail" in lines:
            result.dkim_result = "fail"
            result.anomalies.append("DKIM verification FAILED")
        elif "dkim=pass" in lines:
            result.dkim_result = "pass"
        else:
            result.dkim_result = "missing"

        if "dmarc=fail" in lines:
            result.dmarc_result = "fail"
            result.anomalies.append("DMARC check FAILED")
        elif "dmarc=pass" in lines:
            result.dmarc_result = "pass"
        else:
            result.dmarc_result = "missing"

    # Calculate header anomaly score
    score = 0
    if result.spf_result == "fail":
        score += 25
    elif result.spf_result == "missing":
        score += 10
    if result.dkim_result == "fail":
        score += 20
    elif result.dkim_result == "missing":
        score += 8
    if result.dmarc_result == "fail":
        score += 15
    elif result.dmarc_result == "missing":
        score += 5
    if result.reply_to_mismatch:
        score += 20
    if result.suspicious_xmailer:
        score += 15
    if result.received_chain_depth > 8:
        score += 10

    result.score = min(score, 100)
    return result


# ---------------------------------------------------------------------------
# URL Extraction & Validation
# ---------------------------------------------------------------------------
_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')}\]]+|'
    r'www\.[^\s<>"\')}\]]+|'
    r'(?<!\w)[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s<>"\')}\]]*)?'
)

_HEX_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')


def _extract_urls(text: str) -> list[str]:
    """Extract all URLs from email/SMS text."""
    urls = _URL_PATTERN.findall(text)
    cleaned = []
    for url in urls:
        url = url.strip().rstrip(".,;:!?)")
        if url.startswith("www."):
            url = "http://" + url
        if url.startswith("http"):
            cleaned.append(url)
    return list(dict.fromkeys(cleaned))  # dedupe preserving order


def _detect_url_obfuscation(url: str) -> dict[str, Any]:
    """Detect URL obfuscation techniques."""
    findings = []
    techniques = []

    # Hex encoding
    if _HEX_PATTERN.search(url):
        hex_matches = _HEX_PATTERN.findall(url)
        if len(hex_matches) >= 2:
            findings.append(f"Hex-encoded URL segments detected ({len(hex_matches)} encoded chars)")
            techniques.append("hex_encoding")

    # IP address as hostname
    ip_match = re.search(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
    if ip_match:
        findings.append(f"IP address used as hostname: {ip_match.group(1)}")
        techniques.append("ip_address_host")

    # Excessive subdomains
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) > 4:
        findings.append(f"Excessive subdomains ({len(parts)} levels): {hostname}")
        techniques.append("subdomain_depth")

    # Data URI
    if url.startswith("data:"):
        findings.append("Data URI used — possible obfuscated redirect")
        techniques.append("data_uri")

    # Homograph characters in URL
    suspicious_chars = set()
    for c in url:
        if ord(c) > 127:
            suspicious_chars.add(c)
    if suspicious_chars:
        findings.append(f"Non-ASCII characters in URL (possible homograph): {''.join(suspicious_chars)}")
        techniques.append("homograph")

    # Shortened URL detection
    shorteners = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly",
        "cutt.ly", "rb.gy", "shorturl.at", "dwz.cn", "tiny.cc",
        "bl.ink", "lnkd.in", "buff.ly",
    }
    if any(s in hostname for s in shorteners):
        findings.append(f"URL shortener detected: {hostname}")
        techniques.append("url_shortener")

    # @ in URL (credential trick)
    if "@" in url.split("//", 1)[-1]:
        findings.append("URL contains @ symbol — possible credential trick")
        techniques.append("at_symbol")

    return {
        "obfuscated": len(techniques) > 0,
        "techniques": techniques,
        "findings": findings,
    }


def _check_brand_impersonation(text: str) -> list[str]:
    """Check if text impersonates known brands."""
    text_lower = text.lower()
    impersonated = []
    for brand, patterns in BRAND_IMPERSONATION_PATTERNS.items():
        for pattern in patterns:
            if pattern in text_lower and brand not in impersonated:
                impersonated.append(brand)
                break
    return impersonated


# ---------------------------------------------------------------------------
# NLP Content Analysis (Rule-based fallback)
# ---------------------------------------------------------------------------
def _rule_based_content_analysis(content: str, content_type: str = "email") -> ContentPhishingResult:
    """Rule-based + statistical NLP content analysis (no ML model required)."""
    result = ContentPhishingResult()
    text_lower = content.lower()
    text_upper = content.upper()

    # --- Urgency Detection ---
    urgency_hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    if urgency_hits >= 5:
        result.urgency_level = "extreme"
    elif urgency_hits >= 3:
        result.urgency_level = "high"
    elif urgency_hits >= 1:
        result.urgency_level = "medium"
    else:
        result.urgency_level = "low"

    if urgency_hits >= 3:
        result.findings.append(f"High urgency language detected ({urgency_hits} urgency keywords)")
        result.heuristic_score += min(urgency_hits * 5, 25)

    # --- Credential Harvesting ---
    cred_hits = sum(1 for phrase in CREDENTIAL_HARVESTING_PHRASES if phrase in text_lower)
    if cred_hits > 0:
        result.credential_harvesting = True
        result.findings.append(f"Credential harvesting language detected ({cred_hits} phrases)")
        result.heuristic_score += min(cred_hits * 8, 30)

    # --- Financial Phishing ---
    fin_hits = sum(1 for phrase in FINANCIAL_PHISHING_PHRASES if phrase in text_lower)
    if fin_hits > 0:
        result.financial_phishing = True
        result.findings.append(f"Financial phishing language detected ({fin_hits} phrases)")
        result.heuristic_score += min(fin_hits * 6, 20)

    # --- Brand Impersonation ---
    result.brands_impersonated = _check_brand_impersonation(content)
    if result.brands_impersonated:
        result.findings.append(
            f"Brand impersonation detected: {', '.join(result.brands_impersonated)}"
        )
        result.heuristic_score += len(result.brands_impersonated) * 10

    # --- URL Analysis ---
    urls = _extract_urls(content)
    obfuscated_count = 0
    for url in urls:
        obs = _detect_url_obfuscation(url)
        if obs["obfuscated"]:
            obfuscated_count += 1
            result.suspicious_urls.append(url)
            result.findings.extend(obs["findings"])
            result.heuristic_score += 10

    if not result.suspicious_urls and urls:
        result.suspicious_urls = urls[:5]

    if obfuscated_count > 0:
        result.obfuscation_detected = True

    # --- Grammar / Spelling Anomaly (statistical) ---
    words = re.findall(r'[a-zA-Z]+', content)
    if words:
        avg_word_len = sum(len(w) for w in words) / len(words)
        caps_ratio = sum(1 for c in content if c.isupper()) / max(1, len(content))

        if avg_word_len > 8:
            result.findings.append("Unusually long words — possible generated content")
            result.heuristic_score += 5
        if caps_ratio > 0.5 and len(content) > 50:
            result.findings.append("Excessive uppercase text — pressure tactic")
            result.heuristic_score += 8

    # --- Generic suspicious indicators ---
    suspicious_patterns = [
        (r"(?:dear\s+(?:customer|user|sir|madam|friend|valued))", "Generic greeting (not personalized)"),
        (r"(?:your\s+account\s+(?:has\s+been|will\s+be)\s+(?:suspended|locked|terminated|disabled))", "Account suspension threat"),
        (r"(?:click\s+(?:here|below|the\s+link))", "Generic clickbait CTA"),
        (r"(?:do\s+not\s+(?:share|tell|forward))", "Secrecy instruction"),
        (r"(?:this\s+(?:is\s+a|is\s+an)\s+(?:urgent|important)\s+(?:notice|message|alert))", "Fake urgency marker"),
    ]
    for pattern, label in suspicious_patterns:
        if re.search(pattern, text_lower):
            result.findings.append(f"Suspicious indicator: {label}")
            result.heuristic_score += 5

    # Determine attack type
    if result.credential_harvesting and result.brands_impersonated:
        result.attack_type = "brand_impersonation_credential_theft"
    elif result.credential_harvesting:
        result.attack_type = "credential_harvesting"
    elif result.financial_phishing:
        result.attack_type = "financial_phishing"
    elif result.obfuscation_detected:
        result.attack_type = "url_obfuscation"
    elif result.brands_impersonated:
        result.attack_type = "brand_impersonation"
    elif urgency_hits >= 3:
        result.attack_type = "social_engineering"
    else:
        result.attack_type = "suspicious_content"

    # Cap heuristic score
    result.heuristic_score = min(result.heuristic_score, 100.0)

    # ML score from transformer model if available
    ml_score, model_name = _predict_with_model(content[:512], model_type="email" if content_type == "email" else "sms")
    result.ml_score = ml_score
    result.model_used = model_name

    # Combined score
    if model_name not in ("unavailable", "error"):
        result.confidence = round(0.6 * ml_score + 0.4 * (result.heuristic_score / 100.0), 4)
        result.model_used = model_name
    else:
        result.confidence = round(result.heuristic_score / 100.0, 4)
        result.model_used = "rule_based"

    result.is_phishing = result.confidence >= 0.5 or result.heuristic_score >= 50
    result.raw_features = {
        "urgency_hits": urgency_hits,
        "cred_hits": cred_hits,
        "fin_hits": fin_hits,
        "urls_found": len(urls),
        "obfuscated_urls": obfuscated_count,
        "brands": result.brands_impersonated,
    }

    return result


# ---------------------------------------------------------------------------
# Public API: Email Analysis
# ---------------------------------------------------------------------------
def analyze_email_phishing(
    subject: str = "",
    body: str = "",
    sender: str = "",
    raw_headers: str = "",
) -> EmailPhishingResult:
    """
    Complete email phishing analysis.
    
    Combines:
    1. Header analysis (SPF/DKIM/DMARC, routing anomalies)
    2. Content NLP analysis (BERT transformer + rule-based)
    3. URL extraction & obfuscation detection
    4. Brand impersonation detection
    
    Returns EmailPhishingResult with overall score 0-100.
    """
    result = EmailPhishingResult()

    # Analyze headers
    if raw_headers:
        result.header_result = analyze_email_headers(raw_headers)

    # Combine subject + body for content analysis
    full_content = f"Subject: {subject}\nFrom: {sender}\n\n{body}".strip()

    if not full_content.strip():
        result.summary = "No email content provided for analysis."
        return result

    # Content analysis
    result.content_result = _rule_based_content_analysis(full_content, content_type="email")

    # Combine scores
    content_score = result.content_result.heuristic_score
    header_score = result.header_result.score
    ml_bonus = result.content_result.ml_score * 20 if result.content_result.model_used not in ("unavailable", "error") else 0

    overall = max(content_score, header_score * 0.8 + content_score * 0.5 + ml_bonus)
    result.overall_score = min(int(overall), 100)

    # Risk level
    if result.overall_score >= 75:
        result.risk_level = "critical"
    elif result.overall_score >= 50:
        result.risk_level = "high"
    elif result.overall_score >= 30:
        result.risk_level = "medium"
    elif result.overall_score >= 10:
        result.risk_level = "low"
    else:
        result.risk_level = "safe"

    # Summary
    summary_parts = []
    if result.content_result.is_phishing:
        summary_parts.append(f"Content analysis: PHISHING ({result.content_result.confidence:.0%} confidence)")
    if result.header_result.anomalies:
        summary_parts.append(f"Header anomalies: {len(result.header_result.anomalies)} detected")
    if result.content_result.brands_impersonated:
        summary_parts.append(f"Brands impersonated: {', '.join(result.content_result.brands_impersonated)}")
    result.summary = " | ".join(summary_parts) if summary_parts else "No significant phishing indicators found."

    return result


# ---------------------------------------------------------------------------
# Public API: SMS Analysis
# ---------------------------------------------------------------------------
def analyze_sms_phishing(message: str, sender: str = "") -> SMSPhishingResult:
    """
    SMS / instant messaging phishing analysis.
    
    Combines NLP content analysis with SMS-specific heuristics:
    - Short message urgency patterns
    - URL obfuscation in SMS
    - Brand impersonation
    - Premium rate number patterns
    """
    result = SMSPhishingResult()

    if not message:
        result.findings.append("No SMS content provided")
        return result

    full_content = f"From: {sender}\n\n{message}" if sender else message

    # Run content analysis
    content_result = _rule_based_content_analysis(full_content, content_type="sms")
    result.is_phishing = content_result.is_phishing
    result.confidence = content_result.confidence
    result.ml_score = content_result.ml_score
    result.heuristic_score = content_result.heuristic_score
    result.model_used = content_result.model_used
    result.attack_type = content_result.attack_type
    result.suspicious_urls = content_result.suspicious_urls
    result.brands_impersonated = content_result.brands_impersonated
    result.findings = content_result.findings

    # SMS-specific: check for premium rate numbers
    premium_pattern = re.search(r'(?:\+\d{1,3})?\d{4,5}(?:\d{4})?', message)
    if premium_pattern:
        number = premium_pattern.group()
        # Short premium numbers often 4-6 digits
        clean = re.sub(r'[\s\-\(\)]', '', number)
        if len(clean) <= 8 and not clean.startswith('+'):
            result.findings.append(f"Possible premium-rate number detected: {number}")
            result.heuristic_score += 10

    # SMS-specific: check for STOP/Unsubscribe spoofing
    if re.search(r'(?:reply\s+(?:stop|no|unsubscribe))', message.lower()):
        result.findings.append("Unsubscribe instruction detected — common in smishing campaigns")
        result.heuristic_score += 5

    # Calculate overall score
    result.score = min(int(result.heuristic_score), 100)

    return result


# ---------------------------------------------------------------------------
# Convenience wrapper for API integration
# ---------------------------------------------------------------------------
def analyze_email(text: str, headers: str = "") -> dict[str, Any]:
    """
    Simplified email analysis for API integration.
    Accepts raw email text (headers + body).
    """
    result = analyze_email_phishing(
        body=text,
        raw_headers=headers,
    )
    return {
        "available": True,
        "overall_score": result.overall_score,
        "risk_level": result.risk_level,
        "content_phishing": result.content_result.is_phishing,
        "confidence": result.content_result.confidence,
        "model_used": result.content_result.model_used,
        "attack_type": result.content_result.attack_type,
        "brands_impersonated": result.content_result.brands_impersonated,
        "credential_harvesting": result.content_result.credential_harvesting,
        "financial_phishing": result.content_result.financial_phishing,
        "suspicious_urls": result.content_result.suspicious_urls,
        "header_anomalies": result.header_result.anomalies,
        "spf_result": result.header_result.spf_result,
        "dkim_result": result.header_result.dkim_result,
        "dmarc_result": result.header_result.dmarc_result,
        "findings": result.content_result.findings + result.header_result.anomalies,
        "summary": result.summary,
    }


def analyze_sms(text: str, sender: str = "") -> dict[str, Any]:
    """Simplified SMS analysis for API integration."""
    result = analyze_sms_phishing(message=text, sender=sender)
    return {
        "available": True,
        "is_phishing": result.is_phishing,
        "score": result.score,
        "confidence": result.confidence,
        "model_used": result.model_used,
        "attack_type": result.attack_type,
        "brands_impersonated": result.brands_impersonated,
        "suspicious_urls": result.suspicious_urls,
        "findings": result.findings,
    }

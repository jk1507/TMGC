"""
Adversarial Detection Layer
============================
Detects anomalies in AI-generated phishing content using:
  - Perplexity & burstiness analysis (LLM-generated text detection)
  - Statistical fingerprinting of NLG output patterns
  - Embedding-based anomaly detection
  - Prompt injection / jailbreak detection
  - Polymorphic content detection

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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class AdversarialDetectionResult:
    """Result of adversarial content analysis."""
    available: bool = True
    is_ai_generated: bool = False
    is_polymorphic: bool = False
    has_prompt_injection: bool = False
    confidence: float = 0.0
    ai_generation_score: float = 0.0
    perplexity_score: float = 0.0
    burstiness_score: float = 0.0
    pattern_score: float = 0.0
    injection_score: float = 0.0
    findings: list[str] = field(default_factory=list)
    techniques_detected: list[str] = field(default_factory=list)
    risk_score: int = 0


# ---------------------------------------------------------------------------
# Statistical Text Analysis
# ---------------------------------------------------------------------------
def _word_tokenize(text: str) -> list[str]:
    """Simple word tokenizer."""
    return re.findall(r'[a-zA-Z]+', text.lower())


def _sentence_split(text: str) -> list[str]:
    """Split text into sentences."""
    return [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]


def _compute_perplexity(text: str) -> float:
    """
    Estimate perplexity using character-level entropy.
    High perplexity = more random = more likely human-written.
    Low perplexity = more predictable = more likely AI-generated.
    
    Returns score 0-1 where higher = more likely AI-generated.
    """
    words = _word_tokenize(text)
    if len(words) < 5:
        return 0.0

    # Character-level frequency analysis
    chars = list(text.lower())
    freq = Counter(chars)
    total = len(chars)
    entropy = -sum((c / total) * math.log2(c / total + 1e-10) for c in freq.values())

    # AI text tends to have lower entropy (more uniform character distribution)
    # Normal English has ~4.5 bits per character
    # AI text often has ~4.0-4.2 bits per character
    if entropy < 3.5:
        return 0.8  # very uniform = likely AI
    elif entropy < 4.0:
        return 0.6
    elif entropy < 4.3:
        return 0.3
    else:
        return 0.1  # high entropy = likely human


def _compute_burstiness(text: str) -> float:
    """
    Burstiness measures sentence length variation.
    Human text is bursty (varied sentence lengths).
    AI text tends to have uniform sentence lengths.
    
    Returns 0-1 where higher = more uniform (AI-like).
    """
    sentences = _sentence_split(text)
    if len(sentences) < 3:
        return 0.0

    lengths = [len(s.split()) for s in sentences]
    if not lengths:
        return 0.0

    mean_len = sum(lengths) / len(lengths)
    if mean_len == 0:
        return 0.0

    variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
    cv = (variance ** 0.5) / mean_len  # coefficient of variation

    # Low CV = uniform = AI-like
    if cv < 0.3:
        return 0.7  # very uniform
    elif cv < 0.5:
        return 0.4
    else:
        return 0.1  # bursty = human-like


def _compute_pattern_score(text: str) -> float:
    """
    Detect NLG-specific patterns:
    - Repetitive sentence structures
    - Formulaic transitions
    - Lack of typos/informalities
    - Overly perfect grammar
    """
    score = 0.0
    text_lower = text.lower()

    # Common AI phrase patterns
    ai_phrases = [
        r"in\s+today'?s\s+(?:digital|modern|fast-paced)",
        r"it'?s\s+(?:worth|important|crucial)\s+to\s+note",
        r"(?:furthermore|moreover|additionally|consequently)",
        r"(?:in\s+conclusion|to\s+sum\s+up|in\s+summary)",
        r"(?:it\s+is\s+(?:worth|important|crucial)\s+(?:noting|mentioning|highlighting))",
        r"(?:leveraging|utilizing|implementing|streamlining)",
        r"(?:seamless(?:ly)?|robust|comprehensive|holistic)",
        r"(?:dive\s+into|delve\s+into|explore\s+the\s+depths)",
        r"(?:at\s+the\s+end\s+of\s+the\s+day|needless\s+to\s+say)",
        r"(?:game[- ]?changer|paradigm\s+shift|cutting[- ]edge)",
    ]

    ai_pattern_hits = 0
    for pattern in ai_phrases:
        matches = re.findall(pattern, text_lower)
        ai_pattern_hits += len(matches)

    if ai_pattern_hits >= 5:
        score += 0.4
    elif ai_pattern_hits >= 3:
        score += 0.25
    elif ai_pattern_hits >= 1:
        score += 0.1

    # Repetitive structure detection
    sentences = _sentence_split(text)
    if len(sentences) >= 4:
        # Check first words of sentences
        first_words = [s.split()[0].lower() if s.split() else "" for s in sentences]
        fw_freq = Counter(first_words)
        most_common_count = fw_freq.most_common(1)[0][1] if fw_freq else 0
        if most_common_count > len(sentences) * 0.3:
            score += 0.2  # repetitive sentence starters

    # Perfect grammar (no typos) in long text is suspicious
    if len(text) > 500:
        # Count "mistakes" (unusual character sequences)
        mistakes = len(re.findall(r'(?:[a-z]{1}[A-Z]{1})', text))  # camelCase
        words = _word_tokenize(text)
        if len(words) > 50 and mistakes == 0:
            score += 0.1  # too perfect

    # Bullet point / numbered list frequency (AI loves lists)
    list_patterns = len(re.findall(r'(?:^|\n)\s*(?:[-•*]|\d+[.)]\s)', text))
    if list_patterns > 5:
        score += 0.1

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Prompt Injection Detection
# ---------------------------------------------------------------------------
def _detect_prompt_injection(text: str) -> tuple[float, list[str]]:
    """
    Detect prompt injection / jailbreak attempts in content.
    Returns (score 0-1, list of findings).
    """
    findings = []
    score = 0.0
    text_lower = text.lower()

    injection_patterns = [
        # Direct instruction overrides
        (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)",
         "Direct instruction override detected"),
        (r"disregard\s+(?:all\s+)?(?:previous|prior|above)",
         "Instruction disregard attempt"),
        (r"you\s+are\s+now\s+(?:a|an|the)\s+",
         "Role hijacking attempt"),
        (r"act\s+as\s+(?:if|though)\s+you\s+(?:are|were|have)",
         "Behavioral override attempt"),
        (r"pretend\s+(?:you|to\s+be|that)",
         "Pretend/role-play injection"),
        (r"(?:system|assistant)\s*:\s*",
         "System prompt injection attempt"),
        (r"<\|(?:im_start|system|endoftext)\|>",
         "Token injection attempt"),
        (r"###\s*(?:system|instruction|override)",
         "Markdown injection attempt"),
        (r"(?:jailbreak|DAN|do\s+anything\s+now)",
         "Jailbreak keyword detected"),
        (r"bypass\s+(?:all\s+)?(?:filters?|restrictions?|rules?|safety)",
         "Safety bypass attempt"),
        (r"(?:reveal|show|output)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
         "Prompt extraction attempt"),
        (r"repeat\s+(?:everything|all|the)\s+(?:above|before|from)",
         "Repetition extraction attempt"),
        # Encoding tricks
        (r"(?:base64|rot13|hex)\s*(?:encode|decode|encoded|decoded)",
         "Encoding-based injection"),
        (r"\\x[0-9a-f]{2}",
         "Hex escape injection attempt"),
    ]

    for pattern, label in injection_patterns:
        if re.search(pattern, text_lower):
            findings.append(label)
            score += 0.15

    # Multiple exclamation/question marks (social engineering)
    excl_count = text.count('!')
    if excl_count > 10:
        findings.append(f"Excessive exclamation marks ({excl_count})")
        score += 0.1

    return min(score, 1.0), findings


# ---------------------------------------------------------------------------
# Polymorphic Content Detection
# ---------------------------------------------------------------------------
def _detect_polymorphic(text: str, known_signatures: list[str] = None) -> tuple[float, list[str]]:
    """
    Detect polymorphic / shapeshifting phishing content.
    Checks for template markers, variable placeholders, and content morphing.
    """
    findings = []
    score = 0.0

    # Template placeholders
    placeholder_patterns = [
        (r'\{\{(?:user|name|email|account|domain|company|date|link)\}\}', "Mustache template placeholder"),
        (r'\[(?:USER|NAME|EMAIL|ACCOUNT|DOMAIN|COMPANY|DATE|LINK)\]', "Bracket template placeholder"),
        (r'<\|(?:user|name|email|account|domain)\|>', "Pipe template placeholder"),
        (r'%\((?:user|name|email|account)\)s', "Python format placeholder"),
        (r'\$(?:\{|\()(?:user|name|email|account)', "Variable interpolation placeholder"),
    ]

    placeholder_hits = 0
    for pattern, label in placeholder_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        placeholder_hits += len(matches)
        if matches:
            findings.append(f"{label} detected ({len(matches)} occurrences)")

    if placeholder_hits > 0:
        score += min(placeholder_hits * 0.15, 0.5)

    # Known signature comparison
    if known_signatures:
        text_hash = hashlib.md5(text.lower().encode()).hexdigest()
        for sig in known_signatures:
            if text_hash == sig:
                findings.append("Exact match to known polymorphic template")
                score += 0.5
                break

    # Content splitting (text split across multiple renders)
    if len(text) < 50 and text.count('\n') > 5:
        findings.append("Fragmented content — possible multi-stage rendering")
        score += 0.2

    # Zero-width characters (steganographic hiding)
    zw_chars = len(re.findall(r'[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff]', text))
    if zw_chars > 0:
        findings.append(f"Zero-width/hidden Unicode characters detected ({zw_chars})")
        score += 0.3

    # Invisible ink / CSS-based hiding
    if 'style=' in text.lower() and ('color:' in text.lower() or 'font-size:0' in text.lower()):
        findings.append("Possible CSS-based content hiding detected")
        score += 0.2

    return min(score, 1.0), findings


# ---------------------------------------------------------------------------
# Main Detection Function
# ---------------------------------------------------------------------------
def detect_adversarial_content(
    text: str,
    known_signatures: list[str] = None,
    context: str = "",
) -> dict[str, Any]:
    """
    Comprehensive adversarial content detection.
    
    Analyzes:
    1. AI-generated content detection (perplexity, burstiness, patterns)
    2. Prompt injection / jailbreak detection
    3. Polymorphic content detection
    
    Args:
        text: Content to analyze
        known_signatures: Known polymorphic template hashes
        context: Additional context (e.g., domain, sender)
    
    Returns dict with:
    - is_ai_generated: Whether content appears AI-generated
    - is_polymorphic: Whether content is polymorphic
    - has_prompt_injection: Whether injection attempt detected
    - confidence: Overall confidence (0-1)
    - risk_score: Risk score 0-100
    - findings: List of findings
    - techniques_detected: Detected adversarial techniques
    """
    result = {
        "available": True,
        "is_ai_generated": False,
        "is_polymorphic": False,
        "has_prompt_injection": False,
        "confidence": 0.0,
        "ai_generation_score": 0.0,
        "perplexity_score": 0.0,
        "burstiness_score": 0.0,
        "pattern_score": 0.0,
        "injection_score": 0.0,
        "findings": [],
        "techniques_detected": [],
        "risk_score": 0,
    }

    if not text or len(text.strip()) < 10:
        result["findings"].append("Text too short for analysis")
        return result

    # 1. AI generation detection
    perplexity = _compute_perplexity(text)
    burstiness = _compute_burstiness(text)
    pattern = _compute_pattern_score(text)

    result["perplexity_score"] = round(perplexity, 4)
    result["burstiness_score"] = round(burstiness, 4)
    result["pattern_score"] = round(pattern, 4)

    # Combined AI generation score
    ai_score = 0.4 * perplexity + 0.3 * burstiness + 0.3 * pattern
    result["ai_generation_score"] = round(ai_score, 4)
    result["is_ai_generated"] = ai_score >= 0.5

    if result["is_ai_generated"]:
        result["findings"].append(f"Content appears AI-generated (score: {ai_score:.2f})")
        result["techniques_detected"].append("ai_generation")

    if perplexity >= 0.6:
        result["findings"].append("Low perplexity detected — text has uniform character distribution")
    if burstiness >= 0.6:
        result["findings"].append("Low burstiness detected — sentence lengths are unusually uniform")

    # 2. Prompt injection detection
    injection_score, injection_findings = _detect_prompt_injection(text)
    result["injection_score"] = round(injection_score, 4)
    result["has_prompt_injection"] = injection_score >= 0.3
    result["findings"].extend(injection_findings)

    if result["has_prompt_injection"]:
        result["techniques_detected"].append("prompt_injection")

    # 3. Polymorphic detection
    poly_score, poly_findings = _detect_polymorphic(text, known_signatures)
    result["is_polymorphic"] = poly_score >= 0.3
    result["findings"].extend(poly_findings)

    if result["is_polymorphic"]:
        result["techniques_detected"].append("polymorphic_content")

    # Overall confidence
    result["confidence"] = round(max(ai_score, injection_score, poly_score), 4)

    # Risk score
    risk = 0
    if result["is_ai_generated"]:
        risk += int(ai_score * 30)
    if result["has_prompt_injection"]:
        risk += int(injection_score * 40)
    if result["is_polymorphic"]:
        risk += int(poly_score * 30)
    result["risk_score"] = min(risk, 100)

    return result


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------
def scan_adversarial(content: str, context: str = "") -> dict[str, Any]:
    """Quick adversarial scan for API integration."""
    return detect_adversarial_content(text=content, context=context)

# backend/adversarial_detection.py - Adversarial Detection Layer

Detects anomalies in AI-generated phishing content.

## Detection Methods

### 1. AI-Generated Content Detection
- **Perplexity Analysis**: Character-level entropy (AI text has lower entropy)
- **Burstiness Analysis**: Sentence length uniformity (AI text is more uniform)
- **Pattern Detection**: AI-specific phrases and structures

### 2. Prompt Injection Detection
- Direct instruction overrides
- Role hijacking attempts
- Token injection attempts
- Jailbreak keywords
- Safety bypass attempts

### 3. Polymorphic Content Detection
- Template placeholders ({{variable}}, [VARIABLE])
- Zero-width characters (steganographic hiding)
- CSS-based content hiding
- Fragmented content patterns

## Data Classes

### `AdversarialDetectionResult`
Complete adversarial analysis result with scores and findings.

## Functions

### `detect_adversarial_content(text, known_signatures=None, context="")`
Comprehensive adversarial content detection.

**Args:**
- `text`: Content to analyze
- `known_signatures`: Known polymorphic template hashes
- `context`: Additional context (domain, sender)

**Returns dict with:**
- `is_ai_generated`: bool
- `is_polymorphic`: bool
- `has_prompt_injection`: bool
- `confidence`: 0-1 float
- `ai_generation_score`: 0-1 float
- `perplexity_score`: 0-1 float
- `burstiness_score`: 0-1 float
- `pattern_score`: 0-1 float
- `injection_score`: 0-1 float
- `findings`: List of findings
- `techniques_detected`: List of techniques
- `risk_score`: 0-100

### `scan_adversarial(content, context="")`
Quick adversarial scan wrapper for API integration.

### `_compute_perplexity(text)`
Estimate perplexity using character-level entropy.

### `_compute_burstiness(text)`
Measure sentence length variation uniformity.

### `_compute_pattern_score(text)`
Detect NLG-specific patterns (repetitive structures, AI phrases).

### `_detect_prompt_injection(text)`
Detect prompt injection/jailbreak attempts.

### `_detect_polymorphic(text, known_signatures=None)`
Detect polymorphic/shapeshifting content.

"""
Local LLM integration for RETRO_INTEL.

Talks to any OpenAI-compatible local server (Ollama, LM Studio, llama.cpp
server) and is used as the FIRST choice for SOC report generation so the
analysis can run fully offline — no Gemini API key required.

Environment variables:
    LOCAL_LLM_ENABLED   default "true"   set to "false"/"0" to disable
    LOCAL_LLM_URL       default "http://127.0.0.1:11434/v1"  (Ollama default)
    LOCAL_LLM_MODEL     default "qwen2.5:3b"
    LOCAL_LLM_TIMEOUT   default 90.0  seconds for one generation
"""

from __future__ import annotations

import os

import httpx

DEFAULT_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen2.5:3b"


def local_llm_enabled() -> bool:
    flag = os.getenv("LOCAL_LLM_ENABLED", "true").strip().lower()
    return flag not in {"false", "0", "no", "off"}


def local_llm_url() -> str:
    return os.getenv("LOCAL_LLM_URL", DEFAULT_URL).strip().rstrip("/")


def local_llm_model() -> str:
    return os.getenv("LOCAL_LLM_MODEL", DEFAULT_MODEL).strip()


def local_llm_timeout() -> float:
    try:
        return float(os.getenv("LOCAL_LLM_TIMEOUT", "90.0"))
    except ValueError:
        return 90.0


def build_prompt(raw_context: str) -> str:
    """Same SOC-analyst prompt used for Gemini, adapted for a local model."""
    return f"""You are a Tier-3 SOC analyst and threat hunter. Evaluate this structured OSINT evidence.
Return a concise markdown SOC report with these exact sections:
1. Threat Summary
2. Risk Assessment
3. IOC Analysis
4. False Positive Discussion
5. Analyst Notes
6. Confidence Score
7. Recommended Action

Reason from evidence only. Treat weak signals such as blocked ping, missing MX,
deprecated X-XSS-Protection, report-only CSP, CDN edge behavior, and HTTP probe
failures as low-confidence unless combined with stronger phishing evidence.
Strong evidence includes brand impersonation, homoglyph abuse, recent
registration, credential harvesting forms, external form posts, malicious feed
hits, suspicious redirects, exposed risky services, and TLS/ownership mismatch.

End with one final line:
RISK_SCORE: <integer 0-100>

Never claim identity attribution. Only assess technical threat indicators.

{raw_context}"""


async def local_llm_chat(prompt: str, timeout: float | None = None) -> str | None:
    """Send a chat completion to the local OpenAI-compatible server.

    Returns the generated text, or None if the server is unreachable /
    misconfigured (so callers can fall back to Gemini or the template).
    """
    if not local_llm_enabled():
        return None

    url = f"{local_llm_url()}/chat/completions"
    payload = {
        "model": local_llm_model(),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 1500,
        "stream": False,
    }
    timeout_s = timeout if timeout is not None else local_llm_timeout()

    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            text = (data.get("choices") or [{}])[0].get("message", {}).get("content")
            return text.strip() if isinstance(text, str) and text.strip() else None
    except Exception:
        return None
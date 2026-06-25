"""
Content Similarity Analysis Module
====================================
Compares website content against known legitimate sites to detect
phishing clones and lookalike pages.
"""

from __future__ import annotations

import difflib
import re
from typing import Any
from urllib import request as url_request


def compare_content(
    suspect_url: str,
    reference_url: str,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """
    Compare content of two URLs for similarity analysis.

    Detects:
      - Phishing pages that visually clone legitimate sites
      - Content scraping / mirroring
      - Brand impersonation via page structure similarity

    Returns:
        similarity: 0.0-1.0 similarity score
        likely_clone: True if similarity exceeds threshold
        text_sample_suspect: Text sample from suspect URL
        text_sample_reference: Text sample from reference URL
    """
    suspect_text = _fetch_text(suspect_url, timeout)
    ref_text = _fetch_text(reference_url, timeout)

    if not suspect_text or not ref_text:
        return {
            "available": False,
            "error": "Could not fetch one or both URLs",
        }

    suspect_clean = _clean_text(suspect_text)
    ref_clean = _clean_text(ref_text)

    similarity = difflib.SequenceMatcher(None, suspect_clean, ref_clean).ratio()

    return {
        "available": True,
        "similarity": round(similarity, 4),
        "likely_clone": similarity >= 0.72,
        "suspect_url": suspect_url,
        "reference_url": reference_url,
        "suspect_text_length": len(suspect_clean),
        "reference_text_length": len(ref_clean),
    }


def _fetch_text(url: str, timeout: float) -> str | None:
    """Fetch text content from a URL."""
    try:
        req = url_request.Request(
            url,
            headers={"User-Agent": "TMGC-ContentInspector/1.0"},
        )
        with url_request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            return _html_to_text(html)
    except Exception:
        return None


def _html_to_text(html: str) -> str:
    """Convert HTML to plain text."""
    # Remove scripts and styles
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\\1>", " ", html)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = re.sub(r"\\s+", " ", text).strip().lower()
    return text[:10000]


def _clean_text(text: str) -> str:
    """Clean text for comparison."""
    text = re.sub(r"[^a-z0-9\\s]", " ", text.lower())
    text = re.sub(r"\\s+", " ", text).strip()
    return text[:5000]

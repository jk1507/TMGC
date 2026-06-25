"""
Reputation Timeline Module (v3.0)
==================================
Tracks analysis history and reputation changes for domains over time.

Persists analysis records to a JSON file for historical tracking.
Supports:
  - Recording new analysis results
  - Retrieving timeline for a specific domain
  - Trend analysis (score changes over time)
  - Recent analysis history
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

# Path to timeline data file
TIMELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reputation_timeline.json")

# Maximum entries to keep per domain
MAX_ENTRIES_PER_DOMAIN = 50


def _load_timeline() -> dict[str, list[dict[str, Any]]]:
    """Load the timeline data from disk."""
    if not os.path.exists(TIMELINE_FILE):
        return {}
    try:
        with open(TIMELINE_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except (json.JSONDecodeError, IOError):
        return {}


def _save_timeline(data: dict[str, list[dict[str, Any]]]) -> None:
    """Save the timeline data to disk."""
    try:
        with open(TIMELINE_FILE, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except IOError:
        pass  # Silently fail — timeline is non-critical


def record_analysis(
    domain: str,
    risk_score: int,
    verdict: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Record a new analysis result for a domain.

    Args:
        domain: The analyzed domain.
        risk_score: The risk score (0-100).
        verdict: The verdict string (e.g., "SAFE", "SUSPICIOUS", "PHISHING").
        metadata: Optional additional metadata (findings, components, etc.).

    Returns:
        The recorded entry.
    """
    timeline = _load_timeline()
    domain_key = domain.strip().lower()

    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_score,
        "verdict": verdict,
    }
    if metadata:
        # Only store safe, serializable metadata
        safe_meta = {}
        for k, v in metadata.items():
            if isinstance(v, (str, int, float, bool, list, dict)):
                safe_meta[k] = v
        if safe_meta:
            entry["metadata"] = safe_meta

    if domain_key not in timeline:
        timeline[domain_key] = []

    timeline[domain_key].append(entry)

    # Trim to max entries
    if len(timeline[domain_key]) > MAX_ENTRIES_PER_DOMAIN:
        timeline[domain_key] = timeline[domain_key][-MAX_ENTRIES_PER_DOMAIN:]

    _save_timeline(timeline)

    return entry


def get_timeline(
    domain: str,
    limit: int = 10,
) -> dict[str, Any]:
    """
    Get the analysis timeline for a domain.

    Args:
        domain: The domain to look up.
        limit: Maximum number of entries to return.

    Returns:
        Dict with domain info, entries, and trend analysis.
    """
    timeline = _load_timeline()
    domain_key = domain.strip().lower()

    entries = timeline.get(domain_key, [])

    if not entries:
        return {
            "domain": domain_key,
            "has_history": False,
            "total_entries": 0,
            "entries": [],
            "first_seen": None,
            "last_seen": None,
            "trend": None,
        }

    recent = entries[-limit:]

    # Calculate trend
    scores = [e["risk_score"] for e in entries]
    if len(scores) >= 2:
        recent_scores = scores[-5:] if len(scores) >= 5 else scores
        avg_recent = sum(recent_scores) / len(recent_scores)
        avg_older = sum(scores[:-len(recent_scores)]) / max(len(scores) - len(recent_scores), 1) if len(scores) > len(recent_scores) else avg_recent

        if avg_recent > avg_older + 5:
            trend = "increasing"
        elif avg_recent < avg_older - 5:
            trend = "decreasing"
        else:
            trend = "stable"
    else:
        trend = "stable"

    return {
        "domain": domain_key,
        "has_history": True,
        "total_entries": len(entries),
        "entries": recent,
        "first_seen": entries[0]["timestamp"],
        "last_seen": entries[-1]["timestamp"],
        "trend": trend,
        "min_score": min(scores),
        "max_score": max(scores),
        "avg_score": round(sum(scores) / len(scores), 1),
    }

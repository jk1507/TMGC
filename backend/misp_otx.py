"""
MISP & AlienVault OTX Threat Intelligence Integration
======================================================
Bidirectional integration with open-source threat intelligence feeds:
  - MISP (Malware Information Sharing Platform)
  - AlienVault OTX (Open Threat Exchange)
  - IOC (Indicators of Compromise) correlation
  - Threat feed aggregation and scoring

Part of RETRO_INTEL / TMGC v4.0
"""

from __future__ import annotations

import os
import json
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Optional requests import
_REQUESTS_AVAILABLE = False
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MISP_URL = os.getenv("MISP_URL", "")
MISP_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFYCERT = os.getenv("MISP_VERIFY_CERT", "false").lower() == "true"

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Cache directory
CACHE_DIR = os.path.join(os.path.dirname(__file__), "intel_cache")
CACHE_TTL_HOURS = 6


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class IOCMatch:
    """An Indicator of Compromise match."""
    ioc_type: str  # domain, ip, url, hash, email
    ioc_value: str
    source: str  # misp, otx, urlhaus, etc.
    threat_level: str  # low, medium, high, critical
    tags: list[str] = field(default_factory=list)
    description: str = ""
    first_seen: str = ""
    last_seen: str = ""
    confidence: int = 0


@dataclass
class ThreatIntelResult:
    """Aggregated threat intelligence result."""
    available: bool = True
    domain: str = ""
    ip_address: str = ""
    overall_threat_level: str = "unknown"
    overall_score: int = 0
    ioc_matches: list[IOCMatch] = field(default_factory=list)
    misp_results: dict[str, Any] = field(default_factory=dict)
    otx_results: dict[str, Any] = field(default_factory=dict)
    urlhaus_results: dict[str, Any] = field(default_factory=dict)
    pulse_count: int = 0
    malware_families: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    sources_checked: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------
def _ensure_cache():
    os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_key(source: str, query: str) -> str:
    import hashlib
    return hashlib.md5(f"{source}:{query}".encode()).hexdigest()


def _get_cached(source: str, query: str) -> dict[str, Any] | None:
    _ensure_cache()
    path = os.path.join(CACHE_DIR, f"{_cache_key(source, query)}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > CACHE_TTL_HOURS * 3600:
            return None
        return data
    except Exception:
        return None


def _set_cached(source: str, query: str, data: dict):
    _ensure_cache()
    data["_cached_at"] = time.time()
    path = os.path.join(CACHE_DIR, f"{_cache_key(source, query)}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# AlienVault OTX Integration
# ---------------------------------------------------------------------------
def query_otx(domain: str, ip: str = "") -> dict[str, Any]:
    """
    Query AlienVault OTX for domain/IP intelligence.
    
    Checks:
    - General intelligence (pulses, malware samples)
    - Domain reputation
    - IP reputation
    - URL reputation
    """
    if not OTX_API_KEY or not _REQUESTS_AVAILABLE:
        return {"available": False, "error": "OTX API key not configured or requests not installed"}

    cached = _get_cached("otx", domain)
    if cached:
        return cached

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    result = {
        "available": True,
        "source": "alienvault_otx",
        "domain": domain,
        "pulses": [],
        "pulse_count": 0,
        "malware_families": [],
        "threat_score": 0,
        "tags": [],
        "indicators": [],
    }

    try:
        # Domain general intel
        resp = requests.get(
            f"{OTX_BASE_URL}/indicators/domain/{domain}/general",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            result["pulse_count"] = len(pulses)
            result["pulses"] = [
                {
                    "name": p.get("name", ""),
                    "description": p.get("description", "")[:200],
                    "tags": p.get("tags", []),
                    "created": p.get("created", ""),
                    "adversary": p.get("adversary", ""),
                }
                for p in pulses[:10]
            ]

            # Extract malware families
            for pulse in pulses:
                for tag in pulse.get("tags", []):
                    if tag.lower() not in result["tags"]:
                        result["tags"].append(tag.lower())
                if pulse.get("adversary"):
                    adv = pulse["adversary"]
                    if adv and adv not in result["malware_families"]:
                        result["malware_families"].append(adv)

            # Extract indicators
            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    result["indicators"].append({
                        "type": indicator.get("type", ""),
                        "indicator": indicator.get("indicator", ""),
                        "title": indicator.get("title", ""),
                    })

        # Domain reputation
        resp2 = requests.get(
            f"{OTX_BASE_URL}/indicators/domain/{domain}/reputation",
            headers=headers,
            timeout=10,
        )
        if resp2.status_code == 200:
            rep = resp2.json()
            reputation = rep.get("reputation", 0)
            result["reputation_score"] = reputation
            if reputation < 0:
                result["threat_score"] = min(abs(reputation) * 10, 100)

        # IP reputation if available
        if ip:
            resp3 = requests.get(
                f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general",
                headers=headers,
                timeout=10,
            )
            if resp3.status_code == 200:
                ip_data = resp3.json()
                ip_pulses = ip_data.get("pulse_info", {}).get("pulses", [])
                if ip_pulses:
                    result["ip_pulse_count"] = len(ip_pulses)
                    result["threat_score"] = max(result["threat_score"], min(len(ip_pulses) * 5, 80))

    except Exception as e:
        result["error"] = str(e)
        result["available"] = True

    _set_cached("otx", domain, result)
    return result


# ---------------------------------------------------------------------------
# MISP Integration
# ---------------------------------------------------------------------------
def query_misp(domain: str, ip: str = "") -> dict[str, Any]:
    """
    Query MISP instance for domain/IP intelligence.
    
    Searches for:
    - Domain attributes
    - IP attributes
    - Associated events
    - Threat tags and galaxies
    """
    if not MISP_URL or not MISP_KEY or not _REQUESTS_AVAILABLE:
        return {"available": False, "error": "MISP not configured or requests not installed"}

    cached = _get_cached("misp", domain)
    if cached:
        return cached

    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    verify = MISP_VERIFYCERT

    result = {
        "available": True,
        "source": "misp",
        "domain": domain,
        "events": [],
        "event_count": 0,
        "attribute_count": 0,
        "threat_tags": [],
        "threat_score": 0,
        "galaxies": [],
    }

    try:
        # Search for domain attribute
        search_url = f"{MISP_URL}/attributes/restSearch"
        payload = {
            "value": domain,
            "type": ["domain", "hostname"],
            "to_ids": True,
        }
        resp = requests.post(search_url, headers=headers, json=payload, verify=verify, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get("response", [])
            result["attribute_count"] = len(attributes)

            event_ids = set()
            for attr in attributes:
                event_id = attr.get("Attribute", {}).get("event_id")
                if event_id:
                    event_ids.add(event_id)

                tags = attr.get("Attribute", {}).get("Tag", [])
                for tag in tags:
                    tag_name = tag.get("name", "")
                    if tag_name and tag_name not in result["threat_tags"]:
                        result["threat_tags"].append(tag_name)

            result["event_count"] = len(event_ids)

            # Fetch event details for top events
            for eid in list(event_ids)[:5]:
                try:
                    event_resp = requests.get(
                        f"{MISP_URL}/events/{eid}",
                        headers=headers,
                        verify=verify,
                        timeout=10,
                    )
                    if event_resp.status_code == 200:
                        event_data = event_resp.json().get("Event", {})
                        result["events"].append({
                            "id": eid,
                            "info": event_data.get("info", "")[:200],
                            "tags": [t.get("name", "") for t in event_data.get("Tag", [])[:10]],
                            "threat_level": event_data.get("threat_level_id", ""),
                            "date": event_data.get("date", ""),
                        })
                except Exception:
                    continue

        # Search for IP if provided
        if ip:
            payload2 = {
                "value": ip,
                "type": ["ip-src", "ip-dst"],
                "to_ids": True,
            }
            resp2 = requests.post(search_url, headers=headers, json=payload2, verify=verify, timeout=15)
            if resp2.status_code == 200:
                ip_attrs = resp2.json().get("response", [])
                if ip_attrs:
                    result["ip_event_count"] = len(ip_attrs)

        # Calculate threat score
        score = 0
        if result["event_count"] > 0:
            score += min(result["event_count"] * 15, 60)
        if result["attribute_count"] > 0:
            score += min(result["attribute_count"] * 5, 30)
        critical_tags = [t for t in result["threat_tags"] if any(k in t.lower() for k in ["apt", "malware", "ransomware", "c2"])]
        if critical_tags:
            score += 20
        result["threat_score"] = min(score, 100)

    except Exception as e:
        result["error"] = str(e)
        result["available"] = True

    _set_cached("misp", domain, result)
    return result


# ---------------------------------------------------------------------------
# URLHaus Integration (Open)
# ---------------------------------------------------------------------------
def query_urlhaus(domain: str) -> dict[str, Any]:
    """
    Query URLHaus (abuse.ch) for domain reputation.
    Free API, no key required.
    """
    if not _REQUESTS_AVAILABLE:
        return {"available": False, "error": "requests not installed"}

    cached = _get_cached("urlhaus", domain)
    if cached:
        return cached

    result = {
        "available": True,
        "source": "urlhaus",
        "domain": domain,
        "url_count": 0,
        "malware_urls": [],
        "tags": [],
        "threat_score": 0,
        "status": "unknown",
    }

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["status"] = data.get("query_status", "")
            url_count = data.get("url_count", 0)
            result["url_count"] = url_count
            result["urls_online"] = data.get("urls_online", 0)

            urls = data.get("urls", [])
            for url_entry in urls[:20]:
                result["malware_urls"].append({
                    "url": url_entry.get("url", ""),
                    "threat": url_entry.get("threat", ""),
                    "tags": url_entry.get("tags", []),
                    "date_added": url_entry.get("date_added", ""),
                })
                for tag in url_entry.get("tags", []):
                    if tag and tag not in result["tags"]:
                        result["tags"].append(tag)

            if url_count > 0:
                result["threat_score"] = min(url_count * 10, 80)
                if result["urls_online"] > 0:
                    result["threat_score"] = min(result["threat_score"] + 20, 100)

    except Exception as e:
        result["error"] = str(e)
        result["available"] = True

    _set_cached("urlhaus", domain, result)
    return result


# ---------------------------------------------------------------------------
# Aggregate All Sources
# ---------------------------------------------------------------------------
def query_all_threat_intel(domain: str, ip: str = "") -> dict[str, Any]:
    """
    Query all threat intelligence sources and aggregate results.
    
    Sources:
    - AlienVault OTX
    - MISP (if configured)
    - URLHaus
    """
    result = {
        "available": True,
        "domain": domain,
        "ip_address": ip,
        "sources_checked": [],
        "overall_threat_level": "unknown",
        "overall_score": 0,
        "ioc_matches": [],
        "malware_families": [],
        "tags": [],
        "findings": [],
    }

    # Query OTX
    otx = query_otx(domain, ip)
    if otx.get("available") and not otx.get("error"):
        result["sources_checked"].append("AlienVault OTX")
        result["otx"] = otx
        if otx.get("pulse_count", 0) > 0:
            result["findings"].append(f"OTX: {otx['pulse_count']} threat pulse(s) reference this domain")
        if otx.get("malware_families"):
            result["malware_families"].extend(otx["malware_families"])

    # Query MISP
    misp = query_misp(domain, ip)
    if misp.get("available") and not misp.get("error"):
        result["sources_checked"].append("MISP")
        result["misp"] = misp
        if misp.get("event_count", 0) > 0:
            result["findings"].append(f"MISP: {misp['event_count']} correlated event(s) found")
        if misp.get("threat_tags"):
            result["tags"].extend(misp["threat_tags"])

    # Query URLHaus
    urlhaus = query_urlhaus(domain)
    if urlhaus.get("available") and not urlhaus.get("error"):
        result["sources_checked"].append("URLHaus")
        result["urlhaus"] = urlhaus
        if urlhaus.get("url_count", 0) > 0:
            result["findings"].append(
                f"URLHaus: {urlhaus['url_count']} malicious URL(s) associated "
                f"({urlhaus.get('urls_online', 0)} still online)"
            )

    # Aggregate scores
    scores = []
    if otx.get("available") and not otx.get("error"):
        scores.append(otx.get("threat_score", 0))
    if misp.get("available") and not misp.get("error"):
        scores.append(misp.get("threat_score", 0))
    if urlhaus.get("available") and not urlhaus.get("error"):
        scores.append(urlhaus.get("threat_score", 0))

    result["overall_score"] = max(scores) if scores else 0

    # Overall threat level
    if result["overall_score"] >= 70:
        result["overall_threat_level"] = "critical"
    elif result["overall_score"] >= 50:
        result["overall_threat_level"] = "high"
    elif result["overall_score"] >= 25:
        result["overall_threat_level"] = "medium"
    elif result["overall_score"] > 0:
        result["overall_threat_level"] = "low"
    else:
        result["overall_threat_level"] = "clean"

    # Deduplicate tags and families
    result["tags"] = list(set(result["tags"]))[:20]
    result["malware_families"] = list(set(result["malware_families"]))[:10]

    return result


# ---------------------------------------------------------------------------
# Public convenience API
# ---------------------------------------------------------------------------
def check_threat_intel(domain: str, ip: str = "") -> dict[str, Any]:
    """Quick threat intel check for API integration."""
    return query_all_threat_intel(domain=domain, ip=ip)

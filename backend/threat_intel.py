"""
Threat Intelligence Feeds Module (v3.0)
========================================
Aggregates multiple threat intelligence sources for domain and IP reputation.

Sources:
  - URLhaus (abuse.ch) — free, no API key required
  - Google Safe Browsing — requires API key
  - PhishTank — requires API key
  - VirusTotal — requires API key
  - AbuseIPDB — requires API key
  - urlscan.io — optional API key

Usage:
    from threat_intel import run_all_feeds, check_urlhaus, check_virustotal, ...
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _form_post(url: str, form: dict[str, str], headers: dict[str, str] | None = None, timeout: float = 6.0) -> dict[str, Any]:
    """Make a form-encoded POST request and return parsed JSON."""
    h = {"accept": "application/json"}
    if headers:
        h.update(headers)
    data = urllib.parse.urlencode(form).encode("utf-8")
    h["content-type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _json_post(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None, timeout: float = 6.0) -> dict[str, Any]:
    """Make a JSON POST request and return parsed JSON."""
    h = {"accept": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(payload).encode("utf-8")
    h["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_urlhaus(domain: str, url: str = "") -> dict[str, Any]:
    """URLhaus (abuse.ch) — no API key required."""
    out: dict[str, Any] = {
        "provider": "URLhaus",
        "available": True,
        "flagged": False,
        "source": "live",
        "matches": [],
    }
    try:
        if url:
            j = _form_post("https://urlhaus-api.abuse.ch/v1/url/", {"url": url})
            st = j.get("query_status")
            if st == "ok":
                out["flagged"] = True
                out["matches"].append({
                    "type": "url",
                    "status": j.get("url_status"),
                    "threat": j.get("threat"),
                    "tags": j.get("tags"),
                })
            out["url_status"] = st
        if domain:
            j2 = _form_post("https://urlhaus-api.abuse.ch/v1/host/", {"host": domain})
            st2 = j2.get("query_status")
            if st2 == "ok":
                out["flagged"] = True
                out["matches"].append({
                    "type": "host",
                    "payloads": j2.get("payloads", [])[:3],
                })
            out["host_status"] = st2
        return out
    except Exception as exc:
        return {
            "provider": "URLhaus",
            "available": False,
            "flagged": False,
            "source": "error",
            "error": str(exc),
        }


def check_google_safe_browsing(url: str, api_key: str = "") -> dict[str, Any]:
    """Google Safe Browsing v4 (requires API key)."""
    if not api_key:
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return {
            "provider": "GoogleSafeBrowsing",
            "available": False,
            "flagged": False,
            "source": "disabled",
            "note": "GOOGLE_SAFE_BROWSING_API_KEY not set",
        }
    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={urllib.parse.quote(api_key)}"
    )
    payload = {
        "client": {"clientId": "TMGC", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        j = _json_post(endpoint, payload, timeout=6.0)
        matches = j.get("matches", []) or []
        return {
            "provider": "GoogleSafeBrowsing",
            "available": True,
            "flagged": bool(matches),
            "source": "live",
            "matches": matches[:5],
        }
    except Exception as exc:
        return {
            "provider": "GoogleSafeBrowsing",
            "available": False,
            "flagged": False,
            "source": "error",
            "error": str(exc),
        }


def check_phishtank(url: str, api_key: str = "") -> dict[str, Any]:
    """PhishTank (requires API key)."""
    if not api_key:
        api_key = os.environ.get("PHISHTANK_API_KEY", "")
    if not api_key:
        return {
            "provider": "PhishTank",
            "available": False,
            "flagged": False,
            "source": "disabled",
            "note": "PHISHTANK_API_KEY not set",
        }
    try:
        j = _form_post(
            "https://checkurl.phishtank.com/checkurl/",
            {"url": url, "format": "json", "app_key": api_key},
            headers={"User-Agent": "TMGC-Inspector/1.0"},
            timeout=8.0,
        )
        in_db = bool(j.get("results", {}).get("in_database")) if isinstance(j, dict) else False
        verified = bool(j.get("results", {}).get("verified")) if isinstance(j, dict) else False
        valid = bool(j.get("results", {}).get("valid")) if isinstance(j, dict) else False
        flagged = bool(in_db and (verified or valid))
        return {
            "provider": "PhishTank",
            "available": True,
            "flagged": flagged,
            "source": "live",
            "in_database": in_db,
            "verified": verified,
            "valid": valid,
        }
    except Exception as exc:
        return {
            "provider": "PhishTank",
            "available": False,
            "flagged": False,
            "source": "error",
            "error": str(exc),
        }


def check_virustotal(domain: str, api_key: str = "") -> dict[str, Any]:
    """VirusTotal domain reputation check (requires API key)."""
    if not api_key:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {
            "provider": "VirusTotal",
            "available": False,
            "flagged": False,
            "source": "disabled",
            "note": "VIRUSTOTAL_API_KEY not set",
        }
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        m = int(stats.get("malicious", 0) or 0)
        s = int(stats.get("suspicious", 0) or 0)
        h = int(stats.get("harmless", 0) or 0)
        u = int(stats.get("undetected", 0) or 0)
        return {
            "provider": "VirusTotal",
            "available": True,
            "source": "live",
            "malicious": m,
            "suspicious": s,
            "harmless": h,
            "undetected": u,
            "flagged": (m + s) > 0,
        }
    except urllib.error.HTTPError as exc:
        return {
            "provider": "VirusTotal",
            "available": False,
            "source": "http_error",
            "flagged": False,
            "note": f"HTTP error: {exc.code}",
        }
    except Exception as exc:
        return {
            "provider": "VirusTotal",
            "available": False,
            "source": "error",
            "flagged": False,
            "note": str(exc),
        }


def check_abuseipdb(ip: str, api_key: str = "") -> dict[str, Any]:
    """AbuseIPDB IP reputation check (requires API key)."""
    if not api_key:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {
            "provider": "AbuseIPDB",
            "available": False,
            "flagged": False,
            "source": "disabled",
            "note": "ABUSEIPDB_API_KEY not set",
        }
    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "",
    })
    url = f"https://api.abuseipdb.com/api/v2/check?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        data = payload.get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0) or 0)
        return {
            "provider": "AbuseIPDB",
            "available": True,
            "source": "live",
            "abuse_confidence": confidence,
            "total_reports": int(data.get("totalReports", 0) or 0),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "country": data.get("countryCode", ""),
            "flagged": confidence >= 50,
            "last_reported": data.get("lastReportedAt"),
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return {
                "provider": "AbuseIPDB",
                "available": True,
                "flagged": False,
                "source": "rate_limited",
                "note": "Rate limited — try again later",
            }
        return {
            "provider": "AbuseIPDB",
            "available": False,
            "source": "http_error",
            "flagged": False,
            "note": f"HTTP error: {exc.code}",
        }
    except Exception as exc:
        return {
            "provider": "AbuseIPDB",
            "available": False,
            "source": "error",
            "flagged": False,
            "note": str(exc),
        }


def check_urlscan(domain: str, api_key: str = "") -> dict[str, Any]:
    """urlscan.io search (API key optional)."""
    if not api_key:
        api_key = os.environ.get("URLSCAN_API_KEY", "")
    headers = {"accept": "application/json"}
    if api_key:
        headers["API-Key"] = api_key
    q = urllib.parse.quote(f"domain:{domain}")
    url = f"https://urlscan.io/api/v1/search/?q={q}&size=5"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            j = json.loads(resp.read().decode("utf-8"))
        results = j.get("results", []) or []
        return {
            "provider": "urlscan.io",
            "available": True,
            "flagged": False,
            "source": "live",
            "result_count": int(j.get("total", 0) or 0),
            "recent": [
                {
                    "task": (r.get("task") or {}).get("uuid"),
                    "time": (r.get("task") or {}).get("time"),
                    "url": (r.get("page") or {}).get("url"),
                    "ip": (r.get("page") or {}).get("ip"),
                    "asn": (r.get("page") or {}).get("asn"),
                }
                for r in results[:5]
            ],
        }
    except urllib.error.HTTPError as exc:
        return {
            "provider": "urlscan.io",
            "available": False,
            "flagged": False,
            "source": "http_error",
            "note": f"HTTP error: {exc.code}",
        }
    except Exception as exc:
        return {
            "provider": "urlscan.io",
            "available": False,
            "flagged": False,
            "source": "error",
            "note": str(exc),
        }


def run_all_feeds(
    domain: str,
    ip: str = "",
    website_url: str = "",
) -> dict[str, Any]:
    """
    Run all available threat intelligence feeds for a domain.

    Args:
        domain: The domain to check.
        ip: Optional IP address for AbuseIPDB check.
        website_url: Optional full URL for URLhaus/PhishTank/GSB checks.

    Returns:
        Dict with feed results, overall score, and flagged count.
    """
    results: dict[str, Any] = {
        "feeds": [],
        "total_checked": 0,
        "total_flagged": 0,
        "overall_score": 0.0,
    }

    # URLhaus (free)
    urlhaus_result = check_urlhaus(domain, website_url)
    results["feeds"].append(urlhaus_result)
    results["total_checked"] += 1
    if urlhaus_result.get("flagged"):
        results["total_flagged"] += 1

    # VirusTotal (if key available)
    vt_result = check_virustotal(domain)
    results["feeds"].append(vt_result)
    results["total_checked"] += 1
    if vt_result.get("flagged"):
        results["total_flagged"] += 1

    # AbuseIPDB (if IP and key available)
    if ip:
        abuse_result = check_abuseipdb(ip)
        results["feeds"].append(abuse_result)
        results["total_checked"] += 1
        if abuse_result.get("flagged"):
            results["total_flagged"] += 1

    # urlscan.io (no key needed for basic search)
    urlscan_result = check_urlscan(domain)
    results["feeds"].append(urlscan_result)
    results["total_checked"] += 1

    # Calculate overall score (0-100 based on flagged feeds / total checked)
    if results["total_checked"] > 0:
        results["overall_score"] = (results["total_flagged"] / results["total_checked"]) * 100.0

    return results

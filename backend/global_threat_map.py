"""
Live Global Threat Map Module
=============================
Builds a real-time snapshot of global phishing activity from the bundled
PhishTank dataset (phishtank_online.csv):

  1. Take the most recent verified + online phishing URLs.
  2. Resolve each unique domain to an IP (DNS).
  3. Batch-geocode IPs to country + lat/lon via ip-api.com (free, 100/batch).
  4. Classify the impersonated brand (`target` column) into attack types.
  5. Aggregate per-country hotspots + per-type stats.

Results are cached so repeated calls are instant. Geolocation results are
persisted to disk (intel_cache/geo_cache.json) and only refresh for new IPs.

Usage:
    from global_threat_map import build_snapshot
    snapshot = build_snapshot()

CLI:
    python global_threat_map.py --write-fallback   # warm cache + write frontend snapshot
"""

from __future__ import annotations

import csv
import json
import os
import socket
import threading
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "phishtank_online.csv")
CACHE_DIR = os.path.join(BASE_DIR, "intel_cache")
GEO_CACHE_PATH = os.path.join(CACHE_DIR, "geo_cache.json")

SNAPSHOT_TTL_SECONDS = 20 * 60
MAX_ROWS = 500           # most recent verified+online entries to consider
MAX_UNIQUE_DOMAINS = 300  # DNS resolution budget for a single warm-up
GEO_BATCH_SIZE = 100     # ip-api.com allows 100 queries per POST

_lock = threading.Lock()
_snapshot: dict[str, Any] | None = None
_snapshot_at: float = 0.0

# (key, label, keywords) — keyword matching on the impersonated brand/target.
TYPE_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("email_cloud", "Email & Cloud", (
        "microsoft", "outlook", "office", "google", "gmail", "apple", "icloud",
        "yahoo", "aol", "dropbox", "onedrive", "proton", "adobe", "docusign",
        "cloudflare", "amazon web", "aws",
    )),
    ("banking", "Banking & Finance", (
        "bank", "paypal", "chase", "citi", "wells fargo", "hsbc", "barclays",
        "lloyds", "natwest", "santander", "capital one", "american express",
        "amex", "visa", "mastercard", "revolut", "wise", "cashapp", "cash app",
        "venmo", "payoneer", "credit", "bofa", "n26", "ing bank", "unicredit",
        "commonwealth", "nab", "anz", "westpac", "td bank", "rbc", "royal bank",
        "bradesco", "itau", "caixa", "sber", "raiffeisen", "monzo", "starling",
        "deutsche", "postbank", "kbc", "abn amro", "sns", "swedbank", "nordea",
    )),
    ("social", "Social Media", (
        "instagram", "facebook", "whatsapp", "telegram", "twitter", "x.com",
        "linkedin", "tiktok", "snapchat", "discord", "wechat", "messenger",
        "reddit", "onlyfans", "grindr", "tinder",
    )),
    ("delivery", "Delivery & Shipping", (
        "dhl", "fedex", "usps", "ups", "dpd", "royal mail", "hermes", "evri",
        "gls", "postnl", "posten", "canada post", "australia post", "correos",
        "inpost", "tnt", "parcelforce", "chronopost", "colissimo", "seur",
        "aliexpress parcel", "dpdgroup", "bpost",
    )),
    ("crypto", "Crypto & Wallets", (
        "coinbase", "binance", "metamask", "ledger", "trezor", "kraken",
        "crypto.com", "bitcoin", "ethereum", "trust wallet", "phantom", "bybit",
        "okx", "usdt", "wallet", "crypto", "uniswap", "sushi", "blockchain",
    )),
    ("telecom", "Telecom & ISPs", (
        "vodafone", "verizon", "at&t", "t-mobile", "orange", "o2", "ee ",
        "three ", "telstra", "rogers", "bell ", "movistar", "claro", "jio",
        "airtel", "ntt", "docomo", "bt ", "sky ", "virgin media", "comcast",
        "spectrum", "cricket", "metro pcs", "sprint", "tmobile",
    )),
    ("government", "Government & Tax", (
        "gov", "irs", "tax", "social security", "inland revenue", "h&r block",
        "turbo tax", "revenue", "mva", "dps", "safety", "dol", "ssa",
    )),
    ("gaming_media", "Gaming & Streaming", (
        "netflix", "spotify", "steam", "epic", "riot", "xbox", "playstation",
        "disney", "hulu", "twitch", "roblox", "crunchyroll", "prime video",
        "max ", "paramount", "peacock",
    )),
    ("ecommerce", "E-commerce & Retail", (
        "amazon", "ebay", "aliexpress", "alibaba", "shopify", "wish", "temu",
        "shein", "etsy", "walmart", "best buy", "target ", "zara", "nike",
        "adidas", "zalando", "otto", "asos", "booking", "airbnb", "expedia",
        "rakuten", "mercado", "flipkart", "snapdeal", "paytm", "shopee",
        "lazada", "sephora", "ikea", "h&m", "costco", "home depot", "lowe",
        "wayfair", "kohls", "macys",
    )),
)


TYPE_LABELS: dict[str, str] = {key: label for key, label, _ in TYPE_RULES}


def classify_target(target: str) -> tuple[str, str]:
    """Map an impersonated brand name to an attack-type category."""
    t = (target or "").lower()
    for key, label, words in TYPE_RULES:
        if any(w in t for w in words):
            return key, label
    return "other", "Other / Generic"


def _domain_from_url(url: str) -> str:
    try:
        host = (urlparse(url or "").netloc or "").lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _resolve_ip(domain: str) -> str | None:
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return infos[0][4][0] if infos else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Geo cache (persistent ip -> location)
# ---------------------------------------------------------------------------
def _load_geo_cache() -> dict[str, dict[str, Any]]:
    try:
        with open(GEO_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_geo_cache(cache: dict[str, dict[str, Any]]) -> None:
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(GEO_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
    except Exception:
        pass


def _geocode_ips(ips: set[str]) -> dict[str, dict[str, Any]]:
    """Geocode unseen IPs via ip-api.com batch API (free, 100 per request)."""
    cache = _load_geo_cache()
    todo = [ip for ip in ips if ip not in cache]
    for i in range(0, len(todo), GEO_BATCH_SIZE):
        batch = todo[i:i + GEO_BATCH_SIZE]
        payload = json.dumps([
            {"query": ip, "fields": "status,country,countryCode,lat,lon"}
            for ip in batch
        ]).encode("utf-8")
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                results = json.loads(resp.read().decode("utf-8"))
            for ip, info in zip(batch, results):
                if isinstance(info, dict) and info.get("status") == "success":
                    cache[ip] = {
                        "country": info.get("country", ""),
                        "code": info.get("countryCode", ""),
                        "lat": float(info.get("lat", 0)),
                        "lon": float(info.get("lon", 0)),
                    }
        except Exception:
            pass
        time.sleep(0.4)  # stay well under the free-tier rate limit
    _save_geo_cache(cache)
    return cache


# ---------------------------------------------------------------------------
# Snapshot builder
# ---------------------------------------------------------------------------
def _parse_recent_phishtank() -> list[dict[str, str]]:
    """Most recent verified + online phishing entries from the CSV."""
    if not os.path.exists(CSV_PATH):
        return []
    rows: list[dict[str, str]] = []
    try:
        with open(CSV_PATH, newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                rows.append(row)
    except Exception:
        return []
    rows.sort(key=lambda r: r.get("submission_time") or "", reverse=True)
    out: list[dict[str, str]] = []
    for r in rows:
        if r.get("verified", "").lower() == "yes" and r.get("online", "").lower() == "yes":
            out.append(r)
            if len(out) >= MAX_ROWS:
                break
    return out


def build_snapshot(force: bool = False) -> dict[str, Any]:
    """Return the live global threat snapshot (cached for TTL seconds)."""
    global _snapshot, _snapshot_at
    now = time.time()
    with _lock:
        if _snapshot and not force and (now - _snapshot_at) < SNAPSHOT_TTL_SECONDS:
            return _snapshot

    rows = _parse_recent_phishtank()

    # Resolve unique domains -> IPs (bounded)
    ips: dict[str, str] = {}
    for r in rows:
        if len(ips) >= MAX_UNIQUE_DOMAINS:
            break
        d = _domain_from_url(r.get("url", ""))
        if not d or d in ips:
            continue
        ip = _resolve_ip(d)
        if ip:
            ips[d] = ip

    geo = _geocode_ips(set(ips.values())) if ips else {}

    countries: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"code": "", "name": "", "lat": 0.0, "lon": 0.0, "count": 0, "types": Counter()}
    )
    type_counter: Counter[str] = Counter()
    recent: list[dict[str, Any]] = []

    for r in rows:
        d = _domain_from_url(r.get("url", ""))
        ip = ips.get(d)
        loc = geo.get(ip) if ip else None
        target = (r.get("target") or "Other").strip() or "Other"
        tkey, tlabel = classify_target(target)
        type_counter[tkey] += 1

        if loc and loc.get("code"):
            c = countries[loc["code"]]
            c["code"] = loc["code"]
            c["name"] = loc.get("country", loc["code"])
            c["lat"] = loc["lat"]
            c["lon"] = loc["lon"]
            c["count"] += 1
            c["types"][tkey] += 1

        if len(recent) < 60:
            recent.append({
                "url": (r.get("url") or "")[:90],
                "domain": d,
                "target": target,
                "type": tkey,
                "type_label": tlabel,
                "country": (loc or {}).get("code", ""),
                "submitted": r.get("submission_time", ""),
            })

    country_list = []
    for c in countries.values():
        country_list.append({
            "code": c["code"],
            "name": c["name"],
            "lat": round(c["lat"], 2),
            "lon": round(c["lon"], 2),
            "count": c["count"],
            "types": [{"type": k, "label": TYPE_LABELS.get(k, k), "count": v}
                       for k, v in c["types"].most_common()],
        })
    country_list.sort(key=lambda c: c["count"], reverse=True)

    types = [
        {"type": k, "label": TYPE_LABELS.get(k, k), "count": v}
        for k, v in type_counter.most_common()
    ]

    snapshot = {
        "source": "phishtank",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_attacks": len(rows),
        "geocoded": bool(geo),
        "countries": country_list,
        "types": types,
        "recent": recent,
    }

    with _lock:
        _snapshot = snapshot
        _snapshot_at = now
    return snapshot


def _write_frontend_fallback() -> str:
    """Build a snapshot and write it as a JS module for offline front-end use."""
    snapshot = build_snapshot(force=True)
    frontend_dir = os.path.normpath(os.path.join(BASE_DIR, "..", "front_end"))
    path = os.path.join(frontend_dir, "globalThreatFallback.js")
    with open(path, "w", encoding="utf-8") as f:
        f.write("// Generated from real PhishTank data by backend/global_threat_map.py\n")
        f.write("export const GLOBAL_THREAT_FALLBACK = ")
        f.write(json.dumps(snapshot, ensure_ascii=False, indent=1))
        f.write(";\n")
    return path


if __name__ == "__main__":
    import sys
    snapshot = build_snapshot(force=True)
    print(f"total_attacks={snapshot['total_attacks']} "
          f"geocoded={snapshot['geocoded']} "
          f"countries={len(snapshot['countries'])} "
          f"types={len(snapshot['types'])}")
    print("top countries:", [(c["code"], c["count"]) for c in snapshot["countries"][:8]])
    print("types:", [(t["type"], t["count"]) for t in snapshot["types"]])
    if "--write-fallback" in sys.argv:
        print("wrote", _write_frontend_fallback())
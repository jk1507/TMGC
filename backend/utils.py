"""
Production phishing domain detection utilities.
Deterministic scoring only: no synthetic data, no random values.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import difflib
import ipaddress
import json
import math
import re
import socket
import ssl
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

try:
    import dns.resolver as _dns_resolver  # type: ignore
except Exception:
    _dns_resolver = None  # type: ignore

try:
    import whois as _whois_lib  # type: ignore
except Exception:
    _whois_lib = None  # type: ignore


__all__ = [
    "sanitize_domain",
    "validate_domain",
    "sanitize_url",
    "validate_url",
    "inspect_website",
    "compare_website_to_reference",
    "analyze_urlhaus",
    "analyze_urlscan",
    "analyze_google_safe_browsing",
    "analyze_phishtank",
    "normalize_homoglyphs",
    "detect_typosquatting",
    "detect_homoglyphs",
    "detect_combosquatting",
    "extract_features",
    "analyze_whois_mock",
    "analyze_dns_signals",
    "analyze_ssl_signals",
    "analyze_virustotal",
    "compute_risk_score",
]


_PROTO_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_PORT_RE = re.compile(r":(\d+)$")
_HTTP_PROTO_RE = re.compile(r"^https?://", re.IGNORECASE)
_LABEL_RE = re.compile(
    r"^[a-z0-9\u0080-\uffff](?:[a-z0-9\-_ \u0080-\uffff]{0,61}[a-z0-9\u0080-\uffff])?$",
    re.IGNORECASE,
)
_LABEL_RE = re.compile(r"^[a-z0-9\u0080-\uffff](?:[a-z0-9\-_\u0080-\uffff]{0,61}[a-z0-9\u0080-\uffff])?$", re.IGNORECASE)


RAW_HOMOGLYPHS: Dict[str, str] = {
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
}
TRANS_TABLE = {ord(k): v for k, v in RAW_HOMOGLYPHS.items()}
PAIR_SUBS: List[Tuple[str, str]] = [("rn", "m"), ("vv", "w"), ("cl", "d")]


@dataclass
class DomainConfig:
    brands: List[str] = field(default_factory=lambda: [
        "google", "gmail", "youtube", "android", "chrome",
        "microsoft", "office", "office365", "outlook", "azure", "windows",
        "apple", "icloud", "itunes", "appstore",
        "facebook", "instagram", "whatsapp", "messenger", "meta",
        "paypal", "venmo", "stripe", "square",
        "amazon", "aws", "primevideo",
        "netflix", "disneyplus", "hulu",
        "github", "gitlab", "bitbucket",
        "dropbox", "adobe", "canva", "figma",
        "bankofamerica", "wellsfargo", "citibank", "chase", "capitalone", "hsbc", "barclays",
        "americanexpress", "amex", "mastercard", "visa",
        "sbi", "hdfc", "icici", "axisbank", "kotak",
        "coinbase", "binance", "kraken",
        "cloudflare", "okta", "cisco",
        "fedex", "dhl", "ups", "usps", "irs",
    ])
    keywords: List[str] = field(default_factory=lambda: [
        "login", "signin", "verify", "verification", "secure", "security", "account", "update",
        "password", "reset", "recover", "billing", "payment", "invoice", "wallet",
        "support", "help", "official", "customer", "unlock", "suspend", "alert", "confirm",
        "kyc", "otp", "authorize", "approval",
    ])
    suspicious_tlds: frozenset = field(default_factory=lambda: frozenset({
        "xyz", "top", "club", "online", "site", "web", "info", "biz", "tk", "ml", "ga", "cf", "gq",
        "pw", "ws", "icu", "click", "cam", "mom", "work", "vip", "support", "email", "live",
    }))
    high_trust_tlds: frozenset = field(default_factory=lambda: frozenset({"com", "org", "net", "edu", "gov"}))


CONFIG = DomainConfig()

DARK_WEB_TLDS = frozenset({"onion", "i2p", "bit", "b32", "loki"})
HIGH_RISK_TLDS = frozenset({"xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "ws"})


def _safe_lower(value: object) -> str:
    return str(value).strip().lower()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def sanitize_domain(raw: str) -> str:
    if not raw:
        return ""
    d = raw.strip()
    d = _PROTO_RE.sub("", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    if d.count("@") == 1:
        _, d = d.split("@", 1)
    m = _PORT_RE.search(d)
    if m and not d.startswith("["):
        d = d[: d.rfind(":")]
    return d.strip().strip(".").lower()


def validate_domain(domain: str) -> Tuple[bool, str]:
    d = sanitize_domain(domain)
    if not d:
        return False, "Domain cannot be empty."
    if len(d) > 253:
        return False, "Domain exceeds 253 characters."
    if "." not in d:
        return False, "Invalid domain — must contain at least one dot."
    if ".." in d:
        return False, "Invalid domain — consecutive dots not allowed."
    for label in d.split("."):
        if not label:
            return False, "Empty label in domain."
        if len(label) > 63:
            return False, "A domain label exceeds 63 characters."
        if not _LABEL_RE.match(label):
            return False, f"Label '{label}' contains invalid characters."
    return True, ""


def sanitize_url(raw: str) -> str:
    if not raw:
        return ""
    u = raw.strip()
    if not _HTTP_PROTO_RE.match(u):
        u = "https://" + u
    parts = urllib_parse.urlsplit(u)
    host = parts.hostname or ""
    # normalize host similarly to sanitize_domain
    host = sanitize_domain(host)
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    query = parts.query or ""
    fragless = urllib_parse.urlunsplit((parts.scheme.lower(), host + (f":{parts.port}" if parts.port else ""), path, query, ""))
    return fragless


def _is_private_host(host: str) -> bool:
    h = sanitize_domain(host)
    if h in {"localhost"} or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def validate_url(url: str) -> Tuple[bool, str]:
    u = sanitize_url(url)
    parts = urllib_parse.urlsplit(u)
    if parts.scheme.lower() not in {"http", "https"}:
        return False, "Only http/https URLs are allowed."
    host = parts.hostname or ""
    if not host:
        return False, "URL must include a hostname."
    ok, err = validate_domain(host)
    if not ok:
        return False, f"Invalid hostname in URL: {err}"
    if _is_private_host(host):
        return False, "Private/loopback hostnames are not allowed."
    if parts.port and not (1 <= int(parts.port) <= 65535):
        return False, "Invalid port."
    return True, ""


class _LimitedRedirectHandler(urllib_request.HTTPRedirectHandler):
    def __init__(self, max_redirects: int = 5):
        super().__init__()
        self.max_redirects = max_redirects
        self.chain: List[Dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if len(self.chain) >= self.max_redirects:
            raise urllib_error.HTTPError(req.full_url, code, "Too many redirects", headers, fp)
        self.chain.append({"from": req.full_url, "to": newurl, "code": code})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _extract_html_signals(html: str, base_url: str) -> Dict[str, Any]:
    low = html.lower()
    title = None
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        title = re.sub(r"\s+", " ", re.sub(r"<.*?>", "", m.group(1))).strip()[:200] or None

    forms = re.findall(r"<form\b[^>]*>", low, re.IGNORECASE)
    has_form = bool(forms)
    has_password = bool(re.search(r'type\s*=\s*["\']password["\']', low, re.IGNORECASE))
    has_email = bool(re.search(r'type\s*=\s*["\']email["\']', low, re.IGNORECASE)) or ("name=\"email\"" in low or "name='email'" in low)
    has_otp = "otp" in low or "one-time" in low or "one time" in low

    # form action analysis: external post target is a common phishing signal
    external_actions: List[str] = []
    base_host = (urllib_parse.urlsplit(base_url).hostname or "").lower()
    for fm in re.finditer(r"<form\b[^>]*\baction\s*=\s*['\"]([^'\"]+)['\"][^>]*>", low, re.IGNORECASE):
        action = fm.group(1).strip()
        try:
            abs_action = urllib_parse.urljoin(base_url, action)
            ahost = (urllib_parse.urlsplit(abs_action).hostname or "").lower()
            if ahost and base_host and ahost != base_host:
                external_actions.append(abs_action[:300])
        except Exception:
            continue

    # asset/link host analysis (common in cloned sites)
    linked_hosts: List[str] = []
    for m2 in re.finditer(r"\b(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", low, re.IGNORECASE):
        ref = m2.group(1).strip()
        if not ref or ref.startswith("data:") or ref.startswith("javascript:") or ref.startswith("mailto:"):
            continue
        try:
            abs_ref = urllib_parse.urljoin(base_url, ref)
            h = (urllib_parse.urlsplit(abs_ref).hostname or "").lower()
            if h:
                linked_hosts.append(h)
        except Exception:
            continue
    external_linked = [h for h in linked_hosts if base_host and h and h != base_host]
    same_host_ratio = (1.0 - (len(external_linked) / max(1, len(linked_hosts)))) if linked_hosts else None

    return {
        "title": title,
        "has_form": has_form,
        "has_password_input": has_password,
        "has_email_input": has_email,
        "has_otp_keywords": has_otp,
        "external_form_actions": sorted(set(external_actions))[:5],
        "linked_host_count": len(linked_hosts),
        "external_linked_host_count": len(external_linked),
        "same_host_asset_ratio": round(same_host_ratio, 4) if isinstance(same_host_ratio, float) else None,
    }


def _html_to_text_sample(html: str, limit: int = 5000) -> str:
    s = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    s = re.sub(r"(?is)<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s[:limit]


def inspect_website(url: str, timeout: float = 6.0, max_bytes: int = 512_000) -> Dict[str, Any]:
    """
    Fetches a website (no JS execution) and extracts lightweight HTML signals.
    Includes SSRF protections (blocks private/loopback hostnames).
    """
    ok, err = validate_url(url)
    if not ok:
        return {"available": False, "source": "validation_error", "error": err}

    start_url = sanitize_url(url)
    redir = _LimitedRedirectHandler(max_redirects=5)
    opener = urllib_request.build_opener(redir)

    headers = {
        "User-Agent": "TMGC-Inspector/1.0 (+security-inspection)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    req = urllib_request.Request(start_url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            status = getattr(resp, "status", None) or getattr(resp, "code", None)
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            raw = resp.read(max_bytes + 1)

        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]

        encoding = "utf-8"
        try:
            html = raw.decode("utf-8", errors="replace")
        except Exception:
            html = raw.decode(errors="replace")

        html_signals = _extract_html_signals(html, final_url)
        text_sample = _html_to_text_sample(html, limit=5000)

        return {
            "available": True,
            "source": "live",
            "start_url": start_url,
            "final_url": final_url,
            "status": status,
            "content_type": ctype or None,
            "redirect_chain": redir.chain,
            "truncated": truncated,
            "bytes_read": len(raw),
            "signals": html_signals,
            "text_sample": text_sample[:1200],
        }
    except urllib_error.HTTPError as exc:
        return {
            "available": False,
            "source": "http_error",
            "start_url": start_url,
            "status": exc.code,
            "redirect_chain": redir.chain,
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "available": False,
            "source": "fetch_error",
            "start_url": start_url,
            "redirect_chain": redir.chain,
            "error": str(exc),
        }


def compare_website_to_reference(suspect_url: str, reference_url: str) -> Dict[str, Any]:
    s_ok, s_err = validate_url(suspect_url)
    if not s_ok:
        return {"available": False, "source": "validation_error", "error": f"Suspect URL invalid: {s_err}"}
    r_ok, r_err = validate_url(reference_url)
    if not r_ok:
        return {"available": False, "source": "validation_error", "error": f"Reference URL invalid: {r_err}"}

    suspect = inspect_website(suspect_url)
    ref = inspect_website(reference_url)
    if not suspect.get("available") or not ref.get("available"):
        return {
            "available": False,
            "source": "fetch_error",
            "suspect": {"available": bool(suspect.get("available")), "error": suspect.get("error"), "status": suspect.get("status")},
            "reference": {"available": bool(ref.get("available")), "error": ref.get("error"), "status": ref.get("status")},
        }

    st = (suspect.get("text_sample") or "").strip()
    rt = (ref.get("text_sample") or "").strip()
    title_s = ((suspect.get("signals") or {}).get("title") or "").strip().lower()
    title_r = ((ref.get("signals") or {}).get("title") or "").strip().lower()

    text_ratio = difflib.SequenceMatcher(None, st, rt).ratio() if st and rt else 0.0
    title_ratio = difflib.SequenceMatcher(None, title_s, title_r).ratio() if title_s and title_r else 0.0

    s_host = (urllib_parse.urlsplit(suspect.get("final_url") or suspect_url).hostname or "").lower()
    r_host = (urllib_parse.urlsplit(ref.get("final_url") or reference_url).hostname or "").lower()
    different_host = bool(s_host and r_host and s_host != r_host)

    similarity = 0.85 * float(text_ratio) + 0.15 * float(title_ratio)
    similarity = max(0.0, min(1.0, similarity))

    likely_clone = different_host and similarity >= 0.72

    return {
        "available": True,
        "source": "live",
        "suspect_final_url": suspect.get("final_url"),
        "reference_final_url": ref.get("final_url"),
        "suspect_host": s_host,
        "reference_host": r_host,
        "different_host": different_host,
        "text_similarity": round(text_ratio, 4),
        "title_similarity": round(title_ratio, 4),
        "similarity": round(similarity, 4),
        "likely_clone": likely_clone,
    }


def _json_post(url: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: float = 6.0) -> Dict[str, Any]:
    h = {"accept": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(url, data=data, headers={**h, "content-type": "application/json"}, method="POST")
    with urllib_request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _form_post(url: str, form: Dict[str, str], headers: Optional[Dict[str, str]] = None, timeout: float = 6.0) -> Dict[str, Any]:
    h = {"accept": "application/json"}
    if headers:
        h.update(headers)
    data = urllib_parse.urlencode(form).encode("utf-8")
    req = urllib_request.Request(url, data=data, headers={**h, "content-type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib_request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def analyze_urlhaus(domain: str, url: str = "") -> Dict[str, Any]:
    """
    URLhaus (abuse.ch) — no API key required.
    Checks domain and/or exact URL.
    """
    d = sanitize_domain(domain)
    out: Dict[str, Any] = {"provider": "URLhaus", "available": True, "flagged": False, "source": "live", "matches": []}
    try:
        if url:
            u = sanitize_url(url)
            j = _form_post("https://urlhaus-api.abuse.ch/v1/url/", {"url": u})
            st = j.get("query_status")
            if st == "ok":
                out["flagged"] = True
                out["matches"].append({"type": "url", "status": j.get("url_status"), "threat": j.get("threat"), "tags": j.get("tags")})
            out["url_status"] = st
        if d:
            j2 = _form_post("https://urlhaus-api.abuse.ch/v1/host/", {"host": d})
            st2 = j2.get("query_status")
            if st2 == "ok":
                out["flagged"] = True
                out["matches"].append({"type": "host", "payloads": j2.get("payloads", [])[:3]})
            out["host_status"] = st2
        return out
    except Exception as exc:
        return {"provider": "URLhaus", "available": False, "flagged": False, "source": "error", "error": str(exc)}


def analyze_urlscan(domain: str, api_key: str = "") -> Dict[str, Any]:
    """
    urlscan.io search (API key optional but recommended for higher limits).
    """
    d = sanitize_domain(domain)
    if not d:
        return {"provider": "urlscan.io", "available": False, "flagged": False, "source": "validation_error", "error": "Empty domain"}
    headers = {"accept": "application/json"}
    if api_key:
        headers["API-Key"] = api_key
    q = urllib_parse.quote(f"domain:{d}")
    url = f"https://urlscan.io/api/v1/search/?q={q}&size=5"
    req = urllib_request.Request(url, headers=headers, method="GET")
    try:
        with urllib_request.urlopen(req, timeout=6.0) as resp:
            j = json.loads(resp.read().decode("utf-8"))
        results = j.get("results", []) or []
        # urlscan doesn't label "phishing" directly; we surface evidence and let scoring decide
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
    except urllib_error.HTTPError as exc:
        return {"provider": "urlscan.io", "available": False, "flagged": False, "source": "http_error", "status": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"provider": "urlscan.io", "available": False, "flagged": False, "source": "error", "error": str(exc)}


def analyze_google_safe_browsing(url: str, api_key: str = "") -> Dict[str, Any]:
    """
    Google Safe Browsing v4 (requires API key).
    """
    if not api_key:
        return {"provider": "GoogleSafeBrowsing", "available": False, "flagged": False, "source": "disabled", "note": "GOOGLE_SAFE_BROWSING_API_KEY not set"}
    ok, err = validate_url(url)
    if not ok:
        return {"provider": "GoogleSafeBrowsing", "available": False, "flagged": False, "source": "validation_error", "error": err}
    u = sanitize_url(url)
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={urllib_parse.quote(api_key)}"
    payload = {
        "client": {"clientId": "TMGC", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u}],
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
        return {"provider": "GoogleSafeBrowsing", "available": False, "flagged": False, "source": "error", "error": str(exc)}


def analyze_phishtank(url: str, api_key: str = "") -> Dict[str, Any]:
    """
    PhishTank (requires key) — placeholder integration (API format varies by key type).
    """
    if not api_key:
        return {"provider": "PhishTank", "available": False, "flagged": False, "source": "disabled", "note": "PHISHTANK_API_KEY not set"}
    ok, err = validate_url(url)
    if not ok:
        return {"provider": "PhishTank", "available": False, "flagged": False, "source": "validation_error", "error": err}
    # Many PhishTank keys use the web check endpoint with form params.
    # We'll keep a conservative implementation and surface errors if the key is incompatible.
    u = sanitize_url(url)
    try:
        j = _form_post(
            "https://checkurl.phishtank.com/checkurl/",
            {"url": u, "format": "json", "app_key": api_key},
            headers={"User-Agent": "TMGC-Inspector/1.0"},
            timeout=8.0,
        )
        # Response schema differs; best-effort normalize
        in_db = bool(j.get("results", {}).get("in_database")) if isinstance(j, dict) else False
        verified = bool(j.get("results", {}).get("verified")) if isinstance(j, dict) else False
        valid = bool(j.get("results", {}).get("valid")) if isinstance(j, dict) else False
        flagged = bool(in_db and (verified or valid))
        return {"provider": "PhishTank", "available": True, "flagged": flagged, "source": "live", "in_database": in_db, "verified": verified, "valid": valid}
    except Exception as exc:
        return {"provider": "PhishTank", "available": False, "flagged": False, "source": "error", "error": str(exc)}

def _normalize_homoglyphs(text: str) -> str:
    t = _safe_lower(text)
    for a, b in PAIR_SUBS:
        t = t.replace(a, b)
    return t.translate(TRANS_TABLE)


def normalize_homoglyphs(text: str) -> str:
    return _normalize_homoglyphs(text)


def _skeletonize(text: str) -> str:
    t = _normalize_homoglyphs(text)
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", t)


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def jaro_similarity(s1: str, s2: str) -> float:
    if s1 == s2:
        return 1.0
    l1, l2 = len(s1), len(s2)
    if not l1 or not l2:
        return 0.0
    w = max(max(l1, l2) // 2 - 1, 0)
    m1 = [False] * l1
    m2 = [False] * l2
    matches = 0
    trans = 0
    for i in range(l1):
        lo, hi = max(0, i - w), min(i + w + 1, l2)
        for j in range(lo, hi):
            if not m2[j] and s1[i] == s2[j]:
                m1[i] = m2[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    k = 0
    for i in range(l1):
        if m1[i]:
            while not m2[k]:
                k += 1
            if s1[i] != s2[k]:
                trans += 1
            k += 1
    return (matches / l1 + matches / l2 + (matches - trans / 2) / matches) / 3


def jaro_winkler_similarity(s1: str, s2: str, p: float = 0.1) -> float:
    j = jaro_similarity(s1, s2)
    prefix = 0
    for a, b in zip(s1[:4], s2[:4]):
        if a == b:
            prefix += 1
        else:
            break
    return j + prefix * p * (1 - j)


def detect_typosquatting(domain_name: str) -> Dict[str, Any]:
    label = _skeletonize(domain_name)
    best: Optional[Dict[str, Any]] = None
    for brand in CONFIG.brands:
        b = _skeletonize(brand)
        if not b:
            continue
        dist = levenshtein_distance(label, b)
        jw = jaro_winkler_similarity(label, b)
        lev_score = 1 - dist / max(len(label), len(b), 1)
        combined = 0.65 * jw + 0.35 * lev_score
        row = {
            "brand": brand,
            "edit_distance": dist,
            "jaro_winkler_score": round(jw, 4),
            "levenshtein_score": round(lev_score, 4),
            "combined_score": round(combined, 4),
        }
        if best is None or row["combined_score"] > best["combined_score"]:
            best = row
    if best is None:
        return {
            "detected": False,
            "reason": "No brands loaded",
            "closest_brand": None,
            "jaro_winkler_score": 0.0,
            "levenshtein_score": 0.0,
            "combined_score": 0.0,
            "edit_distance": 999,
        }

    # Check if the original label (before normalization) differs from the normalized form.
    # This catches homoglyph/digit substitutions like "g00gle" → normalized to "google".
    # If normalization changed the label AND the normalized version matches a brand,
    # then the domain is visually impersonating that brand through character substitution.
    exact_brand = best["edit_distance"] == 0 and label == _skeletonize(str(best["brand"]))
    
    # Separate check: was it the normalization that made it an exact brand match?
    original_label = _safe_lower(domain_name)  # Before skeletonize
    normalized_label = _skeletonize(domain_name)
    is_normalization_substitution = (
        exact_brand
        and original_label != normalized_label
        and normalized_label == _skeletonize(str(best["brand"]))
    )
    
    detected = (
        is_normalization_substitution
        or (
            not exact_brand
            and (
                (best["combined_score"] >= 0.84 and best["edit_distance"] <= 3)
                or (best["jaro_winkler_score"] >= 0.90 and best["edit_distance"] <= 2)
            )
        )
    )
    if is_normalization_substitution:
        reason = "Strong brand lookalike (via character substitution)"
    elif detected:
        reason = "Strong brand lookalike"
    else:
        reason = "No strong near-brand signal"
    return {
        "detected": detected,
        "reason": reason,
        "closest_brand": best["brand"],
        "jaro_winkler_score": best["jaro_winkler_score"],
        "levenshtein_score": best["levenshtein_score"],
        "combined_score": best["combined_score"],
        "edit_distance": best["edit_distance"],
    }


def detect_homoglyphs(label: str) -> Dict[str, Any]:
    suspicious: List[Dict[str, Any]] = []
    digit_subs: List[str] = []
    for i, ch in enumerate(label):
        non_ascii = ord(ch) > 127
        ascii_confusable = ch in RAW_HOMOGLYPHS
        if non_ascii or ascii_confusable:
            suspicious.append({
                "index": i,
                "char": ch,
                "ascii_equiv": RAW_HOMOGLYPHS.get(ch, ch),
                "codepoint": hex(ord(ch)),
            })
        if ch.isdigit() and ch in RAW_HOMOGLYPHS:
            digit_subs.append(ch)
    return {
        "detected": bool(suspicious),
        "count": len(suspicious),
        "suspicious_chars": suspicious,
        "normalized_domain": _normalize_homoglyphs(label),
        "ascii_only": all(ord(c) < 128 for c in label),
        "has_digit_substitution": bool(digit_subs),
        "digit_substitutions": digit_subs,
    }


def detect_combosquatting(domain_name: str) -> Dict[str, Any]:
    raw = _safe_lower(domain_name)
    host = sanitize_domain(raw)
    parts = host.split(".")
    registered_label = parts[-2] if len(parts) >= 2 else host
    sk = _skeletonize(registered_label)
    matched_brands = sorted([b for b in CONFIG.brands if _skeletonize(b) in sk and sk != _skeletonize(b)])
    matched_keywords = sorted([k for k in CONFIG.keywords if _skeletonize(k) in sk])
    fusion = []
    for b in matched_brands:
        for k in matched_keywords:
            bsk = _skeletonize(b)
            ksk = _skeletonize(k)
            if bsk + ksk in sk or ksk + bsk in sk:
                fusion.append(f"{b}+{k}")
    return {
        "detected": bool(matched_brands and matched_keywords),
        "matched_brands": matched_brands,
        "matched_keywords": matched_keywords,
        "brand_only": bool(matched_brands and not matched_keywords),
        "keyword_only": bool(matched_keywords and not matched_brands),
        "tokens": [t for t in re.split(r"[\-_.\s]+", raw) if t],
        "fusion_patterns": sorted(set(fusion)),
    }


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def extract_features(full_domain: str) -> Dict[str, Any]:
    s = sanitize_domain(full_domain)
    parts = s.split(".")
    tld = parts[-1] if len(parts) >= 2 else ""
    domain_name = parts[-2] if len(parts) >= 2 else s
    subdomains = parts[:-2] if len(parts) >= 3 else []
    host_sk = _skeletonize(s)
    kw = [k for k in CONFIG.keywords if _skeletonize(k) in host_sk]
    brands = [b for b in CONFIG.brands if _skeletonize(b) in host_sk]
    return {
        "domain_name": domain_name,
        "registered_domain": f"{domain_name}.{tld}" if tld else domain_name,
        "sanitized": s,
        "tld": tld,
        "length": len(domain_name),
        "full_host_length": len(s),
        "digit_count": sum(c.isdigit() for c in domain_name),
        "digit_ratio": round(sum(c.isdigit() for c in domain_name) / max(1, len(domain_name)), 4),
        "hyphen_count": domain_name.count("-"),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "entropy": round(_entropy(domain_name), 4),
        "full_host_entropy": round(_entropy(s), 4),
        "suspicious_tld": tld in CONFIG.suspicious_tlds,
        "high_trust_tld": tld in CONFIG.high_trust_tlds,
        "has_suspicious_keywords": bool(kw),
        "matched_keywords": sorted(set(kw)),
        "brand_hits_anywhere": sorted(set(brands)),
        "contains_brand_anywhere": bool(brands),
        "has_punycode": "xn--" in s,
        "is_ip_like": bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s)),
    }


def _safe_dns_resolve(domain: str, rtype: str) -> List[str]:
    if _dns_resolver is None:
        return []
    try:
        return [str(r).strip() for r in _dns_resolver.resolve(domain, rtype, lifetime=3)]
    except Exception:
        return []


def analyze_dns_signals(domain: str) -> Dict[str, Any]:
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    if tld in DARK_WEB_TLDS:
        return {
            "a_record_count": 0,
            "mx_record_count": 0,
            "ns_record_count": 0,
            "has_mx": False,
            "has_ns": False,
            "has_dns": False,
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "suspicious_nameservers": False,
            "source": "not_applicable_dark_web",
            "note": "Public DNS checks are not applicable for dark-web domains",
        }
    a = _safe_dns_resolve(s, "A")
    mx = _safe_dns_resolve(s, "MX")
    ns = _safe_dns_resolve(s, "NS")
    parking_kw = ("parking", "expired", "suspend", "cheap")
    suspicious_ns = any(any(k in n.lower() for k in parking_kw) for n in ns)
    return {
        "a_record_count": len(a),
        "mx_record_count": len(mx),
        "ns_record_count": len(ns),
        "has_mx": bool(mx),
        "has_ns": bool(ns),
        "has_dns": bool(a or mx or ns),
        "a_records": a[:5],
        "mx_records": mx[:5],
        "ns_records": ns[:5],
        "suspicious_nameservers": suspicious_ns,
        "source": "live" if _dns_resolver else "unavailable",
    }


def analyze_ssl_signals(domain: str, timeout: float = 4.0) -> Dict[str, Any]:
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    if tld in DARK_WEB_TLDS:
        return {
            "has_ssl": False,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "days_to_expiry": None,
            "self_signed_like": False,
            "ssl_error": None,
            "source": "not_applicable_dark_web",
            "note": "Public TLS checks are not applicable for dark-web domains",
        }
    result = {
        "has_ssl": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_to_expiry": None,
        "self_signed_like": False,
        "ssl_error": None,
        "source": "live",
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((s, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=s) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get("issuer", ())
                subject = cert.get("subject", ())
                result["has_ssl"] = True
                result["issuer"] = issuer
                result["subject"] = subject
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
                result["self_signed_like"] = str(issuer).lower() == str(subject).lower() and str(issuer) != "()"
                if cert.get("notAfter"):
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["days_to_expiry"] = (exp - _utcnow()).days
    except Exception as exc:
        result["ssl_error"] = str(exc)
    return result


def _parse_date(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        fmts = ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%d-%b-%Y")
        for f in fmts:
            try:
                d = datetime.strptime(value, f)
                return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def analyze_whois_mock(domain: str) -> Dict[str, Any]:
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    if tld in DARK_WEB_TLDS:
        return {
            "available": False,
            "source": "not_applicable_dark_web",
            "age_days": None,
            "age_str": "not available for dark-web TLD",
            "creation_date": None,
            "registrar": None,
            "privacy_protected": None,
            "suspicious_registrar": False,
            "whois_flag": "Unavailable",
            "note": "WHOIS not applicable for dark-web domains",
        }
    if _whois_lib is None:
        return {
            "available": False,
            "source": "unavailable",
            "age_days": None,
            "age_str": "unknown",
            "creation_date": None,
            "registrar": None,
            "privacy_protected": None,
            "suspicious_registrar": False,
            "whois_flag": "Unavailable",
            "note": "python-whois is not installed",
        }
    try:
        w = _whois_lib.whois(s)
        creation = _parse_date(getattr(w, "creation_date", None) or (w.get("creation_date") if hasattr(w, "get") else None))
        registrar = str(getattr(w, "registrar", None) or (w.get("registrar") if hasattr(w, "get") else "")).strip() or None
        age_days = (_utcnow() - creation).days if creation else None
        text_blob = str(w).lower()
        privacy = any(k in text_blob for k in ("privacy", "redacted", "proxy", "guard"))
        suspicious_reg = bool(registrar and any(k in registrar.lower() for k in ("cheap", "privacy", "unknown")))
        whois_flag = "Legitimate"
        if isinstance(age_days, int) and age_days < 30:
            whois_flag = "Suspicious"
        elif privacy or suspicious_reg:
            whois_flag = "Suspicious"
        age_str = "unknown"
        if isinstance(age_days, int):
            if age_days < 30:
                age_str = f"{age_days} day(s)"
            elif age_days < 365:
                age_str = f"{age_days // 30} month(s)"
            else:
                age_str = f"{age_days // 365} year(s)"
        return {
            "available": True,
            "source": "live",
            "age_days": age_days,
            "age_str": age_str,
            "creation_date": creation.isoformat() if creation else None,
            "registrar": registrar,
            "privacy_protected": privacy,
            "suspicious_registrar": suspicious_reg,
            "whois_flag": whois_flag,
            "note": "Live WHOIS",
        }
    except Exception as exc:
        return {
            "available": False,
            "source": "live_error",
            "age_days": None,
            "age_str": "unknown",
            "creation_date": None,
            "registrar": None,
            "privacy_protected": None,
            "suspicious_registrar": False,
            "whois_flag": "Unavailable",
            "note": f"WHOIS error: {exc}",
        }


def analyze_virustotal(domain: str, api_key: str = "") -> Dict[str, Any]:
    d = sanitize_domain(domain)
    if not api_key:
        return {
            "available": False,
            "source": "disabled",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "flagged": False,
            "note": "VirusTotal API key not configured",
        }
    url = f"https://www.virustotal.com/api/v3/domains/{urllib_parse.quote(d)}"
    req = urllib_request.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib_request.urlopen(req, timeout=4.0) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        m = int(stats.get("malicious", 0) or 0)
        s = int(stats.get("suspicious", 0) or 0)
        h = int(stats.get("harmless", 0) or 0)
        u = int(stats.get("undetected", 0) or 0)
        return {
            "available": True,
            "source": "live",
            "malicious": m,
            "suspicious": s,
            "harmless": h,
            "undetected": u,
            "flagged": (m + s) > 0,
            "note": "VirusTotal live result",
        }
    except urllib_error.HTTPError as exc:
        return {
            "available": False,
            "source": "live_error",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "flagged": False,
            "note": f"VirusTotal HTTP error: {exc.code}",
        }
    except Exception as exc:
        return {
            "available": False,
            "source": "live_error",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "flagged": False,
            "note": f"VirusTotal error: {exc}",
        }


def _determine_attack_type(
    features: Dict[str, Any],
    typo: Dict[str, Any],
    hg: Dict[str, Any],
    combo: Dict[str, Any],
    score: float,
) -> str:
    tld = features.get("tld", "")
    if tld in DARK_WEB_TLDS and (combo.get("detected") or features.get("contains_brand_anywhere")):
        return "Dark Web Brand Impersonation"
    if tld in DARK_WEB_TLDS:
        return "Dark Web / Tor Domain"
    if combo.get("detected"):
        return "Combo-Squatting"
    if typo.get("detected"):
        return "Typosquatting"
    if hg.get("detected"):
        return "Homoglyph Attack"
    if features.get("is_ip_like"):
        return "IP Masquerading"
    return "Suspicious Domain" if score >= 35 else "No Attack Detected"


def _estimate_confidence(
    features: Dict[str, Any],
    typo: Dict[str, Any],
    hg: Dict[str, Any],
    combo: Dict[str, Any],
    whois: Dict[str, Any],
    dns: Dict[str, Any],
    ssl_r: Dict[str, Any],
    vt: Dict[str, Any],
) -> str:
    tld = features.get("tld", "")
    if tld in DARK_WEB_TLDS and (combo.get("detected") or features.get("contains_brand_anywhere")):
        return "High"
    pts = 0
    pts += 2 if typo.get("detected") else 0
    pts += 2 if hg.get("detected") else 0
    pts += 2 if combo.get("detected") else 0
    pts += 2 if whois.get("source") == "live" else 0
    pts += 1 if dns.get("source") == "live" else 0
    pts += 1 if ssl_r.get("source") == "live" else 0
    pts += 2 if vt.get("available") else 0
    return "High" if pts >= 8 else "Medium" if pts >= 4 else "Low"


def compute_risk_score(
    features: Dict[str, Any],
    typo_result: Dict[str, Any],
    homoglyph_result: Dict[str, Any],
    combo_result: Dict[str, Any],
    whois_result: Dict[str, Any],
    dns_result: Optional[Dict[str, Any]] = None,
    ssl_result: Optional[Dict[str, Any]] = None,
    threat_intel_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    dns_result = dns_result or {}
    ssl_result = ssl_result or {}
    threat_intel_result = threat_intel_result or {}

    score = 0.0
    reasons: List[str] = []
    breakdown: Dict[str, float] = {}

    tld = str(features.get("tld", "")).lower().strip(".")

    # 1) Dark web signal (hard high-risk floor)
    if tld in DARK_WEB_TLDS:
        p = 55.0
        if features.get("contains_brand_anywhere") or combo_result.get("detected") or combo_result.get("brand_only"):
            p += 25.0
            reasons.append("Brand impersonation detected on dark-web domain")
        if typo_result.get("detected") or float(typo_result.get("jaro_winkler_score", 0)) >= 0.75:
            p += 10.0
            reasons.append("Typosquatting signal present on dark-web domain")
        score += p
        breakdown["dark_web_tld"] = round(p, 1)
        reasons.append(f"Dark web TLD '.{tld}' is inherently high risk")
    elif tld in HIGH_RISK_TLDS and features.get("contains_brand_anywhere"):
        score += 15.0
        breakdown["high_risk_tld_brand"] = 15.0
        reasons.append(f"High-risk TLD '.{tld}' combined with known brand")

    # 2) Typosquatting
    if typo_result.get("detected"):
        p = 28.0 + 18.0 * float(typo_result.get("combined_score", 0))
        score += p
        breakdown["typosquatting"] = round(p, 1)
        reasons.append(f"Typosquatting detected against brand '{typo_result.get('closest_brand')}'")
    elif float(typo_result.get("combined_score", 0)) >= 0.80:
        p = 10.0
        score += p
        breakdown["near_brand"] = round(p, 1)
        reasons.append("Near-brand visual similarity detected")

    # 3) Homoglyph
    hg_pts = 0.0
    if homoglyph_result.get("detected"):
        hg_pts += min(24.0, 8.0 + 4.5 * int(homoglyph_result.get("count", 0)))
        reasons.append("Confusable/homoglyph characters detected")
    if homoglyph_result.get("has_digit_substitution"):
        hg_pts += 6.0
        reasons.append("Digit substitutions mimic letters")
    if features.get("has_punycode"):
        hg_pts += 10.0
        reasons.append("Punycode/IDN usage increases phishing risk")
    if hg_pts:
        score += hg_pts
        breakdown["homoglyph"] = round(hg_pts, 1)

    # 4) Combo squatting / brand+keyword
    combo_pts = 0.0
    if combo_result.get("detected"):
        combo_pts += 22.0 + 16.0
        reasons.append("Brand + phishing keyword combination detected")
    elif combo_result.get("brand_only"):
        combo_pts += 10.0
        reasons.append("Brand embedded in longer suspicious label")
    elif combo_result.get("keyword_only"):
        combo_pts += 5.0
        reasons.append("Phishing keyword found in domain")
    if combo_result.get("fusion_patterns"):
        combo_pts += 4.0
    if combo_pts:
        score += combo_pts
        breakdown["combosquatting"] = round(combo_pts, 1)

    # 5) Structural
    struct_pts = 0.0
    if features.get("suspicious_tld"):
        struct_pts += 8.0
        reasons.append(f"Suspicious TLD '.{tld}'")
    if int(features.get("subdomain_count", 0)) >= 3:
        struct_pts += 5.0
        reasons.append("Excessive subdomain depth")
    if float(features.get("digit_ratio", 0)) >= 0.30:
        struct_pts += 5.0
    if int(features.get("hyphen_count", 0)) >= 3:
        struct_pts += 5.0
    if float(features.get("entropy", 0)) >= 3.7:
        struct_pts += 4.0
    if features.get("is_ip_like"):
        struct_pts += 18.0
        reasons.append("IP-style host used")
    if features.get("contains_brand_anywhere") and not combo_result.get("detected"):
        struct_pts += 5.0
    if struct_pts:
        score += struct_pts
        breakdown["domain_features"] = round(struct_pts, 1)

    # 6) WHOIS
    whois_pts = 0.0
    age = whois_result.get("age_days")
    if isinstance(age, int):
        if age < 7:
            whois_pts += 22.0
            reasons.append("Very newly registered domain")
        elif age < 30:
            whois_pts += 18.0
            reasons.append("Recently registered domain")
        elif age < 90:
            whois_pts += 8.0
    if whois_result.get("privacy_protected"):
        whois_pts += 6.0
        reasons.append("WHOIS privacy/redaction enabled")
    if whois_result.get("suspicious_registrar"):
        whois_pts += 8.0
        reasons.append("Suspicious registrar pattern")
    if whois_pts:
        score += whois_pts
        breakdown["whois"] = round(whois_pts, 1)

    # 7) DNS (skip if dark-web not applicable)
    dns_pts = 0.0
    if dns_result.get("source") not in ("not_applicable_dark_web",):
        if not dns_result.get("has_dns"):
            dns_pts += 4.0
        if not dns_result.get("has_ns"):
            dns_pts += 3.0
        if dns_result.get("suspicious_nameservers"):
            dns_pts += 5.0
            reasons.append("Suspicious nameserver pattern")
    if dns_pts:
        score += dns_pts
        breakdown["dns"] = round(dns_pts, 1)

    # 8) SSL (skip if dark-web not applicable)
    ssl_pts = 0.0
    if ssl_result.get("source") not in ("not_applicable_dark_web",):
        if ssl_result.get("ssl_error"):
            ssl_pts += 2.0
        if ssl_result.get("self_signed_like"):
            ssl_pts += 6.0
            reasons.append("Self-signed or anomalous SSL certificate")
        exp = ssl_result.get("days_to_expiry")
        if isinstance(exp, int) and exp < 0:
            ssl_pts += 5.0
            reasons.append("SSL certificate is expired")
    if ssl_pts:
        score += ssl_pts
        breakdown["ssl"] = round(ssl_pts, 1)

    # 9) VirusTotal threat intelligence
    ti_pts = 0.0
    if threat_intel_result.get("available"):
        mal = int(threat_intel_result.get("malicious", 0) or 0)
        sus = int(threat_intel_result.get("suspicious", 0) or 0)
        if mal > 0:
            ti_pts += 35.0
            reasons.append(f"VirusTotal flagged as malicious by {mal} engine(s)")
        if sus > 0:
            ti_pts += 20.0
            reasons.append(f"VirusTotal flagged as suspicious by {sus} engine(s)")
    if ti_pts:
        score += ti_pts
        breakdown["threat_intel"] = round(ti_pts, 1)

    # Clean-domain reduction (never for dark-web)
    if (
        tld not in DARK_WEB_TLDS
        and not typo_result.get("detected")
        and not combo_result.get("detected")
        and not homoglyph_result.get("detected")
        and features.get("high_trust_tld")
        and isinstance(age, int)
        and age > 365
    ):
        score -= 5.0

    score = _clamp(score)
    risk_level = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
    if tld in DARK_WEB_TLDS and risk_level in {"Low", "Medium"}:
        risk_level = "High"

    attack_type = _determine_attack_type(features, typo_result, homoglyph_result, combo_result, score)
    confidence = _estimate_confidence(
        features, typo_result, homoglyph_result, combo_result,
        whois_result, dns_result, ssl_result, threat_intel_result
    )

    return {
        "score": round(score, 1),
        "risk_level": risk_level,
        "attack_type": attack_type,
        "confidence": confidence,
        "breakdown": breakdown,
        "reasons": sorted(set(reasons)),
    }

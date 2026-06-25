"""
Production phishing domain detection utilities.
Deterministic scoring only: no synthetic data, no random values.

v2.0 — Production Hardening:
  - SSL/TLS: Full certificate chain validation, expiration, hostname mismatch,
    self-signed, revoked, untrusted root, weak protocol/cipher detection
  - Abused Infrastructure: ngrok, duckdns, serveo, no-ip, ddns.net detection
  - Brand Impersonation: Expanded brands, keyboard proximity attacks
  - Punycode/Homograph: Full punycode decode and visual impersonation warnings
  - Redirect Chain: Safe redirect following, chain analysis
  - URL Path Intelligence: Suspicious keyword detection in paths
  - Subdomain Phishing: Brand impersonation via subdomain abuse
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
import ssl as ssl_module
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
    "analyze_dns_records",
    "analyze_ssl_signals",
    "analyze_virustotal",
    "compute_risk_score",
    "detect_abused_infrastructure",
    "detect_subdomain_phishing",
    "detect_url_path_signals",
    "analyze_redirect_chain",
    "detect_punycode_homograph",
    "is_ssl_expired_error",
    "is_ssl_self_signed_error",
    "is_ssl_hostname_mismatch_error",
    "is_ssl_revoked_error",
    "is_ssl_untrusted_root_error",
    "calculate_keyboard_distance",
    "analyze_certificate_transparency",
    "enumerate_subdomains",
    "analyze_dns_records",
]


_PROTO_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_PORT_RE = re.compile(r":(\d+)$")
_HTTP_PROTO_RE = re.compile(r"^https?://", re.IGNORECASE)
_LABEL_RE = re.compile(
    r"^[a-z0-9\u0080-\uffff](?:[a-z0-9\-_ \u0080-\uffff]{0,61}[a-z0-9\u0080-\uffff])?$",
    re.IGNORECASE,
)

# ==============================================================================
# HOMOGLYPH / CONFUSABLE CHARACTER MAP
# ==============================================================================

RAW_HOMOGLYPHS: Dict[str, str] = {
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
}
TRANS_TABLE = {ord(k): v for k, v in RAW_HOMOGLYPHS.items()}
PAIR_SUBS: List[Tuple[str, str]] = [("rn", "m"), ("vv", "w"), ("cl", "d")]

# ==============================================================================
# KEYBOARD PROXIMITY MAP (QWERTY)
# ==============================================================================

# QWERTY keyboard adjacency for detecting keyboard-walking/adjacent-char attacks
_KEYBOARD_ROWS = [
    set("qwertyuiop[]\\"),
    set("asdfghjkl;'"),
    set("zxcvbnm,./"),
]
_KEYBOARD_NEIGHBORS: Dict[str, str] = {
    # Row 1
    "q": "w", "w": "qe", "e": "wr", "r": "et", "t": "ry", "y": "tu",
    "u": "yi", "i": "uo", "o": "ip", "p": "o[", "[": "p]", "]": "[",
    # Row 2
    "a": "s", "s": "ad", "d": "sf", "f": "dg", "g": "fh", "h": "gj",
    "j": "hk", "k": "jl", "l": "k;", ";": "l'", "'": ";",
    # Row 3
    "z": "x", "x": "zc", "c": "xv", "v": "cb", "b": "vn", "n": "bm",
    "m": "n,", ",": "m.", ".": ",/", "/": ".",
}

# ==============================================================================
# ABUSED INFRASTRUCTURE (Legitimate services frequently used for phishing)
# ==============================================================================

# Services that are legitimate but frequently abused for phishing/C2
ABUSED_INFRA_DOMAINS: Dict[str, str] = {
    # Tunnel / Reverse Proxy Services
    "ngrok.io": "ngrok tunnel",
    "ngrok-free.app": "ngrok tunnel",
    "ngrok.app": "ngrok tunnel",
    "tryngrok.com": "ngrok tunnel",
    "serveo.net": "Serveo tunnel",
    "serveo.com": "Serveo tunnel",
    "localtunnel.me": "localtunnel",
    "localhost.run": "localhost.run tunnel",
    "boringserver.com": "BoringSSL tunnel",
    "cloudflarestunnel.com": "Cloudflare Tunnel",
    "cloudflare-tunnel.com": "Cloudflare Tunnel",
    "cf-tunnel.com": "Cloudflare Tunnel",
    "trycloudflare.com": "Cloudflare Tunnel",
    # Dynamic DNS Services
    "duckdns.org": "DuckDNS dynamic DNS",
    "no-ip.org": "No-IP dynamic DNS",
    "noip.com": "No-IP dynamic DNS",
    "ddns.net": "Dynamic DNS",
    "dynu.net": "Dynu dynamic DNS",
    "dyn.com": "Dyn dynamic DNS",
    "dyndns.org": "DynDNS",
    "dnsdynamic.org": "DNS dynamic",
    "free-dns.org": "Free dynamic DNS",
    "changeip.com": "ChangeIP dynamic DNS",
    "myddns.me": "MyDDNS",
    "myftp.org": "MyFTP dynamic DNS",
    "mynetname.net": "Dynamic DNS",
    "myvnc.com": "VNC dynamic DNS",
    "strangled.net": "Dynamic DNS",
    # URL Shorteners (redirect abuse)
    "bit.ly": "URL shortener (redirect abuse)",
    "tinyurl.com": "URL shortener (redirect abuse)",
    "t.co": "URL shortener (redirect abuse)",
    "shorturl.at": "URL shortener (redirect abuse)",
    "ow.ly": "URL shortener (redirect abuse)",
    "buff.ly": "URL shortener (redirect abuse)",
    "is.gd": "URL shortener (redirect abuse)",
    "cli.gs": "URL shortener (redirect abuse)",
    "rb.gy": "URL shortener (redirect abuse)",
    # Free hosting / PaaS abused for phishing
    "netlify.app": "Netlify (free hosting abused for phishing)",
    "vercel.app": "Vercel (free hosting abused for phishing)",
    "github.io": "GitHub Pages (free hosting abused for phishing)",
    "gitlab.io": "GitLab Pages (free hosting abused for phishing)",
    "pages.dev": "Cloudflare Pages (free hosting abused for phishing)",
    "firebaseapp.com": "Firebase Hosting (free hosting abused for phishing)",
    "web.app": "Firebase Hosting (free hosting abused for phishing)",
    "herokuapp.com": "Heroku (free hosting abused for phishing)",
    "render.com": "Render (free hosting abused for phishing)",
    "railway.app": "Railway (free hosting abused for phishing)",
    "fly.dev": "Fly.io (free hosting abused for phishing)",
    "onrender.com": "Render (free hosting abused for phishing)",
    "glitch.me": "Glitch (free hosting abused for phishing)",
    "repl.co": "Replit (free hosting abused for phishing)",
}

# ==============================================================================
# SSL ERROR PATTERNS
# ==============================================================================

# Python ssl error string patterns for classifying certificate issues
SSL_EXPIRED_PATTERNS = [
    r"certificate has expired",
    r"certificate expired",
    r"expired certificate",
    r"certificate is no longer valid",
]
SSL_SELF_SIGNED_PATTERNS = [
    r"self.signed certificate",
    r"certificate verify failed: self.signed",
    r"self.signed certificate in certificate chain",
]
SSL_HOSTNAME_MISMATCH_PATTERNS = [
    r"hostname.*doesn't match",
    r"doesn't match.*hostname",
    r"hostname mismatch",
    r"certificate.*does not match",
    r"no matching certificate found",
    r"wrong.host",
    r"SSL: CERTIFICATE_VERIFY_FAILED.*certificate verify failed.*hostname mismatch",
]
SSL_REVOKED_PATTERNS = [
    r"certificate revoked",
    r"revoked certificate",
    r"certificate is revoked",
]
SSL_UNTRUSTED_ROOT_PATTERNS = [
    r"unable to get local issuer certificate",
    r"certificate verify failed: unable to get local issuer",
    r"self.signed certificate in certificate chain",
    r"untrusted",
    r"untrusted root",
]
SSL_WEAK_PROTOCOL_PATTERNS = [
    r"tlsv1",
    r"tls 1\.[01]",
    r"protocol version not supported",
]


def is_ssl_expired_error(error_str: str) -> bool:
    """Check if an SSL error is due to an expired certificate."""
    err = error_str.lower()
    return any(re.search(p, err, re.IGNORECASE) for p in SSL_EXPIRED_PATTERNS)


def is_ssl_self_signed_error(error_str: str) -> bool:
    """Check if an SSL error is due to a self-signed certificate."""
    err = error_str.lower()
    return any(re.search(p, err, re.IGNORECASE) for p in SSL_SELF_SIGNED_PATTERNS)


def is_ssl_hostname_mismatch_error(error_str: str) -> bool:
    """Check if an SSL error is due to hostname mismatch."""
    err = error_str.lower()
    return any(re.search(p, err, re.IGNORECASE) for p in SSL_HOSTNAME_MISMATCH_PATTERNS)


def is_ssl_revoked_error(error_str: str) -> bool:
    """Check if an SSL error is due to a revoked certificate."""
    err = error_str.lower()
    return any(re.search(p, err, re.IGNORECASE) for p in SSL_REVOKED_PATTERNS)


def is_ssl_untrusted_root_error(error_str: str) -> bool:
    """Check if an SSL error is due to an untrusted root CA."""
    err = error_str.lower()
    return any(re.search(p, err, re.IGNORECASE) for p in SSL_UNTRUSTED_ROOT_PATTERNS)


# ==============================================================================
# SUSPICIOUS URL PATH KEYWORDS
# ==============================================================================

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "authenticate",
    "secure", "security", "account", "update", "password", "reset",
    "recover", "recovery", "billing", "payment", "invoice", "wallet",
    "support", "help", "official", "customer", "unlock", "suspend",
    "alert", "confirm", "confirmation", "kyc", "otp", "authorize",
    "approval", "2fa", "twofactor", "mfa", "challenge",
    "claim", "reward", "prize", "winner", "free", "gift",
    "refund", "transaction", "transfer", "withdraw", "deposit",
    "token", "secret", "private", "key", "phrase", "seed",
    "id-verify", "identity", "ssn", "sin", "national-id",
    "track", "tracking", "shipping", "delivery", "parcel",
    "invoice", "statement", "document", "file", "share",
    "investment", "trading", "bonus", "promo", "voucher",
    "airdrop", "presale", "whitelist", "nft-mint",
]

# ==============================================================================
# DOMAIN CONFIGURATION
# ==============================================================================


@dataclass
class DomainConfig:
    brands: List[str] = field(default_factory=lambda: [
        # Tech Giants
        "google", "gmail", "youtube", "android", "chrome", "pixel", "nexus",
        "microsoft", "office", "office365", "outlook", "azure", "windows", "bing",
        "apple", "icloud", "itunes", "appstore", "macos", "ios", "ipad", "iphone",
        "facebook", "instagram", "whatsapp", "messenger", "meta", "threads",
        "paypal", "venmo", "stripe", "square", "payoneer",
        "amazon", "aws", "primevideo", "kindle", "alexa", "twitch",
        "netflix", "disneyplus", "hulu", "hbo", "maxgo", "peacock", "paramount",
        "github", "gitlab", "bitbucket", "sourceforge",
        "dropbox", "adobe", "canva", "figma", "sketch", "invision",
        # Banking & Finance
        "bankofamerica", "wellsfargo", "citibank", "citi", "chase",
        "capitalone", "hsbc", "barclays", "natwest", "lloyds",
        "americanexpress", "amex", "mastercard", "visa", "discover",
        "sbi", "hdfc", "icici", "axisbank", "kotak", "yesbank", "pnb",
        "rbc", "tdbank", "scotiabank", "bmo",
        "deutschebank", "societegenerale", "bnpparibas", "ing",
        "paytm", "phonepe", "googlepay", "gpay", "applepay", "samungpay",
        # Crypto / Web3
        "coinbase", "binance", "kraken", "gemini", "crypto", "blockchain",
        "metamask", "trustwallet", "ledger", "trezor", "exodus",
        "uniswap", "pancakeswap", "opensea", "rarible", "etherscan",
        "solana", "ethereum", "bitcoin", "ripple", "cardano", "polkadot",
        "coinmarketcap", "coingecko", "defi", "nft",
        # E-commerce
        "ebay", "etsy", "shopify", "walmart", "target", "bestbuy",
        "homedepot", "lowes", "costco", "kroger", "walgreens", "cvs",
        "alibaba", "aliexpress", "taobao", "jd", "rakuten", "mercado",
        # Social Media
        "twitter", "x", "linkedin", "reddit", "pinterest", "snapchat",
        "tiktok", "telegram", "signal", "discord", "slack", "teams",
        "tumblr", "flickr", "imgur", "quora", "medium",
        "onlyfans", "patreon", "kickstarter", "indiegogo",
        # Cloud & DevOps
        "cloudflare", "okta", "cisco", "paloalto", "crowdstrike",
        "datadog", "newrelic", "splunk", "elastic", "mongodb",
        "digitalocean", "linode", "vultr", "hetzner", "ovh",
        "heroku", "vercel", "netlify", "render", "flyio",
        "docker", "kubernetes", "jenkins", "travis", "circleci",
        # Entertainment
        "spotify", "soundcloud", "deezer", "tidal", "pandora",
        "crunchyroll", "funimation", "roku", "plex",
        "steam", "epicgames", "xbox", "playstation", "nintendo",
        "blizzard", "activision", "ea", "ubisoft", "rockstar",
        "roblox", "minecraft", "fortnite", "valorant",
        # Government & Education
        "irs", "ssa", "uscis", "dhs", "fbi", "cia", "nsa",
        "harvard", "stanford", "mit", "oxford", "cambridge", "yale",
        "princeton", "columbia", "berkeley", "ucla",
        # Logistics
        "fedex", "dhl", "ups", "usps", "canadapost", "royalmail",
        "australiapost", "dhl", "tnt", "dpd", "hermes",
        # Automotive
        "tesla", "toyota", "honda", "ford", "bmw", "mercedes",
        "audi", "volkswagen", "nissan", "hyundai", "kia", "ferrari",
        "lamborghini", "porsche", "jeep", "subaru", "mazda",
        # Telecom & ISP
        "verizon", "att", "tmobile", "sprint", "comcast", "xfinity",
        "spectrum", "charter", "cox", "centurylink", "frontier",
        "vodafone", "orange", "telefonica", "bt", "sky",
        # News & Media
        "nytimes", "wsj", "cnn", "bbc", "theguardian", "reuters",
        "bloomberg", "forbes", "washingtonpost", "usatoday",
        "economist", "time", "npr", "apnews",
        # Food & Beverage
        "starbucks", "mcdonalds", "subway", "kfc", "burgerking",
        "cocacola", "pepsi", "nestle", "kraft", "heinz",
        "dominos", "pizzahut", "papajohns", "dunkin",
        # Travel
        "booking", "expedia", "airbnb", "hotels", "trivago",
        "kayak", "skyscanner", "uber", "lyft", "grubhub",
        "doordash", "ubereats", "postmates",
        # Health
        "webmd", "mayoclinic", "clevelandclinic", "johnshopkins",
        "cvs", "walgreens", "riteaid", "goodrx",
        # Insurance
        "geico", "progressive", "allstate", "statefarm", "libertymutual",
        "aetna", "cigna", "bluecross", "humana", "unitedhealthcare",
    ])
    keywords: List[str] = field(default_factory=lambda: [
        "login", "signin", "sign-in", "verify", "verification", "secure", "security",
        "account", "update", "password", "reset", "recover", "recovery",
        "billing", "payment", "invoice", "wallet", "pay",
        "support", "help", "official", "customer", "unlock", "suspend", "alert",
        "confirm", "confirmation", "kyc", "otp", "authorize", "approval",
        "2fa", "twofactor", "mfa", "challenge", "token",
        "claim", "reward", "prize", "winner", "free", "gift", "bonus",
        "refund", "transaction", "transfer", "withdraw", "deposit",
        "track", "tracking", "shipping", "delivery", "parcel",
        "id-verify", "identity", "ssn", "sin",
        "airdrop", "presale", "whitelist", "nft", "mint",
        "investment", "trading", "promo", "voucher",
    ])
    suspicious_tlds: frozenset = field(default_factory=lambda: frozenset({
        "xyz", "top", "club", "online", "site", "web", "info", "biz",
        "tk", "ml", "ga", "cf", "gq", "pw", "ws", "icu", "click",
        "cam", "mom", "work", "vip", "support", "email", "live", "loan",
    }))
    high_trust_tlds: frozenset = field(default_factory=lambda: frozenset({
        "com", "org", "net", "edu", "gov", "mil"
    }))


CONFIG = DomainConfig()

DARK_WEB_TLDS = frozenset({"onion", "i2p", "bit", "b32", "loki"})
HIGH_RISK_TLDS = frozenset({"xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "ws"})


def _safe_lower(value: object) -> str:
    return str(value).strip().lower()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


# ==============================================================================
# DOMAIN SANITIZATION & VALIDATION
# ==============================================================================


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


# ==============================================================================
# WEBSITE INSPECTION & REDIRECT HANDLING
# ==============================================================================


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


def inspect_website(url: str, timeout: float = 4.0, max_bytes: int = 512_000) -> Dict[str, Any]:
    """Fetches a website (no JS execution) and extracts lightweight HTML signals."""
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


# ==============================================================================
# EXTERNAL API HELPERS
# ==============================================================================


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
    """URLhaus (abuse.ch) — no API key required."""
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
    """urlscan.io search (API key optional)."""
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
    """Google Safe Browsing v4 (requires API key)."""
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
    """PhishTank (requires key) — placeholder integration."""
    if not api_key:
        return {"provider": "PhishTank", "available": False, "flagged": False, "source": "disabled", "note": "PHISHTANK_API_KEY not set"}
    ok, err = validate_url(url)
    if not ok:
        return {"provider": "PhishTank", "available": False, "flagged": False, "source": "validation_error", "error": err}
    u = sanitize_url(url)
    try:
        j = _form_post(
            "https://checkurl.phishtank.com/checkurl/",
            {"url": u, "format": "json", "app_key": api_key},
            headers={"User-Agent": "TMGC-Inspector/1.0"},
            timeout=8.0,
        )
        in_db = bool(j.get("results", {}).get("in_database")) if isinstance(j, dict) else False
        verified = bool(j.get("results", {}).get("verified")) if isinstance(j, dict) else False
        valid = bool(j.get("results", {}).get("valid")) if isinstance(j, dict) else False
        flagged = bool(in_db and (verified or valid))
        return {"provider": "PhishTank", "available": True, "flagged": flagged, "source": "live", "in_database": in_db, "verified": verified, "valid": valid}
    except Exception as exc:
        return {"provider": "PhishTank", "available": False, "flagged": False, "source": "error", "error": str(exc)}


# ==============================================================================
# HOMOGLYPH NORMALIZATION & STRING SIMILARITY
# ==============================================================================


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


def calculate_keyboard_distance(char1: str, char2: str) -> int:
    """
    Calculate the QWERTY keyboard distance between two characters.
    Returns 0 if same key, 1 if adjacent, 2+ otherwise.
    Used for detecting keyboard-walking/phishing patterns.
    """
    c1, c2 = char1.lower(), char2.lower()
    if c1 == c2:
        return 0
    # Check if c2 is a neighbor of c1
    neighbors = _KEYBOARD_NEIGHBORS.get(c1, "")
    if c2 in neighbors:
        return 1
    # Check if they share a row (for 2-step distance)
    for row in _KEYBOARD_ROWS:
        if c1 in row and c2 in row:
            return 2
    return 3


# ==============================================================================
# TYPOSQUATTING DETECTION
# ==============================================================================


def detect_typosquatting(domain_name: str) -> Dict[str, Any]:
    """Enhanced typosquatting detection with keyboard proximity analysis."""
    label = _skeletonize(domain_name)
    best: Optional[Dict[str, Any]] = None
    keyboard_attack_detected = False
    keyboard_attack_brand = None

    for brand in CONFIG.brands:
        b = _skeletonize(brand)
        if not b:
            continue
        dist = levenshtein_distance(label, b)
        jw = jaro_winkler_similarity(label, b)
        lev_score = 1 - dist / max(len(label), len(b), 1)
        combined = 0.65 * jw + 0.35 * lev_score

        # Keyboard proximity check: see if the label has many adjacent-key substitutions
        # relative to the brand. If label[i] != brand[i] and label[i] is keyboard-adjacent
        # to brand[i], that's a keyboard proximity attack.
        if dist <= 3 and dist > 0:
            keyboard_subs = 0
            for i in range(min(len(label), len(b))):
                if i < len(label) and i < len(b) and label[i] != b[i]:
                    if calculate_keyboard_distance(label[i], b[i]) <= 2:
                        keyboard_subs += 1
            if keyboard_subs >= dist:  # All substitutions are keyboard-adjacent
                keyboard_attack_detected = True
                keyboard_attack_brand = brand

        row = {
            "brand": brand,
            "edit_distance": dist,
            "jaro_winkler_score": round(jw, 4),
            "levenshtein_score": round(lev_score, 4),
            "combined_score": round(combined, 4),
            "keyboard_proximity_attack": keyboard_attack_detected and brand == keyboard_attack_brand,
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
            "keyboard_proximity_attack": False,
        }

    exact_brand = best["edit_distance"] == 0 and label == _skeletonize(str(best["brand"]))
    original_label = _safe_lower(domain_name)
    normalized_label = _skeletonize(domain_name)
    is_normalization_substitution = (
        exact_brand
        and original_label != normalized_label
        and normalized_label == _skeletonize(str(best["brand"]))
    )

    detected = (
        is_normalization_substitution
        or best["keyboard_proximity_attack"]
        or (
            not exact_brand
            and (
                (best["combined_score"] >= 0.84 and best["edit_distance"] <= 3)
                or (best["jaro_winkler_score"] >= 0.90 and best["edit_distance"] <= 2)
            )
        )
    )

    if best["keyboard_proximity_attack"]:
        reason = f"Keyboard proximity attack — adjacent keys pressed instead of '{best['brand']}'"
    elif is_normalization_substitution:
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
        "keyboard_proximity_attack": best["keyboard_proximity_attack"],
    }


# ==============================================================================
# HOMOGLYPH & PUNYCODE DETECTION
# ==============================================================================


def detect_homoglyphs(label: str) -> Dict[str, Any]:
    """Enhanced homoglyph detection with Unicode character analysis."""
    suspicious: List[Dict[str, Any]] = []
    digit_subs: List[str] = []
    non_ascii_count = 0
    for i, ch in enumerate(label):
        non_ascii = ord(ch) > 127
        ascii_confusable = ch in RAW_HOMOGLYPHS
        if non_ascii or ascii_confusable:
            suspicious.append({
                "index": i,
                "char": ch,
                "ascii_equiv": RAW_HOMOGLYPHS.get(ch, ch),
                "codepoint": hex(ord(ch)),
                "is_non_ascii": non_ascii,
            })
            if non_ascii:
                non_ascii_count += 1
        if ch.isdigit() and ch in RAW_HOMOGLYPHS:
            digit_subs.append(ch)

    return {
        "detected": bool(suspicious),
        "count": len(suspicious),
        "non_ascii_count": non_ascii_count,
        "suspicious_chars": suspicious,
        "normalized_domain": _normalize_homoglyphs(label),
        "ascii_only": all(ord(c) < 128 for c in label),
        "has_digit_substitution": bool(digit_subs),
        "digit_substitutions": digit_subs,
    }


def detect_punycode_homograph(domain: str) -> Dict[str, Any]:
    """
    Detect punycode/IDN homograph attacks.

    Decodes xn-- prefixed labels and checks if the decoded Unicode
    visually resembles ASCII brands/domains.

    Returns:
        has_punycode: True if domain contains punycode
        decoded: Decoded Unicode form
        ascii_form: Original ASCII form
        visual_impersonation: Whether it visually impersonates a known brand
        impersonated_brand: The brand being impersonated (if any)
        warning: Human-readable warning
    """
    s = sanitize_domain(domain)
    result: Dict[str, Any] = {
        "has_punycode": False,
        "decoded": None,
        "ascii_form": s,
        "visual_impersonation": False,
        "impersonated_brand": None,
        "warning": None,
    }

    if "xn--" not in s:
        return result

    result["has_punycode"] = True

    # Try to decode each label
    decoded_parts = []
    for part in s.split("."):
        if part.startswith("xn--"):
            try:
                decoded = part.encode("ascii").decode("idna")
                decoded_parts.append(decoded)
            except Exception:
                decoded_parts.append(part)
        else:
            decoded_parts.append(part)

    decoded = ".".join(decoded_parts)
    result["decoded"] = decoded

    # Check if the decoded domain visually impersonates a brand
    decoded_label = decoded.split(".")[0].lower() if "." in decoded else decoded.lower()
    skeleton = _skeletonize(decoded_label)

    for brand in CONFIG.brands:
        b_skel = _skeletonize(brand)
        if skeleton == b_skel and decoded_label != brand:
            result["visual_impersonation"] = True
            result["impersonated_brand"] = brand
            result["warning"] = (
                f"Punycode/IDN domain '{decoded}' visually impersonates '{brand}' "
                f"(ASCII form: {s}). This is a known homograph attack technique."
            )
            break

    if not result["visual_impersonation"]:
        result["warning"] = (
            f"Domain contains punycode/IDN encoding (decoded: '{decoded}'). "
            "IDN domains can be used for visual impersonation attacks."
        )

    return result


# ==============================================================================
# COMBO-SQUATTING DETECTION
# ==============================================================================


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


# ==============================================================================
# SUBDOMAIN PHISHING DETECTION
# ==============================================================================


def detect_subdomain_phishing(domain: str) -> Dict[str, Any]:
    """
    Detect brand impersonation via subdomain abuse.

    Example: paypal.login.verify.evil.com
    The real registered domain is evil.com, but the subdomains
    contain brand names to deceive users.

    Returns:
        detected: True if brand impersonation via subdmains detected
        registered_domain: The actual registered domain (e.g., evil.com)
        brands_in_subdomains: List of brands found in subdomains
        warning: Human-readable explanation
    """
    s = sanitize_domain(domain)
    parts = s.split(".")
    result: Dict[str, Any] = {
        "detected": False,
        "registered_domain": None,
        "brands_in_subdomains": [],
        "warning": None,
    }

    if len(parts) < 3:
        return result

    # Extract the registered domain (last 2 parts for standard TLDs)
    tld = parts[-1]
    registered_name = parts[-2]
    registered_domain = f"{registered_name}.{tld}"

    # Check if the registered domain is itself a suspicious/hosting domain
    # (e.g., evil.com, freehosting.com)
    is_abused_infra = False
    for infra_domain, label in ABUSED_INFRA_DOMAINS.items():
        if registered_domain.endswith(infra_domain) or infra_domain.endswith(registered_domain):
            is_abused_infra = True
            break

    # Check subdomains for brand names
    subdomain_parts = parts[:-2]  # Everything before the registered domain

    brands_found: List[str] = []
    for brand in CONFIG.brands:
        b = brand.lower()
        # Check if brand appears as a whole subdomain label
        for sub_part in subdomain_parts:
            sub_clean = sub_part.lower().lstrip("www")
            if sub_clean == b:
                brands_found.append(brand)
                break
            # Homoglyph-normalized check
            if _skeletonize(sub_clean) == _skeletonize(b):
                if brand not in brands_found:
                    brands_found.append(brand)
                break

    if brands_found:
        result["detected"] = True
        result["registered_domain"] = registered_domain
        result["brands_in_subdomains"] = brands_found
        if is_abused_infra:
            result["warning"] = (
                f"Brand impersonation via subdomain abuse: domain contains "
                f"{', '.join(brands_found)} in subdomains but the actual "
                f"registered domain '{registered_domain}' is a known "
                f"free/abused hosting service."
            )
        else:
            result["warning"] = (
                f"Brand impersonation via subdomain abuse: domain contains "
                f"{', '.join(brands_found)} in subdomains but the actual "
                f"registered domain is '{registered_domain}'. "
                f"The brand subdomain is used to deceive users."
            )

    return result


# ==============================================================================
# ABUSED INFRASTRUCTURE DETECTION
# ==============================================================================


def detect_abused_infrastructure(domain: str) -> Dict[str, Any]:
    """
    Detect if a domain is using legitimate but frequently abused infrastructure.

    Categories:
      - Tunnel services (ngrok, serveo, cloudflare tunnels)
      - Dynamic DNS (duckdns, no-ip, ddns.net)
      - URL shorteners (bit.ly, tinyurl)
      - Free hosting (netlify, vercel, github.io)

    Returns:
        detected: True if domain matches abused infrastructure pattern
        service_type: Human-readable service type
        service_name: Specific service name
        category: Category of abuse (tunnel, dyn_dns, url_shortener, free_hosting)
        warning: Human-readable warning
        risk_contribution: Suggested risk score contribution
    """
    s = sanitize_domain(domain)

    for infra_domain, label in ABUSED_INFRA_DOMAINS.items():
        # Determine category from label text
        category = "tunnel" if "tunnel" in label else \
                   "dyn_dns" if "dynamic dns" in label.lower() or "ddns" in label.lower() else \
                   "url_shortener" if "shortener" in label.lower() else \
                   "free_hosting"

        # FREE HOSTING: only flag subdomains (e.g., "eviluser.github.io"),
        # never the root provider domain itself (e.g., "github.io").
        # Root domains like github.io, pages.dev, netlify.app belong to
        # legitimate companies and should not be penalized just because
        # their free hosting platform is abused by phishers.
        if category == "free_hosting":
            if s.endswith("." + infra_domain):
                risk = 15
                return {
                    "detected": True,
                    "service_type": label,
                    "service_name": infra_domain,
                    "category": category,
                    "risk_contribution": risk,
                    "warning": (
                        f"Domain uses {label} ({infra_domain}). "
                        f"This service is legitimate but frequently abused for "
                        f"phishing, C2 infrastructure, and malicious redirects. "
                        f"Additional verification is required before trusting."
                    ),
                }
        else:
            # Other categories (tunnels, dynamic DNS, URL shorteners):
            # flag both subdomains AND exact root domain match.
            if s == infra_domain or s.endswith("." + infra_domain):
                risk = 20 if category == "tunnel" else \
                       15 if category == "dyn_dns" else \
                       10 if category == "url_shortener" else \
                       15  # fallback

                return {
                    "detected": True,
                    "service_type": label,
                    "service_name": infra_domain,
                    "category": category,
                    "risk_contribution": risk,
                    "warning": (
                        f"Domain uses {label} ({infra_domain}). "
                        f"This service is legitimate but frequently abused for "
                        f"phishing, C2 infrastructure, and malicious redirects. "
                        f"Additional verification is required before trusting."
                    ),
                }

    return {
        "detected": False,
        "service_type": None,
        "service_name": None,
        "category": None,
        "risk_contribution": 0,
        "warning": None,
    }


# ==============================================================================
# URL PATH INTELLIGENCE
# ==============================================================================


def detect_url_path_signals(url: str) -> Dict[str, Any]:
    """
    Analyze URL paths for suspicious keywords and patterns.

    Detects:
      - Login/verify/secure paths on suspicious domains
      - Credential harvesting indicators
      - File-sharing/phishing path patterns
      - Suspicious file extensions

    Returns:
        has_suspicious_path: True if suspicious patterns found
        matched_keywords: List of matched keywords
        path_depth: Number of path segments
        path_risk_score: 0-100 risk contribution from path alone
        warning: Human-readable explanation
    """
    parsed = urllib_parse.urlsplit(url)
    path = parsed.path.lower() if parsed.path else "/"

    if path == "/" or not path:
        return {
            "has_suspicious_path": False,
            "matched_keywords": [],
            "path_depth": 0,
            "path_risk_score": 0,
            "warning": None,
        }

    # Split path into segments
    segments = [s for s in path.split("/") if s]
    path_depth = len(segments)

    # Check for suspicious keywords in path
    matched_keywords: List[str] = []
    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path:
            matched_keywords.append(keyword)

    # Check for suspicious file extensions
    suspicious_extensions = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                             ".jar", ".php", ".asp", ".aspx", ".cgi"}
    has_suspicious_ext = False
    for ext in suspicious_extensions:
        if path.endswith(ext):
            has_suspicious_ext = True
            break

    # Check for IPFS / gateway patterns
    has_ipfs = "/ipfs/" in path or "/ipns/" in path

    # Calculate risk score
    risk = 0
    reasons: List[str] = []

    if matched_keywords:
        risk += min(len(matched_keywords) * 8, 30)
        reasons.append(f"Path contains suspicious keywords: {', '.join(matched_keywords[:5])}")

    if has_suspicious_ext:
        risk += 15
        reasons.append("Path ends with a suspicious executable/script file extension")

    if path_depth >= 5:
        risk += 8
        reasons.append(f"Excessive path depth ({path_depth} segments)")

    if has_ipfs:
        risk += 12
        reasons.append("Path references IPFS/IPNS gateway — used to host immutable phishing content")

    detected = risk > 0

    return {
        "has_suspicious_path": detected,
        "matched_keywords": matched_keywords,
        "path_depth": path_depth,
        "path_risk_score": min(risk, 100),
        "has_suspicious_extension": has_suspicious_ext,
        "has_ipfs_reference": has_ipfs,
        "warning": "; ".join(reasons) if reasons else None,
    }


# ==============================================================================
# REDIRECT CHAIN ANALYSIS
# ==============================================================================


def analyze_redirect_chain(url: str, max_redirects: int = 5, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Safely follow redirects and analyze the redirect chain.

    Detects:
      - Suspicious hop count (excessive redirects)
      - Redirect through URL shorteners
      - Redirect to suspicious final destinations
      - Mismatch between initial and final domains

    Returns:
        chain: List of redirect hops [{from, to, code}]
        hop_count: Number of redirects
        initial_domain: Domain of the original URL
        final_domain: Domain of the final URL
        domain_mismatch: True if initial and final domains differ
        suspicious: True if redirect chain is suspicious
        warning: Human-readable explanation
    """
    ok, err = validate_url(url)
    if not ok:
        return {"available": False, "error": err}

    start_url = sanitize_url(url)
    initial_domain = urllib_parse.urlsplit(start_url).hostname or ""

    redir = _LimitedRedirectHandler(max_redirects=max_redirects)
    opener = urllib_request.build_opener(redir)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
    }
    req = urllib_request.Request(start_url, headers=headers, method="HEAD")

    final_url = start_url
    final_domain = initial_domain
    try:
        with opener.open(req, timeout=timeout) as resp:
            final_url = resp.geturl()
            final_domain = urllib_parse.urlsplit(final_url).hostname or initial_domain
    except urllib_error.HTTPError as exc:
        final_url = exc.geturl() or start_url
        final_domain = urllib_parse.urlsplit(final_url).hostname or initial_domain
    except Exception:
        pass

    chain = redir.chain
    hop_count = len(chain)
    domain_mismatch = initial_domain.lower() != final_domain.lower()

    # Check for shorteners in chain
    has_shortener = False
    for hop in chain:
        hop_domain = urllib_parse.urlsplit(hop.get("to", "")).hostname or ""
        for infra, label in ABUSED_INFRA_DOMAINS.items():
            if hop_domain == infra or hop_domain.endswith("." + infra):
                if "shortener" in label.lower():
                    has_shortener = True
                    break

    # Check if final destination is abused infrastructure
    final_infra = None
    for infra, label in ABUSED_INFRA_DOMAINS.items():
        if final_domain == infra or final_domain.endswith("." + infra):
            final_infra = label
            break

    # Determine suspiciousness
    reasons: List[str] = []
    suspicious = False

    if hop_count >= 3:
        suspicious = True
        reasons.append(f"Excessive redirect chain ({hop_count} hops) — often used to evade URL scanners")

    if has_shortener:
        suspicious = True
        reasons.append("Redirect chain passes through URL shortener — can obscure the final destination")

    if domain_mismatch:
        reasons.append(f"Redirects from '{initial_domain}' to '{final_domain}' — possible phishing redirect")

    if final_infra:
        suspicious = True
        reasons.append(f"Final destination uses {final_infra} — frequently abused for phishing")

    return {
        "available": True,
        "chain": chain,
        "hop_count": hop_count,
        "initial_domain": initial_domain,
        "final_domain": final_domain,
        "domain_mismatch": domain_mismatch,
        "has_shortener": has_shortener,
        "final_infrastructure_abuse": final_infra is not None,
        "final_infrastructure_label": final_infra,
        "suspicious": suspicious,
        "warning": " | ".join(reasons) if reasons else None,
    }


# ==============================================================================
# FEATURE EXTRACTION
# ==============================================================================


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


# ==============================================================================
# DNS ANALYSIS
# ==============================================================================


def _safe_dns_resolve(domain: str, rtype: str) -> List[str]:
    if _dns_resolver is None:
        return []
    try:
        return [str(r).strip() for r in _dns_resolver.resolve(domain, rtype, lifetime=2)]
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


# ==============================================================================
# SSL/TLS ANALYSIS (HARDENED v2)
# ==============================================================================


def analyze_ssl_signals(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Enhanced SSL/TLS analysis with full certificate validation and error classification.

    Detects:
      - Expired certificates
      - Self-signed certificates
      - Hostname mismatches
      - Revoked certificates
      - Untrusted root CAs
      - Weak TLS versions/protocols
      - Weak cipher suites

    Uses ssl.create_default_context() for proper validation, then falls back
    to ssl._create_unverified_context() to inspect the raw certificate details
    even when validation fails, classifying the specific error type.
    """
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    if tld in DARK_WEB_TLDS:
        return {
            "has_ssl": False,
            "issuer": None,
            "issuer_org": None,
            "subject": None,
            "subject_cn": None,
            "not_before": None,
            "not_after": None,
            "days_to_expiry": None,
            "days_to_issue": None,
            "self_signed": False,
            "expired": False,
            "hostname_mismatch": False,
            "revoked": False,
            "untrusted_root": False,
            "weak_protocol": False,
            "weak_cipher": False,
            "ssl_error": None,
            "ssl_error_type": None,
            "source": "not_applicable_dark_web",
            "note": "Public TLS checks are not applicable for dark-web domains",
        }

    result = {
        "has_ssl": False,
        "issuer": None,
        "issuer_org": None,
        "subject": None,
        "subject_cn": None,
        "not_before": None,
        "not_after": None,
        "days_to_expiry": None,
        "days_to_issue": None,
        "self_signed": False,
        "expired": False,
        "hostname_mismatch": False,
        "revoked": False,
        "untrusted_root": False,
        "weak_protocol": False,
        "weak_cipher": False,
        "ssl_error": None,
        "ssl_error_type": None,
        "source": "live",
    }

    # First attempt: validated context (will throw if cert is invalid)
    # We catch the error to classify it, then try unvalidated for details
    try:
        ctx = ssl_module.create_default_context()
        with socket.create_connection((s, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=s) as ssock:
                cert = ssock.getpeercert()
                _populate_cert_info(cert, result)
                result["has_ssl"] = True
                return result
    except ssl_module.SSLCertVerificationError as exc:

        result["ssl_error"] = str(exc)
        # Classify the error
        if is_ssl_expired_error(str(exc)):
            result["ssl_error_type"] = "expired"
            result["expired"] = True
        elif is_ssl_self_signed_error(str(exc)):
            result["ssl_error_type"] = "self_signed"
            result["self_signed"] = True
        elif is_ssl_hostname_mismatch_error(str(exc)):
            result["ssl_error_type"] = "hostname_mismatch"
            result["hostname_mismatch"] = True
        elif is_ssl_revoked_error(str(exc)):
            result["ssl_error_type"] = "revoked"
            result["revoked"] = True
        elif is_ssl_untrusted_root_error(str(exc)):
            result["ssl_error_type"] = "untrusted_root"
            result["untrusted_root"] = True
        else:
            result["ssl_error_type"] = "unknown"
    except OSError as exc:
        result["ssl_error"] = str(exc)
        result["ssl_error_type"] = "connection_error"
        return result
    except Exception as exc:
        result["ssl_error"] = str(exc)
        result["ssl_error_type"] = "unknown"
        return result

    # Second attempt: unvalidated context to get raw cert details
    # Use _create_unverified_context() instead of PROTOCOL_TLS_CLIENT + CERT_NONE
    # because _create_unverified_context() is more compatible across Python versions
    # and handles edge cases like SSLv23 method negotiation better.
    try:
        ctx = ssl_module._create_unverified_context()
        ctx.check_hostname = False
        with socket.create_connection((s, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=s) as ssock:
                # Check protocol version
                version = ssock.version() or ""
                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    result["weak_protocol"] = True
                # Check cipher
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0] or ""
                    weak_ciphers = ("RC4", "DES", "3DES", "MD5", "EXP", "NULL", "aNULL", "eNULL")
                    if any(wc.lower() in cipher_name.lower() for wc in weak_ciphers):
                        result["weak_cipher"] = True
                # Get cert for details even when validation fails
                cert = ssock.getpeercert()
                if cert:
                    _populate_cert_info(cert, result)
                    result["has_ssl"] = True
    except Exception:
        pass

    # IMPORTANT: If we have a classified SSL error (expired, self-signed, hostname_mismatch,
    # revoked, untrusted_root), that means the TLS handshake succeeded but certificate
    # verification failed. The server does HAVE a certificate — it's just not trustworthy.
    # Set has_ssl=True so downstream scoring knows a certificate exists.
    if result.get("ssl_error_type") and result["ssl_error_type"] not in ("connection_error", "unknown", None):
        result["has_ssl"] = True

    return result


def _populate_cert_info(cert: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Extract certificate information into the result dict."""
    # Issuer
    issuer = cert.get("issuer", ())
    if issuer:
        result["issuer"] = issuer
        issuer_cn = None
        issuer_org = None
        for attr in issuer:
            for key, value in attr:
                if key == "organizationName":
                    issuer_org = value
                if key == "commonName":
                    issuer_cn = value
        result["issuer_org"] = issuer_org or issuer_cn

    # Subject
    subject = cert.get("subject", ())
    if subject:
        result["subject"] = subject
        subject_cn = None
        for attr in subject:
            for key, value in attr:
                if key == "commonName":
                    subject_cn = value
        result["subject_cn"] = subject_cn

    # Check self-signed: issuer == subject
    result["self_signed"] = str(issuer).lower() == str(subject).lower() and str(issuer) != "()"

    # Dates
    result["not_before"] = cert.get("notBefore")
    result["not_after"] = cert.get("notAfter")

    if cert.get("notAfter"):
        try:
            # Handle both single-digit days ("Dec  5 00:00:00 2023 GMT") and
            # double-digit days ("Dec 25 00:00:00 2023 GMT") by normalizing
            # the space-separated date first
            date_str = cert["notAfter"].strip()
            # Split on whitespace and rejoin with single space
            parts = date_str.split()
            if len(parts) >= 4:
                # Normalize: month, day, time, year, timezone
                month = parts[0]
                day = parts[1].zfill(2)  # zero-pad single-digit days
                time_part = parts[2]
                year = parts[3]
                tz = parts[4] if len(parts) > 4 else "GMT"
                normalized = f"{month} {day} {time_part} {year} {tz}"
                exp = datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - _utcnow()).days
                result["days_to_expiry"] = days
                if days < 0:
                    result["expired"] = True
                    result["ssl_error_type"] = "expired"
        except (ValueError, KeyError, IndexError):
            pass

    if cert.get("notBefore"):
        try:
            date_str = cert["notBefore"].strip()
            parts = date_str.split()
            if len(parts) >= 4:
                month = parts[0]
                day = parts[1].zfill(2)
                time_part = parts[2]
                year = parts[3]
                tz = parts[4] if len(parts) > 4 else "GMT"
                normalized = f"{month} {day} {time_part} {year} {tz}"
                issue = datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result["days_to_issue"] = (_utcnow() - issue).days
        except (ValueError, KeyError, IndexError):
            pass


# ==============================================================================
# CERTIFICATE TRANSPARENCY LOG ANALYSIS (crt.sh)
# ==============================================================================


def analyze_certificate_transparency(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Query Certificate Transparency logs via crt.sh for domain certificate intelligence.

    Discovers:
      - Total number of issued certificates for the domain and its subdomains
      - Recently issued certificates (last 90 days) — potential phishing infrastructure
      - Certificate issuers (CAs) used
      - Subdomains exposed via CT logs (SAN/commonName entries)
      - Suspicious patterns: wildcard certs, self-signed certs in CT, rapid issuance

    API: https://crt.sh/?q=%.domain&output=json
    Rate limit: ~60 req/min/IP (enforced by Nginx)

    Returns:
        available: Whether the query succeeded
        total_certs: Total number of certificates found
        recent_certs_90d: Certificates issued in the last 90 days
        unique_issuers: Distinct certificate authorities that issued certs
        issuers: List of issuer names
        subdomains_discovered: Unique subdomains extracted from cert SAN/CN
        has_wildcard_cert: True if wildcard certs (*.domain) are present
        suspicious_recent_issuance: True if many recent certs issued
        recent_issuance_risk: Risk contribution 0-100
        suspicious_issuers: List of known-abused CAs detected
        warning: Human-readable warning if suspicious
        error: Error message if query failed
    """
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    
    if tld in DARK_WEB_TLDS:
        return {
            "available": False,
            "source": "not_applicable_dark_web",
            "note": "Certificate Transparency is not applicable for dark-web domains.",
        }
    
    result: Dict[str, Any] = {
        "available": False,
        "source": "live",
        "total_certs": 0,
        "recent_certs_90d": 0,
        "unique_issuers": 0,
        "issuers": [],
        "subdomains_discovered": [],
        "has_wildcard_cert": False,
        "suspicious_recent_issuance": False,
        "recent_issuance_risk": 0,
        "suspicious_issuers": [],
        "warning": None,
        "error": None,
    }
    
    # Known CAs that are frequently abused for phishing certificates
    ABUSED_CAS = frozenset({
        "let's encrypt", "letsencrypt", "lets encrypt",
        "zero ssl", "zerossl",
        "buypass", "buypass as",
        "sectigo", "comodo",
        "globalsign",
        "digicert",
    })
    
    # Query crt.sh for the domain and its subdomains
    query = f"%.{s}"
    url = f"https://crt.sh/?q={urllib_parse.quote(query)}&output=json"
    
    try:
        req = urllib_request.Request(
            url,
            headers={
                "User-Agent": "TMGC-CT-Inspector/1.0 (+security-analysis)",
                "Accept": "application/json",
            }
        )
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw_data = resp.read().decode("utf-8")
            entries = json.loads(raw_data)
        
        if not isinstance(entries, list):
            result["error"] = "Unexpected response format from crt.sh"
            return result
        
        # Process entries
        seen_certs: set[str] = set()
        seen_issuers: set[str] = set()
        seen_subdomains: set[str] = set()
        recent_count = 0
        wildcard_certs = False
        suspicious_issuers_found: list[str] = []
        
        now = datetime.now(timezone.utc)
        
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            
            cert_id = entry.get("id")
            if cert_id:
                if str(cert_id) in seen_certs:
                    continue
                seen_certs.add(str(cert_id))
            
            # Extract issuer
            issuer_name = entry.get("issuer_name", "") or ""
            if issuer_name:
                # Parse CN from issuer string
                cn_match = re.search(r"CN\s*=\s*([^,]+)", issuer_name)
                if cn_match:
                    issuer_cn = cn_match.group(1).strip()
                    seen_issuers.add(issuer_cn)
                    # Check if this CA is frequently abused
                    if any(abused.lower() in issuer_cn.lower() for abused in ABUSED_CAS):
                        if issuer_cn not in suspicious_issuers_found:
                            suspicious_issuers_found.append(issuer_cn)
            
            # Check entry timestamp for recency
            entry_ts = entry.get("entry_timestamp", "")
            if entry_ts:
                try:
                    ts = datetime.fromisoformat(entry_ts.replace("Z", "+00:00"))
                    days_ago = (now - ts).days
                    if days_ago <= 90:
                        recent_count += 1
                except (ValueError, TypeError):
                    pass
            
            # Extract subdomains from name_value (SAN/commonName)
            name_value = entry.get("name_value", "") or ""
            names = [n.strip().lower() for n in name_value.split("\n") if n.strip()]
            for name in names:
                # Skip wildcard entries for subdomain enumeration (but track them)
                if name.startswith("*."):
                    wildcard_certs = True
                    actual_name = name[2:]  # Remove *. prefix
                else:
                    actual_name = name
                
                # Only include names that belong to this domain tree
                if actual_name.endswith("." + s) or actual_name == s:
                    seen_subdomains.add(actual_name)
        
        # Filter out the main domain itself from subdomains
        subdomains = sorted([sd for sd in seen_subdomains if sd != s])
        
        # Determine suspiciousness
        recent_issuance_risk = 0
        suspicious_recent = False
        
        if len(seen_certs) > 50:
            # High cert count could indicate fast-flux or many subdomains
            pass  # Not inherently suspicious but noted
        
        if recent_count > 20:
            suspicious_recent = True
            recent_issuance_risk = 30
        elif recent_count > 10:
            suspicious_recent = True
            recent_issuance_risk = 20
        elif recent_count > 5:
            suspicious_recent = True
            recent_issuance_risk = 10
        
        # If recent issuance AND suspicious CA
        if suspicious_recent and suspicious_issuers_found:
            recent_issuance_risk = min(recent_issuance_risk + 15, 100)
        
        # Build warning if needed
        warning = None
        reasons: list[str] = []
        
        if suspicious_recent:
            reasons.append(f"{recent_count} certificates issued in the last 90 days — possible rapid infrastructure churn")
        
        # Check for known-abused patterns
        # Quick-issuance CAs + wildcard + recent = high risk for phishing infrastructure
        if wildcard_certs and suspicious_recent and suspicious_issuers_found:
            reasons.append(
                f"Wildcard certificates issued recently by {', '.join(suspicious_issuers_found[:2])} — "
                "this combination is frequently used for phishing infrastructure"
            )
        
        if reasons:
            warning = " | ".join(reasons)
        
        result["available"] = True
        result["total_certs"] = len(seen_certs)
        result["recent_certs_90d"] = recent_count
        result["unique_issuers"] = len(seen_issuers)
        result["issuers"] = sorted(seen_issuers)[:10]  # Limit to top 10
        result["subdomains_discovered"] = subdomains[:50]  # Limit to top 50
        result["subdomain_count"] = len(subdomains)
        result["has_wildcard_cert"] = wildcard_certs
        result["suspicious_recent_issuance"] = suspicious_recent
        result["recent_issuance_risk"] = recent_issuance_risk
        result["suspicious_issuers"] = suspicious_issuers_found
        result["warning"] = warning
        
    except urllib_error.HTTPError as exc:
        result["error"] = f"crt.sh HTTP error: {exc.code}"
    except urllib_error.URLError as exc:
        result["error"] = f"crt.sh connection error: {exc.reason}"
    except json.JSONDecodeError as exc:
        result["error"] = f"crt.sh response parse error: {exc}"
    except Exception as exc:
        result["error"] = f"crt.sh query error: {exc}"
    
    return result


# ==============================================================================
# ENHANCED DNS ANALYSIS (AAAA, TXT, CNAME, MX, NS)
# ==============================================================================


def analyze_dns_records(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Comprehensive DNS record analysis with full record type enumeration.

    Resolves:
      - A, AAAA, MX, NS, TXT, CNAME records
      - Detects wildcard DNS (random subdomain resolution)
      - Detects SPF, DKIM, DMARC email security records
      - Detects parked/placeholder DNS patterns

    Uses dnspython when available, falls back to socket for basic AAAA lookups.
    The wildcard detection makes one additional DNS query per call.

    Returns:
        available: Whether DNS resolution succeeded
        a_records: IPv4 addresses
        aaaa_records: IPv6 addresses
        mx_records: Mail exchange records
        ns_records: Nameserver records
        txt_records: TXT records (raw)
        cname_records: CNAME target if applicable
        has_mx: Whether MX records exist
        has_ns: Whether NS records exist
        has_txt: Whether TXT records exist
        has_aaaa: Whether AAAA records exist
        has_cname: Whether CNAME record exists
        has_spf: Whether SPF record is configured
        has_dkim: Whether DKIM record is detected
        has_dmarc: Whether DMARC record is detected
        has_wildcard_dns: Whether wildcard DNS is enabled
        spf_record: The SPF record if found
        dkim_record: The DKIM record if found
        dmarc_record: The DMARC record if found
        suspicious_patterns: List of suspicious DNS patterns detected
        source: "live" or "unavailable"
        error: Error message if failed
    """
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    
    result: Dict[str, Any] = {
        "available": False,
        "source": "unavailable" if _dns_resolver is None else "live",
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": [],
        "has_mx": False,
        "has_ns": False,
        "has_txt": False,
        "has_aaaa": False,
        "has_cname": False,
        "has_spf": False,
        "has_dkim": False,
        "has_dmarc": False,
        "has_wildcard_dns": False,
        "spf_record": None,
        "dkim_record": None,
        "dmarc_record": None,
        "suspicious_patterns": [],
        "error": None,
    }
    
    if tld in DARK_WEB_TLDS:
        return {
            "available": False,
            "source": "not_applicable_dark_web",
            "note": "Public DNS checks are not applicable for dark-web domains",
        }
    
    if _dns_resolver is None:
        result["error"] = "dnspython library is not installed; only basic A record resolution available"
        return result
    
    # Resolve each record type
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    resolver = _dns_resolver
    
    for rtype in rtypes:
        try:
            answers = resolver.resolve(s, rtype, lifetime=timeout)
            records = [str(r).strip() for r in answers if str(r).strip()]
            
            if rtype == "A":
                result["a_records"] = records[:10]
            elif rtype == "AAAA":
                result["aaaa_records"] = records[:10]
                result["has_aaaa"] = bool(records)
            elif rtype == "MX":
                # MX records have format: "10 mail.example.com."
                mx_parsed = records[:10]
                result["mx_records"] = mx_parsed
                result["has_mx"] = bool(records)
            elif rtype == "NS":
                result["ns_records"] = records[:10]
                result["has_ns"] = bool(records)
            elif rtype == "TXT":
                result["txt_records"] = records[:20]
                result["has_txt"] = bool(records)
                
                # Parse TXT records for email security
                for txt in records:
                    low = txt.lower()
                    if low.startswith("v=spf1"):
                        result["has_spf"] = True
                        result["spf_record"] = txt[:300]  # Truncate to 300 chars
                    elif low.startswith("v=dkim1"):
                        result["has_dkim"] = True
                        result["dkim_record"] = txt[:300]
                    elif "_dmarc" in txt.lower() or "dmarc" in txt.lower():
                        # DMARC is typically in _dmarc.domain TXT, but some include in domain TXT
                        if "v=dmarc1" in low:
                            result["has_dmarc"] = True
                            result["dmarc_record"] = txt[:300]
            elif rtype == "CNAME":
                result["cname_records"] = records[:5]
                result["has_cname"] = bool(records)
        
        except resolver.NoAnswer:
            pass  # No records of this type
        except resolver.NXDOMAIN:
            result["error"] = "Domain does not exist (NXDOMAIN)"
            return result
        except resolver.Timeout:
            pass  # Timeout for this record type
        except Exception:
            pass  # General failure for this type
    
    # Now check DMARC specifically (_dmarc.domain)
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{s}", "TXT", lifetime=timeout)
        for ans in dmarc_answers:
            txt = str(ans).strip()
            if "v=dmarc1" in txt.lower():
                result["has_dmarc"] = True
                result["dmarc_record"] = txt[:300]
                break
    except Exception:
        pass  # DMARC not configured
    
    # Check for common DKIM selectors
    dkim_selectors = ["default", "google", "dkim", "mail", "selector1", "selector2"]
    for selector in dkim_selectors:
        try:
            dkim_answers = resolver.resolve(f"{selector}._domainkey.{s}", "TXT", lifetime=2.0)
            for ans in dkim_answers:
                txt = str(ans).strip()
                if "v=dkim1" in txt.lower():
                    result["has_dkim"] = True
                    result["dkim_record"] = txt[:300]
                    break
            if result["has_dkim"]:
                break
        except Exception:
            continue
    
    # --- Wildcard DNS detection ---
    # Query a random, non-existent subdomain. If it resolves, wildcard DNS is active.
    import uuid
    random_label = f"x{uuid.uuid4().hex[:8]}x"
    random_sub = f"{random_label}.{s}"
    try:
        answers = resolver.resolve(random_sub, "A", lifetime=2.0)
        wildcard_ips = [str(r).strip() for r in answers if str(r).strip()]
        if wildcard_ips:
            result["has_wildcard_dns"] = True
            result["wildcard_ips"] = wildcard_ips[:5]
    except Exception:
        pass  # No wildcard — expected behavior
    
    # --- Detect suspicious patterns ---
    suspicious: list[str] = []
    
    # No MX records when A records exist (legit sites almost always have email)
    if result["a_records"] and not result["has_mx"]:
        suspicious.append("Domain resolves but has no mail exchange (MX) records — unusual for legitimate sites")
    
    # No SPF record when MX exists
    if result["has_mx"] and not result["has_spf"]:
        suspicious.append("MX records present but no SPF policy — email spoofing protection missing")
    
    # No DMARC when MX and SPF exist
    if result["has_mx"] and result["has_spf"] and not result["has_dmarc"]:
        suspicious.append("SPF configured but no DMARC policy — incomplete email security posture")
    
    # Wildcard DNS (often used by phishing infrastructure)
    if result["has_wildcard_dns"]:
        suspicious.append("Wildcard DNS is enabled — can be used to serve content on any subdomain, common in phishing infrastructure")
    
    result["suspicious_patterns"] = suspicious
    result["available"] = True
    
    return result


# ==============================================================================
# SUBDOMAIN ENUMERATION
# ==============================================================================


def enumerate_subdomains(domain: str, ct_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Enumerate subdomains using Certificate Transparency logs and DNS.

    Primary source: crt.sh (via analyze_certificate_transparency)
    DNS validation: Resolves discovered subdomains to verify they exist

    Returns:
        available: Whether enumeration was possible
        subdomain_count: Total unique subdomains discovered
        subdomains: List of discovered subdomains (limited to 50)
        resolved_count: How many subdomains were DNS-validated
        wildcard_dns: Whether wildcard DNS was detected (makes enumeration unreliable)
        warning: Warning if subdomain enumeration has issues
        error: Error message if enumeration failed
    """
    s = sanitize_domain(domain)
    tld = s.split(".")[-1] if "." in s else ""
    
    result: Dict[str, Any] = {
        "available": False,
        "subdomain_count": 0,
        "subdomains": [],
        "resolved_count": 0,
        "wildcard_dns": False,
        "warning": None,
        "error": None,
    }
    
    if tld in DARK_WEB_TLDS:
        result["warning"] = "Subdomain enumeration is not applicable for dark-web domains."
        return result
    
    # Get CT data if not provided
    if ct_result is None or not ct_result.get("available"):
        ct_result = analyze_certificate_transparency(s)
    
    subdomains = ct_result.get("subdomains_discovered", [])
    
    if not subdomains:
        result["available"] = True
        result["subdomain_count"] = 0
        result["subdomains"] = []
        result["warning"] = "No subdomains discovered via Certificate Transparency logs."
        return result
    
    # DNS-validate a sample of discovered subdomains
    resolved_count = 0
    validated_subdomains: list[Dict[str, Any]] = []
    
    # Limit validation to first 20 to avoid excessive DNS queries
    sample = subdomains[:20]
    for sub in sample:
        if _dns_resolver is not None:
            try:
                _dns_resolver.resolve(sub, "A", lifetime=2.0)
                resolved_count += 1
                validated_subdomains.append({"subdomain": sub, "resolves": True})
            except Exception:
                validated_subdomains.append({"subdomain": sub, "resolves": False})
        else:
            # Fallback: try socket
            try:
                socket.gethostbyname(sub)
                resolved_count += 1
                validated_subdomains.append({"subdomain": sub, "resolves": True})
            except Exception:
                validated_subdomains.append({"subdomain": sub, "resolves": False})
    
    # Check wildcard DNS via CT data
    wildcard_dns = bool(ct_result.get("has_wildcard_cert"))
    
    warning = None
    if wildcard_dns:
        warning = (
            f"Wildcard certificate detected — subdomain enumeration may be incomplete "
            f"as wildcard certs can cover any subdomain. "
            f"Discovered {len(subdomains)} subdomains via CT logs."
        )
    
    result["available"] = True
    result["subdomain_count"] = len(subdomains)
    result["subdomains"] = subdomains[:50]
    result["resolved_count"] = resolved_count
    result["validated_subdomains"] = validated_subdomains
    result["wildcard_dns"] = wildcard_dns
    result["warning"] = warning
    
    return result


# ==============================================================================
# WHOIS ANALYSIS
# ==============================================================================


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


# ==============================================================================
# VIRUSTOTAL INTEGRATION
# ==============================================================================


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


# ==============================================================================
# RISK SCORING
# ==============================================================================


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

    # 2) Typosquatting (with keyboard proximity)
    if typo_result.get("detected"):
        base_p = 28.0 + 18.0 * float(typo_result.get("combined_score", 0))
        if typo_result.get("keyboard_proximity_attack"):
            base_p += 10.0  # Keyboard proximity is more suspicious
            reasons.append("Keyboard proximity attack detected — adjacent keys used instead of brand characters")
        score += base_p
        breakdown["typosquatting"] = round(base_p, 1)
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

    # 6) SSL (enhanced with full error classification)
    ssl_pts = 0.0
    if ssl_result.get("source") not in ("not_applicable_dark_web",):
        # Check for specific SSL error types (hardened v2)
        if ssl_result.get("expired"):
            ssl_pts += 18.0
            reasons.append("SSL certificate is EXPIRED — domain may be compromised or abandoned")
        if ssl_result.get("self_signed"):
            ssl_pts += 12.0
            reasons.append("Self-signed SSL certificate — no chain of trust to a known CA")
        if ssl_result.get("hostname_mismatch"):
            ssl_pts += 15.0
            reasons.append("SSL hostname mismatch — certificate was issued for a different domain")
        if ssl_result.get("revoked"):
            ssl_pts += 25.0
            reasons.append("SSL certificate has been REVOKED — indicates security compromise")
        if ssl_result.get("untrusted_root"):
            ssl_pts += 10.0
            reasons.append("SSL certificate signed by an untrusted root CA")
        if ssl_result.get("weak_protocol"):
            ssl_pts += 8.0
            reasons.append("Weak TLS protocol version detected (TLS 1.0/1.1)")
        if ssl_result.get("weak_cipher"):
            ssl_pts += 6.0
            reasons.append("Weak cipher suite detected (RC4/DES/MD5)")
        # Legacy self_signed_like check (backward compat)
        if ssl_result.get("self_signed_like") and not ssl_result.get("self_signed"):
            ssl_pts += 6.0
            reasons.append("Self-signed-like or anomalous SSL certificate")
        if ssl_result.get("ssl_error") and not any([
            ssl_result.get("expired"), ssl_result.get("self_signed"),
            ssl_result.get("hostname_mismatch"), ssl_result.get("revoked"),
            ssl_result.get("untrusted_root"),
        ]):
            ssl_pts += 2.0
        exp = ssl_result.get("days_to_expiry")
        if isinstance(exp, int) and 0 <= exp < 7:
            ssl_pts += 5.0
            reasons.append(f"SSL certificate expires in {exp} day(s)")
    if ssl_pts:
        score += ssl_pts
        breakdown["ssl"] = round(ssl_pts, 1)

    # 7) WHOIS
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

    # 8) DNS
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

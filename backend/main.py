import asyncio
import os
import re
from dotenv import load_dotenv
import shutil
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse
import json
import ssl
import urllib.request
import urllib.error

# Import stealth proxy/rate-limiting module
from stealth import setup_stealth, build_stealth_opener, stealth_build_request

# Import the new hybrid scoring engine
from scoring import compute_hybrid_score, is_hard_protected, compute_data_completeness

# Import v3.0 threat intelligence feeds module
try:
    from threat_intel import (run_all_feeds, check_urlhaus, check_google_safe_browsing,
        check_phishtank, check_virustotal, check_abuseipdb, check_urlscan)
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False

# Import v3.0 ensemble ML module
try:
    from ml_ensemble import ensemble_predict
    ENSEMBLE_ML_AVAILABLE = True
except ImportError:
    ENSEMBLE_ML_AVAILABLE = False

# Import v3.0 fast-flux / DGA detection module
try:
    from fast_flux_dga import detect_fast_flux, detect_dga
    FAST_FLUX_DGA_AVAILABLE = True
except ImportError:
    FAST_FLUX_DGA_AVAILABLE = False

# Import v3.0 reputation timeline module
try:
    from reputation_timeline import record_analysis, get_timeline
    REPUTATION_TIMELINE_AVAILABLE = True
except ImportError:
    REPUTATION_TIMELINE_AVAILABLE = False

try:
    import dns.resolver as dns_resolver
except ImportError:
    dns_resolver = None

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

try:
    from cryptography import x509
except ImportError:
    x509 = None

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from google import genai
except Exception:
    genai = None

load_dotenv()

# Import utils helpers for ML feature extraction
try:
    from utils import (
        extract_features,
        detect_typosquatting as utils_detect_typosquatting,
        detect_homoglyphs as utils_detect_homoglyphs,
        detect_combosquatting as utils_detect_combosquatting,
        inspect_website,
        normalize_homoglyphs,
        analyze_ssl_signals as utils_analyze_ssl_signals,
        detect_abused_infrastructure as utils_detect_abused_infrastructure,
        detect_subdomain_phishing as utils_detect_subdomain_phishing,
        detect_url_path_signals as utils_detect_url_path_signals,
        analyze_redirect_chain as utils_analyze_redirect_chain,
        detect_punycode_homograph as utils_detect_punycode_homograph,
        analyze_certificate_transparency as utils_analyze_certificate_transparency,
        analyze_dns_records as utils_analyze_dns_records,
        enumerate_subdomains as utils_enumerate_subdomains,
    )
except ImportError:
    extract_features = None
    utils_detect_typosquatting = None
    utils_detect_homoglyphs = None
    utils_detect_combosquatting = None
    inspect_website = None
    normalize_homoglyphs = None
    utils_analyze_ssl_signals = None
    utils_detect_abused_infrastructure = None
    utils_detect_subdomain_phishing = None
    utils_detect_url_path_signals = None
    utils_analyze_redirect_chain = None
    utils_detect_punycode_homograph = None
    utils_analyze_certificate_transparency = None
    utils_analyze_dns_records = None
    utils_enumerate_subdomains = None

# Import owner image detection module
from owner_image_detection import analyze_owner_images

# Import brand impersonation detection engine
try:
    from brand_impersonation import analyze_brand_impersonation, detect_brand_similarity, detect_login_harvesting
    BRAND_IMPERSONATION_AVAILABLE = True
except ImportError:
    analyze_brand_impersonation = None  # type: ignore
    BRAND_IMPERSONATION_AVAILABLE = False

# Import browser automation module (Playwright-based dynamic content analysis)
try:
    from browser_automation import analyze_dynamic_content, is_playwright_installed as bw_is_playwright_installed
    BROWSER_AUTO_AVAILABLE = bw_is_playwright_installed()
except ImportError:
    analyze_dynamic_content = None  # type: ignore
    BROWSER_AUTO_AVAILABLE = False

# ------------------------------------------------------------------------------
# NATIVE PYTHON FALLBACKS FOR SUBPROCESS UTILITIES
# ------------------------------------------------------------------------------

def safe_iso_date(year: int, month: int, day: int) -> str | None:
    try:
        return datetime(year, month, day, tzinfo=UTC).date().isoformat()
    except ValueError:
        return None
def _source_from(values: list[tuple[int, str | None, str]]) -> tuple[int | None, str | None, str | None]:
    if not values:
        return None, None, None
    redirect_index, source_url, value = values[-1]
    return redirect_index, source_url, value
def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + (char_left != char_right)))
        previous = current
    return previous[-1]

from functools import lru_cache
def fallback_dns(domain: str, rtype: str) -> str:
    """Fallback using dnspython or socket when dig is unavailable."""
    if dns_resolver:
        try:
            answers = dns_resolver.resolve(domain, rtype)
            if rtype == "A":
                return "\n".join([str(rdata) for rdata in answers])
            elif rtype == "MX":
                return "\n".join([f"{rdata.preference} {rdata.exchange}" for rdata in answers])
        except Exception:
            pass
    if rtype == "A":
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return "\n".join(ips)
        except Exception:
            pass
    return ""


def fallback_whois(query: str) -> str:
    """Fallback using python-whois when whois CLI is unavailable."""
    if not whois_lib:
        return "python-whois library is not installed."
    try:
        w = whois_lib.whois(query)
        lines = []
        
        dnames = w.get("domain_name")
        if dnames:
            if isinstance(dnames, list):
                lines.append(f"Domain Name: {dnames[0].upper()}")
            else:
                lines.append(f"Domain Name: {str(dnames).upper()}")
        else:
            lines.append(f"Domain Name: {query.upper()}")
            
        reg = w.get("registrar")
        if reg:
            lines.append(f"Registrar: {reg}")
            
        cdate = w.get("creation_date")
        if cdate:
            if isinstance(cdate, list):
                cdate = cdate[0]
            if isinstance(cdate, datetime):
                lines.append(f"Creation Date: {cdate.strftime('%Y-%m-%dT%H:%M:%SZ')}")
            else:
                lines.append(f"Creation Date: {str(cdate)}")
                
        ns_list = w.get("name_servers")
        if ns_list:
            if isinstance(ns_list, list):
                for ns in ns_list:
                    lines.append(f"Name Server: {ns.lower()}")
            else:
                lines.append(f"Name Server: {str(ns_list).lower()}")
                
        if w.get("org"):
            lines.append(f"OrgName: {w.get('org')}")
        if w.get("country"):
            lines.append(f"country: {w.get('country')}")
        if w.get("asn"):
            lines.append(f"origin: {w.get('asn')}")
            
        for k, v in w.items():
            if k not in ["domain_name", "registrar", "creation_date", "name_servers", "org", "country", "asn"]:
                if v and isinstance(v, (str, int)):
                    lines.append(f"{k}: {v}")
                    
        return "\n".join(lines)
    except Exception as e:
        return f"WHOIS fallback error: {e}"


def _try_rdap(ip: str, base_url: str) -> str | None:
    """Try a single RDAP endpoint. Returns formatted text or None."""
    try:
        url = f"{base_url}/ip/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            lines = []

            if data.get("name"):
                lines.append(f"OrgName: {data.get('name')}")
            if data.get("handle"):
                lines.append(f"netname: {data.get('handle')}")

            country = None
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'adr' and item[1].get('label'):
                            label = item[1].get('label')
                            label_parts = [p.strip() for p in label.split('\n') if p.strip()]
                            if label_parts:
                                country = label_parts[-1]
                        if item[0] == 'org':
                            lines.append(f"descr: {item[3]}")
            if country:
                lines.append(f"country: {country}")

            # Try all known ASN field names across RIRs
            # Note: ARIN returns empty list [] rather than None, so check length
            asn = None
            for asn_key in ("arin_originas0_originautnums", "originAutnum", "autnum", "asn"):
                asns = data.get(asn_key)
                if asns is not None and isinstance(asns, (list, tuple)) and len(asns) > 0:
                    asn = f"AS{asns[0]}"
                    break
            if asn:
                lines.append(f"origin: {asn}")

            # Extract organization name from entity vcard (more descriptive than network name)
            org_name = None
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'fn':
                            org_name = str(item[3]) if len(item) > 3 else None
                        if item[0] == 'org':
                            org_name = str(item[3]) if len(item) > 3 else org_name
            if org_name and not any("OrgName" in l for l in lines):
                lines = [f"OrgName: {org_name}" if l.startswith("OrgName:") else l for l in lines]
            elif org_name:
                lines.append(f"OrgName: {org_name}")

            # Infer ASN from org name if no direct ASN was found
            if not any(l.startswith("origin:") for l in lines) and org_name:
                org_lower = org_name.lower()
                for org_key, (asn_val, _) in ORG_TO_ASN.items():
                    if org_key in org_lower:
                        lines.append(f"origin: {asn_val}")
                        break

            # Extract country from entity vcard address field
            country_val = None
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'adr':
                            label = item[1].get('label', '') if isinstance(item[1], dict) else ''
                            if label:
                                parts = [p.strip() for p in label.split('\n') if p.strip()]
                                if parts:
                                    country_val = parts[-1]
            if country_val and not any("country" in l for l in lines):
                lines.append(f"country: {country_val}")

            # Port43 hints for hosting provider
            port43 = data.get("port43", "")
            if port43 and not any("OrgName" in l or "descr" in l for l in lines):
                host_hint = port43.split(".")[-2] if "." in port43 else port43
                if host_hint and len(host_hint) > 2:
                    lines.append(f"OrgName: {host_hint.upper()} (RDAP port43)")

            if lines:
                return "\n".join(lines)
    except Exception:
        pass
    return None


# OrgName-to-ASN mapping for hosting providers
# Used when RDAP returns OrgName from entities but no ASN
ORG_TO_ASN: dict[str, tuple[str, str]] = {
    "google": ("AS15169", "US"),
    "google llc": ("AS15169", "US"),
    "cloudflare": ("AS13335", "US"),
    "cloudflare inc": ("AS13335", "US"),
    "amazon": ("AS16509", "US"),
    "amazon.com": ("AS16509", "US"),
    "amazon technologies": ("AS16509", "US"),
    "aws": ("AS16509", "US"),
    "microsoft": ("AS8075", "US"),
    "microsoft corp": ("AS8075", "US"),
    "meta platforms": ("AS32934", "US"),
    "facebook": ("AS32934", "US"),
    "fastly": ("AS54113", "US"),
    "akamai": ("AS16625", "US"),
    "apple": ("AS714", "US"),
    "apple inc": ("AS714", "US"),
    "digitalocean": ("AS14061", "US"),
    "ovh": ("AS16276", "FR"),
    "ovh sas": ("AS16276", "FR"),
    "github": ("AS36459", "US"),
    "netflix": ("AS2906", "US"),
    "markmonitor": ("AS46844", "US"),
    # Indian ISPs and hosting providers
    "netraj": ("AS134180", "IN"),
    "net rizvi": ("AS134180", "IN"),
    "bharti airtel": ("AS9498", "IN"),
    "airtel": ("AS9498", "IN"),
    "reliance jio": ("AS55836", "IN"),
    "jio": ("AS55836", "IN"),
    "tata communications": ("AS4755", "IN"),
    "tata teleservices": ("AS4755", "IN"),
    "railwire": ("AS133982", "IN"),
    "spectranet": ("AS133714", "IN"),
    "sify": ("AS9583", "IN"),
    "ctrl s": ("AS133296", "IN"),
    "excitel": ("AS133661", "IN"),
    "act fibernet": ("AS133982", "IN"),
    "you broadband": ("AS133661", "IN"),
    # European hosting
    "hetzner": ("AS24940", "DE"),
    "hetzner online": ("AS24940", "DE"),
    "scaleway": ("AS12876", "FR"),
    "online sas": ("AS12876", "FR"),
    "contabo": ("AS51167", "DE"),
    # Asian hosting
    "alibaba cloud": ("AS45102", "CN"),
    "tencent cloud": ("AS132203", "CN"),
    "huawei cloud": ("AS136907", "CN"),
    "linode": ("AS63949", "US"),
    "vultr": ("AS20473", "US"),
    # Additional global
    "namecheap": ("AS22612", "US"),
    "godaddy": ("AS26496", "US"),
    "endurance": ("AS46606", "US"),
}


def _ptr_reverse_lookup(ip: str) -> str | None:
    """Try a PTR reverse DNS lookup on the IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _infer_from_hostname(hostname: str) -> tuple[str | None, str | None, str | None]:
    """Infer hosting/ASN from a hostname (PTR result or domain)."""
    d = hostname.lower()
    if "google" in d or "youtube" in d or "gcp" in d:
        return ("Google LLC", "AS15169", "US")
    if "cloudflare" in d:
        return ("Cloudflare Inc.", "AS13335", "US")
    if "github" in d or "githubusercontent" in d:
        return ("GitHub Inc.", "AS36459", "US")
    if "microsoft" in d or "azure" in d or "live" in d or "office" in d:
        return ("Microsoft Corp.", "AS8075", "US")
    if "amazon" in d or "aws" in d or "cloudfront" in d:
        return ("Amazon.com Inc.", "AS16509", "US")
    if "facebook" in d or "meta" in d or "instagram" in d or "whatsapp" in d:
        return ("Meta Platforms Inc.", "AS32934", "US")
    if "apple" in d or "icloud" in d:
        return ("Apple Inc.", "AS714", "US")
    if "netflix" in d:
        return ("Netflix Inc.", "AS2906", "US")
    if "digitalocean" in d or "digital ocean" in d:
        return ("DigitalOcean LLC", "AS14061", "US")
    if "ovh" in d or "soyoustart" in d:
        return ("OVH SAS", "AS16276", "FR")
    if "fastly" in d:
        return ("Fastly Inc.", "AS54113", "US")
    if "akamai" in d:
        return ("Akamai Technologies", "AS16625", "US")
    if "wikimedia" in d or "wikipedia" in d:
        return ("Wikimedia Foundation Inc.", "AS14907", "US")
    return (None, None, None)


RIR_RDAP_ENDPOINTS = [
    "https://rdap.arin.net/registry",  # North America
    "https://rdap.db.ripe.net/registry",  # Europe
    "https://rdap.apnic.net/registry",  # Asia-Pacific
    "https://rdap.lacnic.net/registry",  # Latin America
    "https://rdap.afrinic.net/registry",  # Africa
]


def fallback_ip_whois(ip: str) -> str:
    """
    IP WHOIS fallback trying RDAP across ALL RIRs, then PTR/CDN heuristic, then python-whois.

    Resolution chain:
      1. RDAP: ARIN, RIPE, APNIC, LACNIC, AFRINIC
      2. PTR reverse DNS + hostname CDN heuristics
      3. python-whois library
    """
    # Step 1: Try each RIR RDAP endpoint
    for endpoint in RIR_RDAP_ENDPOINTS:
        result = _try_rdap(ip, endpoint)
        if result is not None:
            return result

    # Step 2: PTR reverse DNS lookup + CDN heuristics
    ptr_name = _ptr_reverse_lookup(ip)
    if ptr_name:
        provider, asn_num, country_code = _infer_from_hostname(ptr_name)
        if provider:
            lines = [
                f"OrgName: {provider}",
                f"origin: {asn_num}",
                f"country: {country_code}",
            ]
            return "\n".join(lines)

    # Step 3: Last resort - python-whois library
    return fallback_whois(ip)


def fallback_ssl_probe(domain: str) -> str:
    """SSL fallback using python standard ssl/socket libraries and cryptography."""
    try:
        pem = ssl.get_server_certificate((domain, 443), timeout=3.0)
        if not x509:
            return "cryptography library not available for native SSL parsing."
            
        cert = x509.load_pem_x509_certificate(pem.encode())
        
        cn = ""
        org = ""
        for attr in cert.issuer:
            oid_name = attr.oid._name
            if oid_name == 'commonName':
                cn = attr.value
            elif oid_name == 'organizationName':
                org = attr.value
                
        not_before = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", None)
        not_after = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", None)
        
        lines = [
            f"issuer=CN={cn}, O={org}",
            f"notBefore={not_before.strftime('%b %d %H:%M:%S %Y GMT')}",
            f"notAfter={not_after.strftime('%b %d %H:%M:%S %Y GMT')}"
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"SSL probe fallback error: {e}"


async def fallback_port_scan(domain: str, ports: list[int]) -> str:
    """Port scanning fallback using native async sockets."""
    open_ports = []
    
    async def check_port(port: int):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except Exception:
            pass
            
    await asyncio.gather(*(check_port(port) for port in ports))
    
    lines = []
    for port in sorted(open_ports):
        lines.append(f"Connection to {domain} {port} port [tcp] succeeded!")
    return "\n".join(lines)


def _do_curl(url: str) -> str | None:
    """
    Perform a single HTTP request and return all headers with redirect tracing.
    Uses realistic browser headers (via stealth module) to get full
    security headers from CDN edge servers.
    Returns None if the request fails.
    """
    try:
        req = stealth_build_request(
            url,
            headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
            },
        )

        class RedirectTraceHandler(urllib.request.HTTPRedirectHandler):
            def __init__(self):
                super().__init__()
                self.trace = []
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                self.trace.append((req.full_url, code, headers))
                # Cap redirects at 5 to avoid infinite loops
                if len(self.trace) >= 5:
                    raise urllib.error.HTTPError(req.full_url, code, "Too many redirects", headers, fp)
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        handler = RedirectTraceHandler()
        opener = build_stealth_opener(handler)

        output = []
        with opener.open(req, timeout=5.0) as resp:
            # Emit redirect trace blocks
            for orig_url, code, headers in handler.trace:
                output.append(f"HTTP/1.1 {code} Redirect")
                for k, v in headers.items():
                    output.append(f"{k}: {v}")
                output.append("")

            # Emit final response block
            status = getattr(resp, "status", 200)
            output.append(f"HTTP/1.1 {status} OK")
            for k, v in resp.headers.items():
                output.append(f"{k}: {v}")

            return "\n".join(output)
    except Exception:
        return None


def fallback_curl(domain: str) -> str:
    """
    HTTP headers check fallback using urllib with redirect tracking.
    
    Tries HTTPS first, then HTTP. Follows redirects and captures
    ALL response headers from every hop in the redirect chain.
    """
    # First try: HTTPS with full redirect tracing
    result = _do_curl(f"https://{domain}")
    if result is not None:
        return result

    # Second try: HTTP with full redirect tracing
    # Some servers redirect HTTP -> HTTPS, so we still get the final headers
    result = _do_curl(f"http://{domain}")
    if result is not None:
        return result

    return f"HTTP/HTTPS request failed for {domain}"


async def _run_stealth_curl(domain: str) -> "CommandResult":
    """
    HTTP header retrieval using stealth browser headers.

    Uses _do_curl() which sends rotating User-Agent, full Accept header,
    Accept-Language, DNT, Keep-Alive, and Upgrade-Insecure-Requests via
    the stealth module — making the request look like a real browser to
    CDN edge servers so they serve complete security headers.

    Falls back to curl CLI if Python method fails.
    """
    try:
        stdout = await asyncio.to_thread(fallback_curl, domain)
        return CommandResult(
            name="curl",
            command=["stealth_curl", domain],
            status="ok",
            stdout=stdout or "",
            stderr="",
            returncode=0,
        )
    except Exception as exc:
        # Fallback to curl CLI with realistic headers
        try:
            null_device = "NUL" if os.name == "nt" else "/dev/null"
            return await run_command(
                "curl",
                [
                    "curl",
                    "-L", "-D", "-", "-o", null_device,
                    "--user-agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "-H", "Accept-Language: en-US,en;q=0.9",
                    "-H", "DNT: 1",
                    "-H", "Upgrade-Insecure-Requests: 1",
                    "-H", "Accept-Encoding: gzip, deflate",
                    "-H", "Connection: keep-alive",
                    f"https://{domain}",
                ],
            )
        except Exception as exc2:
            return CommandResult(
                name="curl",
                command=["stealth_curl", domain],
                status="failed",
                stdout="",
                stderr="",
                returncode=1,
                error=f"Python stealth curl failed: {exc}; curl CLI fallback also failed: {exc2}",
            )


async def run_python_fallback(name: str, command: list[str]) -> str | None:
    """Execute the native Python fallback depending on utility name."""
    if name == "dig":
        domain = command[1]
        return fallback_dns(domain, "A")
    elif name == "mx":
        domain = command[1]
        return fallback_dns(domain, "MX")
    elif name == "domain_whois":
        domain = command[1]
        return await asyncio.to_thread(fallback_whois, domain)
    elif name == "ip_whois":
        ip = command[1]
        # Try to get domain hint from the curl command output if available
        # The fallback_ip_whois will try RDAP first, then CDN heuristics
        return await asyncio.to_thread(fallback_ip_whois, ip)
    elif name == "ssl":
        m = re.search(r"-connect\s+([a-zA-Z0-9.-]+):443", command[-1])
        if m:
            domain = m.group(1)
            return await asyncio.to_thread(fallback_ssl_probe, domain)
    elif name == "nc":
        domain = command[4]
        ports = [int(p) for p in command[5:]]
        return await fallback_port_scan(domain, ports)
    elif name == "curl":
        url_arg = command[-1]
        parsed = urlparse(url_arg)
        domain = parsed.hostname or url_arg
        return await asyncio.to_thread(fallback_curl, domain)
    return None


def get_ml_prediction(domain: str, parsed_domain: Any, whois_raw_stdout: str, has_valid_ssl: bool = False, has_mx: bool = False, has_asn: bool = False, header_score: int = 0) -> dict:
    """Calculate lexical/whois features and run XGBoost model prediction."""
    try:
        import sys
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        if backend_dir not in sys.path:
            sys.path.append(backend_dir)
        from ml_xgboost import load_xgb, predict_xgb
        import numpy as np
    except Exception as e:
        print("XGBoost module imports failed:", e)
        return {"xgb_available": False}
        
    try:
        clean = domain.strip().lower()
        parts = clean.split(".")
        label = parts[-2] if len(parts) >= 2 else clean
        normalized_label = label
        if normalize_homoglyphs:
            try:
                normalized_label = normalize_homoglyphs(label)
            except Exception:
                pass
        
        features = {}
        if extract_features:
            try:
                features = extract_features(clean)
            except Exception:
                pass
                
        homoglyph_result = {"detected": False, "count": 0, "has_digit_substitution": False}
        if utils_detect_homoglyphs:
            try:
                homoglyph_result = utils_detect_homoglyphs(clean)
            except Exception:
                pass
                
        typo_result = {"detected": False, "jaro_winkler_score": 0.0, "levenshtein_score": 0.0, "edit_distance": 10}
        if utils_detect_typosquatting:
            try:
                typo_result = utils_detect_typosquatting(normalized_label)
                typo_result_raw = utils_detect_typosquatting(label)
                # Prefer raw label result if it detects something (catches normalization substitutions)
                # or if its Jaro-Winkler score is strictly higher than the normalized version
                if typo_result_raw.get("detected", False) or typo_result_raw.get("jaro_winkler_score", 0.0) > typo_result.get("jaro_winkler_score", 0.0):
                    typo_result = typo_result_raw
            except Exception:
                pass
                
        combo_result = {"detected": False, "brand_only": False, "matched_keywords": []}
        if utils_detect_combosquatting:
            try:
                combo_result = utils_detect_combosquatting(clean)
            except Exception:
                pass
    except Exception as e:
        print("Feature extraction failed:", e)
        features = {}
        homoglyph_result = {}
        typo_result = {}
        combo_result = {}
        
    age_days = domain_age_days(parsed_domain.created_date) if parsed_domain else None
    if age_days is None:
        age_days = 365
        
    text_blob = str(whois_raw_stdout or "").lower()
    privacy = any(k in text_blob for k in ("privacy", "redacted", "proxy", "guard"))
    
    registrar = parsed_domain.registrar or "" if parsed_domain else ""
    suspicious_reg = bool(registrar and any(k in registrar.lower() for k in ("cheap", "privacy", "unknown")))
    
    domain_name = clean.split(".", 1)[0]
    letters = sum(c.isalpha() for c in domain_name)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain_name)
    consonant_ratio = consonants / max(1, letters)
    has_excessive_hyphens = float(domain_name.count("-") >= 3)
    
    features["consonant_ratio"] = consonant_ratio
    features["has_excessive_hyphens"] = has_excessive_hyphens
    
    age_log = np.log1p(age_days) / np.log1p(3650)
    
    # ---- Expanded features for better ML separation ----
    # Compute jaro-winkler similarity between the UN-NORMALIZED label and the closest brand.
    # This catches domains like "g00gle" where normalization turns them into exact brand
    # matches, because the un-normalized label still has a high similarity to "google".
    # Also compute whether normalization changed the label at all.
    jaro_raw_vs_brand = 0.0
    label_normalized_changed = 0.0
    if utils_detect_typosquatting:
        try:
            raw_typo_check = utils_detect_typosquatting(label)  # original unnormalized label
            jaro_raw_vs_brand = raw_typo_check.get("jaro_winkler_score", 0.0)
            # If the raw label has high similarity to a brand but detected=False,
            # this means normalization turned it into an exact match — we want to flag that.
            if jaro_raw_vs_brand >= 0.70 and not raw_typo_check.get("detected", False):
                pass  # Still use the similarity score; the model can learn from it
        except Exception:
            pass
    
    # Check if homoglyph normalization changed the label
    if normalize_homoglyphs:
        try:
            normed = normalize_homoglyphs(label)
            if normed != label:
                label_normalized_changed = 1.0
        except Exception:
            pass
    
    # Max consecutive digits in the domain label
    consecutive_digits = 0.0
    if domain_name:
        digit_runs = re.findall(r"\d+", domain_name)
        if digit_runs:
            consecutive_digits = min(max(len(r) for r in digit_runs) / 5.0, 1.0)
    
    # TLD risk score (continuous 0.0-1.0)
    tld_score = 0.0
    tld_from_domain = parts[-1] if len(parts) >= 2 else ""
    if tld_from_domain:
        if tld_from_domain in {"gov", "edu", "mil"}:
            tld_score = 0.0
        elif tld_from_domain in {"com", "org", "net"}:
            tld_score = 0.1
        elif tld_from_domain in {"io", "co", "app", "dev", "ai"}:
            tld_score = 0.2
        elif tld_from_domain in {"info", "biz", "me", "tv"}:
            tld_score = 0.3
        elif tld_from_domain in {"online", "site", "club", "live", "work", "support"}:
            tld_score = 0.6
        elif tld_from_domain in {"xyz", "top", "click", "loan"}:
            tld_score = 0.8
        elif tld_from_domain in {"tk", "ml", "ga", "cf", "gq"}:
            tld_score = 1.0
        elif tld_from_domain in {"onion", "i2p", "bit"}:
            tld_score = 1.0
    
    # Unique brand-like tokens in domain (different from phishing keyword count)
    # Counts how many distinct word-like segments exist in the domain label
    # after splitting on hyphens and underscores. Legitimate brands usually have 1-2 tokens,
    # while combosquatting domains often have 3+ tokens (e.g., "google-account-security").
    normalized_tokens = set()
    if normalize_homoglyphs:
        try:
            label_tokens = re.split(r"[\-_]+", domain_name)
            for t in label_tokens:
                nt = normalize_homoglyphs(t)
                if len(nt) > 2:  # skip very short tokens
                    normalized_tokens.add(nt)
        except Exception:
            pass
    unique_token_count = min(len(normalized_tokens) / 5.0, 1.0)

    vector = [
        min(features.get("length", len(domain_name)) / 50.0, 1.0),            # 0: normalized length
        features.get("digit_ratio", round(sum(c.isdigit() for c in domain_name) / max(1, len(domain_name)), 4)), # 1: digit ratio
        min(features.get("hyphen_count", domain_name.count("-")) / 5.0, 1.0),        # 2: hyphen count
        min(features.get("subdomain_count", len(parts) - 2) / 5.0, 1.0),      # 3: subdomain depth
        min(features.get("entropy", 3.0) / 5.0, 1.0),                         # 4: Shannon entropy
        features.get("consonant_ratio", consonant_ratio),                      # 5: consonant ratio
        float(features.get("suspicious_tld", ("." + parts[-1]) in SUSPICIOUS_TLDS)),  # 6: suspicious TLD
        float(features.get("has_suspicious_keywords", any(k in clean for k in KNOWN_BRANDS))), # 7: has brand keywords
        float(features.get("is_ip_like", bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", clean)))), # 8: IP-like
        float(features.get("has_excessive_hyphens", has_excessive_hyphens)),   # 9: >=3 hyphens
        typo_result.get("jaro_winkler_score", 0.0),                           # 10: Jaro-Winkler (normalized)
        typo_result.get("levenshtein_score", 0.0),                            # 11: Levenshtein (normalized)
        min(typo_result.get("edit_distance", 10) / 10.0, 1.0),                 # 12: edit distance (normalized)
        float(typo_result.get("detected", False)),                            # 13: typosquatting detected
        float(homoglyph_result.get("detected", False)),                       # 14: homoglyph detected
        min(homoglyph_result.get("count", 0) / 5.0, 1.0),                      # 15: homoglyph count
        float(homoglyph_result.get("has_digit_substitution", False)),          # 16: digit substitution
        float(combo_result.get("detected", False)),                           # 17: combosquatting detected
        float(combo_result.get("brand_only", False)),                         # 18: brand only (no kw)
        min(len(combo_result.get("matched_keywords", [])) / 5.0, 1.0),          # 19: keyword count
        age_log,                                                              # 20: domain age (log)
        float(privacy),                                                       # 21: WHOIS privacy
        float(suspicious_reg),                                                # 22: suspicious registrar
        # ---- NEW FEATURES (23-27): added for better ML separation ----
        jaro_raw_vs_brand,                                                    # 23: Jaro-Winkler (unnormalized label)
        label_normalized_changed,                                             # 24: normalization changed label
        consecutive_digits,                                                   # 25: max consecutive digits
        tld_score,                                                            # 26: TLD risk score (0.0-1.0)
        unique_token_count,                                                   # 27: unique normalized tokens in label
        # ---- INFERENCE-TIME FEATURE: SSL validity ----
        # Passed from run_analysis() after SSL probe completed.
        # Provides real infrastructure signal: legitimate sites almost always have SSL.
        float(has_valid_ssl),  # 28: SSL certificate valid (1.0=yes, 0.0=no)
        # ---- INFERENCE-TIME FEATURE: MX presence ----
        # legitimate domains almost always have MX records for email;
        # phishing domains often skip MX configuration entirely.
        float(has_mx),         # 29: MX records present (1.0=yes, 0.0=no)
        # ---- INFERENCE-TIME FEATURE: ASN availability ----
        # legitimate sites run on properly registered infrastructure with
        # identifiable ASN; phishing sites often hide behind obscure hosts.
        float(has_asn),         # 30: ASN data available (1.0=yes, 0.0=no)
        # ---- INFERENCE-TIME FEATURE: Security header posture ----
        # header_score is 0-25+ where higher = more/missing security headers.
        # Legitimate sites have low header_scores (well-configured security);
        # phishing sites tend to have missing security headers (high scores).
        min(header_score / 15.0, 1.0),  # 31: header security deficit 0.0=perfect(max 15=all 5 required headers missing)
    ]
    
    try:
        model = load_xgb()
        if model is not None:
            xgb_result = predict_xgb(model, vector)
            xgb_result["feature_vector"] = vector
            return xgb_result
    except Exception as e:
        print("XGB predict execution failed:", e)
        
    return {"xgb_available": False}


APP_NAME = "RETRO_INTEL: OSINT Domain Threat Analyzer"
COMMAND_TIMEOUT_SECONDS = 6
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEADER_NAMES = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]
OPTIONAL_HEADER_NAMES = {
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
}
HEADER_SCORE_WEIGHTS = {
    "Strict-Transport-Security": 4,
    "Content-Security-Policy": 5,
    "X-Frame-Options": 3,
    "X-Content-Type-Options": 2,
    "Referrer-Policy": 1,
}
COMMON_PORTS = [21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 8443]
SUSPICIOUS_TLDS = {".top", ".xyz", ".click", ".work", ".live", ".loan", ".cc", ".tk", ".gq", ".ml"}
KNOWN_BRANDS = [
    "amazon",
    "google",
    "facebook",
    "paypal",
    "instagram",
    "netflix",
    "microsoft",
    "apple",
    "linkedin",
    "github",
    "whatsapp",
    "telegram",
    "coinbase",
    "binance",
    "flipkart",
    "phonepe",
    "paytm",
]
TRUSTED_INFRA_KEYWORDS = {
    "google", "youtube", "microsoft", "azure", "github", "amazon", "aws", "cloudflare",
    "facebook", "meta", "instagram", "apple", "netflix", "openai", "paypal", "stripe",
}
PORT_INTEL = {
    21: "FTP exposed - file transfer service visible from the internet.",
    22: "SSH exposed - increases administrative attack surface.",
    23: "Telnet exposed - plaintext remote administration risk.",
    25: "SMTP exposed - mail server visible, potential spam relay risk.",
    80: "HTTP exposed - unencrypted web traffic.",
    110: "POP3 exposed - email retrieval protocol visible.",
    143: "IMAP exposed - email inbox access protocol visible.",
    443: "HTTPS - standard secure web traffic (expected).",
    445: "SMB exposed - file sharing surface should not be internet-facing.",
    993: "IMAPS - secure email inbox access (expected).",
    995: "POP3S - secure email retrieval (expected).",
    1433: "MSSQL exposed - database server visible from the internet.",
    1521: "Oracle DB exposed - database server visible from the internet.",
    3306: "MySQL exposed - database server visible from the internet.",
    3389: "RDP exposed - increases remote access attack surface.",
    5432: "PostgreSQL exposed - database server visible from the internet.",
    5900: "VNC exposed - remote desktop service visible from the internet.",
    6379: "Redis exposed - in-memory database visible, potential data leak.",
    8080: "HTTP-alt (8080) - alternate web console or proxy, likely a common alternate web service port.",
    8443: "HTTPS-alt (8443) - alternate TLS web service, likely a common alternate web service port.",
    27017: "MongoDB exposed - NoSQL database visible from the internet.",
}
_COUNTRY_NAME_TO_CODE: dict[str, str] = {
    "united states": "US", "usa": "US", "u.s.a.": "US", "u.s.": "US",
    "united kingdom": "GB", "uk": "GB", "great britain": "GB",
    "germany": "DE", "france": "FR", "canada": "CA",
    "australia": "AU", "japan": "JP", "china": "CN",
    "india": "IN", "brazil": "BR", "russia": "RU",
    "south korea": "KR", "korea": "KR", "netherlands": "NL",
    "italy": "IT", "spain": "ES", "switzerland": "CH",
    "sweden": "SE", "norway": "NO", "denmark": "DK",
    "finland": "FI", "singapore": "SG", "hong kong": "HK",
    "taiwan": "TW", "ireland": "IE", "new zealand": "NZ",
    "poland": "PL", "austria": "AT", "belgium": "BE",
    "portugal": "PT", "israel": "IL", "turkey": "TR",
    "south africa": "ZA", "mexico": "MX", "argentina": "AR",
    "chile": "CL", "colombia": "CO", "czech republic": "CZ",
    "hungary": "HU", "romania": "RO", "ukraine": "UA",
    "vietnam": "VN", "thailand": "TH", "malaysia": "MY",
    "indonesia": "ID", "philippines": "PH", "pakistan": "PK",
    "bangladesh": "BD", "egypt": "EG", "nigeria": "NG",
    "kenya": "KE", "saudi arabia": "SA", "uae": "AE",
    "united arab emirates": "AE",
}



class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class CommandResult(BaseModel):
    name: str
    command: list[str]
    status: str
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    error: str | None = None


class HeaderStatus(BaseModel):
    name: str
    enabled: bool
    value: str | None = None
    status: str = "MISSING"
    strength: str = "MISSING"
    effective: bool = False
    evidence: str = ""
    recommendation: str = ""
    redirect_index: int | None = None
    source_url: str | None = None


class AnalyzeResponse(BaseModel):
    domain: str
    ip_address: str | None
    parsed_meta: dict[str, Any]
    security_headers: dict[str, bool]
    security_header_details: list[HeaderStatus]
    open_ports: list[int]
    dns_data: dict[str, list[str]]
    raw_logs: dict[str, str]
    findings: list[str]
    ai_verdict: str
    risk_score: int
    commands: dict[str, CommandResult]
    raw_context: str
    partial_report: bool
    errors: list[str]
    target_ip: str | None = None
    hosting_space: str | None = None
    country_code: str | None = None
    asn: str | None = None
    domain_age: str | None = None
    registrar: str | None = None
    ssl_issuer: str | None = None
    ssl_dates: dict[str, str | None] = Field(default_factory=dict)
    final_http_status: int | None = None
    port_map: str = ""
    ai_markdown_report: str = ""
    ml_result: dict[str, Any] = Field(default_factory=dict)
    score_components: dict[str, Any] = Field(default_factory=dict)
    website_analysis: dict[str, Any] = Field(default_factory=dict)
    owner_image: dict[str, Any] = Field(default_factory=dict)
    # v3.0 fields
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    ensemble_ml: dict[str, Any] = Field(default_factory=dict)
    score_breakdown: dict[str, Any] = Field(default_factory=dict)
    brand_impersonation: dict[str, Any] = Field(default_factory=dict)
    ai_detailed_report: str = ""
    # v4.0: Data completeness tracking
    data_completeness: dict[str, Any] = Field(default_factory=dict)


@dataclass
class ParsedDomainWhois:
    created_date: str | None = None
    domain_age: str | None = None
    registrar: str | None = None
    nameservers: list[str] | None = None


# Initialize stealth module (proxy + rate limiting) at app startup
# Set HTTP_PROXY / HTTPS_PROXY env vars to enable proxy support
setup_stealth()

app = FastAPI(title=APP_NAME, version="1.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "null",
    ],
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1):\d+$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "online", "service": APP_NAME}


@app.get("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_get(target: str = Query(min_length=3, max_length=2048)) -> AnalyzeResponse:
    return await run_analysis(target)


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_post(request: AnalyzeRequest = Body(...)) -> AnalyzeResponse:
    return await run_analysis(request.url)

@app.post("/api/v1/ai-analysis")
async def ai_analysis(payload: dict):
    url = payload.get("url")

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL is required"
        )

    raw_context = payload.get("raw_context", "")

    if not raw_context:
        raise HTTPException(
            status_code=400,
            detail="No RAW_TXT_LOG available. Run ANALYZE first."
        )

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="Gemini API key not loaded"
        )

    prompt = f"""
    You are a Senior SOC Cybersecurity Analyst.

    Analyze ONLY the raw evidence.

    STRICT RULES:
    - DO NOT use risk_score
    - DO NOT use XGBoost
    - DO NOT use heuristics
    - ONLY use raw evidence

    Tasks:
    1. Explain whether SAFE / SUSPICIOUS / PHISHING
    2. Explain WHY
    3. Detect false positives
    4. Explain infrastructure behavior
    5. Explain SSL/DNS/WHOIS findings
    6. Highlight suspicious indicators
    7. Human-friendly SOC report

    RAW EVIDENCE:

    {raw_context}
    """

    client = genai.Client(api_key=api_key)

    try:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model="gemini-2.5-flash",
            contents=prompt,
        )

        ai_text = getattr(response, "text", "")

    except Exception as e:
        ai_text = f"""
AI Analysis temporarily unavailable.

Reason:
{str(e)}

Possible fixes:
- Wait a few minutes
- Create a new Gemini API key
- Upgrade Gemini quota
"""

    return {
        "formatted_report": ai_text
    }


def score_security_headers(headers: dict[str, Any] | list[HeaderStatus]) -> tuple[int, list[str]]:
    details = headers if isinstance(headers, list) else [
        HeaderStatus(name=name, enabled=bool(enabled), effective=bool(enabled), status="STRONG" if enabled else "MISSING", strength="STRONG" if enabled else "MISSING")
        for name, enabled in headers.items()
    ]
    score = 0
    reasons: list[str] = []
    for header in details:
        if header.name in OPTIONAL_HEADER_NAMES:
            continue
        weight = HEADER_SCORE_WEIGHTS.get(header.name, 0)
        if header.status == "MISSING":
            score += weight
            reasons.append(f"SECURITY HEADER: {header.name} is missing ({header.recommendation or 'review header posture'}).")
        elif header.status in {"WEAK", "MISCONFIGURED"}:
            score += max(1, weight // 2)
            reasons.append(f"SECURITY HEADER: {header.name} is {header.status.lower()} ({header.evidence}).")
        elif header.status == "REPORT_ONLY" and header.name == "Content-Security-Policy":
            score += 2
            reasons.append("SECURITY HEADER: CSP is report-only and does not enforce browser controls.")
    return clamp_score(score), reasons


def classify_score(score: int) -> str:
    """Legacy classification aligned with THREAT_LEVELS from scoring.py."""
    if score >= 71:
        return "CRITICAL"
    if score >= 46:
        return "HIGH RISK"
    if score >= 26:
        return "SUSPICIOUS"
    if score >= 11:
        return "LOW RISK"
    return "SAFE"


def combine_analysis_scores(
    heuristic_score: int,
    header_score: int,
    ai_score: int | None,
    xgb_res: dict[str, Any],
    # Domain context for the new hybrid scoring engine (optional, backward compatible)
    domain: str = "",
    age_days: int | None = None,
    registrar: str | None = None,
    ssl_issuer: str | None = None,
    asn: str | None = None,
    hosting: str | None = None,
    has_dnssec: bool = False,
    has_valid_ssl: bool = False,
    has_mx: bool = False,
    has_nameservers: bool = False,
    privacy_protected: bool = False,
    suspicious_registrar: bool = False,
    is_ip_like: bool = False,
    has_typosquatting: bool = False,
    typosquatting_score: float = 0.0,
    has_homoglyph: bool = False,
    homoglyph_count: int = 0,
    has_digit_substitution: bool = False,
    has_combosquatting: bool = False,
    has_brand_only: bool = False,
    suspicious_tld: bool = False,
    tld: str = "",
    excessive_subdomains: bool = False,
    dark_web_tld: bool = False,
    has_password_form: bool = False,
    has_external_form_action: bool = False,
    # NEW v2.0 SIGNALS
    has_abused_infrastructure: bool = False,
    abused_infra_risk: float = 0.0,
    has_subdomain_phishing: bool = False,
    has_suspicious_url_path: bool = False,
    url_path_risk: float = 0.0,
    has_suspicious_redirect: bool = False,
    redirect_hop_count: int = 0,
    has_punycode_homograph: bool = False,
    homograph_brand: str | None = None,
    has_ssl_expired: bool = False,
    has_ssl_self_signed: bool = False,
    has_ssl_hostname_mismatch: bool = False,
    has_ssl_revoked: bool = False,
    has_ssl_untrusted_root: bool = False,
    has_ssl_weak_protocol: bool = False,
    has_ssl_weak_cipher: bool = False,
    findings: list[str] | None = None,
    # Tool failure flags: tool failures must NEVER be treated as domain risk
    ssl_unavailable: bool = False,
    headers_unavailable: bool = False,
    
    # v3.0: Threat feed and ensemble signals for confidence
    threat_feed_score: float = 0.0,
    threat_feed_count: int = 0,
    threat_feed_flagged_count: int = 0,
    ensemble_model_count: int = 0,
    ensemble_agreement: int = 0,
    ensemble_result: dict[str, Any] | None = None,
    data_completeness: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], list[str]]:
    """
    Combine analysis scores into a final hybrid risk score.

    Uses the new scoring engine from scoring.py when domain context is provided,
    falling back to the legacy algorithm for backward compatibility.
    """
    # If domain context is provided, use the new hybrid scoring engine
    if domain:
        return compute_hybrid_score(
            domain=domain,
            heuristic_score=heuristic_score,
            header_score=header_score,
            xgb_res=xgb_res,
            ai_score=ai_score,
            age_days=age_days,
            registrar=registrar,
            ssl_issuer=ssl_issuer,
            asn=asn,
            hosting=hosting,
            has_dnssec=has_dnssec,
            has_valid_ssl=has_valid_ssl,
            has_mx=has_mx,
            has_nameservers=has_nameservers,
            privacy_protected=privacy_protected,
            suspicious_registrar=suspicious_registrar,
            is_ip_like=is_ip_like,
            has_typosquatting=has_typosquatting,
            typosquatting_score=typosquatting_score,
            has_homoglyph=has_homoglyph,
            homoglyph_count=homoglyph_count,
            has_digit_substitution=has_digit_substitution,
            has_combosquatting=has_combosquatting,
            has_brand_only=has_brand_only,
            suspicious_tld=suspicious_tld,
            tld=tld,
            excessive_subdomains=excessive_subdomains,
            dark_web_tld=dark_web_tld,
            has_password_form=has_password_form,
            has_external_form_action=has_external_form_action,
            # NEW v2.0
            has_abused_infrastructure=has_abused_infrastructure,
            abused_infra_risk=abused_infra_risk,
            has_subdomain_phishing=has_subdomain_phishing,
            has_suspicious_url_path=has_suspicious_url_path,
            url_path_risk=url_path_risk,
            has_suspicious_redirect=has_suspicious_redirect,
            redirect_hop_count=redirect_hop_count,
            has_punycode_homograph=has_punycode_homograph,
            homograph_brand=homograph_brand,
            has_ssl_expired=has_ssl_expired,
            has_ssl_self_signed=has_ssl_self_signed,
            has_ssl_hostname_mismatch=has_ssl_hostname_mismatch,
            has_ssl_revoked=has_ssl_revoked,
            has_ssl_untrusted_root=has_ssl_untrusted_root,
            has_ssl_weak_protocol=has_ssl_weak_protocol,
            has_ssl_weak_cipher=has_ssl_weak_cipher,
            # Tool failure flags: pass through from caller
            ssl_unavailable=ssl_unavailable,
            headers_unavailable=headers_unavailable,
            
            # v3.0: threat feed + ensemble signals for confidence
            threat_feed_score=threat_feed_score,
            threat_feed_count=threat_feed_count,
            threat_feed_flagged_count=threat_feed_flagged_count,
            ensemble_model_count=ensemble_model_count,
            ensemble_agreement=ensemble_agreement,
            ensemble_result=ensemble_result,
            data_completeness=data_completeness,
        )

    # Legacy fallback (when no domain context is provided)
    xgb_available = bool(xgb_res.get("xgb_available"))
    xgb_score = float(xgb_res.get("xgb_score", 0.0) or 0.0) if xgb_available else None
    xgb_verdict = str(xgb_res.get("xgb_verdict", "") or "").lower()

    combined = float(heuristic_score)
    combined += min(header_score * 0.8, 16)

    # ML is a supporting signal. A "legitimate" ML verdict should not erase
    # concrete WHOIS/HTTP/header/SSL evidence gathered during the live probe.
    if xgb_available and xgb_score is not None:
        if xgb_verdict == "phishing":
            combined += min(xgb_score * 0.18, 18)
        elif xgb_verdict == "suspicious":
            combined += min(xgb_score * 0.12, 12)
        elif xgb_verdict == "legitimate":
            if heuristic_score < 15 and header_score < 8:
                combined -= min((100 - xgb_score) * 0.04, 5)
            elif heuristic_score < 25:
                combined -= min((100 - xgb_score) * 0.02, 3)

    # AI is confidence-only. Low AI/fallback scores do not subtract from live evidence.
    if ai_score is not None:
        if ai_score >= 80:
            combined += 6
        elif ai_score >= 60:
            combined += 3

    floor_reasons: list[str] = []

    # Only extreme evidence should force high-risk
    strong_signals = 0

    if xgb_available and xgb_verdict == "phishing" and (xgb_score or 0) >= 80:
        strong_signals += 1

    if ai_score is not None and ai_score >= 85:
        strong_signals += 1

    if heuristic_score >= 75:
        strong_signals += 1

    # Require multiple indicators before forcing high-risk
    if strong_signals >= 2:
        combined = max(combined, 75.0)
        floor_reasons.append(
            "MULTI-SIGNAL RISK: Multiple independent engines detected high-risk behavior."
        )

    final_score = clamp_score(round(combined))
    if xgb_available and xgb_verdict == "legitimate" and (xgb_score or 0) <= 30 and heuristic_score < 15 and header_score < 8:
        final_score = min(final_score, 29)
        floor_reasons.append("FALSE POSITIVE GUARD: ML profile is legitimate and only weak evidence was observed; score capped below suspicious.")
    components = {
        "heuristic_analysis": heuristic_score,
        "security_headers": header_score,
        "xgboost_ml": xgb_score,
        "ai_analysis": ai_score,
        "signal_strength": {
            "heuristic_analysis": "PRIMARY",
            "security_headers": "SUPPORTING",
            "xgboost_ml": "SUPPORTING",
            "ai_analysis": "CONFIDENCE BOOST",
        },
        "final_score": final_score,
    }
    return final_score, components, floor_reasons

def _normalize_country(raw: str | None) -> str | None:
    """Normalize a country string to a 2-letter ISO code."""
    if not raw:
        return None
    s = raw.strip().strip(".").strip()
    if len(s) == 2:
        return s.upper()
    if len(s) == 3:
        # Might be a 3-letter code or abbreviation
        up = s.upper()
        # Check if the full name maps to a code
        for name, code in _COUNTRY_NAME_TO_CODE.items():
            if up == code or name == s.lower():
                return code
        return up
    return _COUNTRY_NAME_TO_CODE.get(s.lower(), s[:2].upper() if s else None)

def _values_for(blocks: list[dict[str, Any]], header_name: str) -> list[tuple[int, str | None, str]]:
    key = header_name.lower()
    values: list[tuple[int, str | None, str]] = []
    for block in blocks:
        for value in block.get("headers", {}).get(key, []):
            values.append((int(block.get("redirect_index", 0)), block.get("url"), value))
    return values

def classify_header(name: str, values: list[tuple[int, str | None, str]], report_only_values: list[tuple[int, str | None, str]] | None = None) -> HeaderStatus:
    report_only_values = report_only_values or []
    redirect_index, source_url, value = _source_from(values)
    evidence = ""
    recommendation = ""
    status = "MISSING"
    effective = False

    if name == "Strict-Transport-Security":
        if value:
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", value, flags=re.IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age >= 15_552_000:
                status, effective = "STRONG", True
                evidence = f"HSTS max-age={max_age}"
            elif max_age > 0:
                status, effective = "WEAK", True
                evidence = f"HSTS max-age={max_age} is below 180 days"
            else:
                status = "MISCONFIGURED"
                evidence = "HSTS present without valid max-age"
            recommendation = "Use max-age of at least 15552000; includeSubDomains/preload when operationally safe."
        else:
            recommendation = "Add HSTS on HTTPS responses after validating subdomain readiness."

    elif name == "Content-Security-Policy":
        ro_index, ro_url, ro_value = _source_from(report_only_values)
        if value:
            low = value.lower()
            if "default-src" in low and ("'unsafe-inline'" not in low or "script-src" in low):
                status, effective = "STRONG", True
                evidence = "Enforced CSP contains baseline source restrictions"
            else:
                status, effective = "WEAK", True
                evidence = "Enforced CSP exists but appears permissive"
            recommendation = "Keep CSP enforced; avoid unsafe-inline/unsafe-eval and define script/object/base-uri policies."
        elif ro_value:
            status = "REPORT_ONLY"
            redirect_index, source_url, value = ro_index, ro_url, ro_value
            evidence = "CSP is report-only; browser enforcement is not active"
            recommendation = "Move validated report-only policy to enforced Content-Security-Policy."
        else:
            recommendation = "Add an enforced CSP appropriate to the application."

    elif name == "Content-Security-Policy-Report-Only":
        if value:
            status = "REPORT_ONLY"
            evidence = "Report-only CSP telemetry header present"
            recommendation = "Use report-only for rollout telemetry, not as a substitute for enforced CSP."
        else:
            status = "OPTIONAL"
            recommendation = "Optional: add report-only CSP while tuning a future enforced policy."

    elif name == "X-Frame-Options":
        if value and value.upper() in {"DENY", "SAMEORIGIN"}:
            status, effective = "STRONG", True
            evidence = f"X-Frame-Options={value.upper()}"
            recommendation = "Keep DENY/SAMEORIGIN or enforce frame-ancestors in CSP."
        elif value:
            status = "MISCONFIGURED"
            evidence = f"Unsupported X-Frame-Options value: {value}"
            recommendation = "Use DENY or SAMEORIGIN, or use CSP frame-ancestors."
        else:
            recommendation = "Add X-Frame-Options or CSP frame-ancestors for clickjacking defense."

    elif name == "X-XSS-Protection":
        if value:
            status = "DEPRECATED"
            evidence = "Legacy browser XSS filter header is present"
        else:
            status = "DEPRECATED"
            evidence = "Header is deprecated and absence is not a modern security failure"
        recommendation = "Rely on CSP and output encoding; do not use this as a positive security signal."

    elif name == "X-Content-Type-Options":
        if value and value.lower() == "nosniff":
            status, effective = "STRONG", True
            evidence = "nosniff prevents MIME type confusion"
        elif value:
            status = "MISCONFIGURED"
            evidence = f"Unexpected value: {value}"
        recommendation = "Set X-Content-Type-Options: nosniff."

    elif name == "Referrer-Policy":
        strong = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
        if value and value.lower() in strong:
            status, effective = "STRONG", True
            evidence = f"Referrer-Policy={value}"
        elif value:
            status, effective = "WEAK", True
            evidence = f"Permissive referrer policy: {value}"
        recommendation = "Prefer strict-origin-when-cross-origin or stricter."

    elif name in OPTIONAL_HEADER_NAMES:
        if value:
            status, effective = "STRONG", True
            evidence = f"{name} present"
        else:
            status = "OPTIONAL"
            evidence = "Context-dependent isolation/privacy header not observed"
        recommendation = "Optional for many sites; enable when isolation or policy control is required."

    return HeaderStatus(
        name=name,
        enabled=effective,
        effective=effective,
        status=status,
        strength=status,
        value=value,
        evidence=evidence or ("Header present" if value else "Header not observed"),
        recommendation=recommendation,
        redirect_index=redirect_index,
        source_url=source_url,
    )

def detect_typosquatting(domain: str) -> str | None:
    label = domain.split(".", 1)[0].lower()

    normalized = (
        label.translate(
            str.maketrans({
                "0": "o",
                "1": "l",
                "3": "e",
                "4": "a",
                "5": "s",
                "7": "t",
                "@": "a",
                "$": "s",
            })
        )
        .replace("-", "")
    )

    for brand in KNOWN_BRANDS:

        # Homoglyph / substitution detection
        if normalized == brand and label != brand:
            return (
                f"The domain visually resembles {brand}.com "
                f"through character substitution or hyphenation "
                f"and may attempt credential theft."
            )

        # Brand + suspicious keywords
        if (
            brand in normalized
            and normalized != brand
            and any(
                keyword in normalized
                for keyword in [
                    "login",
                    "signin",
                    "verify",
                    "secure",
                    "account",
                    "auth",
                    "support",
                    "update",
                    "wallet",
                    "pay",
                ]
            )
        ):
            return (
                f"The domain embeds the brand string "
                f"{brand} with extra login/support/security wording."
            )

        # One-character typo detection
        if (
            levenshtein_distance(normalized, brand) == 1
            and normalized != brand
        ):
            return (
                f"The domain is one edit away from "
                f"{brand}.com, consistent with "
                f"missing/extra/swapped character impersonation."
            )

    return None

def extract_ai_score(text: str) -> int | None:
    match = re.search(r"RISK_SCORE\s*:\s*(\d{1,3})", text or "", flags=re.IGNORECASE)
    return clamp_score(int(match.group(1))) if match else None

def extract_nameservers(text: str) -> list[str]:
    servers: list[str] = []
    for match in re.finditer(r"(?im)^\s*(?:Name Server|nserver|Nameservers?)\s*:\s*([a-z0-9.-]+)", text or ""):
        server = match.group(1).strip().rstrip(".").lower()
        if server and server not in servers:
            servers.append(server)
    return servers

def fallback_ai_report(findings: list[str], score: int) -> str:
    severity = classify_score(score)
    finding_lines = "\n".join(f"- {finding}" for finding in findings)
    return f"""# RETRO_INTEL SOC Evaluation Log

## Executive Severity
{severity}

## Key Findings
{finding_lines}

## Threat Intelligence Assessment
Local heuristic SOC engine completed the dossier using collected DNS, WHOIS, SSL, HTTP header, reachability, and exposed-port evidence. The verdict is evidence-driven and intentionally conservative: suspicious infrastructure signals raise the score, while long-lived domains and HTTPS enforcement only provide limited trust improvement.

## Recommendations
- Validate brand ownership and business context before trusting the domain.
- Investigate any exposed administrative or alternate web ports.
- Add missing security headers, especially CSP and clickjacking protection.
- Treat dead-host or blocked-analysis behavior as an investigation lead, not as proof of safety.

RISK_SCORE: {clamp_score(score)}
"""

def find_first_field(text: str, labels: list[str]) -> str | None:
    # WHOIS registries vary wildly, so labels are tried as multiline anchored fields before loose fallbacks.
    for label in labels:
        pattern = rf"(?im)^\s*{re.escape(label)}\s*:\s*(.+?)\s*$"
        match = re.search(pattern, text or "")
        if match and match.group(1).strip():
            return normalize_whois_value(match.group(1))
    for label in labels:
        pattern = rf"(?is)\b{re.escape(label)}\s*:\s*([^\r\n#]+)"
        match = re.search(pattern, text or "")
        if match and match.group(1).strip():
            return normalize_whois_value(match.group(1))
    return None

def human_age(created_iso: str | None) -> str | None:
    if not created_iso:
        return None
    try:
        created = datetime.fromisoformat(created_iso).replace(tzinfo=UTC)
    except ValueError:
        return None
    delta_days = max((datetime.now(UTC) - created).days, 0)
    if delta_days >= 365:
        years = delta_days // 365
        return f"{years} year{'s' if years != 1 else ''}"
    if delta_days >= 30:
        months = delta_days // 30
        return f"{months} month{'s' if months != 1 else ''}"
    return f"{delta_days} day{'s' if delta_days != 1 else ''}"

def is_trusted_infrastructure(domain: str, parsed_meta: dict[str, Any], age_days: int | None) -> bool:
    text = " ".join(
        str(v).lower()
        for v in [
            domain,
            parsed_meta.get("hosting_space"),
            parsed_meta.get("registrar"),
            parsed_meta.get("ssl_issuer"),
            parsed_meta.get("asn"),
        ]
        if v
    )
    mature = age_days is None or age_days >= 365
    return mature and any(keyword in text for keyword in TRUSTED_INFRA_KEYWORDS)

def normalize_date(raw: str) -> str | None:
    if not raw:
        return None
    value = raw.strip()
    iso_match = re.search(r"\b(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?!\d)", value)
    if iso_match:
        year, month, day = [int(part) for part in iso_match.groups()]
        return safe_iso_date(year, month, day)
    dmy_match = re.search(r"\b(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})\b", value)
    if dmy_match:
        day, month, year = [int(part) for part in dmy_match.groups()]
        return safe_iso_date(year, month, day)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed:
            return parsed.date().isoformat()
    except Exception:
        return None
    return None

def normalize_whois_value(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip(" \t\r\n")

def parse_header_blocks(stdout: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    redirect_index = -1

    for raw_line in (stdout or "").splitlines():
        line = raw_line.rstrip("\r")
        status_match = re.match(r"^HTTP/\S+\s+(\d{3})", line, flags=re.IGNORECASE)
        if status_match:
            if current:
                blocks.append(current)
            redirect_index += 1
            current = {
                "status_code": int(status_match.group(1)),
                "headers": {},
                "url": None,
                "redirect_index": redirect_index,
            }
            continue
        if current is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        header_key = key.strip().lower()
        header_value = value.strip()
        if not header_key:
            continue
        current["headers"].setdefault(header_key, []).append(header_value)
        if header_key == "location":
            current["url"] = header_value

    if current:
        blocks.append(current)
    return blocks

def ping_dead(stdout: str) -> bool:
    text = stdout or ""
    return bool(re.search(r"100%\s*(?:packet\s*)?loss|lost\s*=\s*3\s*\(100%\s*loss\)", text, flags=re.IGNORECASE))


def clean_domain(raw_target: str) -> str:
    """Extract a clean domain from a raw URL or domain string."""
    target = raw_target.strip()
    # Remove protocol prefix
    if "://" in target:
        target = target.split("://", 1)[1]
    # Remove path, query, fragment
    if "/" in target:
        target = target.split("/", 1)[0]
    # Remove port
    if ":" in target:
        target = target.split(":", 1)[0]
    # Remove trailing dot
    target = target.rstrip(".")
    # Lowercase
    target = target.lower()
    return target


async def run_analysis(raw_target: str) -> AnalyzeResponse:
    domain = clean_domain(raw_target)
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid public domain format.")

    dns_a = await run_command("dig", ["dig", domain, "A", "+short"])
    primary_ip = first_ipv4(dns_a.stdout) or await socket_fallback_ip(domain)

    dns_mx_task = run_command("mx", ["dig", domain, "MX", "+short"])
    domain_whois_task = run_command("domain_whois", ["whois", domain])
    ssl_task = run_openssl_probe(domain, primary_ip is not None)
    # HTTP header retrieval: use stealth-enhanced Python _do_curl with full
    # browser headers (rotating User-Agent, Accept, Accept-Language, DNT, etc.)
    # so CDN edge servers serve complete security headers.
    # Falls back to curl CLI if the Python method fails.
    curl_task = _run_stealth_curl(domain)
    nc_task = run_command(
        "nc",
        ["nc", "-zv", "-w", "2", domain, *[str(port) for port in COMMON_PORTS]],
        merge_stderr=True,
    )
    ping_task = run_command("ping", platform_ping_command(domain), timeout=3, merge_stderr=True)

    # Also store the original domain as a hint for IP fallback
    # The fallback_ip_whois can use domain_hint for CDN/PTR inference
    ip_whois_task = (
        run_command("ip_whois", ["whois", primary_ip])
        if primary_ip
        else skipped_command("ip_whois", ["whois", "<primary_ip>"], "Domain did not resolve to IPv4; IP WHOIS skipped.")
    )

    dns_mx, ip_whois, domain_whois, ssl_result, curl_result, nc_result, ping_result = await asyncio.gather(
        dns_mx_task,
        ip_whois_task,
        domain_whois_task,
        ssl_task,
        curl_task,
        nc_task,
        ping_task,
    )

    parsed_ip = parse_ip_whois(ip_whois.stdout)
    parsed_domain = parse_domain_whois(domain_whois.stdout)
    ssl_data = parse_ssl(ssl_result.stdout or ssl_result.stderr or ssl_result.error or "")
    header_details = parse_headers(curl_result.stdout)
    header_map = {header.name: header.effective for header in header_details}
    http_status = parse_final_status(curl_result.stdout)
    open_ports = parse_open_ports(nc_result.stdout or nc_result.stderr)
    raw_logs = {
        "dig": dns_a.stdout or dns_a.stderr or dns_a.error or "",
        "mx": dns_mx.stdout or dns_mx.stderr or dns_mx.error or "",
        "ip_whois": ip_whois.stdout or ip_whois.stderr or ip_whois.error or "",
        "domain_whois": domain_whois.stdout or domain_whois.stderr or domain_whois.error or "",
        "ssl": ssl_result.stdout or ssl_result.stderr or ssl_result.error or "",
        "curl": curl_result.stdout or curl_result.stderr or curl_result.error or "",
        "nc": nc_result.stdout or nc_result.stderr or nc_result.error or "",
        "ping": ping_result.stdout or ping_result.stderr or ping_result.error or "",
    }
    dns_data = {
        "mx_records": compact_lines(dns_mx.stdout),
        "nameservers": parsed_domain.nameservers or [],
        "a_records": compact_lines(dns_a.stdout),
    }
    parsed_meta = {
        "hosting_space": parsed_ip.get("hosting_space") or "N/A",
        "domain_age": parsed_domain.domain_age or "N/A",
        "created_date": parsed_domain.created_date or "N/A",
        "asn": parsed_ip.get("asn") or "N/A",
        "country": parsed_ip.get("country") or "N/A",
        "http_status": http_status,
        "ssl_issuer": ssl_data["issuer"] or "N/A",
        "registrar": parsed_domain.registrar or "N/A",
    }
    website_result = {}
    if inspect_website:
        try:
            website_result = await asyncio.to_thread(inspect_website, f"https://{domain}", 2.5)
        except Exception as exc:
            website_result = {"available": False, "source": "error", "error": str(exc)}

    # ---- TOOL FAILURE DETECTION ----
    # Check stdout content because fallback functions return error strings
    # with status="ok" (they catch exceptions internally).
    # SSL probe succeeds iff stdout starts with "issuer="
    _ssl_out = (ssl_result.stdout or "").strip()
    ssl_unavailable = not _ssl_out.startswith("issuer=")
    # HTTP header fetch succeeds iff stdout starts with "HTTP/1.1" or "HTTP/2"
    _curl_out = (curl_result.stdout or "").strip()
    headers_unavailable = not (_curl_out.startswith("HTTP/1.") or _curl_out.startswith("HTTP/2"))


    findings, heuristic_score = analyze_threat_intel(
        domain=domain,
        primary_ip=primary_ip,
        parsed_meta=parsed_meta,
        security_headers=header_map,
        open_ports=open_ports,
        dns_data=dns_data,
        raw_logs=raw_logs,
        ssl_status=ssl_result.status,
        http_status=http_status,
        website_result=website_result,
        ssl_unavailable=ssl_unavailable,
        headers_unavailable=headers_unavailable,
    )
    commands = {result.name: result for result in [dns_a, dns_mx, ip_whois, domain_whois, ssl_result, curl_result, nc_result, ping_result]}
    raw_context = build_context(domain, primary_ip, parsed_meta, header_map, open_ports, dns_data, findings, commands, website_result)

    # ---- TOOL FAILURE FINDINGS ----
    # Tool/collection failures must be classified as INFO, never as risk findings
    # Only the failure reason is displayed; no risk points are added.
    for _cmd_name, _cmd in [("SSL", ssl_result), ("HTTP", curl_result), ("WHOIS", domain_whois)]:
        if _cmd.status != "ok":
            _reason = _cmd.error or _cmd.stderr or _cmd.status
            _line = f"INFO: {_cmd_name} data unavailable — {_reason}"
            if _line not in findings:
                findings.append(_line)
    
    # Compute header score (fast, synchronous)
    header_score, header_findings = score_security_headers(header_details)
    for finding in header_findings:
        add_finding(findings, finding)
    
    # Run XGBoost ML prediction (fast, CPU-bound, synchronous)
    has_valid_ssl_for_ml = bool(ssl_data.get("issuer"))
    has_mx_val = bool(dns_data.get("mx_records"))
    has_asn_for_ml = bool(parsed_meta.get("asn") and parsed_meta["asn"] != "N/A")
    xgb_res = {"xgb_available": False}
    _ens_feature_vector = None
    try:
        xgb_res = get_ml_prediction(domain, parsed_domain, domain_whois.stdout,
                                     has_valid_ssl_for_ml, has_mx_val, has_asn_for_ml, header_score)
        _ens_feature_vector = xgb_res.pop("feature_vector", None)
    except Exception as e:
        print("ML prediction execution failed:", e)
    
    # Start AI analysis task (runs in parallel with v2.0 engines below)
    ai_task = asyncio.create_task(run_ai_core(raw_context, findings, heuristic_score))

    # v3.0: Start threat intelligence feed checks (runs in parallel)
    _threat_feed_task = None
    if THREAT_INTEL_AVAILABLE:
        try:
            _threat_feed_task = asyncio.create_task(
                asyncio.to_thread(
                    run_all_feeds,
                    domain=domain,
                    ip=primary_ip or "",
                    website_url=f"https://{domain}",
                )
            )
        except Exception:
            _threat_feed_task = None

    # Extract domain info for the new hybrid scoring engine
    age_days_val = domain_age_days(parsed_meta.get("created_date") if parsed_meta.get("created_date") != "N/A" else None)
    has_valid_ssl_val = bool(parsed_meta.get("ssl_issuer") and parsed_meta["ssl_issuer"] != "N/A")
    has_ns_val = bool(dns_data.get("nameservers"))
    findings_text = " ".join(str(f).upper() for f in findings)
    
    # Extract structured signals from findings text
    has_typo = "TYPOSQUATTING" in findings_text or "IMPERSONATION" in findings_text
    has_homoglyph = "HOMOGLYPH" in findings_text or "CONFUSABLE" in findings_text or "UNICODE" in findings_text
    homoglyph_count_val = 0
    if has_homoglyph:
        for f in findings:
            m = re.search(r"suspicious char\(s\)\.?\s*(\d+)", f, re.IGNORECASE)
            if m:
                homoglyph_count_val = max(homoglyph_count_val, int(m.group(1)))
        if homoglyph_count_val == 0:
            homoglyph_count_val = 2  # reasonable default when homoglyph is detected
    has_combo = "COMBO-SQUATTING" in findings_text or "BRAND + PHISHING" in findings_text or "BRAND+KEYWORD" in findings_text
    has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    is_ip_like_flag = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))
    has_privacy = "PRIVACY" in findings_text or "REDACTED" in findings_text or "WHOIS PRIVACY" in findings_text
    has_suspicious_reg = "SUSPICIOUS REGISTRAR" in findings_text
    excessive_subdomains_flag = "EXCESSIVE SUBDOMAIN" in findings_text or "SUBDOMAIN DEPTH" in findings_text
    dark_web = any(domain.endswith(tld) for tld in [".onion", ".i2p", ".bit"])
    has_password = bool(website_result and website_result.get("signals", {}).get("has_password_input"))
    has_external_form = bool(website_result and website_result.get("signals", {}).get("external_form_actions"))
    
    # Extract TLD
    parts = domain.split(".")
    tld_val = parts[-1] if len(parts) >= 2 else ""
    
    # Simple default for detected typosquatting
    typo_score = 0.85 if has_typo else 0.0
    
    # ---- Detect digit substitution directly from domain ----
    # The typosquatting detection in findings may not explicitly use the keyword
    # "HOMOGLYPH" or "DIGIT SUBSTITUTION". Check the domain label itself for
    # digits that are confusable with letters (0->o, 1->l, 3->e, 4->a, 5->s, 7->t).
    DIGIT_CONFUSABLES = "0134567"
    domain_label = parts[0] if parts else ""
    has_digit_substitution_flag = False
    if has_typo:
        # If the domain was flagged as typosquatting AND contains digit confusables
        digit_count = sum(1 for c in domain_label if c in DIGIT_CONFUSABLES)
        if digit_count > 0:
            has_digit_substitution_flag = True
            # Also mark homoglyph if it wasn't already detected
            if not has_homoglyph:
                has_homoglyph = True
                homoglyph_count_val = digit_count
            elif homoglyph_count_val == 0:
                homoglyph_count_val = digit_count

    # ========================================================================
    # TMGC v2.0 — PARALLEL DETECTION ENGINES
    # ========================================================================
    # All I/O-bound v2.0 engines run in parallel for maximum performance.
    # Fast inline-only engines (abused infra, subdomain, punycode, URL path)
    # run immediately. Results are merged after all parallel tasks complete.
    
    # Fast inline engines (no I/O): Sections 2, 3, 4, 5
    abused_infra_result = {}
    has_abused_infrastructure = False
    abused_infra_risk = 0.0
    if utils_detect_abused_infrastructure is not None:
        try:
            abused_infra_result = utils_detect_abused_infrastructure(domain)
            has_abused_infrastructure = abused_infra_result.get("detected", False)
            abused_infra_risk = float(abused_infra_result.get("risk_contribution", 0))
            if has_abused_infrastructure:
                category = abused_infra_result.get("category", "unknown")
                infra_label = abused_infra_result.get("infrastructure_label", "Unknown")
                # Cap infrastructure abuse risk to avoid overweighting platform reputation
                # as domain reputation. Tunnel services and DynDNS are legitimate platforms
                # that CAN be abused — using them alone doesn't make a domain malicious.
                capped_risk = min(float(abused_infra_risk), 15.0)
                if category == "tunnel":
                    add_finding(findings, f"MEDIUM RISK: Domain uses a public tunnel service ({infra_label}). Infrastructure type: Public Tunnel Service.")
                    heuristic_score += int(capped_risk)
                elif category == "dyn_dns":
                    add_finding(findings, f"MEDIUM RISK: Domain uses dynamic DNS ({infra_label}). Infrastructure type: Dynamic DNS Provider.")
                    heuristic_score += int(capped_risk)
                elif category == "url_shortener":
                    add_finding(findings, f"LOW RISK: Domain is a URL shortener ({infra_label}). Infrastructure type: URL Shortener.")
                    heuristic_score += int(capped_risk)
                elif category == "free_hosting":
                    add_finding(findings, f"MEDIUM RISK: Domain uses free hosting ({infra_label}). Infrastructure type: Free Hosting Provider.")
                    heuristic_score += int(capped_risk)
                
                # Store the infrastructure type for frontend display
                infrastructure_type_label = {
                    "tunnel": "Public Tunnel Service",
                    "dyn_dns": "Dynamic DNS Provider",
                    "url_shortener": "URL Shortener",
                    "free_hosting": "Free Hosting Provider",
                }.get(category, infra_label)
        except Exception:
            pass
    
    subdomain_phishing_result = {}
    has_subdomain_phishing = False
    if utils_detect_subdomain_phishing is not None:
        try:
            subdomain_phishing_result = utils_detect_subdomain_phishing(domain)
            has_subdomain_phishing = subdomain_phishing_result.get("detected", False)
            if has_subdomain_phishing:
                brands = subdomain_phishing_result.get("brands_in_subdomains", [])
                registered = subdomain_phishing_result.get("registered_domain", "unknown")
                add_finding(findings, f"HIGH RISK: Brand impersonation via subdomain abuse — "
                    f"{', '.join(brands)} in subdomains but actual registered domain is '{registered}'.")
                heuristic_score += 40
        except Exception:
            pass
    
    punycode_result = {}
    has_punycode_homograph = False
    homograph_brand = None
    if utils_detect_punycode_homograph is not None:
        try:
            punycode_result = utils_detect_punycode_homograph(domain)
            has_punycode_homograph = punycode_result.get("has_punycode", False) and punycode_result.get("visual_impersonation", False)
            homograph_brand = punycode_result.get("impersonated_brand")
            if has_punycode_homograph:
                add_finding(findings, f"HIGH RISK: {punycode_result.get('warning', 'Punycode homograph attack detected')}")
                heuristic_score += 25
            elif punycode_result.get("has_punycode"):
                decoded = punycode_result.get("decoded", "")
                add_finding(findings, f"INFO: Domain uses punycode/IDN encoding (decoded: '{decoded}'). Potentially used for visual deception.")
                heuristic_score += 8
        except Exception:
            pass
    
    url_path_result = {}
    has_suspicious_url_path = False
    url_path_risk = 0.0
    if utils_detect_url_path_signals is not None:
        try:
            full_url = f"https://{domain}"
            url_path_result = utils_detect_url_path_signals(full_url)
            has_suspicious_url_path = url_path_result.get("has_suspicious_path", False)
            url_path_risk = float(url_path_result.get("path_risk_score", 0))
            if has_suspicious_url_path:
                keywords = url_path_result.get("matched_keywords", [])
                if keywords:
                    add_finding(findings, f"LOW RISK: URL path contains suspicious keywords: {', '.join(keywords[:5])}.")
                heuristic_score += int(url_path_risk)
        except Exception:
            pass

    # Parallel I/O-bound engines: SSL, Redirect, CT, DNS, Owner, Browser
    _v2_coros: list[tuple[str, Any]] = []
    _v2_keys: list[str] = []

    def _add_v2_task(key: str, coro: Any) -> None:
        _v2_keys.append(key)
        _v2_coros.append(coro)

    # Section 1: SSL/TLS (I/O bound)
    if utils_analyze_ssl_signals is not None:
        _add_v2_task("ssl", asyncio.to_thread(utils_analyze_ssl_signals, domain, 2.0))

    # Section 6: Redirect Chain (I/O bound)
    if utils_analyze_redirect_chain is not None:
        _add_v2_task("redirect", asyncio.to_thread(utils_analyze_redirect_chain, f"https://{domain}", 5, 3.0))

    # Section 7: Certificate Transparency logs (I/O bound)
    if utils_analyze_certificate_transparency is not None:
        _add_v2_task("ct", asyncio.to_thread(utils_analyze_certificate_transparency, domain, 3.0))

    # Section 8: DNS Records (I/O bound)
    if utils_analyze_dns_records is not None:
        _add_v2_task("dns", asyncio.to_thread(utils_analyze_dns_records, domain, 2.0))

    # Section 10: Owner Images (I/O bound)
    _whois_text = raw_logs.get("domain_whois", "")
    _website_text = (website_result.get("text_sample", "") or "") if isinstance(website_result, dict) else ""
    _add_v2_task("owner", asyncio.to_thread(analyze_owner_images, domain, _whois_text, _website_text, 2.0))

    # Section 11: Browser automation (I/O bound, only if available)
    if BROWSER_AUTO_AVAILABLE and analyze_dynamic_content is not None:
        _add_v2_task("browser", asyncio.to_thread(
            analyze_dynamic_content,
            url=f"https://{domain}",
            timeout=4.0,
            capture_network=True,
            capture_console=False,
            capture_storage=False,
            network_capture_ms=2000,
            stealth=True,
        ))

    # Run all parallel tasks simultaneously
    _v2_raw = []
    if _v2_coros:
        _v2_raw = await asyncio.gather(*_v2_coros, return_exceptions=True)
    _v2_results: dict[str, Any] = dict(zip(_v2_keys, _v2_raw))

    # --- Process Section 1: SSL results ---
    has_ssl_expired = False
    has_ssl_self_signed = False
    has_ssl_hostname_mismatch = False
    has_ssl_revoked = False
    has_ssl_untrusted_root = False
    has_ssl_weak_protocol = False
    has_ssl_weak_cipher = False
    ssl_v2_result = _v2_results.get("ssl", {}) or {}
    if isinstance(ssl_v2_result, dict) and ssl_v2_result:
        try:
            has_ssl_expired = ssl_v2_result.get("expired", False)
            has_ssl_self_signed = ssl_v2_result.get("self_signed", False)
            has_ssl_hostname_mismatch = ssl_v2_result.get("hostname_mismatch", False)
            has_ssl_revoked = ssl_v2_result.get("revoked", False)
            has_ssl_untrusted_root = ssl_v2_result.get("untrusted_root", False)
            has_ssl_weak_protocol = ssl_v2_result.get("weak_protocol", False)
            has_ssl_weak_cipher = ssl_v2_result.get("weak_cipher", False)
            
            if has_ssl_expired:
                add_finding(findings, "HIGH RISK: SSL certificate is EXPIRED — domain may be compromised or abandoned.")
                heuristic_score += 18
            if has_ssl_self_signed:
                add_finding(findings, "MEDIUM RISK: Self-signed SSL certificate — no chain of trust to a known CA.")
                heuristic_score += 12
            if has_ssl_hostname_mismatch:
                add_finding(findings, "HIGH RISK: SSL hostname mismatch — certificate was issued for a different domain.")
                heuristic_score += 15
            if has_ssl_revoked:
                add_finding(findings, "CRITICAL: SSL certificate has been REVOKED — indicates security compromise.")
                heuristic_score += 25
            if has_ssl_untrusted_root:
                add_finding(findings, "SUSPICIOUS: SSL certificate signed by an untrusted root CA.")
                heuristic_score += 10
            if has_ssl_weak_protocol:
                add_finding(findings, "LOW RISK: Weak TLS protocol version detected (TLS 1.0/1.1).")
                heuristic_score += 8
            if has_ssl_weak_cipher:
                add_finding(findings, "LOW RISK: Weak cipher suite detected (RC4/DES/MD5).")
                heuristic_score += 6
                
            ssl_has_no_issues = not (has_ssl_expired or has_ssl_self_signed or has_ssl_hostname_mismatch or has_ssl_revoked)
            has_any_ssl_error = bool(ssl_v2_result.get("ssl_error_type")) and ssl_v2_result["ssl_error_type"] not in ("connection_error", None)
            cert_found = ssl_v2_result.get("has_ssl", False) or has_any_ssl_error
            
            if cert_found and ssl_has_no_issues:
                has_valid_ssl_val = True
            elif cert_found and not ssl_has_no_issues:
                has_valid_ssl_val = False
            elif has_any_ssl_error:
                has_valid_ssl_val = False
        except Exception:
            pass

    # --- Process Section 6: Redirect results ---
    has_suspicious_redirect = False
    redirect_hop_count = 0
    redirect_result = _v2_results.get("redirect", {}) or {}
    if isinstance(redirect_result, dict) and redirect_result.get("suspicious"):
        try:
            has_suspicious_redirect = True
            redirect_hop_count = redirect_result.get("hop_count", 0)
            add_finding(findings, f"LOW RISK: {redirect_result.get('warning', 'Suspicious redirect chain detected')}")
            heuristic_score += min(10 + redirect_hop_count * 3, 30)
        except Exception:
            pass

    # --- Process Section 7: CT Log results ---
    ct_result = _v2_results.get("ct", {}) or {}
    if isinstance(ct_result, dict) and ct_result.get("available"):
        try:
            ct_subdomain_count = ct_result.get("subdomain_count", 0)
            ct_suspicious_issuers = ct_result.get("suspicious_issuers", [])
            has_ct_suspicious_recent = ct_result.get("suspicious_recent_issuance", False)
            ct_recent_issuance_risk = ct_result.get("recent_issuance_risk", 0)
            
            if ct_recent_issuance_risk >= 20:
                recent_certs = ct_result.get("recent_certs_90d", 0)
                total_certs = ct_result.get("total_certs", 0)
                add_finding(findings, (
                    f"MEDIUM RISK: Certificate Transparency shows {recent_certs} certificates "
                    f"issued in last 90 days ({total_certs} total) — "
                    f"potential rapid infrastructure churn or subdomain abuse."
                ))
                heuristic_score += ct_recent_issuance_risk
            
            if ct_suspicious_issuers and has_ct_suspicious_recent:
                add_finding(findings, (
                    f"SUSPICIOUS: Certificates recently issued by {', '.join(ct_suspicious_issuers[:3])} — "
                    f"these CAs are frequently abused for phishing infrastructure."
                ))
                heuristic_score += 15
            
            if ct_result.get("has_wildcard_cert"):
                add_finding(findings, f"INFO: Wildcard certificate detected for {domain} via CT logs — commonly used for legitimate subdomain services.")
            
            if ct_subdomain_count > 50:
                add_finding(findings, f"INFO: CT logs reveal {ct_subdomain_count} subdomains — large attack surface.")
            elif ct_subdomain_count > 10:
                add_finding(findings, f"INFO: CT logs reveal {ct_subdomain_count} subdomains — moderate subdomain footprint.")
        except Exception:
            pass

    # --- Process Section 8: DNS Records results ---
    dns_records_result = _v2_results.get("dns", {}) or {}
    if isinstance(dns_records_result, dict) and dns_records_result.get("available"):
        try:
            if dns_records_result.get("has_aaaa"):
                add_finding(findings, "INFO: Domain has IPv6 (AAAA) records — supports modern internet protocols.")
            
            if dns_records_result.get("has_spf"):
                add_finding(findings, "SAFE: SPF email authentication configured — reduces email spoofing risk.")
            else:
                add_finding(findings, "LOW RISK: No SPF record found — domain may be vulnerable to email spoofing.")
                heuristic_score += 4
            
            if dns_records_result.get("has_dkim"):
                add_finding(findings, "SAFE: DKIM email signing detected — email integrity protection enabled.")
            else:
                add_finding(findings, "LOW RISK: No DKIM signature detected — email authenticity not cryptographically signed.")
                heuristic_score += 3
            
            if dns_records_result.get("has_dmarc"):
                add_finding(findings, "SAFE: DMARC policy configured — domain protected against email spoofing.")
            else:
                add_finding(findings, "LOW RISK: No DMARC policy found — domain may be vulnerable to domain spoofing.")
                heuristic_score += 3
            
            if dns_records_result.get("has_wildcard_dns"):
                add_finding(findings, "MEDIUM RISK: Wildcard DNS is enabled — any subdomain resolves, frequently abused by phishing infrastructure.")
                heuristic_score += 12

            # Extract DNSSEC flag from DNS analysis
            has_dnssec = False
            if dns_records_result.get("has_dnssec", False):
                has_dnssec = True
                add_finding(findings, "SAFE: DNSSEC is enabled - DNS responses are cryptographically authenticated.")
            
            for pattern in dns_records_result.get("suspicious_patterns", []):
                if "MX" not in pattern or "no" not in pattern.lower():
                    if pattern not in [f for f in findings]:
                        add_finding(findings, f"DNS: {pattern}")
                        heuristic_score += 6
        except Exception:
            pass

    # Section 9: Subdomain Enumeration (depends on CT result)
    subdomain_enum_result = {}
    subdomain_enum_count = 0
    if utils_enumerate_subdomains is not None:
        try:
            subdomain_enum_result = utils_enumerate_subdomains(domain, ct_result=ct_result if isinstance(ct_result, dict) else {})
            if subdomain_enum_result.get("available") and subdomain_enum_result.get("subdomain_count", 0) > 0:
                subdomain_enum_count = subdomain_enum_result["subdomain_count"]
                resolved = subdomain_enum_result.get("resolved_count", 0)
                add_finding(findings, f"INFO: Discovered {subdomain_enum_count} subdomains via Certificate Transparency logs ({resolved} DNS-validated).")
        except Exception:
            pass

    # --- Process Section 10: Entity Attribution (Owner Images) results ---
    # Uses evidence-based attribution model — NEVER infers ownership from keyword matches alone.
    owner_image_result = _v2_results.get("owner", {}) or {}
    if isinstance(owner_image_result, dict):
        try:
            attribution_level = owner_image_result.get("attribution_level", "No Ownership Evidence")
            attribution_score = owner_image_result.get("attribution_score", 0)
            display_owner = owner_image_result.get("display_owner", False)
            attribution_evidence = owner_image_result.get("attribution_evidence", [])
            attribution_summary = owner_image_result.get("attribution_summary")
            raw_summary = owner_image_result.get("summary", "")

            # Override for hard-protected (verified organization) domains — runs BEFORE
            # the display_owner check so it applies even when WHOIS/GitHub lookups failed.
            # These are globally recognized organizations like Wikipedia, Google, etc.
            # We KNOW who owns them regardless of lookup results.
            if is_hard_protected(domain):
                attribution_score = 95
                attribution_level = "Verified Organization"
                display_owner = True
                attribution_evidence = ["Domain is on TMGC's verified trusted domain list.", "Globally recognized organization with established infrastructure."]
                attribution_summary = "Verified Organization — This domain is globally recognized. Entity attribution is confirmed via TMGC's verified trusted domain list."
                owner_image_result["attribution_score"] = 95
                owner_image_result["attribution_level"] = "Verified Organization"
                owner_image_result["attribution_severity"] = "verified"
                owner_image_result["display_owner"] = True
                owner_image_result["attribution_summary"] = attribution_summary
                owner_image_result["attribution_evidence"] = attribution_evidence

            # Always add the entity attribution finding
            if display_owner:
                # Only display owner info when evidence-based score >= 50
                add_finding(findings, (
                    f"ENTITY ATTRIBUTION: {attribution_level} (score: {attribution_score}/100). "
                    f"{attribution_summary or ''}"
                ))
                # Add individual evidence items
                for ev in attribution_evidence[:3]:
                    add_finding(findings, f"EVIDENCE: {ev}")

                # Add raw profiles as supplementary info                for gp in (owner_image_result.get("gravatar_profiles") or [])[:1]:
                    add_finding(findings, f"INFO: Gravatar profile found for {gp.get('email', '?')} (display: '{gp.get('display_name') or 'unknown'}')")
                gh = owner_image_result.get("github_profile")
                if gh:
                    add_finding(findings, f"INFO: GitHub {gh.get('type', 'profile')} '{gh.get('login', '?')}' ({gh.get('name') or gh.get('login', '?')}) associated with domain.")
                sm = owner_image_result.get("social_media")
                if sm and sm.get("profile_count", 0) > 0:
                    add_finding(findings, f"INFO: Social media presence detected on: {', '.join(sm.get('platforms_found', []))}.")
                
                if not has_typo:
                    heuristic_score -= 3
            else:
                # Score < 50 — do NOT claim ownership
                if attribution_level == "No Ownership Evidence" and attribution_score == 0:
                    add_finding(findings, (
                        f"ENTITY ATTRIBUTION: {attribution_level}. "
                        f"A GitHub or social media account with a similar name may exist, "
                        f"but no verified relationship between the account and this domain was discovered."
                    ))
                elif attribution_level in ("Possible Association", "No Ownership Evidence"):
                    add_finding(findings, f"ENTITY ATTRIBUTION: {attribution_level} (score: {attribution_score}/100). {attribution_summary or ''}")
                
                # Still show raw profile info for context (not as ownership)
                gh = owner_image_result.get("github_profile")
                if gh and not gh.get("ownership_verified", False):
                    add_finding(findings, (
                        f"INFO: GitHub {gh.get('type', 'profile')} '{gh.get('login', '?')}' "
                        f"username matches domain label but ownership NOT cross-verified. "
                        f"No website↔GitHub link or WHOIS org match was found."
                    ))
                
                # Show emails if discovered (not just probed)
                if owner_image_result.get("discovered_emails_count", 0) > 0:
                    emails = owner_image_result.get("emails_found", [])
                    if emails:
                        add_finding(findings, f"INFO: {owner_image_result['discovered_emails_count']} email address(es) discovered from WHOIS/website content.")
        except Exception:
            pass

    # --- Process Section 11: Browser Automation results ---
    browser_result = _v2_results.get("browser", {}) or {}
    if isinstance(browser_result, dict) and browser_result.get("available"):
        try:
            pc = browser_result.get("page_content", {}) or {}
            if pc.get("has_login_form"):
                add_finding(findings, "BROWSER: Credential harvesting form detected on landing page — password input found in rendered DOM.")
                heuristic_score += 12
            for iframe in (pc.get("iframes") or [])[:5]:
                add_finding(findings, f"BROWSER: Page embeds iframe: {iframe}")
            for form in (pc.get("forms") or [])[:3]:
                if form.get("has_password"):
                    action = form.get("action", "") or "(same page)"
                    add_finding(findings, f"BROWSER: Login form submits to: {action}")
            
            net = browser_result.get("network", {}) or {}
            suspicious_count = net.get("suspicious_requests", 0)
            if suspicious_count > 0:
                add_finding(findings, f"BROWSER: {suspicious_count} suspicious API endpoint(s) detected (login, auth, token, or credential-related).")
                heuristic_score += min(suspicious_count * 5, 15)
            if net.get("api_requests", 0) > 0:
                add_finding(findings, f"BROWSER: {net['api_requests']} API/XHR request(s) intercepted during page load.")
            
            hidden = browser_result.get("hidden_endpoints", {}) or {}
            if hidden.get("total_hidden", 0) > 0:
                add_finding(findings, f"BROWSER: {hidden['total_hidden']} hidden API endpoint(s) discovered via network interception.")
                for g in (hidden.get("graphql_endpoints") or [])[:3]:
                    add_finding(findings, f"BROWSER: GraphQL endpoint discovered: {g.get('url', '')[:80]}")
                for w in (hidden.get("websocket_endpoints") or [])[:3]:
                    add_finding(findings, f"BROWSER: WebSocket connection detected: {w.get('url', '')[:80]}")
                exfil = hidden.get("exfiltration_suspicions", [])
                if exfil:
                    add_finding(findings, f"BROWSER: Potential data exfiltration pattern detected in {len(exfil)} request(s).")
                    heuristic_score += min(len(exfil) * 6, 20)
            
            console = browser_result.get("console", {}) or {}
            if console.get("has_errors"):
                errors = console.get("errors", [])
                add_finding(findings, f"BROWSER: {len(errors)} JavaScript error(s) captured during page execution.")
                for err in errors[:3]:
                    add_finding(findings, f"BROWSER: JS Error: {err[:150]}")
            
            storage = browser_result.get("storage", {}) or {}
            if storage.get("tracking_cookies"):
                add_finding(findings, f"BROWSER: {len(storage['tracking_cookies'])} tracking/analytics cookie(s) detected.")
            if storage.get("local_storage_entries", 0) > 0:
                add_finding(findings, f"BROWSER: {storage['local_storage_entries']} localStorage entr(ies) found.")
            add_finding(findings, f"INFO: Browser automation completed successfully ({browser_result.get('execution_time', '?')}s).")
        except Exception:
            pass
    elif isinstance(browser_result, dict) and browser_result.get("error"):
        error = browser_result.get("error", "")
        if "playwright is not installed" not in error.lower():
            add_finding(findings, f"BROWSER: Dynamic analysis unavailable — {error[:100]}")

    # ========================================================================
    # v3.0: Fast-Flux and DGA Detection (Phase 5)
    # ========================================================================
    fast_flux_result: dict[str, Any] = {}
    dga_result: dict[str, Any] = {}
    if FAST_FLUX_DGA_AVAILABLE:
        try:
            _a_records = compact_lines(dns_a.stdout)
            _ns_records = parsed_domain.nameservers or []
            _mx_records = compact_lines(dns_mx.stdout)
            fast_flux_result = detect_fast_flux(
                domain=domain,
                a_records=_a_records,
                ns_records=_ns_records,
                mx_records=_mx_records,
            )
            if fast_flux_result.get("detected"):
                ff_risk = fast_flux_result.get("risk_contribution", 0)
                heuristic_score += ff_risk
                add_finding(findings, (
                    f"FAST-FLUX: {fast_flux_result.get('summary', 'Fast-flux pattern detected.')}"
                ))

            dga_result = detect_dga(domain)
            if dga_result.get("detected"):
                dga_risk = dga_result.get("risk_contribution", 0)
                heuristic_score += dga_risk
                add_finding(findings, (
                    f"DGA: {dga_result.get('summary', 'DGA pattern detected.')}"
                ))
        except Exception:
            pass

    # Await the AI analysis task that was launched in parallel with v2.0 engines
    try:
        ai_report, ai_score = await asyncio.wait_for(ai_task, timeout=12.0)
    except asyncio.TimeoutError:
        ai_report = "⚠ AI Analysis timed out after 12s"
        ai_score = None
    except Exception as exc:
        ai_report = f"⚠ AI Analysis failed: {exc}"
        ai_score = None

    # ========================================================================
    # v3.0: Process Threat Intelligence Feed Results
    # ========================================================================
    threat_intel_result: dict[str, Any] = {}
    threat_feed_score = 0.0
    threat_feed_findings_count = 0
    if _threat_feed_task is not None:
        try:
            threat_intel_result = await asyncio.wait_for(_threat_feed_task, timeout=15.0)
        except asyncio.TimeoutError:
            threat_intel_result = {"timed_out": True, "summary": "Threat intelligence feeds timed out after 15s."}
        except Exception:
            threat_intel_result = {}

    if isinstance(threat_intel_result, dict) and threat_intel_result.get("feeds"):
        feeds = threat_intel_result.get("feeds", [])
        flagged = threat_intel_result.get("flagged_feeds", [])
        feed_score = float(threat_intel_result.get("feed_score", 0))
        agreement_bonus = float(threat_intel_result.get("agreement_bonus", 0))
        flagged_count = int(threat_intel_result.get("flagged_count", 0))

        threat_feed_score = feed_score + agreement_bonus
        heuristic_score += int(min(threat_feed_score, 60))

        # Add findings for each flagged feed
        for f in flagged:
            feed_name = f.get("feed", "Unknown")
            reason = f.get("reason", "Flagged by threat intelligence feed")
            confidence = f.get("confidence", 0)
            add_finding(findings, f"THREAT FEED: {feed_name} flagged this domain (confidence: {confidence}%). {reason}")
            threat_feed_findings_count += 1

        # Add agreement finding if multiple feeds flagged
        if flagged_count >= 2:
            feed_names = [f.get("feed", "?") for f in flagged]
            add_finding(findings, (
                f"MULTI-FEED AGREEMENT: {flagged_count} threat intelligence feeds independently "
                f"flagged this domain: {', '.join(feed_names)}. Agreement bonus: +{agreement_bonus:.0f} risk."
            ))

        # Add findings for clean feeds (informational)
        clean_feeds = [f for f in feeds if f.get("status") == "clean"]
        if clean_feeds and not flagged:
            clean_names = [f.get("feed", "?") for f in clean_feeds]
            add_finding(findings, f"SAFE: Clean across threat feeds: {', '.join(clean_names)}.")

        # Add findings for disabled feeds (missing API keys)
        disabled_feeds = [f for f in feeds if f.get("status") == "disabled"]
        if disabled_feeds:
            disabled_names = [f.get("feed", "?") for f in disabled_feeds]
            add_finding(findings, f"INFO: Some threat feeds not configured (no API key): {', '.join(disabled_names)}.")

    # ========================================================================
    # v3.0: Ensemble ML Prediction (alongside XGBoost)
    # ========================================================================
    ensemble_result: dict[str, Any] = {}
    ensemble_model_count = 0
    ensemble_agreement = 0
    # Use the feature vector extracted earlier (popped from xgb_res)
    if ENSEMBLE_ML_AVAILABLE and _ens_feature_vector is not None:
        try:
            ensemble_result = ensemble_predict(_ens_feature_vector)
            ensemble_model_count = ensemble_result.get("model_count", 0) if isinstance(ensemble_result, dict) else 0
            ensemble_agreement = ensemble_result.get("model_agreement", 0) if isinstance(ensemble_result, dict) else 0
        except Exception as exc:
            print(f"Ensemble ML failed: {exc}")
            ensemble_result = {}

    if isinstance(ensemble_result, dict) and ensemble_result.get("ensemble_score") is not None:
        ens_score = ensemble_result.get("ensemble_score", 0)
        ens_verdict = ensemble_result.get("ensemble_verdict", "N/A")
        ens_agreement = ensemble_result.get("model_agreement", 0)
        ens_models = ensemble_result.get("available_models", [])
        ens_count = ensemble_result.get("model_count", 0)

        add_finding(findings, (
            f"ENSEMBLE ML: {ens_count} model(s) voted — Score: {ens_score}/100, "
            f"Verdict: {ens_verdict.upper()}, Model Agreement: {ens_agreement}%"
        ))

        # If ensemble disagrees with XGBoost, note the divergence
        if xgb_res.get("xgb_available"):
            xgb_score = xgb_res.get("xgb_score", 0.0)
            if abs(ens_score - xgb_score) > 20:
                add_finding(findings, (
                    f"ML DIVERGENCE: XGBoost ({xgb_score}/100) and Ensemble ({ens_score}/100) "
                    f"diverge by {abs(ens_score - xgb_score):.0f} points — investigate further."
                ))


    # ========================================================================
    # DATA COMPLETENESS TRACKING
    # ========================================================================
    # Check which commands completed successfully with meaningful output.
    # Tool failures, timeouts, and missing data NEVER increase risk.
    _dc = compute_data_completeness(
        dns_a_ok=bool(dns_a.status == "ok" and dns_a.stdout.strip()),
        dns_mx_ok=bool(dns_mx.status == "ok" and dns_mx.stdout.strip()),
        domain_whois_ok=bool(domain_whois.status == "ok" and domain_whois.stdout.strip() and not domain_whois.stdout.startswith("python-whois") and not domain_whois.stdout.startswith("WHOIS fallback") and not domain_whois.stdout.startswith("ERROR")),
        ssl_ok=not ssl_unavailable,
        http_ok=not headers_unavailable,
        ip_whois_ok=bool(primary_ip is not None and ip_whois.status == "ok" and ip_whois.stdout.strip() and not ip_whois.stdout.startswith("WHOIS") and not ip_whois.stdout.startswith("ERROR")),
        port_scan_ok=bool(nc_result.status == "ok" and (nc_result.stdout.strip() or nc_result.stderr.strip())),
        ping_ok=bool(ping_result.status == "ok" and ping_result.stdout.strip() and not ping_result.stdout.startswith("Pinging") and "100%" not in ping_result.stdout),
    )
    if _dc["insufficient"]:
        add_finding(findings, f"INSUFFICIENT DATA: Only {_dc['completeness_pct']}% ({_dc['passed_count']}/{_dc['total_checked']} checks) completed. Not enough evidence to classify.")
        for chk, sts in _dc["checks"].items():
            if sts == "FAIL":
                add_finding(findings, f"  CHECK FAIL: {chk}")
    risk_score, score_components, floor_findings = combine_analysis_scores(
        heuristic_score=heuristic_score,
        header_score=header_score,
        ai_score=ai_score,
        xgb_res=xgb_res,            # New hybrid scoring context
        domain=domain,
        ssl_unavailable=ssl_unavailable,
        headers_unavailable=headers_unavailable,
        
        age_days=age_days_val,
        registrar=parsed_meta.get("registrar") if parsed_meta.get("registrar") != "N/A" else None,
        ssl_issuer=parsed_meta.get("ssl_issuer") if parsed_meta.get("ssl_issuer") != "N/A" else None,
        asn=parsed_meta.get("asn") if parsed_meta.get("asn") != "N/A" else None,
        hosting=parsed_meta.get("hosting_space") if parsed_meta.get("hosting_space") != "N/A" else None,
        has_valid_ssl=has_valid_ssl_val,
        has_mx=has_mx_val,
        has_nameservers=has_ns_val,
        privacy_protected=has_privacy,
        suspicious_registrar=has_suspicious_reg,
        is_ip_like=is_ip_like_flag,
        has_typosquatting=has_typo,
        typosquatting_score=typo_score,
        has_homoglyph=has_homoglyph,
        homoglyph_count=homoglyph_count_val,
        has_digit_substitution=has_digit_substitution_flag,
        has_combosquatting=has_combo,
        suspicious_tld=has_suspicious_tld,
        tld=tld_val,
        excessive_subdomains=excessive_subdomains_flag,
        dark_web_tld=dark_web,
        has_password_form=has_password,
        has_external_form_action=has_external_form,
        # NEW v2.0 HARDENED SIGNALS
        has_abused_infrastructure=has_abused_infrastructure,
        abused_infra_risk=abused_infra_risk,
        has_subdomain_phishing=has_subdomain_phishing,
        has_suspicious_url_path=has_suspicious_url_path,
        url_path_risk=url_path_risk,
        has_suspicious_redirect=has_suspicious_redirect,
        redirect_hop_count=redirect_hop_count,
        has_punycode_homograph=has_punycode_homograph,
        homograph_brand=homograph_brand,
        has_ssl_expired=has_ssl_expired,
        has_ssl_self_signed=has_ssl_self_signed,
        has_ssl_hostname_mismatch=has_ssl_hostname_mismatch,
        has_ssl_revoked=has_ssl_revoked,
        has_ssl_untrusted_root=has_ssl_untrusted_root,
        has_ssl_weak_protocol=has_ssl_weak_protocol,
        has_ssl_weak_cipher=has_ssl_weak_cipher,
        # v3.0: threat feed + ensemble signals for confidence
        threat_feed_score=threat_feed_score,
        threat_feed_count=threat_intel_result.get("enabled_count", 0) if isinstance(threat_intel_result, dict) else 0,
        threat_feed_flagged_count=threat_feed_findings_count,
        has_dnssec=has_dnssec,
        ensemble_model_count=ensemble_model_count,
        ensemble_agreement=ensemble_agreement,        ensemble_result=ensemble_result if isinstance(ensemble_result, dict) else None)
    for finding in floor_findings:
        add_finding(findings, finding)

    if xgb_res.get("xgb_available"):
        xgb_score = xgb_res.get("xgb_score", 0.0)
        verdict = xgb_res.get("xgb_verdict", "N/A")
        add_finding(findings, f"ML ANALYSIS: XGBoost flags domain as {verdict.upper()} (score: {xgb_score}/100)")
        
        # Verdict Contradiction Explanation in findings (user-facing)
        # When ML says Legitimate/Uncertain but the final score is high,
        # the heuristic/scoring engine overrode the ML based on concrete evidence.
        if verdict in ("Legitimate", "Uncertain") and risk_score >= 26:
            severity = classify_score(risk_score)
            add_finding(findings, (
                f"VERDICT OVERRIDE: ML model classified as {verdict.upper()} ({xgb_score}%), "
                f"but heuristic override raised to {severity} — SSL/security/infrastructure "
                f"evidence outweighed ML signal."
            ))
    else:
        add_finding(findings, "ML ANALYSIS: XGBoost model unavailable; score used rules, security headers, and AI analysis.")

    # Append ML results to the AI markdown report
    if xgb_res.get("xgb_available"):
        xgb_score = xgb_res.get("xgb_score", 0.0)
        verdict = xgb_res.get("xgb_verdict", "N/A")
        severity = classify_score(risk_score)
        
        # Verdict Contradiction Explanation
        # When ML says Legitimate/Uncertain but the final hybrid score is high
        # (SUSPICIOUS or above), the heuristic/scoring engine overrode the ML
        # based on concrete evidence (SSL, infrastructure, phishing patterns).
        # Provide an explicit explanation.
        contradiction_note = ""
        if verdict in ("Legitimate", "Uncertain") and severity in ("SUSPICIOUS", "HIGH RISK", "CRITICAL"):
            contradiction_note = (
                f"\n\n### ⚠ Verdict Override Explanation\n"
                f"**ML Model**: {verdict.upper()} ({xgb_score}/100)\n"
                f"**Heuristic Override**: {severity}\n"
                f"**Final Score**: {risk_score}/100\n\n"
                f"The ML model classified this domain as {verdict.lower()}, but the heuristic/scoring engine "
                f"overrode this verdict based on concrete evidence from SSL certificate analysis, "
                f"infrastructure profiling, phishing pattern detection, and/or security posture assessment. "
                f"The hybrid scoring system weights heuristic evidence higher than ML alone when "
                f"multi-signal phishing indicators are present.\n"
            )
        
        ml_banner = f"""# RETRO_INTEL Hybrid Threat Report: {domain}

## Executive Severity
{severity} (Hybrid Score: {risk_score}/100)

## Machine Learning Classifier (XGBoost)
- **Verdict**: {verdict.upper()}
- **Model Score**: {xgb_score}/100
- **Status**: ACTIVE
- **Final Hybrid Score**: {risk_score}/100
{contradiction_note}
---

"""
        ai_report_hybrid = ml_banner + ai_report
    else:
        ai_report_hybrid = ai_report
    score_components["classification"] = classify_score(risk_score)

    errors = [
        result.error or result.stderr
        for result in commands.values()
        if result.status not in {"ok", "skipped"} and (result.error or result.stderr)
    ]

    # v3.0: Record reputation timeline
    if REPUTATION_TIMELINE_AVAILABLE:
        try:
            record_analysis(
                domain=domain,
                risk_score=risk_score,
                classification=score_components.get("classification", classify_score(risk_score)),
                threat_feeds=threat_intel_result if isinstance(threat_intel_result, dict) else None,
                ensemble_ml=ensemble_result if isinstance(ensemble_result, dict) else None,
                score_components=score_components,
            )
        except Exception:
            pass


    # ========================================================================
    # Brand Impersonation Detection
    # ========================================================================
    brand_impersonation_result: dict[str, Any] = {}
    if BRAND_IMPERSONATION_AVAILABLE and analyze_brand_impersonation is not None:
        try:
            _whois_text = raw_logs.get("domain_whois", "")
            _ssl_issuer = parsed_meta.get("ssl_issuer", "") if parsed_meta.get("ssl_issuer") != "N/A" else ""
            _website_signals = website_result.get("signals", {}) if isinstance(website_result, dict) else {}
            _html_content = website_result.get("text_sample", "") if isinstance(website_result, dict) else ""
            _owner_image_imp = owner_image_result if isinstance(owner_image_result, dict) else {}

            brand_impersonation_result = analyze_brand_impersonation(
                domain=domain,
                whois_text=_whois_text,
                ssl_issuer=_ssl_issuer,
                html_content=_html_content,
                website_signals=_website_signals,
                social_profiles=_owner_image_imp,
                website_metadata=website_result if isinstance(website_result, dict) else None,
            )

            _imp_score_dict = brand_impersonation_result.get("impersonation_score", {})
            _imp_score_val = _imp_score_dict.get("impersonation_score", 0) if isinstance(_imp_score_dict, dict) else 0
            if _imp_score_val >= 35:
                _verdict = _imp_score_dict.get("verdict", "Unknown") if isinstance(_imp_score_dict, dict) else "Unknown"
                _detected_brand = brand_impersonation_result.get("brand_similarity", {}).get("detected_brand")

                add_finding(findings, (
                    f"BRAND IMPERSONATION ALERT: {_verdict} (score: {_imp_score_val}/100). "
                    f"Detected brand: {_detected_brand or 'Unknown'}."
                ))
                heuristic_score += min(_imp_score_val // 2, 25)

                _login_harvesting = brand_impersonation_result.get("login_harvesting", {})
                if isinstance(_login_harvesting, dict) and _login_harvesting.get("credential_harvesting"):
                    _indicators = _login_harvesting.get("indicators", [])
                    if _indicators:
                        add_finding(findings, f"CREDENTIAL HARVESTING: {' | '.join(_indicators[:3])}")
                    heuristic_score += 20
        except Exception as e:
            brand_impersonation_result = {"error": str(e)[:200]}

    # Automatically trigger detailed AI analysis report
    ai_detailed_report = ""
    try:
        _api_key = os.getenv("GEMINI_API_KEY")
        if _api_key and genai is not None:
            _ai_client = genai.Client(api_key=_api_key)
            _ai_prompt = (
                "You are a Senior SOC Cybersecurity Analyst.\n"
                "Analyze ONLY the raw evidence below.\n"
                "RAW EVIDENCE:\n"
                f"{raw_context}"
            )
            _ai_response = await asyncio.wait_for(
                asyncio.to_thread(
                    _ai_client.models.generate_content,
                    model="gemini-2.5-flash",
                    contents=_ai_prompt,
                ),
                timeout=10.0,
            )
            ai_detailed_report = getattr(_ai_response, "text", "") or ""
    except Exception:
        ai_detailed_report = ""

    # Build port_map string from open ports for response
    port_map = ""
    if open_ports:
        port_entries = []
        for port in sorted(open_ports):
            desc = PORT_INTEL.get(port, f"Port {port} open")
            port_entries.append(f"{port}: {desc}")
        port_map = "\n".join(port_entries)

    return AnalyzeResponse(
        domain=domain,
        ip_address=primary_ip,
        parsed_meta=parsed_meta,
        security_headers=header_map,
        security_header_details=header_details,
        open_ports=open_ports,
        dns_data=dns_data,
        raw_logs=raw_logs,
        findings=findings,
        ai_verdict=ai_report_hybrid,
        risk_score=risk_score,
        commands=commands,
        raw_context=raw_context,
        partial_report=False,
        errors=errors,
        target_ip=primary_ip,
        hosting_space=parsed_meta.get("hosting_space"),
        country_code=parsed_meta.get("country"),
        asn=parsed_meta.get("asn"),
        domain_age=parsed_meta.get("domain_age"),
        registrar=parsed_meta.get("registrar"),
        ssl_issuer=parsed_meta.get("ssl_issuer"),
        ssl_dates=ssl_data.get("dates", {}),
        final_http_status=http_status,
        port_map=port_map,
        ai_markdown_report=ai_report_hybrid,
        ai_detailed_report=ai_detailed_report,
        ml_result=xgb_res,
        score_components=score_components,
        website_analysis=website_result,
        owner_image=owner_image_result,
        threat_intel=threat_intel_result,
        ensemble_ml=ensemble_result,
        score_breakdown=score_components,
        brand_impersonation=brand_impersonation_result,
    )

async def run_command(
    name: str,
    command: list[str],
    timeout: int = COMMAND_TIMEOUT_SECONDS,
    merge_stderr: bool = False,
) -> CommandResult:
    executable = command[0]
    is_available = shutil.which(executable) is not None
    
    stdout, stderr = "", ""
    status = "failed_lookup"
    error_msg = None
    
    if is_available:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT if merge_stderr else asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
            stdout = stdout_bytes.decode(errors="replace").strip() if stdout_bytes else ""
            stderr = stderr_bytes.decode(errors="replace").strip() if stderr_bytes else ""
            status = "ok" if process.returncode == 0 else "failed_lookup"
        except TimeoutError:
            status = "timeout"
            error_msg = f"Connection timed out or command exceeded {timeout}s."
            try:
                process.kill()
            except Exception:
                pass
        except Exception as exc:
            status = "failed_lookup"
            error_msg = str(exc)
    else:
        error_msg = f"Required command '{executable}' is not installed or not on PATH."

    # Intercept command failure or unavailability and run Python fallback
    if status != "ok":
        try:
            fallback_stdout = await asyncio.wait_for(
                run_python_fallback(name, command),
                timeout=timeout
            )
            if fallback_stdout is not None:
                return CommandResult(
                    name=name,
                    command=command,
                    status="ok",
                    stdout=fallback_stdout,
                    stderr="",
                    returncode=0
                )
        except Exception as fallback_exc:
            error_msg = f"{error_msg} (Fallback failed: {fallback_exc})"
            
    return CommandResult(
        name=name,
        command=command,
        status=status,
        stdout=stdout,
        stderr=stderr,
        returncode=0 if status == "ok" else 1,
        error=error_msg
    )

async def run_ai_core(raw_context: str, findings: list[str], fallback_score: int) -> tuple[str, int | None]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key or genai is None:
        return fallback_ai_report(findings, fallback_score), fallback_score

    prompt = f"""
You are a Tier-3 SOC analyst and threat hunter. Evaluate this structured OSINT evidence.
Return a concise markdown SOC report with these exact sections:
1. Threat Summary
2. Risk Assessment
3. MITRE ATT&CK Mapping
4. IOC Analysis
5. False Positive Discussion
6. Analyst Notes
7. Confidence Score
8. Recommended Action

Reason from evidence only. Treat weak signals such as blocked ping, missing MX,
deprecated X-XSS-Protection, report-only CSP, CDN edge behavior, and HTTP probe
failures as low-confidence unless combined with stronger phishing evidence.
Strong evidence includes brand impersonation, homoglyph abuse, recent
registration, credential harvesting forms, external form posts, malicious feed
hits, suspicious redirects, exposed risky services, and TLS/ownership mismatch.

End with one final line:
RISK_SCORE: <integer 0-100>

Never claim identity attribution. Only assess technical threat indicators.

{raw_context}
"""
    try:
        client = genai.Client(api_key=api_key)
        response = await asyncio.to_thread(client.models.generate_content, model="gemini-2.5-flash", contents=prompt)
        text = getattr(response, "text", "") or ""
        score = extract_ai_score(text)
        return text or fallback_ai_report(findings, fallback_score), score
    except Exception:
        return fallback_ai_report(findings, fallback_score), fallback_score

def add_finding(findings: list[str], finding: str) -> None:
    if finding not in findings:
        findings.append(finding)

def analyze_threat_intel(
    domain: str,
    primary_ip: str | None,
    parsed_meta: dict[str, Any],
    security_headers: dict[str, bool],
    open_ports: list[int],
    dns_data: dict[str, list[str]],
    raw_logs: dict[str, str],
    ssl_status: str,
    http_status: int | None,
    website_result: dict[str, Any] | None = None,
    ssl_unavailable: bool = False,
    headers_unavailable: bool = False,
) -> tuple[list[str], int]:
    findings: list[str] = []
    score = 0
    created_date = parsed_meta.get("created_date")
    age_days = domain_age_days(created_date if created_date != "N/A" else None)
    trusted_infra = is_trusted_infrastructure(domain, parsed_meta, age_days)
    website_result = website_result or {}

    if age_days is not None and age_days < 90:
        add_finding(findings, "HIGH RISK: Recently registered domain - frequently associated with phishing, malware delivery, scams, or disposable infrastructure.")
        score += 28
    elif age_days is not None and age_days < 365:
        add_finding(findings, "MEDIUM RISK: Domain is less than one year old; treat as moderately suspicious until reputation is established.")
        score += 14
    elif age_days is not None and age_days > 1825:
        add_finding(findings, "LOW RISK: Long-established infrastructure reduces probability of throwaway malicious usage. This does not guarantee safety.")
        score -= 4
    elif age_days is None and not trusted_infra:
        add_finding(findings, "INFO: Domain creation date unavailable - WHOIS lookup could not retrieve registration date. Tool failure is not domain risk.")

    if not trusted_infra:
        # Check if infrastructure CONFIRMED via other signals (SSL + HTTP:200)
        # When a domain has valid SSL AND an HTTP 200 response, we KNOW it has
        # functioning infrastructure even if WHOIS/ASN lookups failed.
        # Missing WHOIS/ASN data should be INFO, not MEDIUM RISK, in this case.
        has_confirmed_infra = bool(
            parsed_meta.get("ssl_issuer") and parsed_meta["ssl_issuer"] != "N/A"
            and parsed_meta.get("http_status") == 200
        )
        if parsed_meta.get("asn") in {None, "", "N/A"}:
            if has_confirmed_infra:
                add_finding(findings, "INFO: ASN was unavailable from IP WHOIS (infrastructure confirmed via SSL + HTTP).")
            else:
                add_finding(findings, "INFO: ASN was unavailable from IP WHOIS - IP WHOIS lookup could not determine ASN. Tool failure is not domain risk.")
        if parsed_meta.get("country") in {None, "", "N/A", "UN"}:
            if has_confirmed_infra:
                add_finding(findings, "INFO: Country/region was unavailable from IP WHOIS (infrastructure confirmed via SSL + HTTP).")
            else:
                add_finding(findings, "INFO: Country/region was unavailable from IP WHOIS - IP WHOIS lookup could not determine location. Tool failure is not domain risk.")
        if parsed_meta.get("registrar") in {None, "", "N/A"}:
            if has_confirmed_infra:
                add_finding(findings, "INFO: Registrar was unavailable from domain WHOIS (infrastructure confirmed via SSL + HTTP).")
            else:
                add_finding(findings, "INFO: Registrar was unavailable from domain WHOIS - WHOIS lookup could not determine registrar. Tool failure is not domain risk.")

    typo = detect_typosquatting(domain)
    if typo:
        add_finding(findings, f"HIGH RISK: Potential typosquatting / impersonation detected. {typo}")
        score += 30

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        add_finding(findings, "SUSPICIOUS: TLD historically associated with elevated phishing abuse.")
        score += 8

    if not dns_data.get("mx_records"):
        if trusted_infra:
            add_finding(findings, "INFO: No MX records found; suppressed as weak evidence for mature/trusted infrastructure.")
        else:
            add_finding(findings, "LOW RISK: No MX records found; weak signal only unless paired with phishing evidence.")
            score += 2
    suspicious_ns = [ns for ns in dns_data.get("nameservers", []) if any(term in ns for term in ["parking", "sedoparking", "bodis", "cashparking"])]
    if suspicious_ns:
        add_finding(findings, f"SUSPICIOUS: Parked-domain nameserver pattern detected: {', '.join(suspicious_ns)}.")
        score += 10
    if primary_ip is None:
        add_finding(findings, "MEDIUM RISK: Domain did not resolve to IPv4 during analysis.")
        score += 8
    elif ping_dead(raw_logs.get("ping", "")):
        if trusted_infra:
            add_finding(findings, "INFO: ICMP ping blocked; suppressed because many trusted/CDN environments block ping.")
        else:
            add_finding(findings, "LOW RISK: ICMP ping blocked or unreachable; weak infrastructure signal.")
            score += 2
    if ssl_status not in {"ok", "skipped"} or parsed_meta.get("ssl_issuer") == "N/A":
        if ssl_unavailable:
            add_finding(findings, "INFO: SSL/TLS data unavailable - SSL probe could not complete (timeout/network error). Tool failure is not domain risk.")
        else:
            add_finding(findings, "SSL: No valid SSL certificate detected - TLS handshake succeeded but no valid certificate was presented.")
            score += 4 if trusted_infra else 8
    if http_status is None or http_status >= 400:
        if headers_unavailable:
            add_finding(findings, "INFO: HTTP probe failed or returned an error - HTTP request could not reach the server. Tool failure is not domain risk.")
        elif trusted_infra:
            add_finding(findings, "INFO: HTTP probe failed or returned an error; suppressed as weak CDN/edge behavior.")
        else:
            add_finding(findings, "LOW RISK: HTTP probe failed or returned an error; requires context.")
            score += 3

    for port in open_ports:
        if port in PORT_INTEL:
            # Standard web ports (80=HTTP, 443=HTTPS) are expected on any
            # web server. HTTP on port 80 typically redirects to HTTPS on
            # port 443. These are not risk indicators and should be INFO.
            if port in (80, 443):
                add_finding(findings, f"INFO: Port {port} ({'HTTP' if port == 80 else 'HTTPS'}) - standard web port, expected.")
            # Suppress 8080/8443 false positives for Cloudflare-hosted domains
            elif port in (8080, 8443) and "CLOUDFLARE" in parsed_meta.get("hosting_space", "").upper():
                add_finding(findings, f"INFO: Port {port} open on Cloudflare edge - expected for proxy infrastructure.")
            else:
                add_finding(findings, f"EXPOSED PORT: {PORT_INTEL[port]}")
                score += 8 if port in {23, 3389, 445, 5900} else 5

    signals = website_result.get("signals") or {}
    redirect_chain = website_result.get("redirect_chain") or []
    if signals.get("has_password_input"):
        add_finding(findings, "HIGH RISK: Credential collection surface detected (password input present).")
        score += 12
    if signals.get("has_otp_keywords"):
        add_finding(findings, "HIGH RISK: OTP or one-time-code wording detected; common in credential harvesting flows.")
        score += 8
    if signals.get("external_form_actions"):
        add_finding(findings, "HIGH RISK: Login/form submission posts to an external host.")
        score += 18
    if len(redirect_chain) >= 3:
        add_finding(findings, "MEDIUM RISK: Multi-hop redirect chain observed during website inspection.")
        score += 6
    if signals.get("has_password_input") and detect_typosquatting(domain):
        add_finding(findings, "HIGH RISK: Brand-lookalike domain also presents a credential form.")
        score += 20

    # ---- CLONE WEBSITE DETECTION ----
    # Check if the website title or content suggests a different brand identity
    # than what the domain name naturally represents. This catches clone/phishing
    # sites that mimic well-known brands.
    website_title = website_result.get("signals", {}).get("title", "") or ""
    if website_title and signals.get("has_password_input"):
        title_lower = website_title.lower()
        # Check if the page title mentions a brand NOT present in the domain
        for brand in KNOWN_BRANDS:
            if brand in title_lower and brand not in domain.lower():
                add_finding(
                    findings,
                    f"HIGH RISK: Page title references '{brand.title()}' but domain does not match â€” "
                    f"potential brand cloning / phishing page."
                )
                score += 20
                # If also has external form action, escalate further
                if signals.get("external_form_actions"):
                    score += 15
                    add_finding(
                        findings,
                        f"CRITICAL: Page clones '{brand.title()}' AND submits credentials externally â€” "
                        f"confirmed credential harvesting."
                    )
                break

    # Check for .edu-style domain impersonation (e.g. domains ending in "edu" patterns
    # but not actually .edu TLDs, which often target educational institutions)
    domain_label = domain.split(".")[0].lower() if "." in domain else domain.lower()
    if "edu" in domain_label and not domain.endswith(".edu"):
        add_finding(
            findings,
            "SUSPICIOUS: Domain label contains 'edu' but TLD is not .edu â€” "
            "may impersonate educational institution."
        )
        score += 8

  # Security header analysis
# Only evaluate headers if website responded successfully

    if http_status and http_status < 400:

        # HSTS (important)
        hsts_value = raw_logs.get("curl", "").lower()

        if security_headers.get("Strict-Transport-Security", False):

            hsts_match = re.search(r"max-age=(\d+)", hsts_value)

            if hsts_match and int(hsts_match.group(1)) >= 15552000:
                add_finding(
                    findings,
                    "SAFE: Strong HSTS policy detected (1 year HTTPS enforcement)."
                )
                score -= 2

            else:
                add_finding(
                    findings,
                    "LOW RISK: Weak HSTS configuration detected."
                )
                score += 1

        else:
            # Check for Alt-Svc header (HTTP/3 support) as signal of modern infrastructure
            # Many HSTS-preloaded domains (google.com, amazon.com) don't send HSTS header
            # but use Alt-Svc for upgrade signaling instead. Don't penalize these.
            raw_log = (raw_logs.get("curl", "") or "").lower()
            has_alt_svc = "alt-svc" in raw_log and "h3=" in raw_log
            if has_alt_svc:
                add_finding(
                    findings,
                    "INFO: HSTS header not sent but Alt-Svc (HTTP/3) detected - domain likely HSTS preloaded."
                )
            else:
                add_finding(
                    findings,
                    "LOW RISK: HSTS missing. HTTPS downgrade protection unavailable."
                )
                score += 2

        # CSP
        if security_headers.get("Content-Security-Policy", False):
            add_finding(
                findings,
                "SAFE: CSP present. Script injection protections enabled."
            )
            score -= 1

        else:
            add_finding(
                findings,
                "LOW RISK: Missing CSP slightly increases XSS exposure."
            )
            score += 2

        # X-Frame-Options
        if security_headers.get("X-Frame-Options", False):
            add_finding(
                findings,
                "SAFE: Clickjacking protection enabled."
            )
        else:
            add_finding(
                findings,
                "LOW RISK: Missing clickjacking protection."
            )
            score += 1

        add_finding(
            findings,
            "INFO: X-XSS-Protection is deprecated and excluded from positive/negative risk scoring."
        )

    if not findings:
        add_finding(findings, "SAFE: No high-confidence adverse indicator was observed in the collected command evidence.")
    return findings, clamp_score(score)

def build_context(
    domain: str,
    primary_ip: str | None,
    parsed_meta: dict[str, Any],
    security_headers: dict[str, bool],
    open_ports: list[int],
    dns_data: dict[str, list[str]],
    findings: list[str],
    commands: dict[str, CommandResult],
    website_result: dict[str, Any] | None = None,
) -> str:
    blocks = [
        f"TARGET_DOMAIN: {domain}",
        f"PRIMARY_IPV4: {primary_ip or 'NO_RESOLUTION'}",
        f"PARSED_META: {parsed_meta}",
        f"SECURITY_HEADERS: {security_headers}",
        f"OPEN_PORTS: {open_ports}",
        f"DNS_DATA: {dns_data}",
        f"WEBSITE_ANALYSIS: {website_result or {}}",
        "FINDINGS:\n" + "\n".join(f"- {finding}" for finding in findings),
    ]
    for name, result in commands.items():
        blocks.append(
            "\n".join(
                [
                    f"\n===== {name.upper()} =====",
                    f"COMMAND: {' '.join(result.command)}",
                    f"STATUS: {result.status}",
                    f"STDOUT:\n{result.stdout or '<empty>'}",
                    f"STDERR_OR_ERROR:\n{result.stderr or result.error or '<none>'}",
                ]
            )
        )
    return "\n".join(blocks)

def compact_lines(stdout: str) -> list[str]:
    return [line.strip() for line in (stdout or "").splitlines() if line.strip()]

def domain_age_days(created_iso: str | None) -> int | None:
    if not created_iso:
        return None
    try:
        created = datetime.fromisoformat(created_iso).replace(tzinfo=UTC)
        return max((datetime.now(UTC) - created).days, 0)
    except ValueError:
        return None

def first_ipv4(stdout: str) -> str | None:
    for candidate in IPV4_RE.findall(stdout or ""):
        octets = candidate.split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            return candidate
    return None

def parse_domain_whois(stdout: str) -> ParsedDomainWhois:
    text = stdout or ""
    created_raw = find_first_field(
        text,
        [
            "Creation Date",
            "created",
            "Registered On",
            "Domain record activated",
            "Domain Registration Date",
            "registration time",
            "activated",
        ],
    )
    created_date = normalize_date(created_raw) if created_raw else None
    registrar = find_first_field(text, ["Registrar", "Registrar Name", "Sponsoring Registrar", "registrar"])
    nameservers = extract_nameservers(text)
    return ParsedDomainWhois(
        created_date=created_date,
        domain_age=human_age(created_date) if created_date else None,
        registrar=registrar,
        nameservers=nameservers,
    )

def parse_final_status(stdout: str) -> int | None:
    statuses = re.findall(r"^HTTP/\S+\s+(\d{3})", stdout or "", flags=re.MULTILINE)
    return int(statuses[-1]) if statuses else None

def parse_headers(stdout: str) -> list[HeaderStatus]:
    blocks = parse_header_blocks(stdout)
    return [
        classify_header(name, _values_for(blocks, name), _values_for(blocks, "Content-Security-Policy-Report-Only"))
        for name in HEADER_NAMES
    ]

def parse_ip_whois(stdout: str) -> dict[str, str | None]:
    text = stdout or ""
    hosting = find_first_field(text, ["OrgName", "org-name", "descr", "owner", "netname", "organization", "abuse-mailbox"])
    asn_raw = find_first_field(text, ["origin", "OriginAS", "aut-num", "originas", "ASN"])
    country_raw = find_first_field(text, ["country", "Country", "Registrant Country"])

    asn = None
    if asn_raw:
        match = re.search(r"(?:AS)?\s*(\d{1,10})", asn_raw, flags=re.IGNORECASE)
        asn = f"AS{match.group(1)}" if match else asn_raw.upper()

    return {
        "hosting_space": hosting or None,
        "asn": asn,
        "country": _normalize_country(country_raw),
    }

def parse_open_ports(stdout: str) -> list[int]:
    open_ports: set[int] = set()
    for port in COMMON_PORTS:
        patterns = [
            rf"\b{port}\b.*(?:succeeded|open)",
            rf"(?:succeeded|open).*\b{port}\b",
            rf"\({port}\).*open",
        ]
        if any(re.search(pattern, stdout or "", flags=re.IGNORECASE) for pattern in patterns):
            open_ports.add(port)
    return sorted(open_ports)

def parse_ssl(stdout: str) -> dict[str, str | None]:
    data = {"issuer": None, "not_before": None, "not_after": None}
    text = stdout or ""
    issuer_match = re.search(r"(?im)^\s*issuer\s*=\s*(.+)$", text)
    if issuer_match:
        issuer = issuer_match.group(1).strip()
        # OpenSSL issuer formatting is inconsistent; prefer CN, then organization, then the full issuer string.
        cn_match = re.search(r"(?:^|,\s*)CN\s*=\s*([^,]+)", issuer, flags=re.IGNORECASE)
        org_match = re.search(r"(?:^|,\s*)O\s*=\s*([^,]+)", issuer, flags=re.IGNORECASE)
        data["issuer"] = normalize_whois_value((cn_match or org_match).group(1) if (cn_match or org_match) else issuer)
    not_before_match = re.search(r"(?im)^\s*(?:notBefore\s*=|Not Before\s*:)\s*(.+)$", text)
    not_after_match = re.search(r"(?im)^\s*(?:notAfter\s*=|Not After\s*:)\s*(.+)$", text)
    data["not_before"] = not_before_match.group(1).strip() if not_before_match else None
    data["not_after"] = not_after_match.group(1).strip() if not_after_match else None
    return data

def platform_ping_command(domain: str) -> list[str]:
    return ["ping", "-n", "3", domain] if os.name == "nt" else ["ping", "-c", "3", domain]

async def run_openssl_probe(domain: str, can_resolve: bool) -> CommandResult:
    if not can_resolve:
        return CommandResult(name="ssl", command=["python", "fallback_ssl_probe", domain], status="skipped", error="Domain did not resolve; SSL probe skipped.")

    # Use Python-native SSL probe directly (avoids bash dependency which doesn't exist on Windows)
    try:
        stdout = await asyncio.to_thread(fallback_ssl_probe, domain)
        return CommandResult(
            name="ssl",
            command=["python", "fallback_ssl_probe", domain],
            status="ok",
            stdout=stdout or "",
            stderr="",
            returncode=0,
        )
    except Exception as exc:
        return CommandResult(
            name="ssl",
            command=["python", "fallback_ssl_probe", domain],
            status="failed",
            stdout="",
            stderr="",
            returncode=1,
            error=f"Python SSL probe failed: {exc}",
        )

async def skipped_command(name: str, command: list[str], reason: str) -> CommandResult:
    return CommandResult(name=name, command=command, status="skipped", error=reason)

async def socket_fallback_ip(domain: str) -> str | None:
    try:
        return await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception:
        return None

def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))



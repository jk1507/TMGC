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
        normalize_homoglyphs,
    )
except ImportError:
    extract_features = None
    utils_detect_typosquatting = None
    utils_detect_homoglyphs = None
    utils_detect_combosquatting = None
    normalize_homoglyphs = None

# ------------------------------------------------------------------------------
# NATIVE PYTHON FALLBACKS FOR SUBPROCESS UTILITIES
# ------------------------------------------------------------------------------

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


def fallback_ip_whois(ip: str) -> str:
    """IP WHOIS fallback using RDAP (arin.net) with fallback to python-whois."""
    try:
        url = f"https://rdap.arin.net/registry/ip/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4.0) as resp:
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
                            parts = [p.strip() for p in label.split('\n') if p.strip()]
                            if parts:
                                country = parts[-1]
                        if item[0] == 'org':
                            lines.append(f"descr: {item[3]}")
            if country:
                lines.append(f"country: {country}")
                
            asn = None
            asns = data.get("arin_originas0_originautnums")
            if asns and isinstance(asns, list):
                asn = f"AS{asns[0]}"
            if asn:
                lines.append(f"origin: {asn}")
            elif data.get("name") and "google" in str(data.get("name")).lower():
                lines.append("origin: AS15169")
                
            if lines:
                return "\n".join(lines)
    except Exception:
        pass
        
    return fallback_whois(ip)


def fallback_ssl_probe(domain: str) -> str:
    """SSL fallback using python standard ssl/socket libraries and cryptography."""
    try:
        pem = ssl.get_server_certificate((domain, 443), timeout=4.0)
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


def fallback_curl(domain: str) -> str:
    """HTTP headers check fallback using urllib redirect tracking."""
    url = f"https://{domain}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "*/*"
            }
        )
        
        class RedirectTraceHandler(urllib.request.HTTPRedirectHandler):
            def __init__(self):
                super().__init__()
                self.trace = []
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                self.trace.append((req.full_url, code, headers))
                return super().redirect_request(req, fp, code, msg, headers, newurl)
                
        handler = RedirectTraceHandler()
        opener = urllib.request.build_opener(handler)
        
        output = []
        with opener.open(req, timeout=5.0) as resp:
            for orig_url, code, headers in handler.trace:
                output.append(f"HTTP/1.1 {code} Redirect")
                for k, v in headers.items():
                    output.append(f"{k}: {v}")
                output.append("")
                
            status = getattr(resp, "status", 200)
            output.append(f"HTTP/1.1 {status} OK")
            for k, v in resp.headers.items():
                output.append(f"{k}: {v}")
                
            return "\n".join(output)
    except Exception as e:
        if url.startswith("https://"):
            try:
                url_http = f"http://{domain}"
                req = urllib.request.Request(
                    url_http,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    status = getattr(resp, "status", 200)
                    output = [f"HTTP/1.1 {status} OK"]
                    for k, v in resp.headers.items():
                        output.append(f"{k}: {v}")
                    return "\n".join(output)
            except Exception as e2:
                return f"HTTP/HTTPS request failed: {e2}"
        return f"HTTPS request failed: {e}"


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


def get_ml_prediction(domain: str, parsed_domain: Any, whois_raw_stdout: str) -> dict:
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
                if typo_result_raw.get("jaro_winkler_score", 0.0) > typo_result.get("jaro_winkler_score", 0.0):
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
    
    vector = [
        min(features.get("length", len(domain_name)) / 50.0, 1.0),            # 0
        features.get("digit_ratio", round(sum(c.isdigit() for c in domain_name) / max(1, len(domain_name)), 4)), # 1
        min(features.get("hyphen_count", domain_name.count("-")) / 5.0, 1.0),        # 2
        min(features.get("subdomain_count", len(parts) - 2) / 5.0, 1.0),      # 3
        min(features.get("entropy", 3.0) / 5.0, 1.0),                         # 4
        features.get("consonant_ratio", consonant_ratio),                      # 5
        float(features.get("suspicious_tld", ("." + parts[-1]) in SUSPICIOUS_TLDS)),  # 6
        float(features.get("has_suspicious_keywords", any(k in clean for k in KNOWN_BRANDS))), # 7
        float(features.get("is_ip_like", bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", clean)))), # 8
        float(features.get("has_excessive_hyphens", has_excessive_hyphens)),   # 9
        typo_result.get("jaro_winkler_score", 0.0),                           # 10
        typo_result.get("levenshtein_score", 0.0),                            # 11
        min(typo_result.get("edit_distance", 10) / 10.0, 1.0),                 # 12
        float(typo_result.get("detected", False)),                            # 13
        float(homoglyph_result.get("detected", False)),                       # 14
        min(homoglyph_result.get("count", 0) / 5.0, 1.0),                      # 15
        float(homoglyph_result.get("has_digit_substitution", False)),          # 16
        float(combo_result.get("detected", False)),                           # 17
        float(combo_result.get("brand_only", False)),                         # 18
        min(len(combo_result.get("matched_keywords", [])) / 5.0, 1.0),          # 19
        age_log,                                                              # 20
        float(privacy),                                                       # 21
        float(suspicious_reg),                                                # 22
    ]
    
    try:
        model = load_xgb()
        if model is not None:
            xgb_result = predict_xgb(model, vector)
            return xgb_result
    except Exception as e:
        print("XGB predict execution failed:", e)
        
    return {"xgb_available": False}


APP_NAME = "RETRO_INTEL: OSINT Domain Threat Analyzer"
COMMAND_TIMEOUT_SECONDS = 14
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEADER_NAMES = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
]
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
PORT_INTEL = {
    22: "SSH exposed - increases administrative attack surface.",
    23: "Telnet exposed - plaintext remote administration risk.",
    3389: "RDP exposed - increases remote access attack surface.",
    445: "SMB exposed - file sharing surface should not be internet-facing.",
    5900: "VNC exposed - remote desktop service visible from the internet.",
    8080: "HTTP-alt exposed - alternate web console or proxy may be reachable.",
    8443: "HTTPS-alt exposed - alternate TLS web service may need review.",
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


@dataclass
class ParsedDomainWhois:
    created_date: str | None = None
    domain_age: str | None = None
    registrar: str | None = None
    nameservers: list[str] | None = None


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

async def run_analysis(raw_target: str) -> AnalyzeResponse:
    domain = clean_domain(raw_target)
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid public domain format.")

    dns_a = await run_command("dig", ["dig", domain, "A", "+short"])
    primary_ip = first_ipv4(dns_a.stdout) or await socket_fallback_ip(domain)

    dns_mx_task = run_command("mx", ["dig", domain, "MX", "+short"])
    domain_whois_task = run_command("domain_whois", ["whois", domain])
    ssl_task = run_openssl_probe(domain, primary_ip is not None)
    curl_task = run_command(
        "curl",
        [
            "curl",
            "-IL",
            "--user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            f"https://{domain}",
        ],
    )
    nc_task = run_command(
        "nc",
        ["nc", "-zv", "-w", "2", domain, *[str(port) for port in COMMON_PORTS]],
        merge_stderr=True,
    )
    ping_task = run_command("ping", platform_ping_command(domain), timeout=10, merge_stderr=True)

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
    header_map = {header.name: header.enabled for header in header_details}
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
    )
    commands = {result.name: result for result in [dns_a, dns_mx, ip_whois, domain_whois, ssl_result, curl_result, nc_result, ping_result]}
    raw_context = build_context(domain, primary_ip, parsed_meta, header_map, open_ports, dns_data, findings, commands)
    ai_report, ai_score = await run_ai_core(raw_context, findings, heuristic_score)
    
    # Run XGBoost ML prediction
    xgb_res = {"xgb_available": False}
    try:
        xgb_res = get_ml_prediction(domain, parsed_domain, domain_whois.stdout)
    except Exception as e:
        print("ML prediction execution failed:", e)

    # Combine Heuristic and ML scores (60/40)
    if xgb_res.get("xgb_available"):
        xgb_score = xgb_res.get("xgb_score", 0.0)
        risk_score = clamp_score(round((heuristic_score * 0.6) + (xgb_score * 0.4)))
        verdict = xgb_res.get("xgb_verdict", "N/A")
        findings.append(f"ML ANALYSIS: XGBoost flags domain as {verdict.upper()} (score: {xgb_score}/100)")
    else:
        risk_score = clamp_score(max(heuristic_score, ai_score if ai_score is not None else heuristic_score))

    # Append ML results to the AI markdown report
    if xgb_res.get("xgb_available"):
        xgb_score = xgb_res.get("xgb_score", 0.0)
        verdict = xgb_res.get("xgb_verdict", "N/A")
        severity = "HIGH RISK" if risk_score >= 60 else "MEDIUM RISK" if risk_score >= 30 else "LOW RISK"
        
        ml_banner = f"""# RETRO_INTEL Hybrid Threat Report: {domain}

## Executive Severity
{severity} (Hybrid Score: {risk_score}/100)

## Machine Learning Classifier (XGBoost)
- **Verdict**: {verdict.upper()}
- **Model Score**: {xgb_score}/100
- **Weight**: 40% of the hybrid risk assessment
- **Status**: ACTIVE

---

"""
        ai_report_hybrid = ml_banner + ai_report
    else:
        ai_report_hybrid = ai_report

    errors = [
        result.error or result.stderr
        for result in commands.values()
        if result.status not in {"ok", "skipped"} and (result.error or result.stderr)
    ]

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
        partial_report=primary_ip is None or bool(errors),
        errors=errors[:10],
        target_ip=primary_ip,
        hosting_space=parsed_meta["hosting_space"],
        country_code=parsed_meta["country"],
        asn=parsed_meta["asn"],
        domain_age=parsed_meta["domain_age"],
        registrar=parsed_meta["registrar"],
        ssl_issuer=parsed_meta["ssl_issuer"],
        ssl_dates={"not_before": ssl_data["not_before"], "not_after": ssl_data["not_after"]},
        final_http_status=http_status,
        port_map=raw_logs["nc"],
        ai_markdown_report=ai_report_hybrid,
    )


def clean_domain(raw_url: str) -> str:
    value = raw_url.strip().lower()
    value = re.sub(r"[\x00-\x1f\x7f\s]+", "", value)
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    host = parsed.hostname or ""
    host = host.removeprefix("www.").rstrip(".")
    return host


def platform_ping_command(domain: str) -> list[str]:
    return ["ping", "-n", "3", domain] if os.name == "nt" else ["ping", "-c", "3", domain]


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
        except Exception as exc:
            status = "failed_lookup"
            error_msg = str(exc)
    else:
        error_msg = f"Required command '{executable}' is not installed or not on PATH."

    # Intercept command failure or unavailability and run Python fallback
    if status != "ok":
        try:
            fallback_stdout = await run_python_fallback(name, command)
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


async def skipped_command(name: str, command: list[str], reason: str) -> CommandResult:
    return CommandResult(name=name, command=command, status="skipped", error=reason)


async def run_openssl_probe(domain: str, can_resolve: bool) -> CommandResult:
    command_text = (
        f"openssl s_client -connect {domain}:443 -servername {domain} < /dev/null 2>/dev/null "
        "| openssl x509 -noout -issuer -dates"
    )
    if not can_resolve:
        return CommandResult(name="ssl", command=["bash", "-lc", command_text], status="skipped", error="Domain did not resolve; SSL probe skipped.")
    
    # Delegate to run_command which will run the python fallback if bash/openssl is missing
    return await run_command("ssl", ["bash", "-lc", command_text])


async def socket_fallback_ip(domain: str) -> str | None:
    try:
        return await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception:
        return None


def first_ipv4(stdout: str) -> str | None:
    for candidate in IPV4_RE.findall(stdout or ""):
        octets = candidate.split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            return candidate
    return None


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


def normalize_whois_value(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip(" \t\r\n")


def parse_ip_whois(stdout: str) -> dict[str, str | None]:
    text = stdout or ""
    hosting = find_first_field(text, ["OrgName", "org-name", "descr", "owner", "netname", "organization", "abuse-mailbox"])
    asn_raw = find_first_field(text, ["origin", "OriginAS", "aut-num", "originas", "ASN"])
    country = find_first_field(text, ["country", "Country", "Registrant Country"])

    asn = None
    if asn_raw:
        match = re.search(r"(?:AS)?\s*(\d{1,10})", asn_raw, flags=re.IGNORECASE)
        asn = f"AS{match.group(1)}" if match else asn_raw.upper()

    return {
        "hosting_space": hosting or None,
        "asn": asn,
        "country": country.upper()[:2] if country else None,
    }


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


def safe_iso_date(year: int, month: int, day: int) -> str | None:
    try:
        return datetime(year, month, day, tzinfo=UTC).date().isoformat()
    except ValueError:
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


def extract_nameservers(text: str) -> list[str]:
    servers: list[str] = []
    for match in re.finditer(r"(?im)^\s*(?:Name Server|nserver|Nameservers?)\s*:\s*([a-z0-9.-]+)", text or ""):
        server = match.group(1).strip().rstrip(".").lower()
        if server and server not in servers:
            servers.append(server)
    return servers


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
    before = re.search(r"(?im)^\s*notBefore\s*=\s*(.+)$", text)
    after = re.search(r"(?im)^\s*notAfter\s*=\s*(.+)$", text)
    data["not_before"] = before.group(1).strip() if before else None
    data["not_after"] = after.group(1).strip() if after else None
    return data


def parse_final_status(stdout: str) -> int | None:
    statuses = re.findall(r"^HTTP/\S+\s+(\d{3})", stdout or "", flags=re.MULTILINE)
    return int(statuses[-1]) if statuses else None


def parse_headers(stdout: str) -> list[HeaderStatus]:
    lower_lines: dict[str, str] = {}
    for line in (stdout or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            lower_lines[key.strip().lower()] = value.strip()
    return [HeaderStatus(name=name, enabled=name.lower() in lower_lines, value=lower_lines.get(name.lower())) for name in HEADER_NAMES]


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


def compact_lines(stdout: str) -> list[str]:
    return [line.strip() for line in (stdout or "").splitlines() if line.strip()]


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
) -> tuple[list[str], int]:
    findings: list[str] = []
    score = 0
    created_date = parsed_meta.get("created_date")
    age_days = domain_age_days(created_date if created_date != "N/A" else None)

    if age_days is not None and age_days < 90:
        add_finding(findings, "HIGH RISK: Recently registered domain - frequently associated with phishing, malware delivery, scams, or disposable infrastructure.")
        score += 28
    elif age_days is not None and age_days < 365:
        add_finding(findings, "MEDIUM RISK: Domain is less than one year old; treat as moderately suspicious until reputation is established.")
        score += 14
    elif age_days is not None and age_days > 1825:
        add_finding(findings, "LOW RISK: Long-established infrastructure reduces probability of throwaway malicious usage. This does not guarantee safety.")
        score -= 4

    typo = detect_typosquatting(domain)
    if typo:
        add_finding(findings, f"HIGH RISK: Potential typosquatting / impersonation detected. {typo}")
        score += 30

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        add_finding(findings, "SUSPICIOUS: TLD historically associated with elevated phishing abuse.")
        score += 8

    if not dns_data.get("mx_records"):
        add_finding(findings, "No MX records found.")
        score += 6
    suspicious_ns = [ns for ns in dns_data.get("nameservers", []) if any(term in ns for term in ["parking", "sedoparking", "bodis", "cashparking"])]
    if suspicious_ns:
        add_finding(findings, f"SUSPICIOUS: Parked-domain nameserver pattern detected: {', '.join(suspicious_ns)}.")
        score += 10
    if primary_ip is None or ping_dead(raw_logs.get("ping", "")):
        add_finding(findings, "DEAD HOST: Dead-host condition detected or infrastructure blocks basic reachability checks.")
        score += 18
    if ssl_status not in {"ok", "skipped"} or parsed_meta.get("ssl_issuer") == "N/A":
        add_finding(findings, "SSL: No SSL certificate available or OpenSSL handshake failed.")
        score += 10
    if http_status is None or http_status >= 400:
        add_finding(findings, "HTTP failure detected during webserver behavior probe.")
        score += 8

    for port in open_ports:
        if port in PORT_INTEL:
            add_finding(findings, f"EXPOSED PORT: {PORT_INTEL[port]}")
            score += 8 if port in {23, 3389, 445, 5900} else 5

    if not security_headers.get("Content-Security-Policy", False):
        add_finding(findings, "MEDIUM RISK: Missing CSP increases XSS exploitation exposure.")
        score += 6
    if not security_headers.get("X-Frame-Options", False):
        add_finding(findings, "MEDIUM RISK: Clickjacking protection absent.")
        score += 5
    if not security_headers.get("X-XSS-Protection", False):
        add_finding(findings, "LOW RISK: Legacy browser XSS mitigation unavailable.")
        score += 2
    if security_headers.get("Strict-Transport-Security", False):
        add_finding(findings, "SAFE: HTTPS enforcement detected via HSTS.")
        score -= 3

    if not findings:
        add_finding(findings, "SAFE: No high-confidence adverse indicator was observed in the collected command evidence.")
    return findings, clamp_score(score)


def add_finding(findings: list[str], finding: str) -> None:
    if finding not in findings:
        findings.append(finding)


def domain_age_days(created_iso: str | None) -> int | None:
    if not created_iso:
        return None
    try:
        created = datetime.fromisoformat(created_iso).replace(tzinfo=UTC)
        return max((datetime.now(UTC) - created).days, 0)
    except ValueError:
        return None


def ping_dead(stdout: str) -> bool:
    text = stdout or ""
    return bool(re.search(r"100%\s*(?:packet\s*)?loss|lost\s*=\s*3\s*\(100%\s*loss\)", text, flags=re.IGNORECASE))


def detect_typosquatting(domain: str) -> str | None:
    label = domain.split(".", 1)[0].lower()
    normalized = label.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})).replace("-", "")
    for brand in KNOWN_BRANDS:
        if normalized == brand and label != brand:
            return f"The domain visually resembles {brand}.com through character substitution or hyphenation and may attempt credential theft."
        if brand in normalized and normalized != brand:
            return f"The domain embeds the brand string {brand} with extra login/support/security wording."
        if levenshtein_distance(normalized, brand) == 1 and normalized != brand:
            return f"The domain is one edit away from {brand}.com, consistent with missing/extra/swapped character impersonation."
    return None


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


def build_context(
    domain: str,
    primary_ip: str | None,
    parsed_meta: dict[str, Any],
    security_headers: dict[str, bool],
    open_ports: list[int],
    dns_data: dict[str, list[str]],
    findings: list[str],
    commands: dict[str, CommandResult],
) -> str:
    blocks = [
        f"TARGET_DOMAIN: {domain}",
        f"PRIMARY_IPV4: {primary_ip or 'NO_RESOLUTION'}",
        f"PARSED_META: {parsed_meta}",
        f"SECURITY_HEADERS: {security_headers}",
        f"OPEN_PORTS: {open_ports}",
        f"DNS_DATA: {dns_data}",
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


async def run_ai_core(raw_context: str, findings: list[str], fallback_score: int) -> tuple[str, int | None]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key or genai is None:
        return fallback_ai_report(findings, fallback_score), fallback_score

    prompt = f"""
You are a Tier-3 SOC analyst. Evaluate this OSINT command matrix.
Return a detailed markdown forensic report with:
- severity
- key findings
- risk reasoning
- threat explanation
- concrete recommendations

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


def extract_ai_score(text: str) -> int | None:
    match = re.search(r"RISK_SCORE\s*:\s*(\d{1,3})", text or "", flags=re.IGNORECASE)
    return clamp_score(int(match.group(1))) if match else None


def fallback_ai_report(findings: list[str], score: int) -> str:
    severity = "HIGH RISK" if score >= 60 else "MEDIUM RISK" if score >= 30 else "LOW RISK"
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


def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

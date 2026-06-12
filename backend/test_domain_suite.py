"""
test_domain_suite.py - RETRO_INTEL Automated QA Testing Suite
===============================================================

Runs batch analysis against the live RETRO_INTEL API and produces:
  - Structured table with per-domain analysis
  - Automatic issue detection (false positives, false negatives, confidence bugs, etc.)
  - Final summary with pass/fail statistics

Usage:
  1. Start the RETRO_INTEL backend:   cd backend && python main.py
  2. Run this script:                 python backend/test_domain_suite.py

Requirements: None beyond Python stdlib. No production logic is duplicated.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

API_URL = "http://127.0.0.1:8000/api/v1/analyze"
HEALTH_URL = "http://127.0.0.1:8000/health"

# ==============================================================================
# TEST DOMAINS - organized by expected threat category
# ==============================================================================

LEGITIMATE_DOMAINS: list[str] = [
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "chatgpt.com",
    "openai.com",
    "youtube.com",
    "paypal.com",
    "cloudflare.com",
    "wikipedia.org",
]

SUSPICIOUS_DOMAINS: list[str] = [
    "randomdomain123.xyz",
    "unknownstartup.xyz",
    "weird-random-domain.site",
]

PHISHING_DOMAINS: list[str] = [
    "g00gle.com",
    "go0gle.com",
    "paypa1.com",
    "goog1e.com",
    "faceb00k-login.top",
    "micr0soft-login.xyz",
    "google-account-security.xyz",
    "secure-paypal-login.tk",
]

EDGE_CASE_DOMAINS: list[str] = [
    "localhost",
    "127.0.0.1",
    "example.com",
]

ALL_CATEGORIES: list[tuple[str, list[str]]] = [
    ("LEGITIMATE", LEGITIMATE_DOMAINS),
    ("SUSPICIOUS", SUSPICIOUS_DOMAINS),
    ("PHISHING", PHISHING_DOMAINS),
    ("EDGE CASES", EDGE_CASE_DOMAINS),
]

# Sets used by issue detectors
TRUSTED_SET: set[str] = set(LEGITIMATE_DOMAINS)
PHISHING_SET: set[str] = set(PHISHING_DOMAINS)

# Domains that are expected to have HSTS
HSTS_EXPECTED: set[str] = {
    "google.com", "github.com", "microsoft.com", "amazon.com",
    "openai.com", "youtube.com", "paypal.com", "cloudflare.com",
}

# ==============================================================================
# CONSTANTS FOR THRESHOLDS
# ==============================================================================

FALSE_POSITIVE_THRESHOLD = 20   # trusted domain scoring above this is a FP
FALSE_NEGATIVE_THRESHOLD = 70   # phishing domain scoring below this is a FN
BROKEN_CONFIDENCE_THRESHOLD = 50  # high confidence + score below this = bug

# ==============================================================================
# API CLIENT
# ==============================================================================


def call_analysis(domain: str) -> dict[str, Any] | None:
    """POST the domain to the RETRO_INTEL analyzer and return the JSON response."""
    payload = json.dumps({"url": domain}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            return dict(json.loads(resp.read().decode("utf-8")))
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        print(f"  [API ERROR] {domain}: {exc}")
        return None


def health_check() -> str | None:
    """Return a status string if the API is reachable, else None."""
    try:
        req = urllib.request.Request(HEALTH_URL)
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("status")
    except Exception:
        return None


# ==============================================================================
# FIELD EXTRACTORS
# ==============================================================================


def get_verdict(risk_score: int) -> str:
    """Map a numeric risk score to a human-readable verdict."""
    if risk_score >= 90:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH RISK"
    if risk_score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def get_ml_score(data: dict[str, Any]) -> str:
    """Extract the ML score from ml_result."""
    ml = data.get("ml_result", {})
    if ml.get("xgb_available"):
        s = ml.get("xgb_score")
        if s is not None:
            return str(s)
    return "N/A"


def get_ml_verdict(data: dict[str, Any]) -> str:
    """Extract the ML verdict from ml_result."""
    ml = data.get("ml_result", {})
    if ml.get("xgb_available"):
        v = ml.get("xgb_verdict", "")
        return v if v else "N/A"
    return "N/A"


def get_confidence(data: dict[str, Any]) -> str:
    """Extract the dynamic confidence label and percentage."""
    sc = data.get("score_components", {})
    conf = sc.get("dynamic_confidence", {})
    if conf:
        level = conf.get("confidence_level", "")
        pct = conf.get("confidence_pct")
        if level and pct is not None:
            return f"{level} ({pct}%)"
        return str(level) if level else "N/A"
    return "N/A"


def has_typosquatting(findings: list[str]) -> str:
    """Return YES/NO depending on whether typosquatting is flagged."""
    for f in findings:
        upper = f.upper()
        if "TYPOSQUATTING" in upper or "IMPERSONATION" in upper:
            return "YES"
    return "NO"


def has_brand_impersonation(findings: list[str]) -> str:
    """Return YES/NO depending on brand impersonation indicators."""
    upper_text = " ".join(f.upper() for f in findings)
    if "BRAND" in upper_text and ("IMPERSONATION" in upper_text or "LOOKALIKE" in upper_text or "RESEMBLES" in upper_text):
        return "YES"
    if "TYPOSQUATTING" in upper_text:
        return "YES"
    return "NO"

def has_dnssec(findings: list[str]) -> str:
    """Return YES/NO depending on whether DNSSEC is enabled."""
    upper_text = " ".join(f.upper() for f in findings)
    if "DNSSEC" in upper_text and "ENABLED" in upper_text:
        return "YES"
    if "DNSSEC" in upper_text and "DISABLED" in upper_text:
        return "NO"
    return "N/A"

def has_hsts(findings: list[str]) -> str:
    """Return HSTS status string from findings."""
    upper_text = " ".join(f.upper() for f in findings)
    if "STRONG HSTS" in upper_text:
        return "Strong"
    if "HSTS MISSING" in upper_text or "MISSING HSTS" in upper_text:
        return "Missing"
    if "WEAK HSTS" in upper_text:
        return "Weak"
    return "N/A"


# ==============================================================================
# TABLE RENDERER
# ==============================================================================

TABLE_HEADERS = [
    "Domain", "Score", "Verdict", "Confidence", "ML Score",
    "ML Verdict", "Age", "Registrar", "SSL Issuer", "DNSSEC",
    "Typosquat", "Brand Imp.", "Findings", "Runtime",
]

TABLE_WIDTHS = [30, 6, 12, 18, 8, 12, 10, 20, 22, 7, 10, 12, 8, 8]


def _trunc(val: str, width: int) -> str:
    if len(val) > width:
        return val[: width - 1] + "…"
    return val.ljust(width)


def _sep() -> str:
    return "+" + "+".join("-" * w for w in TABLE_WIDTHS) + "+"


def _row(values: list[str]) -> str:
    return "|" + "|".join(_trunc(v, w) for v, w in zip(values, TABLE_WIDTHS)) + "|"


def print_table(results: list[dict[str, Any]]) -> None:
    """Print a formatted table of results."""

    # ---- ANSI colour helpers
    def colour(text: str, ansi: str) -> str:
        return f"{ansi}{text}\033[0m"

    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"

    print(_sep())
    print(_row(TABLE_HEADERS))
    print(_sep())

    for r in results:
        domain = r["domain"]
        score = str(r["risk_score"])
        verdict = r["verdict"]
        confidence = r["confidence"]
        ml_score = r["ml_score"]
        ml_verdict = r["ml_verdict"]
        age = (r.get("domain_age") or "N/A")[:10]
        registrar = (r.get("registrar") or "N/A")[:20]
        ssl = (r.get("ssl_issuer") or "N/A")[:22]
        dnssec = r.get("dnssec", "N/A")[:7]
        typo = r.get("typosquatting", "N/A")[:10]
        brand = r.get("brand_impersonation", "N/A")[:12]
        fc = str(r.get("findings_count", 0))
        rt = f"{r.get('runtime', 0):.2f}s"

        cells = [domain, score, verdict, confidence, ml_score,
                 ml_verdict, age, registrar, ssl, dnssec,
                 typo, brand, fc, rt]
        raw = _row(cells)

        if verdict in ("CRITICAL", "HIGH RISK"):
            print(colour(raw, RED))
        elif verdict == "SUSPICIOUS":
            print(colour(raw, YELLOW))
        elif verdict == "SAFE":
            print(colour(raw, GREEN))
        else:
            print(raw)

    print(_sep())


def print_category_header(category: str) -> None:
    """Print a coloured section header for each domain category."""
    print()
    print(f"\033[1;36m{'=' * 80}\033[0m")
    print(f"\033[1;36m  CATEGORY: {category}\033[0m")
    print(f"\033[1;36m{'=' * 80}\033[0m")
    print()


# ==============================================================================
# ISSUE DETECTION
# ==============================================================================

def detect_issues(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """
    Run all integrated issue detectors against a list of results.

    Returns a list of issue dicts with keys: type, domain, detail
    """
    issues: list[dict[str, str]] = []

    for r in results:
        domain: str = r["domain"]
        score: int = r["risk_score"]
        verdict: str = r["verdict"]
        ml_verdict: str = r["ml_verdict"]
        confidence: str = r["confidence"]
        findings: list[str] = r.get("findings_raw", [])

        # -- FALSE_POSITIVE: trusted domain scoring unexpectedly high
        if domain in TRUSTED_SET and score > FALSE_POSITIVE_THRESHOLD:
            issues.append({
                "type": "FALSE_POSITIVE",
                "domain": domain,
                "detail": (f"Trusted domain scored {score}/100 - "
                           f"expected <= {FALSE_POSITIVE_THRESHOLD}"),
            })

        # -- FALSE_NEGATIVE: phishing domain scoring too low
        if domain in PHISHING_SET and score < FALSE_NEGATIVE_THRESHOLD:
            issues.append({
                "type": "FALSE_NEGATIVE",
                "domain": domain,
                "detail": (f"Phishing domain scored {score}/100 - "
                           f"expected >= {FALSE_NEGATIVE_THRESHOLD}"),
            })

        # -- BROKEN_CONFIDENCE: confidence contradicts strong signals
        # Confidence represents CERTAINTY, not safety.
        # Only flag if High confidence on something that should clearly be
        # high-risk but scored low (e.g. phishing domain with high confidence
        # scoring < 50). SAFE + High confidence is VALID.
        if "High" in confidence and score < BROKEN_CONFIDENCE_THRESHOLD and domain in PHISHING_SET:
            issues.append({
                "type": "BROKEN_CONFIDENCE",
                "domain": domain,
                "detail": (f"High confidence ({confidence}) with low "
                           f"risk score ({score}/100)"),
            })

        # -- BROKEN_ASN: missing or unresolvable ASN / country
        country = r.get("country", "")
        asn = r.get("asn", "")
        if country in ("", "N/A", "UN") or asn in ("", "N/A"):
            issues.append({
                "type": "BROKEN_ASN",
                "domain": domain,
                "detail": f"ASN={asn!r}, Country={country!r}",
            })

        # -- HEADER_BUG: major trusted domain without HSTS
        if domain in HSTS_EXPECTED:
            hsts = has_hsts(findings)
            if hsts == "Missing":
                issues.append({
                    "type": "HEADER_BUG",
                    "domain": domain,
                    "detail": "Major trusted domain reported as missing HSTS",
                })

        # -- LOGIC_CONTRADICTION: SAFE verdict + ML says Phishing
        if verdict == "SAFE" and ml_verdict == "Phishing":
            issues.append({
                "type": "LOGIC_CONTRADICTION",
                "domain": domain,
                "detail": "Overall SAFE verdict but ML classifies as Phishing",
            })

    return issues


def print_issues(issues: list[dict[str, str]]) -> None:
    """Print all detected issues grouped by type."""
    if not issues:
        print(f"\n\033[92m[OK] No issues detected - all systems nominal.\033[0m")
        return

    # Group by type
    grouped: dict[str, list[dict[str, str]]] = {}
    for issue in issues:
        grouped.setdefault(issue["type"], []).append(issue)

    print(f"\n\033[1;91m{'=' * 60}")
    print(f"  ISSUES DETECTED  ({len(issues)} total)")
    print(f"{'=' * 60}\033[0m")

    for issue_type, group in sorted(grouped.items()):
        print(f"\n  \033[1;93m{issue_type}\033[0m  ({len(group)})")
        for issue in group:
            print(f"    \033[91m->\033[0m {issue['domain']}")
            print(f"      {issue['detail']}")


# ==============================================================================
# SUMMARY
# ==============================================================================

def print_summary(results: list[dict[str, Any]], issues: list[dict[str, str]]) -> None:
    """Print a final rollup with pass/fail and per-type issue counts."""
    total = len(results)
    succeeded = sum(1 for r in results if r.get("status") == "ok")
    failed = total - succeeded

    scores = [r["risk_score"] for r in results if r.get("status") == "ok"]
    avg_score = sum(scores) / len(scores) if scores else 0
    total_time = sum(r.get("runtime", 0) for r in results)
    avg_time = total_time / total if total else 0

    type_counts: dict[str, int] = {}
    for i in issues:
        type_counts[i["type"]] = type_counts.get(i["type"], 0) + 1

    print()
    print("=" * 60)
    print("  FINAL SUMMARY")
    print("=" * 60)
    print(f"  Total tested:          {total}")
    print(f"  Succeeded:             {succeeded}")
    print(f"  Failed (API error):    {failed}")
    print(f"  Average risk score:    {avg_score:.1f}/100")
    print(f"  Total runtime:         {total_time:.2f}s")
    print(f"  Average runtime:       {avg_time:.2f}s")
    print()
    recommendation_issues = (
        type_counts.get('HEADER_BUG', 0)
        + type_counts.get('LOGIC_CONTRADICTION', 0)
    )

    print(f"  Issue breakdown:")
    print(f"    False Positives:     {type_counts.get('FALSE_POSITIVE', 0)}")
    print(f"    False Negatives:     {type_counts.get('FALSE_NEGATIVE', 0)}")
    print(f"    Confidence Bugs:     {type_counts.get('BROKEN_CONFIDENCE', 0)}")
    print(f"    Parsing Bugs:        {type_counts.get('BROKEN_ASN', 0)}")
    print(f"    Recommendation:      {recommendation_issues}")
    print(f"    Total Issues:        {len(issues)}")
    print("=" * 60)
    print()


# ==============================================================================
# PER-DOMAIN TEST RUNNER
# ==============================================================================

def run_domain(domain: str) -> dict[str, Any] | None:
    """Analyze a single domain via the API and return a result dict."""
    start = time.time()
    data = call_analysis(domain)
    elapsed = time.time() - start

    if data is None:
        return {
            "domain": domain,
            "status": "error",
            "risk_score": 0,
            "verdict": "ERROR",
            "confidence": "N/A",
            "ml_score": "N/A",
            "ml_verdict": "N/A",
            "domain_age": "N/A",
            "registrar": "N/A",
            "ssl_issuer": "N/A",
            "dnssec": "N/A",
            "typosquatting": "N/A",
            "brand_impersonation": "N/A",
            "findings_count": 0,
            "findings_raw": [],
            "runtime": elapsed,
            "country": "",
            "asn": "",
        }

    parsed = data.get("parsed_meta", {})
    findings = data.get("findings", [])
    risk_score = data.get("risk_score", 0)
    domain_age = parsed.get("domain_age", "N/A")

    return {
        "domain": domain,
        "status": "ok",
        "risk_score": risk_score,
        "verdict": get_verdict(risk_score),
        "confidence": get_confidence(data),
        "ml_score": get_ml_score(data),
        "ml_verdict": get_ml_verdict(data),
        "domain_age": domain_age,
        "registrar": parsed.get("registrar", "N/A"),
        "ssl_issuer": parsed.get("ssl_issuer", "N/A"),
        "dnssec": has_dnssec(findings),
        "typosquatting": has_typosquatting(findings),
        "brand_impersonation": has_brand_impersonation(findings),
        "findings_count": len(findings),
        "findings_raw": findings,
        "runtime": elapsed,
        "country": parsed.get("country", ""),
        "asn": parsed.get("asn", ""),
    }


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

def main() -> int:
    print(f"\033[1;36m{'=' * 60}")
    print("  RETRO_INTEL — Automated QA Test Suite")
    print(f"{'=' * 60}\033[0m")
    print(f"  API:       {API_URL}")
    print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Domains:   {sum(len(d) for _, d in ALL_CATEGORIES)} total")
    print(f"{'=' * 60}\n")

    # -- Prerequisite: API must be running
    hs = health_check()
    if hs != "online":
        print("\033[91m[FAIL] RETRO_INTEL API is not reachable.\033[0m")
        print("    Start the backend:  cd backend && python main.py")
        print("    Then re-run:        python backend/test_domain_suite.py")
        return 1
    print("\033[92m[OK] API is online\033[0m\n")

    all_results: list[dict[str, Any]] = []
    all_issues: list[dict[str, str]] = []

    # -- Run each category
    for category, domains in ALL_CATEGORIES:
        print_category_header(category)
        cat_results: list[dict[str, Any]] = []

        for domain in domains:
            result = run_domain(domain)
            if result:
                cat_results.append(result)

        print_table(cat_results)
        all_results.extend(cat_results)

        # Immediate issue detection per category
        all_issues.extend(detect_issues(cat_results))

    # -- Output issues and summary
    print_issues(all_issues)
    print_summary(all_results, all_issues)

    # Return exit code: 0 if no false-positive/negative issues, 1 otherwise
    blocking = {i["type"] for i in all_issues
                if i["type"] in ("FALSE_POSITIVE", "FALSE_NEGATIVE")}
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())

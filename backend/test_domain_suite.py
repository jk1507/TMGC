"""
test_domain_suite.py - RETRO_INTEL Automated QA Testing Suite
===============================================================

Runs batch analysis against the live RETRO_INTEL API with asyncio concurrency
for fast execution. Produces:
  - Structured table with per-domain analysis
  - Automatic issue detection (false positives, false negatives, etc.)
  - Final summary with pass/fail statistics

Usage:
  1. Start the RETRO_INTEL backend:  cd backend && python -m uvicorn main:app
  2. Run this script:                python backend/test_domain_suite.py
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from datetime import datetime
from typing import Any

import httpx
from tqdm import tqdm

API_URL = "http://127.0.0.1:8000/api/v1/analyze"
HEALTH_URL = "http://127.0.0.1:8000/health"

MAX_CONCURRENT = 10
PER_REQUEST_TIMEOUT = 30  # seconds

# ==============================================================================
# TEST DOMAINS
# ==============================================================================

LEGITIMATE_DOMAINS: list[str] = [
    "google.com", "github.com", "microsoft.com", "amazon.com",
    "chatgpt.com", "openai.com", "youtube.com", "paypal.com",
    "cloudflare.com", "wikipedia.org",
]

SUSPICIOUS_DOMAINS: list[str] = [
    "randomdomain123.xyz", "unknownstartup.xyz", "weird-random-domain.site",
]

PHISHING_DOMAINS: list[str] = [
    "g00gle.com", "go0gle.com", "paypa1.com", "goog1e.com",
    "faceb00k-login.top", "micr0soft-login.xyz",
    "google-account-security.xyz", "secure-paypal-login.tk",
]

EDGE_CASE_DOMAINS: list[str] = [
    "localhost", "127.0.0.1", "example.com",
]

ALL_CATEGORIES: list[tuple[str, list[str]]] = [
    ("LEGITIMATE", LEGITIMATE_DOMAINS),
    ("SUSPICIOUS", SUSPICIOUS_DOMAINS),
    ("PHISHING", PHISHING_DOMAINS),
    ("EDGE CASES", EDGE_CASE_DOMAINS),
]

TRUSTED_SET: set[str] = set(LEGITIMATE_DOMAINS)
PHISHING_SET: set[str] = set(PHISHING_DOMAINS)

HSTS_EXPECTED: set[str] = {
    "google.com", "github.com", "microsoft.com", "amazon.com",
    "openai.com", "youtube.com", "paypal.com", "cloudflare.com",
}

# ==============================================================================
# THRESHOLDS
# ==============================================================================

FALSE_POSITIVE_THRESHOLD = 20   # trusted domain scoring above this is a FP
FALSE_NEGATIVE_THRESHOLD = 70   # phishing domain scoring below this is a FN
BROKEN_CONFIDENCE_THRESHOLD = 50

# ==============================================================================
# FIELD EXTRACTORS
# ==============================================================================


def get_verdict(risk_score: int) -> str:
    if risk_score >= 90:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH RISK"
    if risk_score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def get_ml_score(data: dict[str, Any]) -> str:
    ml = data.get("ml_result", {})
    if ml.get("xgb_available"):
        s = ml.get("xgb_score")
        return str(s) if s is not None else "N/A"
    return "N/A"


def get_ml_verdict(data: dict[str, Any]) -> str:
    ml = data.get("ml_result", {})
    if ml.get("xgb_available"):
        v = ml.get("xgb_verdict", "")
        return v if v else "N/A"
    return "N/A"


def get_confidence(data: dict[str, Any]) -> str:
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
    for f in findings:
        u = f.upper()
        if "TYPOSQUATTING" in u or "IMPERSONATION" in u:
            return "YES"
    return "NO"


def has_brand_impersonation(findings: list[str]) -> str:
    ut = " ".join(f.upper() for f in findings)
    if "BRAND" in ut and ("IMPERSONATION" in ut or "LOOKALIKE" in ut or "RESEMBLES" in ut):
        return "YES"
    if "TYPOSQUATTING" in ut:
        return "YES"
    return "NO"


def has_dnssec(findings: list[str]) -> str:
    ut = " ".join(f.upper() for f in findings)
    if "DNSSEC" in ut and "ENABLED" in ut:
        return "YES"
    if "DNSSEC" in ut and "DISABLED" in ut:
        return "NO"
    return "N/A"


def has_hsts(findings: list[str]) -> str:
    ut = " ".join(f.upper() for f in findings)
    if "STRONG HSTS" in ut:
        return "Strong"
    if "HSTS MISSING" in ut or "MISSING HSTS" in ut:
        return "Missing"
    if "WEAK HSTS" in ut:
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
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def _trunc(val: str, width: int) -> str:
    if len(val) > width:
        return val[: width - 1] + "…"
    return val.ljust(width)


def _sep() -> str:
    return "+" + "+".join("-" * w for w in TABLE_WIDTHS) + "+"


def _row(values: list[str]) -> str:
    return "|" + "|".join(_trunc(v, w) for v, w in zip(values, TABLE_WIDTHS)) + "|"


def _colour(text: str, ansi: str) -> str:
    return f"{ansi}{text}{RESET}"


def print_table(results: list[dict[str, Any]]) -> None:
    """Print a formatted table of results."""
    print(_sep())
    print(_row(TABLE_HEADERS))
    print(_sep())

    for r in results:
        cells = [
            r["domain"], str(r["risk_score"]), r["verdict"], r["confidence"],
            r["ml_score"], r["ml_verdict"],
            (r.get("domain_age") or "N/A")[:10],
            (r.get("registrar") or "N/A")[:20],
            (r.get("ssl_issuer") or "N/A")[:22],
            (r.get("dnssec", "N/A"))[:7],
            (r.get("typosquatting", "N/A"))[:10],
            (r.get("brand_impersonation", "N/A"))[:12],
            str(r.get("findings_count", 0)),
            f"{r.get('runtime', 0):.2f}s",
        ]
        raw = _row(cells)
        v = r["verdict"]
        if v in ("CRITICAL", "HIGH RISK"):
            print(_colour(raw, RED))
        elif v == "SUSPICIOUS":
            print(_colour(raw, YELLOW))
        elif v == "SAFE":
            print(_colour(raw, GREEN))
        else:
            print(raw)

    print(_sep())


def print_category_header(category: str) -> None:
    print()
    print(f"\033[1;36m{'=' * 80}{RESET}")
    print(f"\033[1;36m  CATEGORY: {category}{RESET}")
    print(f"\033[1;36m{'=' * 80}{RESET}")
    print()


# ==============================================================================
# ISSUE DETECTION
# ==============================================================================

def detect_issues(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Run all integrated issue detectors against a list of results."""
    issues: list[dict[str, str]] = []

    for r in results:
        domain: str = r["domain"]
        score: int = r["risk_score"]
        verdict: str = r["verdict"]
        ml_verdict: str = r["ml_verdict"]
        confidence: str = r["confidence"]
        findings: list[str] = r.get("findings_raw", [])

        if domain in TRUSTED_SET and score > FALSE_POSITIVE_THRESHOLD:
            issues.append({
                "type": "FALSE_POSITIVE", "domain": domain,
                "detail": f"Trusted domain scored {score}/100 - expected <= {FALSE_POSITIVE_THRESHOLD}",
            })

        if domain in PHISHING_SET and score < FALSE_NEGATIVE_THRESHOLD:
            issues.append({
                "type": "FALSE_NEGATIVE", "domain": domain,
                "detail": f"Phishing domain scored {score}/100 - expected >= {FALSE_NEGATIVE_THRESHOLD}",
            })

        if "High" in confidence and score < BROKEN_CONFIDENCE_THRESHOLD and domain in PHISHING_SET:
            issues.append({
                "type": "BROKEN_CONFIDENCE", "domain": domain,
                "detail": f"High confidence ({confidence}) with low risk score ({score}/100)",
            })

        country = r.get("country", "")
        asn = r.get("asn", "")
        if country in ("", "N/A", "UN") or asn in ("", "N/A"):
            issues.append({
                "type": "BROKEN_ASN", "domain": domain,
                "detail": f"ASN={asn!r}, Country={country!r}",
            })

        if domain in HSTS_EXPECTED:
            hsts = has_hsts(findings)
            if hsts == "Missing":
                issues.append({
                    "type": "HEADER_BUG", "domain": domain,
                    "detail": "Major trusted domain reported as missing HSTS",
                })

        if verdict == "SAFE" and ml_verdict == "Phishing":
            issues.append({
                "type": "LOGIC_CONTRADICTION", "domain": domain,
                "detail": "Overall SAFE verdict but ML classifies as Phishing",
            })

    return issues


def print_issues(issues: list[dict[str, str]]) -> None:
    if not issues:
        print(f"\n\033[92m[OK] No issues detected - all systems nominal.{RESET}")
        return

    grouped: dict[str, list[dict[str, str]]] = {}
    for issue in issues:
        grouped.setdefault(issue["type"], []).append(issue)

    print(f"\n\033[1;91m{'=' * 60}")
    print(f"  ISSUES DETECTED  ({len(issues)} total)")
    print(f"{'=' * 60}{RESET}")

    for issue_type, group in sorted(grouped.items()):
        print(f"\n  \033[1;93m{issue_type}{RESET}  ({len(group)})")
        for issue in group:
            print(f"    \033[91m->{RESET} {issue['domain']}")
            print(f"      {issue['detail']}")


def print_summary(results: list[dict[str, Any]], issues: list[dict[str, str]]) -> None:
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
    rec_issues = type_counts.get('HEADER_BUG', 0) + type_counts.get('LOGIC_CONTRADICTION', 0)
    print(f"  Issue breakdown:")
    print(f"    False Positives:     {type_counts.get('FALSE_POSITIVE', 0)}")
    print(f"    False Negatives:     {type_counts.get('FALSE_NEGATIVE', 0)}")
    print(f"    Confidence Bugs:     {type_counts.get('BROKEN_CONFIDENCE', 0)}")
    print(f"    Parsing Bugs:        {type_counts.get('BROKEN_ASN', 0)}")
    print(f"    Recommendation:      {rec_issues}")
    print(f"    Total Issues:        {len(issues)}")
    print("=" * 60)
    print()


# ==============================================================================
# PER-DOMAIN ANALYZER
# ==============================================================================

def build_result(domain: str, data: dict[str, Any] | None, elapsed: float) -> dict[str, Any]:
    """Build a result dict from API response or None."""
    if data is None:
        return {
            "domain": domain, "status": "error", "risk_score": 0, "verdict": "ERROR",
            "confidence": "N/A", "ml_score": "N/A", "ml_verdict": "N/A",
            "domain_age": "N/A", "registrar": "N/A", "ssl_issuer": "N/A",
            "dnssec": "N/A", "typosquatting": "N/A", "brand_impersonation": "N/A",
            "findings_count": 0, "findings_raw": [], "runtime": elapsed,
            "country": "", "asn": "",
        }

    parsed = data.get("parsed_meta", {})
    findings = data.get("findings", [])
    risk_score = data.get("risk_score", 0)

    return {
        "domain": domain, "status": "ok", "risk_score": risk_score,
        "verdict": get_verdict(risk_score), "confidence": get_confidence(data),
        "ml_score": get_ml_score(data), "ml_verdict": get_ml_verdict(data),
        "domain_age": parsed.get("domain_age", "N/A"),
        "registrar": parsed.get("registrar", "N/A"),
        "ssl_issuer": parsed.get("ssl_issuer", "N/A"),
        "dnssec": has_dnssec(findings),
        "typosquatting": has_typosquatting(findings),
        "brand_impersonation": has_brand_impersonation(findings),
        "findings_count": len(findings), "findings_raw": findings,
        "runtime": elapsed, "country": parsed.get("country", ""),
        "asn": parsed.get("asn", ""),
    }


async def analyze_one(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    pbar: tqdm,
) -> dict[str, Any]:
    """Analyze a single domain via the API with concurrency control."""
    async with sem:
        t0 = time.time()
        payload = {"url": domain}
        try:
            resp = await client.post(
                API_URL,
                json=payload,
                timeout=httpx.Timeout(PER_REQUEST_TIMEOUT),
            )
            data = resp.json()
        except Exception:
            data = None
        elapsed = time.time() - t0
        result = build_result(domain, data, elapsed)

        status = result["status"]
        score = result["risk_score"]
        if status == "ok":
            pbar.set_postfix_str(f"{domain[:25]:25s} score={score:3d}  {result['verdict']:12s}  {elapsed:.1f}s")
        else:
            pbar.set_postfix_str(f"{domain[:25]:25s} ERROR  {elapsed:.1f}s")

        pbar.update(1)
        return result


# ==============================================================================
# MAIN
# ==============================================================================

async def main() -> int:
    categories_total = sum(len(d) for _, d in ALL_CATEGORIES)

    print(f"\033[1;36m{'=' * 60}")
    print("  RETRO_INTEL — Automated QA Test Suite (Async)")
    print(f"{'=' * 60}{RESET}")
    print(f"  API:       {API_URL}")
    print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Domains:   {categories_total} total")
    print(f"  Concurrency: {MAX_CONCURRENT}, Timeout: {PER_REQUEST_TIMEOUT}s")
    print(f"{'=' * 60}\n")

    # -- Prerequisite --
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(HEALTH_URL)
            hs = r.json().get("status")
        if hs != "online":
            print(f"\033[91m[FAIL] API status: {hs}{RESET}")
            return 1
    except Exception:
        print("\033[91m[FAIL] RETRO_INTEL API is not reachable.{RESET}")
        print("    Start the backend:  cd backend && python -m uvicorn main:app")
        return 1
    print("\033[92m[OK] API is online\033[0m\n")

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    all_results: list[dict[str, Any]] = []
    all_issues: list[dict[str, str]] = []

    pbar = tqdm(total=categories_total, desc="Analyzing", unit="dom", ncols=110,
                bar_format="{l_bar}{bar:20}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}")

    async with httpx.AsyncClient(timeout=httpx.Timeout(PER_REQUEST_TIMEOUT + 5)) as client:
        for category, domains in ALL_CATEGORIES:
            print_category_header(category)

            tasks = [analyze_one(client, d, sem, pbar) for d in domains]
            cat_results = await asyncio.gather(*tasks)

            print_table(cat_results)
            all_results.extend(cat_results)
            all_issues.extend(detect_issues(cat_results))

    pbar.close()

    # -- Output issues and summary --
    print_issues(all_issues)
    print_summary(all_results, all_issues)

    blocking = {i["type"] for i in all_issues
                if i["type"] in ("FALSE_POSITIVE", "FALSE_NEGATIVE")}
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

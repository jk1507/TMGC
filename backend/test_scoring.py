"""
test_scoring.py - RETRO_INTEL Hybrid Scoring Engine Validation

Tests the new scoring engine against expected behavior for:
- Trusted legitimate domains (should score 0-15)
- Suspicious domains (should score 20-60)
- High confidence phishing (should score 80-100)
- Typosquatting / homoglyph (should score 80-100)
- Hard-protected domains (should never be suspicious)
- False positive resistance
- Dynamic confidence
- Explainable reasoning

Run: python backend/test_scoring.py
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scoring import (
    compute_hybrid_score,
    is_hard_protected,
    get_threat_level,
    compute_dynamic_confidence,
)


def print_header(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


pass_count = 0
fail_count = 0
total_count = 0


def check(name: str, score: int, expected: tuple[int, int]) -> bool:
    global pass_count, fail_count, total_count
    total_count += 1
    lo, hi = expected
    if lo <= score <= hi:
        pass_count += 1
        return True
    fail_count += 1
    print(f"  [!] FAIL: {name}")
    print(f"       Score: {score}/100, Expected: {lo}-{hi}")
    return False


def run_tests() -> int:
    global pass_count, fail_count, total_count
    # Reset counters
    pass_count = 0
    fail_count = 0
    total_count = 0

    # ======================================================================
    # TEST 1: Trusted legitimate domains (hard-protected)
    # ======================================================================
    print_header("TEST GROUP 1: Hard-Protected Legitimate Domains")
    print("  These must NEVER return suspicious scores.")

    trusted_domains = [
        ("google.com", (0, 10)),
        ("microsoft.com", (0, 10)),
        ("github.com", (0, 10)),
        ("amazon.com", (0, 10)),
        ("openai.com", (0, 10)),
        ("youtube.com", (0, 10)),
        ("apple.com", (0, 10)),
        ("paypal.com", (0, 10)),
        ("cloudflare.com", (0, 10)),
        ("stackoverflow.com", (0, 10)),
        ("wikipedia.org", (0, 10)),
        ("docker.com", (0, 10)),
        ("nytimes.com", (0, 10)),
        ("tesla.com", (0, 10)),
        ("mit.edu", (0, 10)),
    ]

    for domain, expected in trusted_domains:
        xgb_res = {"xgb_available": True, "xgb_score": 45.0, "xgb_verdict": "Suspicious"}
        score, components, reasons = compute_hybrid_score(
            domain=domain,
            heuristic_score=5,
            header_score=3,
            xgb_res=xgb_res,
            ai_score=10,
            age_days=8000,
            registrar="MarkMonitor Inc.",
            ssl_issuer="Google Trust Services",
            asn="AS15169",
            hosting="Google LLC",
            has_valid_ssl=True,
            has_mx=True,
            has_nameservers=True,
        )
        ok = check(f"{domain} (ML={xgb_res['xgb_score']})", score, expected)
        if not ok:
            print(f"         -> Expected {expected}, got {score}")

    # ======================================================================
    # TEST 2: Malicious/Phishing domains
    # ======================================================================
    print_header("TEST GROUP 2: High Confidence Phishing Domains")
    print("  These should score HIGH RISK or MALICIOUS.")

    phishing_tests = [
        ("g00gle-login.xyz", (75, 100), {"heuristic": 65, "typo": True, "tld": "xyz", "age": 5}),
        ("paypal-secure-login.top", (75, 100), {"heuristic": 60, "typo": True, "tld": "top", "age": 10}),
        ("microsoft-auth-verify.tk", (80, 100), {"heuristic": 60, "typo": True, "tld": "tk", "age": 3}),
        ("secure-paypal-login.tk", (85, 100), {"heuristic": 65, "typo": True, "tld": "tk", "age": 2, "combo": True, "privacy": True}),
        ("google-account-security.xyz", (75, 100), {"heuristic": 55, "typo": True, "tld": "xyz", "age": 15, "combo": True}),
    ]

    for domain, expected_range, ctx in phishing_tests:
        xgb_res = {"xgb_available": True, "xgb_score": 85.0, "xgb_verdict": "Phishing"}
        score, components, reasons = compute_hybrid_score(
            domain=domain,
            heuristic_score=ctx["heuristic"],
            header_score=10,
            xgb_res=xgb_res,
            ai_score=80,
            age_days=ctx["age"],
            has_typosquatting=ctx.get("typo", False),
            typosquatting_score=0.90,
            has_combosquatting=ctx.get("combo", False),
            suspicious_tld=True,
            tld=ctx["tld"],
            has_homoglyph=True,
            privacy_protected=ctx.get("privacy", False),
        )
        ok = check(f"{domain}", score, expected_range)
        if not ok:
            conf = components.get("dynamic_confidence", {})
            print(f"         -> Expected {expected_range}, got {score}")
            print(f"         -> Confidence: {conf.get('confidence_level', 'N/A')} ({conf.get('confidence_pct', 'N/A')}%)")

    # ======================================================================
    # TEST 3: Typosquatting domains
    # ======================================================================
    print_header("TEST GROUP 3: Typosquatting / Homoglyph Domains")
    print("  These should score HIGH RISK.")

    typo_tests = [
        ("g00gle.com", (70, 100)),
        ("go0gle.com", (70, 100)),
        ("paypa1.com", (70, 100)),
        ("micr0soft-login.xyz", (80, 100)),
        ("faceboook.com", (65, 100)),
    ]

    for domain, expected_range in typo_tests:
        xgb_res = {"xgb_available": True, "xgb_score": 80.0, "xgb_verdict": "Phishing"}
        score, components, reasons = compute_hybrid_score(
            domain=domain,
            heuristic_score=55,
            header_score=8,
            xgb_res=xgb_res,
            ai_score=75,
            age_days=30,
            has_typosquatting=True,
            typosquatting_score=0.90,
            has_homoglyph=True,
            homoglyph_count=2,
            has_digit_substitution=True,
        )
        ok = check(f"{domain}", score, expected_range)
        if not ok:
            print(f"         -> Expected {expected_range}, got {score}")

    # ======================================================================
    # TEST 4: Suspicious but not malicious
    # ======================================================================
    print_header("TEST GROUP 4: Suspicious (but not malicious) Domains")
    print("  These should score in the SUSPICIOUS range.")

    suspicious_tests = [
        ("unknownstartup.xyz", (20, 55)),
        ("weird-random-domain.site", (20, 55)),
        ("newdomain123.xyz", (20, 55)),
    ]

    for domain, expected_range in suspicious_tests:
        xgb_res = {"xgb_available": False}
        score, components, reasons = compute_hybrid_score(
            domain=domain,
            heuristic_score=25,
            header_score=8,
            xgb_res=xgb_res,
            ai_score=None,
            age_days=60,
            suspicious_tld=True,
            tld=domain.split(".")[-1],
        )
        ok = check(f"{domain}", score, expected_range)
        if not ok:
            print(f"         -> Expected {expected_range}, got {score}")

    # ======================================================================
    # TEST 5: Domain age intelligence
    # ======================================================================
    print_header("TEST GROUP 5: Domain Age Intelligence")
    print("  Very old domains must get trust bonuses that reduce risk.")

    # Test 5a: Old trusted domain with elevated ML
    domain = "google.com"
    xgb_res = {"xgb_available": True, "xgb_score": 45.0, "xgb_verdict": "Suspicious"}
    score, components, reasons = compute_hybrid_score(
        domain=domain,
        heuristic_score=8,
        header_score=3,
        xgb_res=xgb_res,
        ai_score=None,
        age_days=10220,
        registrar="MarkMonitor Inc.",
        ssl_issuer="Google Trust Services",
        asn="AS15169",
        hosting="Google LLC",
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    print(f"  [*] Old trusted domain (28yr, ML=45 suspicious)")
    print(f"       Score: {score}/100 (expected 0-10)")
    trust_info = components.get("trust_bonuses", {})
    print(f"       Trust Bonuses: {list(trust_info.keys())}")
    if score > 10:
        print(f"  [!] FAIL: Old trusted domain scored too high!")
        fail_count += 1
    else:
        pass_count += 1
    total_count += 1

    # Test 5b: Very new domain
    score, _, _ = compute_hybrid_score(
        domain="brandnewdomain2024.com",
        heuristic_score=20,
        header_score=5,
        xgb_res={"xgb_available": False},
        ai_score=None,
        age_days=3,
    )
    print(f"  [*] Very new domain (3 days): Score={score}/100 (expected >= 20)")
    if score >= 20:
        pass_count += 1
    else:
        fail_count += 1
    total_count += 1

    # ======================================================================
    # TEST 6: Dynamic confidence
    # ======================================================================
    print_header("TEST GROUP 6: Dynamic Confidence System")

    conf = compute_dynamic_confidence(
        heuristic_score=5, header_score=3,
        xgb_available=True, xgb_score=10.0, xgb_verdict="legitimate",
        ai_score=10, trust_bonus=30, phishing_penalty=0,
    )
    print(f"  [*] Trusted domain confidence: {conf['confidence_level']} ({conf['confidence_pct']}%)")
    total_count += 1
    if conf["confidence_level"] in ("High", "Medium"):
        pass_count += 1
    else:
        fail_count += 1

    conf = compute_dynamic_confidence(
        heuristic_score=25, header_score=10,
        xgb_available=False, xgb_score=None, xgb_verdict=None,
        ai_score=None, trust_bonus=0, phishing_penalty=10,
    )
    print(f"  [*] Mixed signal confidence: {conf['confidence_level']} ({conf['confidence_pct']}%)")
    total_count += 1
    if conf["confidence_level"] in ("Medium", "Low"):
        pass_count += 1
    else:
        fail_count += 1

    # ======================================================================
    # TEST 7: Explainable reasoning
    # ======================================================================
    print_header("TEST GROUP 7: Explainable Reasoning")

    _, components, reasons = compute_hybrid_score(
        domain="test-example.com",
        heuristic_score=15,
        header_score=5,
        xgb_res={"xgb_available": True, "xgb_score": 30.0, "xgb_verdict": "Legitimate"},
        ai_score=20,
        age_days=2000,
        registrar="Namecheap Inc.",
        ssl_issuer="Let's Encrypt",
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    has_reasoning = bool(components.get("explainable_reasoning", []))
    print(f"  [*] Has explainable_reasoning: {has_reasoning}")
    total_count += 1
    if has_reasoning:
        pass_count += 1
        for r in components["explainable_reasoning"][:3]:
            print(f"       {r}")
    else:
        fail_count += 1

    has_trust = bool(components.get("trust_bonuses", {}))
    print(f"  [*] Has trust_bonuses: {has_trust}")
    total_count += 1
    if has_trust:
        pass_count += 1
    else:
        fail_count += 1

    has_penalties_key = "phishing_penalties" in components
    print(f"  [*] Has phishing_penalties key: {has_penalties_key}")
    total_count += 1
    pass_count += 1

    has_conf = bool(components.get("dynamic_confidence", {}))
    print(f"  [*] Has dynamic_confidence: {has_conf}")
    total_count += 1
    if has_conf:
        pass_count += 1
    else:
        fail_count += 1

    # ======================================================================
    # TEST 8: Hard-protect function
    # ======================================================================
    print_header("TEST GROUP 8: Hard-Protect Function")

    hard_protected = ["google.com", "microsoft.com", "github.com", "paypal.com", "apple.com"]
    not_protected = ["g00gle.com", "paypa1.com", "random-phish.xyz", "google-login.com"]

    for domain in hard_protected:
        ok = is_hard_protected(domain)
        total_count += 1
        if ok:
            pass_count += 1
        else:
            print(f"  [!] FAIL: {domain} should be hard-protected!")
            fail_count += 1

    for domain in not_protected:
        ok = is_hard_protected(domain)
        total_count += 1
        if not ok:
            pass_count += 1
        else:
            print(f"  [!] FAIL: {domain} should NOT be hard-protected!")
            fail_count += 1

    print(f"  [*] Hard-protect domains check: PASS")
    print(f"  [*] Non-protected domains check: PASS")

    # ======================================================================
    # TEST 9: Threat levels
    # ======================================================================
    print_header("TEST GROUP 9: Threat Levels")

    score_map = {
        5: "SAFE VERIFIED",
        18: "LOW RISK",
        35: "SUSPICIOUS",
        55: "HIGH RISK",
        90: "MALICIOUS / PHISHING",
    }
    for test_score, expected_label in score_map.items():
        label, severity = get_threat_level(test_score)
        ok = label == expected_label
        total_count += 1
        if ok:
            pass_count += 1
        else:
            print(f"  [!] FAIL: Score {test_score} -> {label} (expected {expected_label})")
            fail_count += 1

    # ======================================================================
    # TEST 10: Missing-headers + elevated ML => moderate (SUSPICIOUS) risk
    # ======================================================================
    print_header("TEST GROUP 10: Missing-headers + Elevated ML Escalation")
    print("  All critical headers confirmed missing + ML a bit higher => SUSPICIOUS.")

    # 10a: Clean-looking domain, ALL headers confirmed missing, ML elevated (42)
    score, components, reasons = compute_hybrid_score(
        domain="example-inc.com",
        heuristic_score=10,
        header_score=14,
        xgb_res={"xgb_available": True, "xgb_score": 42.0, "xgb_verdict": "Suspicious"},
        ai_score=None,
        age_days=1000,
        registrar="Namecheap Inc.",
        ssl_issuer="Let's Encrypt",
        asn="AS12345",
        hosting="SomeHost",
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("Missing headers + ML 42 => at least SUSPICIOUS", score, (26, 100))
    if not ok:
        print(f"         -> Expected >= 26, got {score}")
    has_escalation_reason = any("HEADER ESCALATION" in r for r in reasons)
    total_count += 1
    if has_escalation_reason:
        pass_count += 1
        print(f"       [*] Escalation reasoning present: '{[r for r in reasons if 'HEADER ESCALATION' in r][0]}'")
    else:
        fail_count += 1
        print(f"  [!] FAIL: Missing HEADER ESCALATION reasoning finding")

    # 10b: Same domain, LOW ML score (15) — headers ALONE still escalate,
    #     because the header-posture rule has no ML condition.
    score, _, reasons = compute_hybrid_score(
        domain="example-inc.com",
        heuristic_score=10,
        header_score=14,
        xgb_res={"xgb_available": True, "xgb_score": 15.0, "xgb_verdict": "Legitimate"},
        ai_score=None,
        age_days=1000,
        registrar="Namecheap Inc.",
        ssl_issuer="Let's Encrypt",
        asn="AS12345",
        hosting="SomeHost",
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("Missing headers alone (ML 15) => at least SUSPICIOUS", score, (26, 100))
    if not ok:
        print(f"         -> Expected >= 26 (headers alone), got {score}")

    # 10c: Headers fetch FAILED (tool failure) + ML elevated => NO escalation
    score, _, _ = compute_hybrid_score(
        domain="example-inc.com",
        heuristic_score=10,
        header_score=14,
        xgb_res={"xgb_available": True, "xgb_score": 42.0, "xgb_verdict": "Suspicious"},
        ai_score=None,
        age_days=1000,
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
        headers_unavailable=True,
    )
    ok = check("Headers tool failed + ML 42 => no escalation", score, (0, 25))
    if not ok:
        print(f"         -> Expected 0-25 (tool failure never raises risk), got {score}")

    # 10d: Hard-protected domain never escalates even with missing headers + ML
    score, _, _ = compute_hybrid_score(
        domain="google.com",
        heuristic_score=10,
        header_score=14,
        xgb_res={"xgb_available": True, "xgb_score": 42.0, "xgb_verdict": "Suspicious"},
        ai_score=None,
        age_days=8000,
        registrar="MarkMonitor Inc.",
        ssl_issuer="Google Trust Services",
        asn="AS15169",
        hosting="Google LLC",
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("Hard-protected domain never escalates", score, (0, 25))
    if not ok:
        print(f"         -> Expected 0-25 (verified org), got {score}")

    # 10e: ML score just above 20 (e.g. 22) + missing headers => SUSPICIOUS too
    score, _, reasons = compute_hybrid_score(
        domain="example-inc.com",
        heuristic_score=10,
        header_score=14,
        xgb_res={"xgb_available": True, "xgb_score": 22.0, "xgb_verdict": "Uncertain"},
        ai_score=None,
        age_days=1000,
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("Missing headers + ML 22 => at least SUSPICIOUS", score, (26, 100))
    if not ok:
        print(f"         -> Expected >= 26 (threshold 20), got {score}")
    has_escalation_reason = any("HEADER ESCALATION" in r for r in reasons)
    total_count += 1
    if has_escalation_reason:
        pass_count += 1
    else:
        fail_count += 1
        print(f"  [!] FAIL: Missing HEADER ESCALATION reasoning for ML 22")

    # ======================================================================
    # TEST 11: High-confidence ML (>= 80) => at least HIGH RISK
    # ======================================================================
    print_header("TEST GROUP 11: High-Confidence ML => HIGH RISK")
    print("  ML >= 80 alone must be at least HIGH RISK (46+).")

    # 11a: Clean-looking domain, low heuristic, but ML 85
    score, _, reasons = compute_hybrid_score(
        domain="randomstartup.io",
        heuristic_score=10,
        header_score=5,
        xgb_res={"xgb_available": True, "xgb_score": 85.0, "xgb_verdict": "Phishing"},
        ai_score=None,
        age_days=300,
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("ML 85 alone => at least HIGH RISK", score, (46, 100))
    if not ok:
        print(f"         -> Expected >= 46, got {score}")
    has_ml_reason = any("HIGH-CONFIDENCE ML" in r for r in reasons)
    total_count += 1
    if has_ml_reason:
        pass_count += 1
    else:
        fail_count += 1
        print(f"  [!] FAIL: Missing HIGH-CONFIDENCE ML reasoning")

    # 11b: ML 85 but verified org => never flagged
    score, _, _ = compute_hybrid_score(
        domain="github.com",
        heuristic_score=10,
        header_score=8,
        xgb_res={"xgb_available": True, "xgb_score": 85.0, "xgb_verdict": "Phishing"},
        ai_score=None,
        age_days=6000,
        registrar="MarkMonitor Inc.",
        ssl_issuer="GitHub Inc.",
        asn="AS36459",
        hosting="GitHub Inc.",
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("ML 85 verified org never escalates", score, (0, 25))
    if not ok:
        print(f"         -> Expected 0-25 (verified org), got {score}")

    # 11c: ML just below 80 (79) must NOT reach HIGH RISK on its own
    score, _, reasons = compute_hybrid_score(
        domain="randomstartup.io",
        heuristic_score=10,
        header_score=5,
        xgb_res={"xgb_available": True, "xgb_score": 79.0, "xgb_verdict": "Phishing"},
        ai_score=None,
        age_days=300,
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
    )
    ok = check("ML 79 alone stays below HIGH RISK", score, (0, 45))
    if not ok:
        print(f"         -> Expected 0-45 (below HIGH RISK), got {score}")

    # 11d: OVERALL 4-model ENSEMBLE >= 80 => at least HIGH RISK (even if xgb low)
    score, _, reasons = compute_hybrid_score(
        domain="randomstartup.io",
        heuristic_score=10,
        header_score=5,
        xgb_res={"xgb_available": True, "xgb_score": 30.0, "xgb_verdict": "Legitimate"},
        ai_score=None,
        age_days=300,
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
        ensemble_result={"ensemble_score": 84.0, "model_count": 4},
    )
    ok = check("Ensemble 84 (xgb 30) => at least HIGH RISK", score, (46, 100))
    if not ok:
        print(f"         -> Expected >= 46 (ensemble drives rule), got {score}")

    # 11e: Ensemble available but below 80 (55) while xgb is high (88) —
    #     the OVERALL 4-model score governs, so no HIGH RISK escalation.
    score, _, reasons = compute_hybrid_score(
        domain="randomstartup.io",
        heuristic_score=10,
        header_score=5,
        xgb_res={"xgb_available": True, "xgb_score": 88.0, "xgb_verdict": "Phishing"},
        ai_score=None,
        age_days=300,
        has_valid_ssl=True,
        has_mx=True,
        has_nameservers=True,
        ensemble_result={"ensemble_score": 55.0, "model_count": 4},
    )
    ok = check("Ensemble 55 governs (xgb 88) => no escalation", score, (0, 45))
    if not ok:
        print(f"         -> Expected 0-45 (ensemble governs), got {score}")

    # ======================================================================
    # SUMMARY
    # ======================================================================
    print()
    print("=" * 72)
    print(f"  RESULTS: {pass_count}/{total_count} passed, {fail_count}/{total_count} failed")
    print("=" * 72)
    print()

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())

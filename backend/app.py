"""
Flask API for production phishing-domain analysis.
Uses deterministic heuristics + real network/threat-intel signals.
"""

import os
from datetime import datetime
from flask import Flask, Response, jsonify, request

from ml_model import get_experimental_ml_status
from utils import (
    analyze_dns_signals,
    analyze_ssl_signals,
    analyze_virustotal,
    analyze_whois_mock,
    compute_risk_score,
    detect_combosquatting,
    detect_homoglyphs,
    detect_typosquatting,
    analyze_google_safe_browsing,
    analyze_phishtank,
    analyze_urlhaus,
    analyze_urlscan,
    extract_features,
    compare_website_to_reference,
    inspect_website,
    normalize_homoglyphs,
    sanitize_domain,
    sanitize_url,
    validate_domain,
    validate_url,
)


app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/<path:path>", methods=["OPTIONS"])
@app.route("/", methods=["OPTIONS"])
def handle_options(path=""):
    _ = path
    resp = Response()
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp, 204


def run_analysis(domain: str) -> dict:
    clean = sanitize_domain(domain)
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean
    normalized_label = normalize_homoglyphs(label)

    features = extract_features(clean)
    homoglyph_result = detect_homoglyphs(clean)
    typo_result = detect_typosquatting(normalized_label)

    typo_result_raw = detect_typosquatting(label)
    if typo_result_raw.get("jaro_winkler_score", 0) > typo_result.get("jaro_winkler_score", 0):
        typo_result = typo_result_raw

    combo_result = detect_combosquatting(clean)
    whois_result = analyze_whois_mock(clean)
    dns_result = analyze_dns_signals(clean)
    ssl_result = analyze_ssl_signals(clean)

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    vt_result = analyze_virustotal(clean, api_key=vt_key)

    risk = compute_risk_score(
        features=features,
        typo_result=typo_result,
        homoglyph_result=homoglyph_result,
        combo_result=combo_result,
        whois_result=whois_result,
        dns_result=dns_result,
        ssl_result=ssl_result,
        threat_intel_result=vt_result,
    )

    return {
        "domain": clean,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "score": risk["score"],
        "risk_level": risk["risk_level"],
        "is_fake": risk["risk_level"] in {"High", "Critical"},
        "attack_type": risk["attack_type"],
        "confidence": risk["confidence"],
        "reasons": risk["reasons"],
        "domain_age": whois_result.get("age_str"),
        "domain_age_days": whois_result.get("age_days"),
        "creation_date": whois_result.get("creation_date"),
        "registrar": whois_result.get("registrar"),
        "whois_flag": whois_result.get("whois_flag"),
        "privacy_protected": whois_result.get("privacy_protected"),
        "typosquatting": typo_result,
        "homoglyph": homoglyph_result,
        "combosquatting": combo_result,
        "features": features,
        "dns": dns_result,
        "ssl": ssl_result,
        "threat_intelligence": {"provider": "VirusTotal", **vt_result},
        "ml_classification": get_experimental_ml_status(),
        "score_breakdown": risk["breakdown"],
    }


def _website_score_adjustment(domain: str, website_result: dict) -> dict:
    """
    Adds a small, explainable adjustment based on HTML inspection signals.
    Does not override deterministic domain scoring; it only adds evidence.
    """
    adj = 0.0
    reasons = []
    breakdown = {}

    if not website_result or not website_result.get("available"):
        return {"adjustment": 0.0, "reasons": [], "breakdown": {}}

    sig = (website_result.get("signals") or {})
    has_pw = bool(sig.get("has_password_input"))
    ext_actions = sig.get("external_form_actions") or []

    if has_pw:
        adj += 8.0
        breakdown["website_password_form"] = 8.0
        reasons.append("Website contains a password input (login/credential collection)")

    if ext_actions:
        adj += 12.0
        breakdown["website_external_form_action"] = 12.0
        reasons.append("Website form posts to a different domain (external action)")

    # If the domain already looks like a brand-impersonation, add a small bump when a login form exists
    try:
        features = extract_features(domain)
        if has_pw and features.get("contains_brand_anywhere"):
            adj += 6.0
            breakdown["website_brand_plus_login"] = 6.0
            reasons.append("Brand mention combined with login form increases phishing likelihood")
    except Exception:
        pass

    return {"adjustment": adj, "reasons": reasons, "breakdown": breakdown}


def _clone_score_adjustment(domain: str, clone_result: dict, website_result: dict) -> dict:
    adj = 0.0
    reasons = []
    breakdown = {}

    if not clone_result or not clone_result.get("available"):
        return {"adjustment": 0.0, "reasons": [], "breakdown": {}}

    sim = float(clone_result.get("similarity", 0) or 0)
    likely = bool(clone_result.get("likely_clone"))
    different_host = bool(clone_result.get("different_host"))

    if different_host and sim >= 0.72:
        p = 22.0 + 18.0 * min(1.0, (sim - 0.72) / 0.28)
        adj += p
        breakdown["website_clone_similarity"] = round(p, 1)
        reasons.append("Website content is highly similar to the official site but hosted on a different domain")

        sig = (website_result.get("signals") or {}) if website_result else {}
        if sig.get("has_password_input"):
            adj += 10.0
            breakdown["website_clone_with_login"] = 10.0
            reasons.append("Clone-like website also contains a login/password form")

    elif likely:
        adj += 15.0
        breakdown["website_likely_clone"] = 15.0
        reasons.append("Website appears to be a likely clone of the official site")

    return {"adjustment": adj, "reasons": reasons, "breakdown": breakdown}


def _threat_feed_adjustment(feeds: list) -> dict:
    adj = 0.0
    reasons = []
    breakdown = {}

    flagged = [f for f in (feeds or []) if isinstance(f, dict) and f.get("flagged")]
    if flagged:
        adj += 35.0
        breakdown["threat_feeds_flagged"] = 35.0
        reasons.append("One or more external threat feeds flagged this domain/URL")

    return {"adjustment": adj, "reasons": reasons, "breakdown": breakdown}


def _compute_strict_evidence_score(result: dict) -> dict:
    """
    Evidence-only scoring: uses live network/threat-intel + fetched-page evidence.
    Intentionally excludes lexical/brand-string heuristics (typo/homoglyph/combo/keywords/etc.).
    """
    score = 0.0
    reasons = []
    breakdown = {}

    whois = result.get("whois_flag")
    age = result.get("domain_age_days")
    privacy = bool(result.get("privacy_protected"))
    if isinstance(age, int) and age >= 0:
        if age < 7:
            score += 22.0
            breakdown["whois:new_7d"] = 22.0
            reasons.append("Very newly registered domain (WHOIS)")
        elif age < 30:
            score += 18.0
            breakdown["whois:new_30d"] = 18.0
            reasons.append("Recently registered domain (WHOIS)")
        elif age < 90:
            score += 8.0
            breakdown["whois:new_90d"] = 8.0
    if privacy:
        score += 6.0
        breakdown["whois:privacy"] = 6.0
        reasons.append("WHOIS privacy/redaction enabled")
    if whois == "Suspicious":
        score += 6.0
        breakdown["whois:flag"] = 6.0

    dns = result.get("dns") or {}
    if dns.get("source") == "live":
        if not dns.get("has_dns"):
            score += 4.0
            breakdown["dns:no_records"] = 4.0
        if dns.get("suspicious_nameservers"):
            score += 5.0
            breakdown["dns:suspicious_ns"] = 5.0
            reasons.append("Suspicious nameserver pattern")

    ssl_r = result.get("ssl") or {}
    if ssl_r.get("source") == "live":
        if ssl_r.get("ssl_error"):
            score += 2.0
            breakdown["ssl:error"] = 2.0
        if ssl_r.get("self_signed_like"):
            score += 6.0
            breakdown["ssl:self_signed_like"] = 6.0
            reasons.append("Self-signed or anomalous SSL certificate")
        exp = ssl_r.get("days_to_expiry")
        if isinstance(exp, int) and exp < 0:
            score += 5.0
            breakdown["ssl:expired"] = 5.0
            reasons.append("SSL certificate is expired")

    vt = (result.get("threat_intelligence") or {})
    if vt.get("available"):
        mal = int(vt.get("malicious", 0) or 0)
        sus = int(vt.get("suspicious", 0) or 0)
        if mal > 0:
            score += 35.0
            breakdown["vt:malicious"] = 35.0
            reasons.append(f"VirusTotal flagged malicious by {mal} engine(s)")
        if sus > 0:
            score += 20.0
            breakdown["vt:suspicious"] = 20.0
            reasons.append(f"VirusTotal flagged suspicious by {sus} engine(s)")

    # Website inspection evidence
    w = result.get("website") or {}
    if w.get("available"):
        sig = w.get("signals") or {}
        if sig.get("has_password_input"):
            score += 8.0
            breakdown["website:password_form"] = 8.0
            reasons.append("Website contains a password input (credential collection)")
        if sig.get("external_form_actions"):
            score += 12.0
            breakdown["website:external_form_action"] = 12.0
            reasons.append("Website form posts to a different domain (external action)")

    # Clone detection evidence
    clone = result.get("website_clone_check") or {}
    if clone.get("available") and clone.get("different_host") and float(clone.get("similarity", 0) or 0) >= 0.72:
        p = 22.0 + 18.0 * min(1.0, (float(clone.get("similarity", 0)) - 0.72) / 0.28)
        score += p
        breakdown["clone:similarity"] = round(p, 1)
        reasons.append("Website content highly similar to official site on different host")

    # External threat feeds
    feeds = result.get("external_threat_feeds") or []
    flagged = [f for f in feeds if isinstance(f, dict) and f.get("flagged")]
    if flagged:
        score += 35.0
        breakdown["feeds:flagged"] = 35.0
        reasons.append("External threat feeds flagged this domain/URL")

    score = max(0.0, min(100.0, round(score, 1)))
    risk_level = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
    return {
        "score": score,
        "risk_level": risk_level,
        "is_fake": risk_level in {"High", "Critical"},
        "reasons": sorted(set(reasons)),
        "breakdown": breakdown,
    }


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Phishing Domain Detection API",
        "version": "3.0.0",
        "mode": "deterministic_rule_engine",
        "endpoints": {
            "POST /analyze-domain": "Analyze one domain",
            "POST /analyze-batch": "Analyze up to 20 domains",
            "POST /inspect-website": "Fetch + inspect a website URL",
            "GET /health": "Service health",
            "GET /examples": "Test domains",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Phishing Domain Detection",
        "version": "3.0.0",
        "ml_model": "disabled_experimental",
        "virustotal_configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/analyze-domain", methods=["POST"])
def analyze_domain():
    domain = ""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Request body must be JSON."}), 400
        domain = data.get("domain", "").strip()
        include_website = bool(data.get("inspect_website", False))
        website_url = data.get("url", "").strip()
        reference = (data.get("reference_domain") or data.get("official_domain") or data.get("reference_url") or "").strip()
        strict_evidence_only = bool(data.get("strict_evidence_only", False))
        ok, err = validate_domain(domain)
        if not ok:
            return jsonify({"error": err}), 400

        result = run_analysis(domain)
        result["scoring_mode"] = "deterministic_rule_engine"

        if include_website:
            # If url is not provided, default to https://<domain>
            if not website_url:
                website_url = sanitize_url(domain)
            w_ok, w_err = validate_url(website_url)
            website_result = inspect_website(website_url) if w_ok else {"available": False, "source": "validation_error", "error": w_err}
            bump = _website_score_adjustment(result["domain"], website_result)

            clone_bump = {"adjustment": 0.0, "reasons": [], "breakdown": {}}
            clone_result = None
            if reference:
                ref_url = sanitize_url(reference)
                clone_result = compare_website_to_reference(website_url, ref_url)
                clone_bump = _clone_score_adjustment(result["domain"], clone_result, website_result)

            # External threat feeds (some require API keys)
            feeds = []
            try:
                feeds.append(analyze_urlhaus(result["domain"], website_url))
            except Exception:
                pass
            try:
                feeds.append(analyze_urlscan(result["domain"], api_key=os.getenv("URLSCAN_API_KEY", "")))
            except Exception:
                pass
            try:
                feeds.append(analyze_google_safe_browsing(website_url, api_key=os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")))
            except Exception:
                pass
            try:
                feeds.append(analyze_phishtank(website_url, api_key=os.getenv("PHISHTANK_API_KEY", "")))
            except Exception:
                pass

            feed_bump = _threat_feed_adjustment(feeds)

            # combine in a transparent way
            base_score = float(result.get("score", 0) or 0)
            combined = min(
                100.0,
                round(
                    base_score
                    + float(bump["adjustment"])
                    + float(clone_bump["adjustment"])
                    + float(feed_bump["adjustment"]),
                    1,
                ),
            )

            result["website"] = website_result
            result["website_score_adjustment"] = bump
            if reference:
                result["reference"] = {"input": reference, "url": sanitize_url(reference)}
                result["website_clone_check"] = clone_result
                result["website_clone_adjustment"] = clone_bump
            result["external_threat_feeds"] = feeds
            result["external_threat_feeds_adjustment"] = feed_bump
            result["score_before_website"] = base_score
            result["score"] = combined
            # keep original risk_level if already high; otherwise recompute simple level for display
            result["risk_level"] = (
                "Critical" if combined >= 80 else "High" if combined >= 60 else "Medium" if combined >= 35 else "Low"
            )
            result["is_fake"] = result["risk_level"] in {"High", "Critical"}
            # merge reasons/breakdown
            result["reasons"] = sorted(
                set((result.get("reasons") or []) + bump["reasons"] + clone_bump["reasons"] + feed_bump["reasons"])
            )
            sb = result.get("score_breakdown") or {}
            sb.update({f"website:{k}": v for k, v in bump["breakdown"].items()})
            sb.update({f"website_clone:{k}": v for k, v in clone_bump["breakdown"].items()})
            sb.update({f"threat_feeds:{k}": v for k, v in feed_bump["breakdown"].items()})
            result["score_breakdown"] = sb

        # Optional strict mode: only evidence-based signals + threat feeds + website/clone inspection
        if strict_evidence_only:
            strict = _compute_strict_evidence_score(result)
            result["scoring_mode"] = "strict_evidence_only"
            result["score"] = strict["score"]
            result["risk_level"] = strict["risk_level"]
            result["is_fake"] = strict["is_fake"]
            # Replace reasons/breakdown to ensure they match evidence-only scoring
            result["reasons"] = strict["reasons"]
            result["score_breakdown"] = strict["breakdown"]

        return jsonify(result), 200
    except Exception as exc:
        app.logger.error("Analysis error for '%s': %s", domain, exc, exc_info=True)
        return jsonify({"error": "Internal analysis error.", "detail": str(exc)}), 500


@app.route("/inspect-website", methods=["POST"])
def inspect_website_route():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Request body must be JSON."}), 400
        url = (data.get("url") or data.get("domain") or "").strip()
        if not url:
            return jsonify({"error": "Provide 'url' (or 'domain')."}), 400
        ok, err = validate_url(url)
        if not ok:
            return jsonify({"error": err}), 400
        return jsonify(inspect_website(url)), 200
    except Exception as exc:
        app.logger.error("Website inspection error: %s", exc, exc_info=True)
        return jsonify({"error": "Internal inspection error.", "detail": str(exc)}), 500

@app.route("/analyze-batch", methods=["POST"])
def analyze_batch():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400
    domains = data.get("domains", [])
    if not isinstance(domains, list) or not domains:
        return jsonify({"error": "Provide a non-empty list under 'domains'."}), 400
    if len(domains) > 20:
        return jsonify({"error": "Maximum 20 domains per batch."}), 400

    results = []
    for d in domains:
        ok, err = validate_domain(d)
        if not ok:
            results.append({"domain": d, "error": err})
            continue
        try:
            results.append(run_analysis(d))
        except Exception as exc:
            results.append({"domain": d, "error": str(exc)})
    return jsonify({"count": len(results), "results": results}), 200


@app.route("/examples", methods=["GET"])
def examples():
    return jsonify({
        "examples": [
            {"domain": "google.com", "expected": "Low"},
            {"domain": "g00gle.com", "expected": "Typosquatting/Homoglyph"},
            {"domain": "paypal-login.com", "expected": "Combo-Squatting"},
            {"domain": "secure-amazon-verify.xyz", "expected": "High"},
            {"domain": "paypal-login.onion", "expected": "High/Critical"},
        ]
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  Phishing Domain Detection Backend")
    print("=" * 60)
    print("[INIT] Deterministic rule-based mode (ML disabled).")
    print("[INIT] Set VIRUSTOTAL_API_KEY for live threat intel.")

    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    print(f"[INIT] Starting Flask on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)

"""
Batch HTTP test using asyncio httpx concurrency for fast API testing.
Tests 100+ domains against the live RETRO_INTEL backend.

Usage:
  1. Start RETRO_INTEL backend:  cd backend && python -m uvicorn main:app
  2. Run this script:            python backend/test_100_domains.py
"""
import asyncio
import csv
import json
import os
import re
import time
from typing import Any

import httpx
from tqdm import tqdm

API_URL = "http://127.0.0.1:8000/api/v1/analyze"
HEALTH_URL = "http://127.0.0.1:8000/health"

# Concurrency settings
MAX_CONCURRENT = 10
PER_REQUEST_TIMEOUT = 30  # seconds

DOMAINS = [
    # --- 80 Legitimate/Top Domains ---
    "google.com", "youtube.com", "facebook.com", "yahoo.com", "amazon.com",
    "wikipedia.org", "reddit.com", "microsoft.com", "apple.com", "netflix.com",
    "github.com", "twitter.com", "linkedin.com", "instagram.com", "zoom.us",
    "office.com", "live.com", "bing.com", "ebay.com", "pinterest.com",
    "wordpress.com", "tumblr.com", "blogspot.com", "salesforce.com", "paypal.com",
    "spotify.com", "medium.com", "stackoverflow.com", "imgur.com", "vimeo.com",
    "dropbox.com", "cloudflare.com", "imdb.com", "nytimes.com", "cnn.com",
    "bbc.co.uk", "theguardian.com", "forbes.com", "bloomberg.com", "reuters.com",
    "huffpost.com", "wsj.com", "nike.com", "adidas.com", "starbucks.com",
    "mcdonalds.com", "subway.com", "walmart.com", "target.com", "homedepot.com",
    "ikea.com", "hm.com", "zara.com", "toyota.com", "ford.com",
    "honda.com", "bmw.com", "mercedes-benz.com", "tesla.com", "samsung.com",
    "sony.com", "panasonic.com", "lg.com", "intel.com", "amd.com",
    "nvidia.com", "oracle.com", "ibm.com", "cisco.com", "adobe.com",
    "canva.com", "figma.com", "slack.com", "trello.com", "asana.com",
    "salesforce.com", "hubspot.com", "mailchimp.com", "shopify.com", "stripe.com",

    # --- 25 Phishing/Typosquatting/Combosquatting/Homoglyph Test Domains ---
    "g00gle.com", "paypa1.com", "secure-netflix-verify.xyz", "paypal-login.com",
    "faceboook.com", "microsoft-support.tk", "secure-amazon-verify.xyz",
    "goog1e.com", "amaz0n.com", "netflix-update.xyz", "chase-billing.site",
    "bankofamerica-login.online", "apple-id-verify.club", "instagram-verify.top",
    "whatsapp-security.ga", "coinbase-wallet.ml", "binance-verify.cf",
    "fedex-tracking.gq", "dhl-shipping.pw", "ups-billing.ws",
    "yahoo-mail-login.info", "outlook-security.live", "gmail-verify.email",
    "adobe-update.work", "dropbox-share.site",
]


def parse_xgb(findings: list[str]) -> tuple[str, float | str]:
    """Extract XGBoost verdict and score from findings list."""
    verdict = "N/A"
    score: float | str = "N/A"
    for finding in findings:
        if "ML ANALYSIS" in finding:
            if "LEGITIMATE" in finding:
                verdict = "LEGITIMATE"
            elif "PHISHING" in finding:
                verdict = "PHISHING"
            m = re.search(r"score:\s*([0-9.]+)", finding)
            if m:
                score = float(m.group(1))
    return verdict, score


async def analyze_one(
    client: httpx.AsyncClient,
    domain: str,
    sem: asyncio.Semaphore,
    pbar: tqdm,
) -> dict[str, Any]:
    """Analyze a single domain via the HTTP API with concurrency control."""
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
            duration = time.time() - t0

            risk_score = data.get("risk_score", 0)
            findings = data.get("findings", [])
            xgb_verdict, xgb_score = parse_xgb(findings)

            result = {
                "domain": domain,
                "status": "SUCCESS",
                "risk_score": risk_score,
                "xgb_verdict": xgb_verdict,
                "xgb_score": xgb_score,
                "findings_count": len(findings),
                "duration_sec": round(duration, 3),
                "error": "",
            }
            pbar.set_postfix_str(f"{domain[:25]:25s} score={risk_score:3d}  {duration:.1f}s")

        except httpx.TimeoutException:
            duration = time.time() - t0
            result = {
                "domain": domain, "status": "TIMEOUT", "risk_score": "N/A",
                "xgb_verdict": "N/A", "xgb_score": "N/A", "findings_count": 0,
                "duration_sec": round(duration, 3), "error": "HTTP timeout",
            }
            pbar.set_postfix_str(f"{domain[:25]:25s} TIMEOUT {duration:.1f}s")

        except Exception as e:
            duration = time.time() - t0
            result = {
                "domain": domain, "status": "FAILED", "risk_score": "N/A",
                "xgb_verdict": "N/A", "xgb_score": "N/A", "findings_count": 0,
                "duration_sec": round(duration, 3), "error": str(e)[:120],
            }
            pbar.set_postfix_str(f"{domain[:25]:25s} ERROR: {str(e)[:40]}")

        pbar.update(1)
        return result


async def main():
    print(f"[START] Starting concurrent batch evaluation of {len(DOMAINS)} domains")
    print(f"   API: {API_URL}")
    print(f"   Concurrency: {MAX_CONCURRENT} | Timeout: {PER_REQUEST_TIMEOUT}s per domain")
    print()

    # Health check
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(HEALTH_URL)
            status = r.json().get("status")
            if status != "online":
                print(f"[WARN] API status: {status} (expected 'online')")
            else:
                print("[OK] API is online")
    except Exception as e:
        print(f"[FAIL] API unreachable: {e}")
        print("  Start backend:  cd backend && python -m uvicorn main:app")
        return 1
    print()

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    batch_start = time.time()

    pbar = tqdm(total=len(DOMAINS), desc="Analyzing", unit="dom", ncols=100,
                bar_format="{l_bar}{bar:20}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}")

    async with httpx.AsyncClient(timeout=httpx.Timeout(PER_REQUEST_TIMEOUT + 5)) as client:
        tasks = [
            analyze_one(client, domain, sem, pbar)
            for i, domain in enumerate(DOMAINS)
        ]
        results = await asyncio.gather(*tasks)
    pbar.close()

    total_time = time.time() - batch_start

    # ---- Generate reports ----
    success_count = sum(1 for r in results if r["status"] == "SUCCESS")
    timeout_count = sum(1 for r in results if r["status"] == "TIMEOUT")
    fail_count = sum(1 for r in results if r["status"] == "FAILED")

    os.makedirs("artifacts", exist_ok=True)

    # JSON report
    json_path = "artifacts/batch_test_results.json"
    with open(json_path, "w") as f:
        json.dump({
            "summary": {
                "total_domains": len(DOMAINS),
                "success": success_count,
                "timeout": timeout_count,
                "failed": fail_count,
                "total_duration_sec": round(total_time, 2),
                "average_duration_sec": round(total_time / len(DOMAINS), 2),
                "concurrency": MAX_CONCURRENT,
            },
            "results": results,
        }, f, indent=2)

    # CSV report
    csv_path = "artifacts/batch_test_results.csv"
    csv_fields = ["domain", "status", "risk_score", "xgb_verdict", "xgb_score",
                  "findings_count", "duration_sec", "error"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(results)

    # Print summary
    print()
    print("=" * 60)
    print(" BATCH TEST SUMMARY")
    print("=" * 60)
    print(f"Total domains tested: {len(DOMAINS)}")
    print(f"Successes:            {success_count}")
    print(f"Timeouts:             {timeout_count}")
    print(f"Failures:             {fail_count}")
    print(f"Total wall time:      {total_time:.2f}s")
    print(f"Avg per domain:       {total_time / len(DOMAINS):.2f}s")
    print(f"Throughput:           {len(DOMAINS) / total_time:.1f} domains/sec")
    print(f"Reports saved to:     {json_path} and {csv_path}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

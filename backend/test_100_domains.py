import urllib.request
import json
import csv
import time
import os

API_URL = "http://127.0.0.1:8000/api/v1/analyze"

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
    "adobe-update.work", "dropbox-share.site"
]

def run_test():
    print(f"🚀 Starting batch evaluation of {len(DOMAINS)} domains against backend at {API_URL}...")
    
    results = []
    success_count = 0
    fail_count = 0
    start_time_batch = time.time()
    
    for idx, domain in enumerate(DOMAINS, 1):
        print(f"[{idx}/{len(DOMAINS)}] Analyzing {domain}...", end="", flush=True)
        start_time = time.time()
        
        payload = {"url": domain}
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )
        
        duration = 0
        try:
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                duration = time.time() - start_time
                success_count += 1
                
                # Extract scores and verdicts
                risk_score = data.get("risk_score", 0)
                findings = data.get("findings", [])
                
                # Extract XGBoost ML specific details
                xgb_verdict = "N/A"
                xgb_score = "N/A"
                for finding in findings:
                    if "ML ANALYSIS" in finding:
                        # Extract score and verdict using simple parse
                        # e.g., "ML ANALYSIS: XGBoost flags domain as LEGITIMATE (score: 13.5/100)"
                        if "LEGITIMATE" in finding:
                            xgb_verdict = "LEGITIMATE"
                        elif "PHISHING" in finding:
                            xgb_verdict = "PHISHING"
                        
                        m = re.search(r"score:\s*([0-9.]+)", finding)
                        if m:
                            xgb_score = float(m.group(1))
                
                results.append({
                    "domain": domain,
                    "status": "SUCCESS",
                    "risk_score": risk_score,
                    "xgb_verdict": xgb_verdict,
                    "xgb_score": xgb_score,
                    "findings_count": len(findings),
                    "duration_sec": round(duration, 3),
                    "error": ""
                })
                print(f" Done in {duration:.2f}s (Score: {risk_score}, ML Verdict: {xgb_verdict})")
        except Exception as e:
            duration = time.time() - start_time
            fail_count += 1
            results.append({
                "domain": domain,
                "status": "FAILED",
                "risk_score": "N/A",
                "xgb_verdict": "N/A",
                "xgb_score": "N/A",
                "findings_count": 0,
                "duration_sec": round(duration, 3),
                "error": str(e)
            })
            print(f" FAILED in {duration:.2f}s: {e}")
            
    total_time = time.time() - start_time_batch
    
    # Create artifacts directory if missing
    os.makedirs("artifacts", exist_ok=True)
    
    # Save JSON Report
    json_path = "artifacts/batch_test_results.json"
    with open(json_path, "w") as f:
        json.dump({
            "summary": {
                "total_domains": len(DOMAINS),
                "success": success_count,
                "failed": fail_count,
                "total_duration_sec": round(total_time, 2),
                "average_duration_sec": round(total_time / len(DOMAINS), 2)
            },
            "results": results
        }, f, indent=2)
        
    # Save CSV Report
    csv_path = "artifacts/batch_test_results.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "status", "risk_score", "xgb_verdict", "xgb_score", "findings_count", "duration_sec", "error"])
        writer.writeheader()
        writer.writerows(results)
        
    print("\n" + "=" * 60)
    print(" BATCH TEST SUMMARY")
    print("=" * 60)
    print(f"Total domains tested: {len(DOMAINS)}")
    print(f"Successes:            {success_count}")
    print(f"Failures:             {fail_count}")
    print(f"Total Time:           {total_time:.2f}s")
    print(f"Avg Time per Domain:  {total_time / len(DOMAINS):.2f}s")
    print(f"Reports saved to:     {json_path} and {csv_path}")
    print("=" * 60)

if __name__ == "__main__":
    import re
    run_test()

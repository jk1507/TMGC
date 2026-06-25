"""
Quick Test — Run analysis on a batch of test domains.
Tests the full analysis pipeline against known phishing and legitimate domains.
"""

import asyncio
import json
import sys
import time

# Add backend to path
sys.path.insert(0, ".")

from main import run_analysis

# Test domains: mix of suspicious and legitimate
TEST_DOMAINS = [
    # Known phishing/lookalike domains
    "paypa1.com",
    "g00gle.com",
    "faceboook.com",
    "amaz0n-secure.com",
    "netflix-verify.xyz",
    "microsoft-support.tk",
    "apple-id-login.com",
    "instagr4m-login.com",
    "linked1n-verify.com",
    "paypa1-login.xyz",
    "secure-paypal.com",
    "amazon-login-verify.com",
    "google-account-verify.com",
    "netflix-billing.com",
    "apple-icloud-login.com",
    "whatsapp-web-verify.com",
    "telegram-auth-login.com",
    "coinbase-verify.com",
    "binance-auth.tk",
    "flipkart-offer-prize.com",
    
    # Legitimate domains
    "google.com",
    "github.com",
    "wikipedia.org",
    "stackoverflow.com",
    "npmjs.com",
    
    # Suspicious patterns
    "xn--paypal-8we.com",
    "secure-login-page.xyz",
    "account-verify-update.com",
    "banking-portal-login.tk",
    "free-prize-winner.com",
    
    # Domain infrastructure tests
    "ngrok.io",
    "duckdns.org",
    "bit.ly",
    "netlify.app",
    "vercel.app",
    
    # More lookalikes
    "g00gle-account-verify.com",
    "micr0soft-365-login.com",
    "app1e-id-reset.com",
    "amaz0n-pay-verify.com",
    "faceb00k-login.com",
    "instagr4m-auth.com",
    "tw1tter-verify.com",
    "1inkedin-connect.com",
    "whatsapp-web-login.com",
    "telegr4m-auth.com",
    "c0inbase-wallet.com",
    "b1nance-trade.com",
    "ad0be-license.com",
    "sp0tify-premium.com",
    "netf1ix-billing.com",
    "paypa1-claim.com",
    "flipk4rt-offer.com",
    "ph0nepe-pay.com",
    "paytm-wallet-verify.com",
    "sb1-online-login.com",
    "hdfc-bank-login.com",
    "icici-net-banking.com",
    
    # Normal safe domains
    "python.org",
    "nodejs.org",
    "docker.com",
    "kubernetes.io",
    "react.dev",
    "typescriptlang.org",
    "rust-lang.org",
    "golang.org",
    "gitlab.com",
    "bitbucket.org",
    "atlassian.com",
    "jira.com",
    "notion.so",
    "figma.com",
    "canva.com",
    
    # More phishing patterns
    "login-google-account.com",
    "verify-facebook-id.com",
    "reset-apple-password.com",
    "update-amazon-billing.com",
    "secure-microsoft-account.com",
    "confirm-netflix-payment.com",
    "recover-instagram-profile.com",
    "verify-linkedin-email.com",
    "reset-twitter-password.com",
    "auth-google-services.com",
    "id-apple-icloud.com",
    "manage-amazon-order.com",
    "support-microsoft-help.com",
    "billing-paypal-invoice.com",
    "coinbase-wallet-auth.com",
    "binance-trade-verify.com",
    "flipkart-order-tracking.com",
    "phonepe-transfer-now.com",
    "paytm-wallet-recharge.com",
    "sbi-net-banking-login.com",
    
    # More legitimate
    "vercel.com",
    "netlify.com",
    "cloudflare.com",
    "digitalocean.com",
    "heroku.com",
    "render.com",
    "railway.app",
    "fly.io",
    "supabase.com",
    "mongodb.com",
    "redis.io",
    "postgresql.org",
    "sqlite.org",
    "nginx.com",
    "apache.org",
    
    # Suspicious infrastructure
    "serveo.net",
    "ngrok-free.app",
    "trycloudflare.com",
    "myddns.me",
    "duckdns.org",
    "no-ip.org",
    "ddns.net",
    "dynu.net",
    "changeip.com",
    "mynetname.net",
    "strangled.net",
    "shorturl.at",
    "rb.gy",
    "is.gd",
    "tinyurl.com",
    
    # Government/education (should be safe)
    "whitehouse.gov",
    "usa.gov",
    "harvard.edu",
    "mit.edu",
    "nasa.gov",
    "gov.uk",
    "who.int",
    "nobelprize.org",
    "archive.org",
    "gutenberg.org",
    
    # Brand domains (should be safe)
    "samsung.com",
    "sony.com",
    "lg.com",
    "nvidia.com",
    "amd.com",
    "intel.com",
    "cisco.com",
    "vmware.com",
    "tesla.com",
    "spacex.com",
]


async def run_tests():
    """Run analysis on all test domains."""
    print(f"🧪 TMGC Quick Test — {len(TEST_DOMAINS)} domains")
    print("=" * 60)
    
    results = {
        "total": len(TEST_DOMAINS),
        "tested": 0,
        "failed": 0,
        "errors": [],
        "domains": [],
    }
    
    for i, domain in enumerate(TEST_DOMAINS, 1):
        print(f"\n[{i}/{len(TEST_DOMAINS)}] Analyzing: {domain}")
        start = time.time()
        
        try:
            response = await run_analysis(domain)
            elapsed = time.time() - start
            
            score = response.risk_score
            verdict = "SAFE" if score < 26 else "SUSPICIOUS" if score < 46 else "HIGH" if score < 71 else "CRITICAL"
            
            print(f"  Score: {score}/100 | Verdict: {verdict} | Time: {elapsed:.1f}s")
            
            results["domains"].append({
                "domain": domain,
                "score": score,
                "verdict": verdict,
                "time": round(elapsed, 2),
                "findings_count": len(response.findings),
            })
            results["tested"] += 1
            
        except Exception as exc:
            elapsed = time.time() - start
            print(f"  FAILED: {exc}")
            results["failed"] += 1
            results["errors"].append({"domain": domain, "error": str(exc)})
    
    # Summary
    print("\n" + "=" * 60)
    print(f"📊 RESULTS: {results['tested']} tested, {results['failed']} failed")
    
    if results["domains"]:
        scores = [d["score"] for d in results["domains"]]
        avg = sum(scores) / len(scores)
        print(f"   Average score: {avg:.1f}/100")
        print(f"   Min score: {min(scores)}/100")
        print(f"   Max score: {max(scores)}/100")
        
        high_risk = [d for d in results["domains"] if d["score"] >= 46]
        print(f"   High-risk domains: {len(high_risk)}")
        
        safe = [d for d in results["domains"] if d["score"] < 26]
        print(f"   Safe domains: {len(safe)}")
    
    # Save results
    output_path = "test_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Results saved to {output_path}")
    
    return results


if __name__ == "__main__":
    asyncio.run(run_tests())

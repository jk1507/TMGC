"""Fix detect_abused_infrastructure to not flag root free hosting domains."""
import re

with open('utils.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Pattern: the for loop in detect_abused_infrastructure
# We need to change the matching logic for free_hosting category
old = """    for infra_domain, label in ABUSED_INFRA_DOMAINS.items():
        if s == infra_domain or s.endswith("." + infra_domain):
            # Categorize
            category = "tunnel" if "tunnel" in label else \\
                       "dyn_dns" if "dynamic dns" in label.lower() or "ddns" in label.lower() else \\
                       "url_shortener" if "shortener" in label.lower() else \\
                       "free_hosting"

            risk = 20 if category == "tunnel" else \\
                   15 if category == "dyn_dns" else \\
                   10 if category == "url_shortener" else \\
                   15  # free_hosting

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
            }"""

new = """    for infra_domain, label in ABUSED_INFRA_DOMAINS.items():
        # Determine category from label text
        category = "tunnel" if "tunnel" in label else \\
                   "dyn_dns" if "dynamic dns" in label.lower() or "ddns" in label.lower() else \\
                   "url_shortener" if "shortener" in label.lower() else \\
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
                risk = 20 if category == "tunnel" else \\
                       15 if category == "dyn_dns" else \\
                       10 if category == "url_shortener" else \\
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
                }"""

if old in content:
    content = content.replace(old, new, 1)
    with open('utils.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Fix applied successfully!")
else:
    print("Pattern NOT found. Checking what we have...")
    # Find the function
    idx = content.find("def detect_abused_infrastructure")
    if idx >= 0:
        fn = content[idx:idx+1200]
        print(repr(fn))
    else:
        print("Could not find function detect_abused_infrastructure")

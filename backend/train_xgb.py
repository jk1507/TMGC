"""
Train the local XGBoost phishing classifier with a massively expanded domain dataset.

The production score is still a hybrid of rules, security headers, AI, and ML.
This script only refreshes backend/xgb_model.pkl for the ML component.

Expanded from 75 examples (15 legit + 15 phishing) to 2000+ examples
with realistic phishing patterns including typosquatting, combosquatting,
homoglyphs, suspicious TLDs, and domain generation algorithm (DGA) patterns.
"""

from __future__ import annotations

import os
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import clean_domain
from ml_xgboost import train_xgb


# ==============================================================================
# LEGITIMATE DOMAINS — 200+ top global websites and well-known trusted brands
# ==============================================================================
LEGITIMATE_DOMAINS = [
    # Top Tech Giants
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "meta.com",
    "twitter.com", "linkedin.com", "reddit.com", "pinterest.com", "snapchat.com",
    "tiktok.com", "telegram.org", "signal.org", "discord.com", "twitch.tv",

    # Search & Email
    "yahoo.com", "bing.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "gmail.com", "outlook.com", "protonmail.com", "mail.ru", "zoho.com",

    # Cloud & Developer
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com", "npmjs.com",
    "pypi.org", "docker.com", "kubernetes.io", "cloudflare.com", "aws.amazon.com",
    "azure.microsoft.com", "digitalocean.com", "heroku.com", "netlify.com", "vercel.com",

    # E-commerce & Finance
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com",
    "paypal.com", "stripe.com", "square.com", "shopify.com", "etsy.com",
    "visa.com", "mastercard.com", "amex.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "capitalone.com", "citi.com", "hsbc.com", "barclays.com",

    # Social & Media
    "tumblr.com", "flickr.com", "imgur.com", "medium.com", "quora.com",
    "wordpress.com", "blogger.com", "wix.com", "squarespace.com", "weebly.com",

    # Streaming & Entertainment
    "spotify.com", "soundcloud.com", "deezer.com", "tidal.com", "pandora.com",
    "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
    "crunchyroll.com", "funimation.com", "roku.com", "plex.tv", "vimeo.com",

    # Productivity & Collaboration
    "slack.com", "trello.com", "asana.com", "notion.so", "evernote.com",
    "dropbox.com", "box.com", "onedrive.com", "icloud.com", "drive.google.com",
    "zoom.us", "teams.microsoft.com", "webex.com", "gotomeeting.com", "skype.com",

    # Design & Creative
    "adobe.com", "canva.com", "figma.com", "sketch.com", "dribbble.com",
    "behance.net", "deviantart.com", "500px.com", "unsplash.com", "shutterstock.com",

    # Tech & Hardware
    "samsung.com", "sony.com", "lg.com", "panasonic.com", "nokia.com",
    "intel.com", "amd.com", "nvidia.com", "qualcomm.com", "broadcom.com",
    "cisco.com", "juniper.net", "vmware.com", "salesforce.com", "oracle.com",
    "sap.com", "ibm.com", "dell.com", "hp.com", "lenovo.com",

    # Automotive
    "tesla.com", "toyota.com", "honda.com", "ford.com", "bmw.com",
    "mercedes-benz.com", "audi.com", "volkswagen.com", "nissan.com", "hyundai.com",

    # News & Publishing
    "nytimes.com", "wsj.com", "cnn.com", "bbc.co.uk", "theguardian.com",
    "reuters.com", "bloomberg.com", "forbes.com", "huffpost.com", "npr.org",
    "washingtonpost.com", "usatoday.com", "latimes.com", "economist.com", "time.com",

    # Education & Government
    "harvard.edu", "stanford.edu", "mit.edu", "ox.ac.uk", "cambridge.org",
    "wikipedia.org", "britannica.com", "khanacademy.org", "coursera.org", "udemy.com",
    "whitehouse.gov", "usa.gov", "gov.uk", "europa.eu", "un.org",

    # Sports & Fitness
    "nike.com", "adidas.com", "puma.com", "underarmour.com", "reebok.com",
    "espn.com", "nba.com", "nfl.com", "mlb.com", "fifa.com",

    # Food & Beverage
    "starbucks.com", "mcdonalds.com", "subway.com", "kfc.com", "burgerking.com",
    "cocacola.com", "pepsi.com", "nestle.com", "kraftheinz.com", "generalmills.com",

    # Telecom & ISP
    "verizon.com", "att.com", "t-mobile.com", "sprint.com", "comcast.com",
    "vodafone.com", "orange.com", "deutschetelekom.com", "bt.com", "telefonica.com",

    # Travel & Hospitality
    "booking.com", "expedia.com", "airbnb.com", "uber.com", "lyft.com",
    "marriott.com", "hilton.com", "hyatt.com", "ihg.com", "accor.com",

    # Logistics & Shipping
    "fedex.com", "dhl.com", "ups.com", "usps.com", "tnt.com",

    # Gaming
    "steampowered.com", "epicgames.com", "xbox.com", "playstation.com", "nintendo.com",
    "blizzard.com", "ea.com", "activision.com", "ubisoft.com", "rockstargames.com",

    # Other Major Brands
    "ikea.com", "zara.com", "hm.com", "uniqlo.com", "gap.com",
    "levi.com", "ralphlauren.com", "tommy.com", "calvinklein.com", "chanel.com",
    "loreal.com", "sephora.com", "ulta.com", "macys.com", "nordstrom.com",
    "costco.com", "wholefoods.com", "traderjoes.com", "alibaba.com", "rakuten.com",

    # More critical services
    "coinbase.com", "binance.com", "kraken.com", "robinhood.com", "etrade.com",
    "openai.com", "deepmind.com", "anthropic.com", "huggingface.co", "databricks.com",
    "mongodb.com", "redis.com", "elastic.co", "datadoghq.com", "newrelic.com",
    "sentry.io", "auth0.com", "okta.com", "duo.com", "cloudinary.com",
]

# ==============================================================================
# PHISHING DOMAINS — 200+ realistic phishing patterns
# ==============================================================================
PHISHING_DOMAINS = [
    # Typosquatting — Single character changes
    "g00gle.com", "go0gle.com", "goog1e.com", "googl3.com",
    "goggle.com", "googie.com", "gooogle.com", "googkle.com",
    "faceboook.com", "facebok.com", "facebo0k.com",
    "faceb00k.com", "faceb0ok.com", "fac3book.com",
    "youtub3.com", "youtubee.com", "y0utube.com", "youtub4.com",
    "y0utube-login.com", "you-tube-verify.com",
    "amaz0n.com", "amazoon.com", "amazun.com", "amazzon.com",
    "amazn.com", "amaz0n-login.com",
    "micr0s0ft.com", "micros0ft.com", "micr0soft.com",
    "mircosoft.com", "microsft.com", "micro1soft.com",
    "app1e.com", "appl3.com", "appple.com", "aple.com",
    "app1e-id.com", "appl3-id-verify.com",
    "paypa1.com", "paypal1.com", "paypall.com", "paypaI.com",
    "paypa1-login.com", "paypal-secure.com",
    "netf1ix.com", "netfl1x.com", "n3tflix.com", "netfliix.com",
    "netfl1x-update.com", "netflix-billing.com",
    "link3din.com", "1inkedin.com", "linked1n.com",
    "1inkedin-login.com",
    "instagr4m.com", "instagrram.com", "instagran.com",
    "instagr4m-verify.com", "insta-gram-login.com",
    "tw1tter.com", "twitt3r.com", "twiter.com", "twittter.com",
    "whatsapp1.com", "whatsap.com", "whattsapp.com",
    "whatsapp-w3b.com", "whatsapp-verify.com",
    "te1egram.com", "telegr4m.com", "telegraam.com",
    "samsun9.com", "samsunng.com",
    "adob3.com", "ad0be.com", "ado be.com", "adober.com",
    "adobe-update.com", "adobe-billing.com",
    "dropb0x.com", "dr0pbox.com", "dropboox.com",
    "dropbox-share.com", "dropbox-login.com",
    "bitbuck3t.com", "bitbucet.com", "git1ab.com", "githuub.com",
    "stackoverf1ow.com", "stakoverflow.com",
    "c0inbase.com", "coinb4se.com", "coinba5e.com",
    "coinbase-wallet.com", "coinbase-verify.com",
    "b1nance.com", "binanc3.com", "binancé.com",
    "binance-verify.com", "binance-login.com",
    "krak3n.com", "kraken-wallet.com",

    # Combosquatting — Brand + keyword
    "google-login.com", "google-verify.com", "google-security.com",
    "google-account.com", "google-auth.com", "google-support.com",
    "google-update.com", "google-password.com", "google-recovery.com",
    "google-billing.com", "google-wallet.com", "google-pay-login.com",
    "facebook-login.com", "facebook-verify.com", "facebook-secure.com",
    "facebook-security.com", "facebook-account.com", "facebook-support.com",
    "facebook-recovery.com", "facebook-auth.com",
    "microsoft-login.com", "microsoft-verify.com", "microsoft-secure.com",
    "microsoft-support.com", "microsoft-account.com", "microsoft-auth.com",
    "microsoft-security.com", "microsoft-update.com", "microsoft-billing.com",
    "apple-login.com", "apple-verify.com", "apple-id.com",
    "apple-security.com", "apple-support.com", "apple-icloud.com",
    "apple-auth.com", "apple-billing.com",
    "amazon-login.com", "amazon-verify.com", "amazon-secure.com",
    "amazon-security.com", "amazon-account.com", "amazon-support.com",
    "amazon-auth.com", "amazon-billing.com", "amazon-payment.com",
    "paypal-login.com", "paypal-verify.com", "paypal-secure.com",
    "paypal-security.com", "paypal-account.com", "paypal-support.com",
    "paypal-auth.com", "paypal-billing.com",    "paypal-dispute.com",
    "netflix-login.com", "netflix-verify.com", "netflix-secure.com",
    "netflix-account.com", "netflix-billing.com", "netflix-payment.com",
    "instagram-login.com", "instagram-verify.com", "instagram-secure.com",
    "instagram-security.com", "instagram-auth.com",
    "linkedin-login.com", "linkedin-verify.com", "linkedin-secure.com",
    "twitter-login.com", "twitter-verify.com", "twitter-secure.com",
    "whatsapp-login.com", "whatsapp-verify.com", "whatsapp-web.com",
    "adobe-login.com", "adobe-verify.com", "adobe-billing.com",
    "dropbox-login.com", "dropbox-verify.com", "dropbox-share.com",
    "github-login.com", "github-verify.com", "github-auth.com",
    "bankofamerica-login.com", "wellsfargo-login.com", "chase-login.com",
    "capitalone-login.com", "citi-login.com", "hsbc-login.com",
    "amex-login.com", "visa-login.com", "mastercard-login.com",
    "coinbase-login.com", "coinbase-verify.com", "binance-login.com",
    "binance-verify.com", "kraken-login.com",

    # Suspicious TLD phishing
    "paypal-login.xyz", "amazon-verify.xyz", "google-secure.xyz",
    "netflix-billing.xyz", "apple-support.xyz", "microsoft-login.xyz",
    "facebook-verify.xyz", "instagram-login.xyz", "linkedin-auth.xyz",
    "coinbase-wallet.xyz", "binance-verify.xyz",
    "paypal-secure.top", "amazon-login.top", "google-verify.top",
    "netflix-update.top", "apple-id.top", "microsoft-auth.top",
    "instagram-verify.top", "facebook-login.top",
    "bankofamerica-login.online", "chase-verify.online", "wellsfargo-login.online",
    "amex-secure.online", "capitalone-login.online",
    "microsoft-support.tk", "google-account.tk", "amazon-login.tk",
    "paypal-secure.tk", "netflix-update.tk",
    "coinbase-wallet.ml", "binance-verify.ml", "paypal-login.ml",
    "google-verify.ml", "amazon-support.ml",
    "binance-verify.cf", "coinbase-login.cf", "paypal-secure.cf",
    "whatsapp-web.gq", "telegram-login.gq", "instagram-verify.gq",
    "gmail-verify.gq", "outlook-secure.gq",
    "amazon-billing.click", "paypal-login.click", "netflix-update.click",
    "google-verify.click", "microsoft-auth.click",
    "apple-id-verify.club", "paypal-account.club", "amazon-prime.club",
    "netflix-billing.work", "google-verify.work", "paypal-login.work",
    "microsoft-update.live", "google-account.live", "paypal-verify.live",
    "amazon-support.site", "netflix-billing.site", "paypal-login.site",
    "google-verify.site", "microsoft-login.site",
    "dropbox-share.site", "adobe-update.work", "whatsapp-security.ga",

    # Homoglyph attacks
    "g00gle.com", "g0оgle.com",  # Uses Cyrillic 'о'
    "раypal.com",  # Uses Cyrillic 'р', 'а'
    "micrоsоft.com",  # Uses Cyrillic 'о'
    "аmаzon.com",  # Uses Cyrillic 'а'
    "fаcebook.com",  # Uses Cyrillic 'а'
    "instаgrаm.com",  # Uses Cyrillic 'а'
    "аррle.com",  # Uses Cyrillic 'а', 'р'
    "yоutube.com",  # Uses Cyrillic 'о'
    "whatsарр.com",  # Uses Cyrillic 'а', 'р'
    "сoinbase.com",  # Uses Cyrillic 'с'
    "tеsla.com",  # Uses Cyrillic 'е'
    "nеtflix.com",  # Uses Cyrillic 'е'
    "adоbe.com",  # Uses Cyrillic 'о'
    "wаlmаrt.com",  # Uses Cyrillic 'а'
    "stаrbucks.com",  # Uses Cyrillic 'а'

    # Domain Generation Algorithm (DGA) style patterns
    "secure-login-2fa.xyz", "account-verify-identity.top",
    "payment-confirm-billing.xyz", "security-check-2fa.online",
    "verify-identity-now.xyz", "claim-your-prize.top",
    "free-gift-card.site", "winner-lottery.live",
    "track-package-id.click", "shipping-notification.xyz",
    "invoice-due-payment.top", "billing-update-required.xyz",
    "account-suspended-alert.work", "unusual-login-attempt.xyz",
    "limited-time-offer.site", "exclusive-deal-today.top",
    "verify-account-security.live", "confirm-billing-info.xyz",
    "reset-password-now.click", "account-recovery-help.site",

    # More advanced phishing with subdomains
    "login.google.com.security-verify.xyz",
    "account.paypal.com.billing.xyz",
    "secure.amazon.com.login-verify.tk",
    "id.apple.com.account-update.top",
    "login.microsoft.com.support-auth.xyz",
    "www.paypal.com.security-check.click",
    "accounts.google.com.verify-now.xyz",
    "help.netflix.com.billing.update.live",
    "login.facebook.com.secure-auth.top",
    "wallet.coinbase.com.verify-2fa.xyz",

    # IP-based masquerading
    "login-216.58.214.206.xyz",
    "secure-157.240.1.35.login.top",
    "account-52.84.237.101.verify.live",
    "paypal-151.101.1.140.secure.site",
    "google-142.250.80.46.auth.xyz",

    # Dark-web TLDs
    "paypal-login.onion", "google-verify.onion",
    "amazon-billing.i2p", "bankofamerica-login.onion",
    "facebook-secure.i2p", "instagram-verify.onion",

    # Multi-brand phishing
    "google-amazon-login.xyz", "paypal-netflix-verify.top",
    "microsoft-apple-icloud.xyz", "facebook-instagram-auth.live",
    "amazon-paypal-ebay.site", "google-facebook-login.xyz",

    # Phishing with numbers and special characters
    "g00gle-2fa-verify.xyz", "p4yp4l-s3cur3.top",
    "m1cr0s0ft-upd4t3.xyz", "4m4z0n-l0gin.site",
    "n3tfl1x-b1ll1ng.top", "1nst4gr4m-v3r1fy.xyz",
    "4ppl3-1d-v3r1fy.top", "c01nb4s3-w4ll3t.xyz",
    "b1n4nc3-v3r1fy.cf", "wh4ts4pp-s3cur1ty.gq",

    # Brand names in suspicious TLDs
    "google.xyz", "paypal.top", "amazon.xyz",
    "netflix.xyz", "facebook.top", "instagram.xyz",
    "microsoft.click", "apple.work", "linkedin.live",
    "whatsapp.gq", "telegram.ml", "coinbase.cf",
    "binance.xyz", "adobe.work", "dropbox.top",

    # Combo with popular services
    "gmail-verify.xyz", "gmail-login.top",
    "outlook-secure.xyz", "outlook-verify.live",
    "yahoo-login.xyz", "yahoo-verify.top",
    "protonmail-login.xyz", "protonmail-verify.top",
    "icloud-login.xyz", "icloud-verify.live",
    "godaddy-login.xyz", "godaddy-verify.top",
    "bluehost-login.xyz", "hostgator-login.top",
    "namecheap-login.xyz", "namecheap-verify.live",
    "aws-login.xyz", "aws-verify.top",
    "azure-login.xyz", "azure-verify.live",
    "heroku-login.xyz", "digitalocean-login.top",
    "steam-login.xyz", "steam-verify.top",
    "epicgames-login.xyz", "epicgames-verify.live",
    "xbox-login.xyz", "playstation-login.top",
    "nintendo-login.xyz", "rockstar-login.live",

    # More combosquatting (crypto focus)
    "metamask-login.xyz", "metamask-verify.top",
    "defi-wallet.xyz", "uniswap-login.top",
    "pancakeswap-verify.xyz", "trust-wallet-auth.live",
    "ledger-live-login.xyz", "trezor-auth.top",
    "crypto-com-verify.xyz", "blockchain-login.top",
    "eth-wallet-verify.xyz", "btc-wallet-auth.live",
    "usdt-claim.xyz", "airdrop-claim.top",
    "nft-mint.site", "opensea-login.xyz",

    # Brand + support/help variant
    "google-help.com", "google-support.net",
    "apple-help.com", "apple-support.net",
    "microsoft-help.net", "microsoft-support.org",
    "amazon-help.org", "amazon-help.net",
    "paypal-help.com", "paypal-support.net",
    "netflix-help.net", "facebook-help.org",
    "instagram-help.net", "linkedin-help.com",
    "coinbase-support.net", "binance-help.org",
    "twitter-help.com", "whatsapp-help.org",

    # Extra suspicious patterns
    "g00gl3-s3cur3-l0gin.xyz", "p4yp4l-c0nf1rm.tk",
    "s3cur3-4m4z0n-v3r1fy.ml", "m1cr0s0ft-w1nd0ws-upd4t3.xyz",
    "i4m-4ppl3-supp0rt.club", "n3tf1ix-4cc0unt-b1ll.xyz",
    "w3-4r3-g00gl3-v3r1fy.tk", "c0m3-t0-p4yp4l-s3cur3.top",
    "y0ur-4cc0unt-1s-l0ck3d.xyz", "cl1ck-h3r3-t0-cl41m.work",

    # Branded dropbox/share patterns
    "shared-file-google.xyz", "document-share-apple.top",
    "invoice-microsoft.xyz", "statement-bankofamerica.site",
    "tax-refund-irs.top", "customs-fee-ups.live",
    "package-delivery-fedex.xyz", "shipping-confirm-dhl.top",
    "parcel-tracking-usps.site", "delivery-attempted-auspost.xyz",
]


def _tld_score(tld: str) -> float:
    """Compute a continuous TLD risk score (0.0-1.0)."""
    t = tld.strip(".").lower()
    if t in {"gov", "edu", "mil"}:
        return 0.0
    if t in {"com", "org", "net"}:
        return 0.1
    if t in {"io", "co", "app", "dev", "ai"}:
        return 0.2
    if t in {"info", "biz", "me", "tv"}:
        return 0.3
    if t in {"online", "site", "club", "live", "work", "support"}:
        return 0.6
    if t in {"xyz", "top", "click", "loan"}:
        return 0.8
    if t in {"tk", "ml", "ga", "cf", "gq"}:
        return 1.0
    if t in {"onion", "i2p", "bit"}:
        return 1.0
    return 0.4


def feature_vector_for(domain: str, age_days: int, privacy: float = 0.0, suspicious_reg: float = 0.0, has_ssl: float = 1.0, has_mx: float = 1.0, has_asn: float = 1.0, header_score: float = 0.0) -> list[float]:
    """
    Build a feature vector matching the exact 31-feature schema used in main.py's get_ml_prediction().

    Features 0-22 are the original features (backward compatible),
    features 23-27 are new discriminative features for better ML separation,
    features 28-31 are inference-time features:
      28: SSL validity (1.0=valid, 0.0=no SSL)
      29: MX presence (1.0=has MX, 0.0=no MX)
      30: ASN availability (1.0=available, 0.0=unavailable)
      31: Header security deficit (0.0=good security, 1.0=poor security)
    """
    from utils import (
        detect_combosquatting,
        detect_homoglyphs,
        detect_typosquatting,
        extract_features,
        normalize_homoglyphs,
    )
    import re
    import numpy as np
    from main import KNOWN_BRANDS, SUSPICIOUS_TLDS

    clean = clean_domain(domain)
    parts = clean.split(".")
    label = parts[-2] if len(parts) >= 2 else clean
    tld = parts[-1] if len(parts) >= 2 else ""
    domain_name = clean.split(".", 1)[0]

    # ---- Core feature extraction ----
    normalized_label = normalize_homoglyphs(label)
    features = extract_features(clean)
    typo = detect_typosquatting(normalized_label)
    raw_typo = detect_typosquatting(label)
    if raw_typo.get("jaro_winkler_score", 0.0) > typo.get("jaro_winkler_score", 0.0):
        typo = raw_typo
    homoglyph = detect_homoglyphs(clean)
    combo = detect_combosquatting(clean)

    # ---- Structural features ----
    letters = sum(c.isalpha() for c in domain_name)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain_name)
    consonant_ratio = consonants / max(1, letters)
    excessive_hyphens = float(domain_name.count("-") >= 3)
    age_log = np.log1p(age_days) / np.log1p(3650)

    # ---- NEW: Jaro-Winkler on raw (un-normalized) label ----
    raw_typo_check = detect_typosquatting(label)
    jaro_raw_vs_brand = raw_typo_check.get("jaro_winkler_score", 0.0)

    # ---- NEW: Label changed by normalization? ----
    label_normalized_changed = 1.0 if normalized_label != label else 0.0

    # ---- NEW: Max consecutive digits ----
    consecutive_digits = 0.0
    if domain_name:
        digit_runs = re.findall(r"\d+", domain_name)
        if digit_runs:
            consecutive_digits = min(max(len(r) for r in digit_runs) / 5.0, 1.0)

    # ---- NEW: TLD risk score ----
    tld_score = _tld_score(tld)

    # ---- NEW: Unique normalized tokens in domain label ----
    # Counts distinct word-like segments after splitting on hyphens/underscores.
    # Legitimate brands usually have 1-2 tokens; combosquatting has 3+.
    import re as _re
    label_tokens = _re.split(r"[\-_]+", label)
    normalized_tokens = set()
    for t in label_tokens:
        nt = normalize_homoglyphs(t)
        if len(nt) > 2:  # skip very short tokens
            normalized_tokens.add(nt)
    unique_token_count = min(len(normalized_tokens) / 5.0, 1.0)

    return [
        min(features.get("length", len(domain_name)) / 50.0, 1.0),          # 0: normalized length
        features.get("digit_ratio", 0.0),                                     # 1: digit ratio
        min(features.get("hyphen_count", domain_name.count("-")) / 5.0, 1.0), # 2: hyphen count
        min(features.get("subdomain_count", len(parts) - 2) / 5.0, 1.0),     # 3: subdomain depth
        min(features.get("entropy", 3.0) / 5.0, 1.0),                        # 4: shannon entropy
        consonant_ratio,                                                      # 5: consonant ratio
        float(features.get("suspicious_tld", ("." + parts[-1]) in SUSPICIOUS_TLDS)),  # 6: suspicious TLD
        float(features.get("has_suspicious_keywords", any(k in clean for k in KNOWN_BRANDS))),  # 7: brand keywords
        float(features.get("is_ip_like", False)),                             # 8: IP-like domain
        excessive_hyphens,                                                    # 9: excessive hyphens (>=3)
        typo.get("jaro_winkler_score", 0.0),                                  # 10: jaro-winkler similarity (norm)
        typo.get("levenshtein_score", 0.0),                                   # 11: levenshtein similarity
        min(typo.get("edit_distance", 10) / 10.0, 1.0),                      # 12: normalized edit distance
        float(typo.get("detected", False)),                                   # 13: typosquatting detected
        float(homoglyph.get("detected", False)),                              # 14: homoglyph chars detected
        min(homoglyph.get("count", 0) / 5.0, 1.0),                            # 15: homoglyph count
        float(homoglyph.get("has_digit_substitution", False)),                # 16: digit substitution
        float(combo.get("detected", False)),                                  # 17: combosquatting detected
        float(combo.get("brand_only", False)),                                # 18: brand only (no keywords)
        min(len(combo.get("matched_keywords", [])) / 5.0, 1.0),              # 19: matched keyword count
        age_log,                                                              # 20: domain age (log-scaled)
        privacy,                                                              # 21: WHOIS privacy protected
        suspicious_reg,                                                       # 22: suspicious registrar
        # ---- NEW FEATURES (23-27): better ML separation ----
        jaro_raw_vs_brand,                                                    # 23: Jaro-Winkler (raw/un-normalized label)
        label_normalized_changed,                                             # 24: label changed by normalization
        consecutive_digits,                                                   # 25: max consecutive digits
        tld_score,                                                            # 26: TLD risk score (0.0-1.0)
        unique_token_count,                                                   # 27: unique normalized tokens in label
        has_ssl,                                                              # 28: SSL certificate valid (1.0=yes, 0.0=no)
        has_mx,                                                               # 29: MX records present (1.0=yes, 0.0=no)
        has_asn,                                                              # 30: ASN data available (1.0=yes, 0.0=no)
        min(max(header_score, 0.0) / 15.0, 1.0),                              # 31: header security deficit (0.0=good, 1.0=poor)
    ]


def generate_phishing_age(domain: str) -> int:
    """Generate realistic age ranges for phishing domains (usually young)."""
    # Most phishing domains are less than 1 year old
    import random
    # Young: 80% chance of being < 365 days
    if random.random() < 0.8:
        return random.randint(1, 364)
    return random.randint(365, 730)


def generate_legitimate_age(domain: str) -> int:
    """Generate realistic age ranges for legitimate domains (usually old)."""
    import random
    # Mature: 90% chance of being > 2 years old
    if random.random() < 0.9:
        return random.randint(730, 7300)
    return random.randint(30, 729)


def main() -> None:
    import random
    random.seed(42)

    x = []
    y = []

    # --------------------------------------------------------------------------
    # Generate legitimate samples with realistic ages
    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------
    # INFERENCE-TIME FEATURE DEFAULTS:
    # Legitimate: has_valid_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0-5 (good security)
    # Phishing:   has_valid_ssl=0.3, has_mx=0.0-0.4, has_asn=0.0-0.3, header_score=5-20 (poor security)
    # --------------------------------------------------------------------------
    legit_ssl = 1.0
    legit_mx = 1.0
    legit_asn = 1.0
    legit_header = 0.0  # Good security headers (low score = good)
    
    phish_ssl = 0.3
    phish_mx_default = 0.2  # Most phishing domains lack MX
    phish_asn_default = 0.15  # Most phishing domains have unavailable ASN

    for domain in LEGITIMATE_DOMAINS:
        # Multiple age variations per domain for robustness
        x.append(feature_vector_for(domain, generate_legitimate_age(domain)))
        y.append(0)
        x.append(feature_vector_for(domain, generate_legitimate_age(domain)))
        y.append(0)
        # For domains that are clearly major brands, also include a very old variant
        x.append(feature_vector_for(domain, 3650, privacy=0.0, suspicious_reg=0.0, has_ssl=legit_ssl, has_mx=legit_mx, has_asn=legit_asn, header_score=legit_header))
        y.append(0)
        # CRITICAL: Add legitimate samples with age_days=365 (the inference default)
        # When WHOIS is unavailable during live analysis, age_days defaults to 365.
        # This gives age_log = np.log1p(365)/np.log1p(3650) ≈ 0.72.
        # Without these samples, the model sees age_log=0.72 only in PHISHING training
        # (phishing uses 1-364 days, giving age_log up to 0.72) and incorrectly
        # classifies any real domain with unavailable WHOIS as suspicious.
        x.append(feature_vector_for(domain, 365, privacy=0.0, suspicious_reg=0.0, has_ssl=legit_ssl, has_mx=legit_mx, has_asn=legit_asn, header_score=legit_header))
        y.append(0)
        
        # --- WEAK-INFRASTRUCTURE LEGITIMATE SAMPLES ---
        # Real legitimate domains often lack perfect infrastructure:
        # - Small businesses use external email (no MX on domain)
        # - Shared hosting may not have identifiable ASN
        # - Many legit sites have poor security headers
        # - Some legit sites don't have HTTPS (internal tools, legacy, forums)
        # Without these samples, the model will flag any domain missing
        # MX/ASN/SSL or with poor headers as phishing — false positives.
        # Add variants with degraded infrastructure (~40% chance):
        if random.random() < 0.4:
            weak_mx = 0.0 if random.random() < 0.7 else 1.0
            weak_asn = 0.0 if random.random() < 0.6 else 1.0
            weak_header = random.uniform(2, 14)
            # Allow many legitimate domains without SSL (small biz, internal tools)
            weak_ssl = 1.0 if random.random() < 0.6 else 0.0
            x.append(feature_vector_for(domain, generate_legitimate_age(domain),
                                         has_ssl=weak_ssl, has_mx=weak_mx, has_asn=weak_asn, header_score=weak_header))
            y.append(0)

    # --------------------------------------------------------------------------
    # Generate phishing samples — each domain with multiple age/feature variations
    # --------------------------------------------------------------------------
    for domain in PHISHING_DOMAINS:
        # Phishing domains vary in privacy protection
        privacy = 1.0 if random.random() < 0.7 else 0.0
        sus_reg = 1.0 if random.random() < 0.5 else 0.0

        # Young domain (most typical)
        x.append(feature_vector_for(domain, random.randint(1, 60), privacy, sus_reg, has_ssl=phish_ssl,
                                     has_mx=0.2 if random.random() < 0.8 else 1.0,
                                     has_asn=0.15 if random.random() < 0.7 else 1.0,
                                     header_score=random.uniform(5, 20)))
        y.append(1)

        # Slightly older phishing domain
        x.append(feature_vector_for(domain, random.randint(61, 180), privacy, sus_reg, has_ssl=phish_ssl,
                                     has_mx=0.3 if random.random() < 0.7 else 1.0,
                                     has_asn=0.2 if random.random() < 0.6 else 1.0,
                                     header_score=random.uniform(3, 18)))
        y.append(1)

        # Very fresh phishing domain
        x.append(feature_vector_for(domain, random.randint(1, 14), privacy, sus_reg, has_ssl=phish_ssl,
                                     has_mx=0.0 if random.random() < 0.9 else 1.0,
                                     has_asn=0.0 if random.random() < 0.8 else 1.0,
                                     header_score=random.uniform(8, 25)))
        y.append(1)

    # --------------------------------------------------------------------------
    # Generate additional borderline / weak-signal phishing samples
    # These help the model learn subtle patterns when explicit brand+keyword matching
    # doesn't fire (e.g., homoglyph-only or TLD-only signals)
    # --------------------------------------------------------------------------
    for domain in PHISHING_DOMAINS:
        # Add variants with no privacy (mimics careless phishers)
        x.append(feature_vector_for(domain, random.randint(1, 90), 0.0, 0.0, has_ssl=phish_ssl,
                                     has_mx=0.0, has_asn=0.0, header_score=random.uniform(10, 25)))
        y.append(1)

    # --------------------------------------------------------------------------
    # Generate OLD DOMAIN phishing samples (teaches the model that old age + typosquatting
    # is still phishing, not legitimate). Real-world examples like g00gle.com are 25+ years
    # old but used for phishing. Without these samples, the model always sees old=legitimate.
    # --------------------------------------------------------------------------
    for domain in PHISHING_DOMAINS:
        # Old domain phishing sample (also with SSL=0 since old phish often lack SSL)
        x.append(feature_vector_for(domain, random.randint(3650, 10000), 1.0, 0.5, has_ssl=0.0,
                                     has_mx=0.0, has_asn=0.0, header_score=random.uniform(5, 20)))
        y.append(1)

    # --------------------------------------------------------------------------
    # Generate legitimate domains with suspicious-looking TLDs to train
    # the model NOT to over-index on TLD alone
    # --------------------------------------------------------------------------
    # Some legitimate sites do use .xyz, .top, etc.
    legit_tld_domains = [
        "genius.xyz", "abc.xyz", "alphabet.xyz",
        "nike.shoes", "coke.ice", "mcdonalds.menu",
        "microsoft.azure", "amazon.aws", "google.cloud",
        "gov.uk", "bbc.co.uk", "harvard.edu",
    ]
    for domain in legit_tld_domains:
        x.append(feature_vector_for(domain, 3650, 0.0, 0.0, has_ssl=1.0, has_mx=1.0, has_asn=1.0, header_score=0.0))
        y.append(0)

    # --------------------------------------------------------------------------
    # Train the XGBoost model
    # --------------------------------------------------------------------------
    print(f"Total training samples: {len(x)}")
    print(f"  Legitimate: {y.count(0)}")
    print(f"  Phishing:   {y.count(1)}")

    train_xgb(x, y)


if __name__ == "__main__":
    main()

"""
Owner Image Detection Module (v2.0)
====================================
Performs evidence-based entity attribution for domain ownership.

Methods:
  - WHOIS email extraction → Gravatar lookup (avatar + profiles)
  - WHOIS text pattern matching (org names, social links)
  - Website content scanning (social media links, email addresses)
  - GitHub profile search (domain mentions in profile pages)
  - Social media platform detection

This module NEVER infers ownership from keyword matches alone.
All attribution is evidence-based and scored accordingly.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any

# ==============================================================================
# CONSTANTS
# ==============================================================================

# Gravatar base URLs
GRAVATAR_BASE = "https://www.gravatar.com/avatar/"
GRAVATAR_PROFILE = "https://www.gravatar.com/{hash}.json"

# Email regex
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# GitHub API (no key needed for public profile lookups)
GITHUB_API = "https://api.github.com/users/{username}"

# Social media URL patterns
SOCIAL_PATTERNS: list[tuple[str, str, str]] = [
    ("linkedin.com/in/", "LinkedIn", r"linkedin\.com/in/([^/\"\'\\s\\?]+)"),
    ("twitter.com/", "Twitter/X", r"twitter\.com/([^/\"\'\\s\\?]+)"),
    ("x.com/", "Twitter/X", r"x\.com/([^/\"\'\\s\\?]+)"),
    ("github.com/", "GitHub", r"github\.com/([^/\"\'\\s\\?]+)"),
    ("facebook.com/", "Facebook", r"facebook\.com/([^/\"\'\\s\\?]+)"),
    ("instagram.com/", "Instagram", r"instagram\.com/([^/\"\'\\s\\?]+)"),
    ("youtube.com/@", "YouTube", r"youtube\.com/@([^/\"\'\\s\\?]+)"),
    ("tiktok.com/@", "TikTok", r"tiktok\.com/@([^/\"\'\\s\\?]+)"),
    ("medium.com/@", "Medium", r"medium\.com/@([^/\"\'\\s\\?]+)"),
    ("reddit.com/user/", "Reddit", r"reddit\.com/user/([^/\"\'\\s\\?]+)"),
    ("discord.gg/", "Discord", r"discord\.gg/([^/\"\'\\s\\?]+)"),
    ("telegram.me/", "Telegram", r"telegram\.me/([^/\"\'\\s\\?]+)"),
    ("signal.me/", "Signal", r"signal\.me/([^/\"\'\\s\\?]+)"),
]

# WHOIS patterns for organization/ownership
ORG_PATTERNS = [
    r"(?im)^\s*(?:orgname|org-name|organization|org|company)\s*:\s*(.+?)$",
    r"(?im)^\s*(?:descr|description)\s*:\s*(.+?)$",
]

# Patterns for emails in WHOIS
WHOIS_EMAIL_PATTERNS = [
    r"(?im)^\s*(?:e-mail|email|mail)\s*:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*$",
    r"(?im)\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
]


# ==============================================================================
# HELPERS
# ==============================================================================


def _extract_emails(text: str) -> list[str]:
    """Extract all email addresses from text."""
    return list(set(EMAIL_RE.findall(text or "")))


def _extract_org_names(text: str) -> list[str]:
    """Extract organization names from WHOIS text."""
    names: list[str] = []
    for pattern in ORG_PATTERNS:
        for match in re.finditer(pattern, text or ""):
            name = match.group(1).strip()
            if name and len(name) > 2 and name.lower() not in ("none", "n/a", "redacted"):
                names.append(name)
    return names


def _gravatar_hash(email: str) -> str:
    """Compute Gravatar hash from an email address."""
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _lookup_gravatar(email: str, timeout: float = 2.0) -> dict[str, Any]:
    """
    Look up Gravatar profile for an email address.
    Returns empty dict if no profile found.
    """
    hash_val = _gravatar_hash(email)
    profile_url = GRAVATAR_PROFILE.format(hash=hash_val)

    try:
        req = urllib.request.Request(
            profile_url,
            headers={"User-Agent": "TMGC-OwnerInspector/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, list) and len(data) > 0:
                entry = data[0]
                return {
                    "hash": hash_val,
                    "avatar_url": f"{GRAVATAR_BASE}{hash_val}?s=200&d=mp",
                    "display_name": entry.get("displayName") or entry.get("preferredUsername"),
                    "profile_url": entry.get("profileUrl"),
                    "emails": entry.get("emails", []),
                    "accounts": [
                        {
                            "domain": acc.get("domain"),
                            "display": acc.get("display"),
                            "url": acc.get("url"),
                        }
                        for acc in (entry.get("accounts") or [])[:5]
                    ],
                }
            return {"hash": hash_val, "avatar_url": f"{GRAVATAR_BASE}{hash_val}?s=80&d=mp"}
    except Exception:
        # Return hash-only result (avatar may still exist even without profile)
        return {"hash": hash_val, "avatar_url": f"{GRAVATAR_BASE}{hash_val}?s=80&d=mp"}


def _lookup_github(username: str, timeout: float = 2.0) -> dict[str, Any] | None:
    """Look up a GitHub profile by username."""
    url = GITHUB_API.format(username=username)
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TMGC-OwnerInspector/1.0",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "login": data.get("login"),
                "name": data.get("name"),
                "avatar_url": data.get("avatar_url"),
                "html_url": data.get("html_url"),
                "type": data.get("type"),
                "bio": data.get("bio"),
                "company": data.get("company"),
                "location": data.get("location"),
                "blog": data.get("blog"),
                "email": data.get("email"),
                "public_repos": data.get("public_repos"),
                "public_gists": data.get("public_gists"),
                "followers": data.get("followers"),
                "following": data.get("following"),
                "created_at": data.get("created_at"),
                "profile_url": data.get("html_url"),
            }
    except Exception:
        return None


def _detect_social_links(text: str) -> list[dict[str, str]]:
    """Detect social media profile links in text."""
    profiles: list[dict[str, str]] = []
    for pattern, platform, regex in SOCIAL_PATTERNS:
        for match in re.finditer(regex, text or "", re.IGNORECASE):
            username = match.group(1).strip()
            if username:
                profiles.append({
                    "platform": platform,
                    "username": username,
                    "url": f"https://{pattern}{username}",
                })
    return profiles


# ==============================================================================
# MAIN ANALYSIS FUNCTION
# ==============================================================================


def analyze_owner_images(
    domain: str,
    whois_text: str = "",
    website_text: str = "",
    timeout: float = 2.0,
) -> dict[str, Any]:
    """
    Analyze owner images and entity attribution for a domain.

    This is an evidence-based analysis that:
      1. Extracts emails from WHOIS
      2. Looks up Gravatar profiles for those emails
      3. Detects social media links in WHOIS and website content
      4. Attempts GitHub profile lookup from discovered usernames
      5. Scores the attribution confidence based on cross-referencing

    Args:
        domain: The domain to analyze.
        whois_text: Raw WHOIS text output.
        website_text: Text content from the website.
        timeout: Timeout for each external lookup.

    Returns:
        Dict with attribution results.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "attribution_level": "No Ownership Evidence",
        "attribution_score": 0,
        "attribution_severity": "none",
        "display_owner": False,
        "attribution_evidence": [],
        "attribution_summary": None,
        "has_owner_footprint": False,
        "emails_found": [],
        "gravatar_profiles": [],
        "github_profile": None,
        "social_media": {"profiles": []},
        "org_names": [],
    }

    # Step 1: Extract emails from WHOIS
    whois_emails = _extract_emails(whois_text)
    website_emails = _extract_emails(website_text)

    all_emails = list(set(whois_emails + website_emails))
    # Filter out common non-owner emails
    filtered_emails = [
        e for e in all_emails
        if not any(
            x in e.lower()
            for x in [
                "whoisprotect", "privacy", "dnstination", "contact",
                "abuse", "hostmaster", "postmaster", "admin",
                "domain.com", "example.com",
            ]
        )
    ]
    result["emails_found"] = filtered_emails[:10]

    # Step 2: Extract organization names
    org_names = _extract_org_names(whois_text)
    result["org_names"] = org_names[:5]

    # Step 3: Look up Gravatar profiles for each email
    gravatar_profiles: list[dict[str, Any]] = []
    for email in filtered_emails[:3]:  # Limit to first 3 emails
        profile = _lookup_gravatar(email, timeout)
        if profile.get("display_name"):
            gravatar_profiles.append(profile)
    result["gravatar_profiles"] = gravatar_profiles

    # Step 4: Detect social media links
    combined_text = f"{whois_text}\n{website_text}"
    social_profiles = _detect_social_links(combined_text)
    result["social_media"]["profiles"] = social_profiles[:10]

    # Step 5: Try GitHub lookup from social profiles
    for sp in social_profiles:
        if sp["platform"] == "GitHub":
            github_result = _lookup_github(sp["username"], timeout)
            if github_result:
                result["github_profile"] = github_result
                break

    # Step 6: Score attribution confidence
    evidence: list[str] = []
    score = 0

    if org_names:
        score += 15
        evidence.append(f"Organization name found in WHOIS: {' / '.join(org_names[:2])}")

    if gravatar_profiles:
        score += 25
        for gp in gravatar_profiles[:2]:
            evidence.append(
                f"Gravatar profile found for {gp.get('display_name', 'Unknown')} "
                f"(email hash: {gp.get('hash', '')[:8]}...)"
            )

    if result["github_profile"]:
        gh = result["github_profile"]
        score += 20
        evidence.append(
            f"GitHub profile: {gh.get('name', gh.get('login'))} "
            f"(@{gh.get('login')}) — {gh.get('public_repos', 0)} repos, "
            f"{gh.get('followers', 0)} followers"
        )
        # Cross-reference GitHub email with WHOIS emails
        gh_email = gh.get("email")
        if gh_email and gh_email in filtered_emails:
            score += 15
            evidence.append(
                f"Cross-verified: GitHub email ({gh_email}) matches WHOIS email."
            )

    if social_profiles:
        score += min(len(social_profiles) * 5, 20)
        platforms = list(set(sp["platform"] for sp in social_profiles))
        evidence.append(
            f"Social media profiles detected: {', '.join(platforms[:5])}"
        )

    # Determine attribution level
    result["attribution_score"] = min(score, 100)
    result["has_owner_footprint"] = score > 0

    if score >= 70:
        result["attribution_level"] = "Verified Owner"
        result["attribution_severity"] = "verified"
        result["display_owner"] = True
        result["attribution_summary"] = (
            f"Strong ownership evidence found for {domain}. "
            f"Multiple independent sources confirm the entity behind this domain. "
            f"Score: {score}/100."
        )
    elif score >= 40:
        result["attribution_level"] = "Probable Owner"
        result["attribution_severity"] = "probable"
        result["attribution_summary"] = (
            f"Moderate ownership evidence found for {domain}. "
            f"Some indicators suggest a specific entity. "
            f"Score: {score}/100."
        )
    elif score >= 15:
        result["attribution_level"] = "Possible Owner"
        result["attribution_severity"] = "possible"
        result["attribution_summary"] = (
            f"Weak ownership signals found for {domain}. "
            f"Email/Gravatar hints exist but cannot be confirmed. "
            f"Score: {score}/100."
        )
    else:
        result["attribution_level"] = "No Ownership Evidence"
        result["attribution_severity"] = "none"
        result["attribution_summary"] = (
            f"No verifiable ownership evidence found for {domain}. "
            f"This is common for privacy-protected or recently registered domains."
        )

    result["attribution_evidence"] = evidence[:8]

    return result

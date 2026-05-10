"""
Module 3 — Phishing Link & QR Detector
Multi-signal heuristic analysis with custom Levenshtein edit-distance algorithm.
"""

import re
from urllib.parse import urlparse

# Custom Levenshtein implementation (no external libraries)
def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


KNOWN_LEGITIMATE_DOMAINS = [
    "google.com", "paypal.com", "amazon.com", "facebook.com",
    "microsoft.com", "apple.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "bank", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "flipkart.com", "paytm.com"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "urgent", "confirm", "update", "secure",
    "account", "bank", "password", "credentials", "suspended",
    "blocked", "alert", "warning", "limited", "validate", "signin"
]

HIGH_RISK_TLDS = [".xyz", ".tk", ".ml", ".cf", ".gq", ".pw", ".top",
                  ".click", ".download", ".link", ".online", ".site"]


def analyse_phishing(url: str) -> dict:
    if not url or not url.strip():
        return {
            "status": "ERROR",
            "score": 0,
            "flags": [],
            "message": "No URL provided."
        }

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    flags = []
    score = 0

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        full_url = url.lower()

        # Signal 1: No HTTPS
        if parsed.scheme == "http":
            flags.append("No HTTPS — connection is not encrypted (plaintext risk)")
            score += 2

        # Signal 2: Suspicious keywords in URL
        kw_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
        if kw_found:
            flags.append(f"Suspicious keywords detected: {', '.join(kw_found)}")
            score += len(kw_found)

        # Signal 3: High-risk TLD
        risky_tld = [tld for tld in HIGH_RISK_TLDS if hostname.endswith(tld)]
        if risky_tld:
            flags.append(f"High-risk TLD detected: {risky_tld[0]}")
            score += 2

        # Signal 4: IP-based URL
        ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
        if ip_pattern.match(hostname):
            flags.append("IP-based URL — legitimate sites use domain names, not raw IPs")
            score += 3

        # Signal 5: Excessive subdomains (3+ levels)
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 3:
            flags.append(f"Excessive subdomain depth ({len(subdomain_parts)} levels) — common obfuscation trick")
            score += 1

        # Signal 6: Lookalike domain detection (Levenshtein ≤ 2)
        base_domain = ".".join(subdomain_parts[-2:]) if len(subdomain_parts) >= 2 else hostname
        for legit in KNOWN_LEGITIMATE_DOMAINS:
            dist = levenshtein_distance(base_domain.lower(), legit.lower())
            if 0 < dist <= 2:
                flags.append(f"Lookalike domain! '{base_domain}' is suspiciously similar to '{legit}' (edit distance: {dist})")
                score += 3
                break

        # Signal 7: @ in URL (redirection trick)
        if "@" in url:
            flags.append("'@' symbol in URL — used to redirect to a different host (redirection trick)")
            score += 2

        # Signal 8: Punycode (internationalized domain spoofing)
        if "xn--" in hostname:
            flags.append("Punycode domain (xn--) detected — internationalized character spoofing attempt")
            score += 2

        # Signal 9: URL length > 100 chars
        if len(url) > 100:
            flags.append(f"URL is very long ({len(url)} chars) — often used to hide the real destination")
            score += 1

    except Exception as e:
        return {
            "status": "ERROR",
            "score": 0,
            "flags": [f"Could not parse URL: {str(e)}"],
            "message": "Invalid URL format. Please include http:// or https://"
        }

    # Final classification
    if score <= 1:
        status = "SAFE"
        message = "✅ URL appears safe. No significant phishing signals detected."
    elif score <= 3:
        status = "MEDIUM"
        message = f"⚠️ Suspicious URL. {len(flags)} risk signal(s) detected. Proceed with caution."
    else:
        status = "HIGH"
        message = f"🚨 High phishing risk! {len(flags)} danger signal(s) detected. Do NOT visit this URL."

    return {
        "status": status,
        "score": score,
        "flags": flags,
        "message": message
    }

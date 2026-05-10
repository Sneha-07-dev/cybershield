"""
Module 1 — Digital Footprint Leak Checker
Scans text for breach indicator keywords.
"""

BREACH_KEYWORDS = [
    "pastebin", "leak", "dump", "breach", "hacked", "exposed", "darkweb",
    "dark web", "data breach", "credential", "pwned", "compromised",
    "stolen", "harvested", "exfiltrated"
]

def check_footprint(text: str) -> dict:
    if not text or not text.strip():
        return {
            "status": "ERROR",
            "matched_keywords": [],
            "message": "No text provided for analysis."
        }

    normalized = text.lower()
    matched = [kw for kw in BREACH_KEYWORDS if kw in normalized]

    if matched:
        return {
            "status": "HIGH",
            "matched_keywords": matched,
            "message": f"⚠️ High risk! Your text contains {len(matched)} breach indicator(s): {', '.join(matched)}. "
                       f"This content may be associated with a data leak or breach. "
                       f"Change affected passwords immediately and check haveibeenpwned.com."
        }
    else:
        return {
            "status": "SAFE",
            "matched_keywords": [],
            "message": "✅ No breach indicators detected in the provided text. Your digital footprint looks clean."
        }

"""
Module 4 — Public Wi-Fi Risk Indicator
Assesses risk based on encryption type and network visibility.
"""

ENCRYPTION_SCORES = {
    "OPEN":  3,
    "WEP":   2,
    "WPA":   1,
    "WPA2":  1,
    "WPA3":  0,
}

ENCRYPTION_INFO = {
    "OPEN":  "No encryption — all traffic is visible to anyone on the same network.",
    "WEP":   "WEP is broken and can be cracked in under 60 seconds with free tools.",
    "WPA":   "WPA has known vulnerabilities and is considered outdated.",
    "WPA2":  "WPA2 is standard but vulnerable to KRACK attacks on public networks.",
    "WPA3":  "WPA3 is the most secure modern Wi-Fi standard. Good choice.",
}


def assess_wifi(encryption: str, is_public: bool, ssid: str = "") -> dict:
    encryption = encryption.upper().strip() if encryption else "OPEN"

    if encryption not in ENCRYPTION_SCORES:
        return {
            "status": "ERROR",
            "score": 0,
            "encryption": encryption,
            "flags": [],
            "tips": [],
            "message": f"Unknown encryption type: '{encryption}'. Use OPEN, WEP, WPA, WPA2, or WPA3."
        }

    score = ENCRYPTION_SCORES[encryption]
    flags = []
    tips = []

    # Public network penalty
    if is_public:
        score += 1
        flags.append("Public network — shared with unknown users and potentially monitored")

    # Evil twin warning
    if is_public and encryption in ("OPEN", "WPA2"):
        flags.append("Evil twin hotspot risk — an attacker may create a fake access point with the same name")
        tips.append("Verify the exact network name (SSID) with staff before connecting")

    # Captive portal warning
    if is_public and encryption == "OPEN":
        flags.append("Captive portal likely — your device will auto-connect and expose your MAC address")

    # MITM risk for open networks
    if encryption == "OPEN":
        flags.append("MITM (Man-in-the-Middle) attack risk — attacker can intercept all unencrypted traffic")
        tips.append("Never use this network for banking, email, or any sensitive login")
        tips.append("Use your mobile data hotspot instead of this open network")

    if encryption in ("WEP", "WPA"):
        flags.append(f"Outdated encryption ({encryption}) — upgrade to WPA2 or WPA3 if possible")

    # Tips
    if is_public:
        tips.append("Always use a trusted VPN when connecting to any public Wi-Fi network")
        tips.append("Avoid accessing banking, email, or work accounts on public Wi-Fi")
        tips.append("Enable 'Forget Network' after use to prevent auto-reconnect")

    if encryption == "WPA3":
        tips.append("WPA3 is the safest option. Your encryption is up to date.")

    # Status classification
    if score == 0:
        status = "SAFE"
        message = "✅ Low risk. WPA3 private network — excellent security posture."
    elif score <= 2:
        status = "MEDIUM"
        message = f"⚠️ Moderate risk. {len(flags)} concern(s) detected. Take precautions before transmitting sensitive data."
    else:
        status = "HIGH"
        message = f"🚨 High risk! {len(flags)} serious risk(s) detected. Avoid sensitive activities on this network."

    return {
        "status": status,
        "score": score,
        "encryption": encryption,
        "encryption_info": ENCRYPTION_INFO.get(encryption, ""),
        "flags": flags,
        "tips": tips,
        "message": message
    }

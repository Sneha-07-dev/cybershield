"""
Module 5 — Cyber Risk Dashboard
Aggregates all four module results into a weighted risk score (0–10).
"""

STATUS_WEIGHT = {
    "HIGH":   2,
    "WEAK":   2,
    "MEDIUM": 1,
    "LOW":    0,
    "SAFE":   0,
    "STRONG": 0,
    "ERROR":  0,
}

MAX_MODULE_SCORE = 2
NUM_MODULES = 4
MAX_SCORE = NUM_MODULES * MAX_MODULE_SCORE  # 8


def build_dashboard(footprint_result: dict, password_result: dict,
                    phishing_result: dict, wifi_result: dict) -> dict:

    results = {
        "footprint": footprint_result,
        "password": password_result,
        "phishing": phishing_result,
        "wifi": wifi_result,
    }

    total_score = 0
    breakdown = {}

    for module_name, result in results.items():
        status = result.get("status", "ERROR")
        weight = STATUS_WEIGHT.get(status, 0)
        total_score += weight
        breakdown[module_name] = {
            "status": status,
            "weight": weight,
            "message": result.get("message", "")
        }

    # Normalize to 0–10 scale
    normalized_score = round((total_score / MAX_SCORE) * 10, 1)
    percentage = (total_score / MAX_SCORE) * 100

    # Overall classification
    if total_score == 0:
        overall_status = "SAFE"
        summary = "🛡️ Excellent! Your digital security posture is strong across all five dimensions. Keep it up!"
    elif percentage <= 40:
        overall_status = "LOW"
        summary = "✅ Low overall risk. A few minor issues were detected. Review the flagged modules and apply the suggested improvements."
    elif percentage <= 70:
        overall_status = "MEDIUM"
        summary = "⚠️ Moderate risk detected across your security profile. Several areas need attention — please review each module's recommendations."
    else:
        overall_status = "HIGH"
        summary = "🚨 High overall cyber risk! Multiple serious vulnerabilities detected. Take immediate action on all flagged modules."

    return {
        "overall_status": overall_status,
        "summary": summary,
        "score": total_score,
        "normalized_score": normalized_score,
        "max_score": MAX_SCORE,
        "percentage": round(percentage, 1),
        "breakdown": breakdown
    }

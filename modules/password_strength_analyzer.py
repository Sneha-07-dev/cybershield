"""
Module 2 — Password Strength Analyser
Evaluates password against 5 industry-standard security rules.
"""

import re

RULES = [
    {
        "id": "length",
        "description": "At least 8 characters long",
        "pattern": lambda p: len(p) >= 8,
        "tip": "Use at least 8 characters. Consider a passphrase like 'Coffee@Morning!2024'."
    },
    {
        "id": "uppercase",
        "description": "Contains at least one uppercase letter (A–Z)",
        "pattern": lambda p: bool(re.search(r'[A-Z]', p)),
        "tip": "Add at least one UPPERCASE letter (e.g., A, B, C...)."
    },
    {
        "id": "lowercase",
        "description": "Contains at least one lowercase letter (a–z)",
        "pattern": lambda p: bool(re.search(r'[a-z]', p)),
        "tip": "Add at least one lowercase letter (e.g., a, b, c...)."
    },
    {
        "id": "digit",
        "description": "Contains at least one numeric digit (0–9)",
        "pattern": lambda p: bool(re.search(r'[0-9]', p)),
        "tip": "Include at least one number (0–9) in your password."
    },
    {
        "id": "special",
        "description": "Contains at least one special character (!@#$%^&*...)",
        "pattern": lambda p: bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', p)),
        "tip": "Add a special character like !, @, #, $, %, ^, &, or *."
    }
]

def analyse_password(password: str) -> dict:
    if not password:
        return {
            "status": "ERROR",
            "score": 0,
            "rules_passed": [],
            "tips": [],
            "message": "No password provided."
        }

    score = 0
    tips = []
    rules_passed = []

    for rule in RULES:
        if rule["pattern"](password):
            score += 1
            rules_passed.append(rule["description"])
        else:
            tips.append(rule["tip"])

    if score <= 2:
        status = "WEAK"
        message = "❌ Weak password. This password can be cracked almost instantly. Apply the improvement tips below."
    elif score <= 4:
        status = "MEDIUM"
        message = "⚠️ Medium-strength password. Good start, but it can still be improved. Follow the remaining tips."
    else:
        status = "STRONG"
        message = "✅ Strong password! Your password meets all 5 security criteria. Great job staying secure."

    return {
        "status": status,
        "score": score,
        "max_score": 5,
        "rules_passed": rules_passed,
        "tips": tips,
        "message": message
    }

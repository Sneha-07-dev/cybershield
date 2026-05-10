# 🛡️ CyberShield — Personal Cybersecurity Awareness Tool

**BCA Final Year Project | Vijayanagara Sri Krishnadevaraya University College, Hospet**
**Academic Year 2025–26**

---

## 📋 Project Overview

CyberShield is a full-stack, localhost-based personal cybersecurity awareness tool built with Python and Flask. It provides five independent security modules accessible via a clean REST API and a single-page web interface.

---

## 🚀 Quick Start (Setup in 3 Steps)

### Step 1 — Install Python dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Run the server
```bash
python app.py
```

### Step 3 — Open in browser
```
http://localhost:5000
```

---

## 📁 Project Structure

```
cybershield/
├── app.py                          # Flask REST API server (main entry point)
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── modules/
│   ├── __init__.py
│   ├── footprint_checker.py        # Module 1 — Digital Footprint Leak Checker
│   ├── password_strength_analyzer.py  # Module 2 — Password Strength Analyser
│   ├── phishing_link_qr_detector.py   # Module 3 — Phishing Link Detector
│   ├── public_wifi_risk_indicator.py  # Module 4 — Wi-Fi Risk Indicator
│   └── cyber_risk_dashboard.py     # Module 5 — Aggregate Risk Dashboard
└── templates/
    └── index.html                  # Single-page frontend UI
```

---

## 🔌 API Endpoints

| Endpoint          | Method | Description                                |
|-------------------|--------|--------------------------------------------|
| `/api/ping`       | GET    | Server health check                        |
| `/api/footprint`  | POST   | Module 1 — Digital Footprint Leak Checker  |
| `/api/password`   | POST   | Module 2 — Password Strength Analyser      |
| `/api/phishing`   | POST   | Module 3 — Phishing Link & QR Detector     |
| `/api/wifi`       | POST   | Module 4 — Public Wi-Fi Risk Indicator     |
| `/api/scan-all`   | POST   | Module 5 — All modules + Risk Dashboard    |

---

## 📡 API Usage Examples

### Module 1 — Footprint Checker
```json
POST /api/footprint
{ "text": "Your email was found in a pastebin dump with hacked credentials." }
```

### Module 2 — Password Analyser
```json
POST /api/password
{ "password": "MyP@ssw0rd!" }
```

### Module 3 — Phishing Detector
```json
POST /api/phishing
{ "url": "http://paypa1.com/login/verify?account=suspended" }
```

### Module 4 — Wi-Fi Risk
```json
POST /api/wifi
{ "encryption": "OPEN", "is_public": true, "ssid": "Airport_Free_WiFi" }
```

### Module 5 — Full Scan
```json
POST /api/scan-all
{
  "text": "paste text here",
  "password": "your password",
  "url": "https://example.com",
  "encryption": "WPA2",
  "is_public": true
}
```

---

## 🧪 Test the Phishing Detector

Try these URLs to see different risk levels:

- **SAFE**: `https://www.google.com`
- **MEDIUM**: `http://login-verify-account.com`
- **HIGH**: `http://192.168.1.1/login/verify?account=suspended&urgent=true`
- **HIGH (lookalike)**: `http://paypa1.com/login`
- **HIGH (bad TLD)**: `http://secure-banking-login.xyz/verify`

---

## 💡 Technology Stack

| Component | Technology |
|-----------|-----------|
| Web Framework | Flask 3.0 |
| CORS | Flask-CORS 4.0 |
| Backend | Python 3.8+ |
| Frontend | HTML5 + CSS3 + Vanilla JS (ES6+) |
| Phishing Engine | urllib.parse + re (standard library) |
| Lookalike Detection | Custom Levenshtein Algorithm |
| Data Exchange | JSON |

---

## 🔒 Privacy

All user input is processed **in-memory only**. Nothing is stored, logged, or transmitted to any external server. The entire application runs offline on localhost.

---

*CyberShield — BCA Final Year Project | VSK University College, Hospet, Karnataka | 2025–26*

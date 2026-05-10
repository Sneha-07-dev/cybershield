"""
CyberShield — Flask REST API Server
BCA Final Year Project | Vijayanagara Sri Krishnadevaraya University College
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from modules.footprint_checker import check_footprint
from modules.password_strength_analyzer import analyse_password
from modules.phishing_link_qr_detector import analyse_phishing
from modules.public_wifi_risk_indicator import assess_wifi
from modules.cyber_risk_dashboard import build_dashboard

app = Flask(__name__)
CORS(app)


def coerce_bool(value) -> bool:
    """Safely coerce string 'true'/'1'/'yes' to Python bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    return False


# ─── Health Check ──────────────────────────────────────────────────────────────
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "message": "CyberShield API is running."})


# ─── Module 1: Digital Footprint ──────────────────────────────────────────────
@app.route("/api/footprint", methods=["POST"])
def footprint():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    result = check_footprint(text)
    return jsonify(result)


# ─── Module 2: Password Strength ──────────────────────────────────────────────
@app.route("/api/password", methods=["POST"])
def password():
    data = request.get_json(silent=True) or {}
    pwd = data.get("password", "")
    result = analyse_password(pwd)
    return jsonify(result)


# ─── Module 3: Phishing Detector ──────────────────────────────────────────────
@app.route("/api/phishing", methods=["POST"])
def phishing():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    result = analyse_phishing(url)
    return jsonify(result)


# ─── Module 4: Wi-Fi Risk Indicator ───────────────────────────────────────────
@app.route("/api/wifi", methods=["POST"])
def wifi():
    data = request.get_json(silent=True) or {}
    encryption = data.get("encryption", "OPEN")
    is_public = coerce_bool(data.get("is_public", True))
    ssid = data.get("ssid", "")
    result = assess_wifi(encryption, is_public, ssid)
    return jsonify(result)


# ─── Module 5: Scan All + Dashboard ───────────────────────────────────────────
@app.route("/api/scan-all", methods=["POST"])
def scan_all():
    data = request.get_json(silent=True) or {}

    footprint_result = check_footprint(data.get("text", ""))
    password_result  = analyse_password(data.get("password", ""))
    phishing_result  = analyse_phishing(data.get("url", ""))
    wifi_result      = assess_wifi(
        data.get("encryption", "OPEN"),
        coerce_bool(data.get("is_public", True)),
        data.get("ssid", "")
    )

    dashboard = build_dashboard(footprint_result, password_result, phishing_result, wifi_result)

    return jsonify({
        "dashboard": dashboard,
        "modules": {
            "footprint": footprint_result,
            "password":  password_result,
            "phishing":  phishing_result,
            "wifi":      wifi_result,
        }
    })


# ─── Serve Frontend ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    print("=" * 55)
    print("  🛡️  CyberShield — Personal Cybersecurity Tool")
    print("  BCA Final Year Project | VSK University")
    print("=" * 55)
    print("  Server: http://localhost:5000")
    print("  API:    http://localhost:5000/api/ping")
    print("=" * 55)
    app.run(debug=True, port=5000)

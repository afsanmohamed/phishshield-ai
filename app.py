from flask import Flask, render_template, request, redirect
import pickle
from collections import Counter

app = Flask(__name__)

# Load trained ML model
model = pickle.load(open("phishing_model.pkl", "rb"))

# Store scan history
history = []

# 🔍 Feature extraction function (7 features)
def extract_features(url):
    return [[
        len(url),                                      # URL length
        url.count("@"),                                # @ symbol
        1 if "https" in url else 0,                    # HTTPS
        1 if "-" in url else 0,                        # Hyphen
        url.count("."),                                # Dot count
        1 if any(word in url.lower()
            for word in ["login","verify","secure","update","bank","account","free","offer"]) else 0,
        1 if url.lower().startswith("http://") else 0 # HTTP usage
    ]]

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    risk = None
    level = None
    extra_warning = None
    reasons = []

    if request.method == "POST":
        url = request.form["url"]

        features = extract_features(url)

        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0][1] * 100
        risk = round(probability, 2)

        # Result
        if prediction == 1:
            result = "🔴 Phishing Link"
        else:
            result = "🟢 Safe Link"

        # Threat level
        if risk < 30:
            level = "Low Risk"
        elif risk < 60:
            level = "Medium Risk"
        else:
            level = "High Risk"

        # ⚠ Fake login page warning
        brands = ["facebook", "instagram", "bank", "paytm", "amazon"]
        suspicious = ["login", "verify", "secure", "update"]

        if any(b in url.lower() for b in brands) and any(s in url.lower() for s in suspicious):
            extra_warning = "⚠ Possible Fake Login Page"

        # 🔍 Reason-based explanation
        if "@" in url:
            reasons.append("URL contains '@' symbol")

        if url.lower().startswith("http://"):
            reasons.append("Uses HTTP instead of HTTPS")

        if "-" in url:
            reasons.append("Suspicious hyphen in domain")

        if any(word in url.lower()
            for word in ["login","verify","secure","update","bank","free","offer"]):
            reasons.append("Contains suspicious keywords")

        if len(url) > 75:
            reasons.append("URL length is unusually long")

        # Save history
        history.append({
            "url": url,
            "result": result,
            "risk": risk
        })

    # 📊 Statistics
    counts = Counter(item["result"] for item in history)
    safe_count = counts.get("🟢 Safe Link", 0)
    phish_count = counts.get("🔴 Phishing Link", 0)

    return render_template(
        "index.html",
        result=result,
        risk=risk,
        level=level,
        extra_warning=extra_warning,
        reasons=reasons,
        history=history,
        safe_count=safe_count,
        phish_count=phish_count
    )

# 🧹 Clear history
@app.route("/clear", methods=["POST"])
def clear():
    history.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
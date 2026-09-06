from flask import Flask, render_template, request
import os, tldextract

app = Flask(__name__)

# -----------------------------
# Detection Functions
# -----------------------------

def check_keywords(text):
    keywords = [
        "urgent", "verify", "password", "click here", "account suspended",
        "limited time", "act now", "update", "security alert", "confirm",
        "reset", "bank", "credentials", "login", "sign in",
        "unlock", "validate", "attention", "alert", "warning",
        "immediately", "final notice", "expire", "reactivate", "restricted",
        "unusual activity", "locked", "billing", "invoice", "payment required",
        "refund", "claim", "offer", "promotion", "bonus",
        "congratulations", "winner", "lottery", "prize", "gift card",
        "free", "deal", "discount", "special", "exclusive",
        "threat", "compromise", "breach", "phishing", "malware"
    ]
    found = [word for word in keywords if word in text.lower()]
    return found

def check_url(url):
    if not url.strip():
        return False
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    trusted = [
        "google.com", "paypal.com", "microsoft.com", "apple.com", "amazon.com",
        "facebook.com", "instagram.com", "twitter.com", "linkedin.com", "youtube.com",
        "whatsapp.com", "outlook.com", "live.com", "yahoo.com", "github.com",
        "stackoverflow.com", "wikipedia.org", "netflix.com", "adobe.com", "dropbox.com",
        "zoom.us", "reddit.com", "office.com", "salesforce.com", "oracle.com",
        "ibm.com", "intel.com", "nvidia.com", "tesla.com", "samsung.com",
        "sony.com", "hp.com", "dell.com", "huawei.com", "bbc.com",
        "cnn.com", "nytimes.com", "forbes.com", "coursera.org", "udemy.com",
        "edx.org", "khanacademy.org", "mit.edu", "harvard.edu", "stanford.edu",
        "cloudflare.com", "slack.com", "trello.com", "asana.com", "shopify.com"
    ]
    return domain not in trusted

def check_attachment(filename):
    risky = [".exe", ".scr", ".js", ".bat"]
    return any(filename.endswith(ext) for ext in risky)

def calculate_score(text, url, attachment):
    score = 0
    reasons = []
    if check_keywords(text):
        score += 40
        reasons.append(f"Keywords found: {', '.join(check_keywords(text))}")
    if check_url(url):
        score += 40
        reasons.append("Suspicious URL/domain")
    if attachment and check_attachment(attachment):
        score += 20
        reasons.append(f"Risky attachment: {attachment}")
    return score, reasons

def save_to_log(result_text):
    with open("analysis_log.txt", "a") as log:
        log.write(result_text + "\n")

# -----------------------------
# Flask Routes
# -----------------------------

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    email_text = request.form.get("email_text")
    url = request.form.get("url")
    file = request.files.get("attachment")

    score, reasons = calculate_score(email_text, url, file.filename if file else None)

    result_text = f"Score: {score}% | Reasons: {', '.join(reasons)}"
    save_to_log(result_text)

    return render_template("result.html", score=score, reasons=reasons)

if __name__ == "__main__":
    app.run(debug=True)

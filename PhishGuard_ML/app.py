from pathlib import Path
import os

from flask import Flask, jsonify, render_template, request

from detector import analyze_url

app = Flask(__name__)

MAX_URL_LENGTH = 2048


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/check")
def check_url():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    if len(url) > MAX_URL_LENGTH:
        return jsonify({"error": "URL is too long. Maximum length is 2048 characters."}), 400

    # Ye line add ki hai render logs me search data dekhne ke liye:
    print(f"🔍 USER SEARCHED URL: {url}", flush=True)

    try:
        result = analyze_url(url)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("URL scan failed")
        return jsonify({"error": "The URL could not be scanned. Please try another URL."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)

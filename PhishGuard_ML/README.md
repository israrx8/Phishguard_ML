# PhishGuard — ML URL Detection

A Flask web application that uses the supplied trained Random Forest model and the supplied URL feature-extraction pipeline.

## Project structure

```text
PhishGuard_ML/
├── app.py
├── detector.py
├── featureExtraction.py
├── RandomForestModel.sav
├── requirements.txt
├── Dockerfile
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── script.js
```

## Run on Mac

```bash
cd ~/Desktop/PhishGuard_ML

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## How the result works

The supplied Random Forest model is binary:

```text
0 = Legitimate
1 = Phishing
```

PhishGuard counts how many trees vote for phishing and converts that to a 0–100 model score:

```text
0–39   = Safe
40–69  = Suspicious
70–100 = Risky
```

This keeps the supplied trained model while giving the website the three result states requested for the project.

## Important

The model and features come from an educational phishing-URL project. A Safe result is not a guarantee that a website is harmless.

The project includes legacy WHOIS and web-traffic features because the supplied Random Forest model was trained with those feature columns. External lookups can fail, in which case the original project's fallback values are used.

## Google Cloud Run

After installing the Google Cloud CLI and configuring a Google Cloud project:

```bash
gcloud init
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com
gcloud run deploy phishguard --source . --region asia-south2 --allow-unauthenticated
```

Cloud Run will build the Docker image and return a public HTTPS service URL.


## If the browser shows a blank/white page

Do not double-click `templates/index.html`. Flask must serve the page.

Run:

```bash
cd ~/Desktop/PhishGuard_ML
chmod +x start.sh
./start.sh
```

Then open:

```text
http://127.0.0.1:5000
```

Keep the Terminal window running while using the website.

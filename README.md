Perfect babe 😌 — here’s a **professional GitHub-ready README** for your AI Threat Analyzer backend. You can copy this into a `README.md` file in your repo:

---

````markdown
# AI Threat Analyzer (Ultimate Max Mode)

![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100.0-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

**AI Threat Analyzer** is a Python/FastAPI backend that scans URLs and screenshots for phishing, malware, suspicious domains, and visual anomalies. It uses AI (OpenAI GPT-4) to generate human-readable summaries of potential risks.

---

## Features

- URL risk analysis including:
  - Blacklisted domains
  - Suspicious TLDs
  - SSL certificate validation
  - Redirect chain analysis
  - Phishing keywords detection
  - Malware signatures detection
  - JavaScript and HTML content evaluation
  - Domain age checking
- Screenshot risk analysis:
  - Brightness and variance analysis
  - AI-generated visual risk summary
- AI-powered risk summaries using OpenAI GPT-4
- Interactive API documentation with Swagger UI
- CORS enabled for all origins

---

## Requirements

**Python Packages:**

```bash
fastapi uvicorn requests python-whois python-dotenv dnspython pillow openai python-multipart playwright
````

Install with:

```bash
pip install fastapi uvicorn requests python-whois python-dotenv dnspython pillow openai python-multipart playwright
```

**Additional Setup:**

* Install Chromium for Playwright:

```bash
playwright install chromium
```

* Environment variables (`.env` file):

```
OPENAI_API_KEY=your_openai_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key (optional)
GOOGLE_SAFEBROWSING_KEY=your_google_key (optional)
IP_REP_API_KEY=your_ip_rep_key (optional)
```

---

## Installation

1. Clone the repository:

```bash
git clone git@github.com:Haron456/AI-BACKEND.git
cd AI-BACKEND
```

2. Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
playwright install chromium
```

4. Add your `.env` file with required API keys.

---

## Usage

Start the backend server:

```bash
uvicorn main:app --reload
```

* Server runs at: `http://127.0.0.1:8000`
* Swagger UI: `http://127.0.0.1:8000/docs`

---

## API Endpoints

### Root & Health

* `GET /` → Basic status check
* `GET /health` → Health check

### URL Analysis

* `POST /scan-url` or `/scan` or `/analyze`

  * Request Body:

```json
{
  "url": "https://example.com"
}
```

* Response Example:

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "risk": "medium",
  "score": 0.45,
  "categories": ["suspicious_tld","password_field_found"],
  "summary_text": "AI-generated summary...",
  "redirect_chain": ["https://example.com"],
  "ssl_cert": {"not_before": "...", "not_after": "..."},
  "domain_age_days": 120,
  "hash": "sha256hashvalue",
  "preview": "<HTML content snippet>"
}
```

### Screenshot Analysis

* `POST /scan-screenshot`

  * Request Body:

```json
{
  "image_base64": "data:image/png;base64,...."
}
```

* Response Example:

```json
{
  "risk": "low",
  "score": 0.15,
  "categories": ["very_dark","low_variance_visuals"],
  "meta": {
    "width": 800,
    "height": 600,
    "brightness": 120,
    "variance": 300,
    "indicators": ["very_dark","low_variance_visuals"]
  },
  "summary_text": "AI-generated visual analysis..."
}
```

---

## Notes

* `.env` file is required for AI summaries.
* Do **not** push your `venv` folder to GitHub — add it to `.gitignore`.
* Backend supports CORS for all origins.
* Optional API keys (VirusTotal, Google Safe Browsing, IP Rep) enhance analysis but are not required.

---



---

## Author

**Haron** – [GitHub](https://github.com/Haron456)

---

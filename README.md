
#  AI Threat Analyzer

An advanced **AI-powered cybersecurity API** built with **FastAPI** that analyzes URLs and website screenshots to detect **phishing, malware, scam pages, and impersonation attacks** using rule-based analysis, OCR, browser automation, and AI summaries.

---

## Features

###  URL Threat Analysis
- Domain age detection (WHOIS + SSL fallback)
- DNS resolution checks
- SSL certificate validation
- Redirect chain analysis
- Suspicious TLD detection
- Login & phishing path detection
- HTML content inspection
- Malware signature scanning
- Obfuscated script detection
- Risk scoring (Low / Medium / High)

###  Screenshot & Image Analysis
- OCR using **Tesseract**
- AI OCR fallback (OpenAI)
- Brand/logo keyword detection
- Login form detection
- Phishing keyword detection
- AI-generated user-friendly security summary

### AI Enhancements
- AI-generated explanations for detected risks
- AI-assisted OCR when Tesseract confidence is low
- Natural-language security advice

### ⚡ Performance & Security
- Rate limiting (15 requests/minute)
- Caching for domain age lookups
- Headless browser analysis (Playwright)
- Private & localhost URL blocking
- CORS enabled

---

## Tech Stack

- **FastAPI**
- **Python 3.10+**
- **Playwright (Chromium)**
- **Tesseract OCR**
- **OpenAI API**
- **SlowAPI (Rate Limiting)**
- **WHOIS / DNS / SSL**
- **Pillow (Image Processing)**

---

## things that must be installed

### 1️ 1 System Dependencies
```bash
sudo apt install tesseract-ocr
````

### 2️2 Python Dependencies

```bash
pip install -r requirements.txt
```

### 3️4 Playwright Setup

```bash
playwright install chromium
```

---

##  Environment Variables

Create a `.env` file in the project root:

```env
OPENAI_API_KEY=your_openai_key_here
VIRUSTOTAL_API_KEY=optional
GOOGLE_SAFEBROWSING_KEY=optional
IP_REP_API_KEY=optional
TESSERACT_CMD=/usr/bin/tesseract
```

---

##  Running the Server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

##  API Endpoints

###  Health Check

```http
GET /
GET /health
```

---

###  Scan a URL

```http
POST /scan-url
POST /scan
POST /analyze
```

**Request Body**

```json
{
  "url": "https://example.com"
}
```

**Response Includes**

* Risk level & score
* Threat indicators
* Domain age
* SSL info
* Redirect chain
* AI-generated summary

---

###  Scan a Screenshot

```http
POST /scan-screenshot
```

**Request Body**

```json
{
  "image_base64": "BASE64_IMAGE_DATA"
}
```

**Response Includes**

* OCR extracted text
* Detected brands/logos
* Login form detection
* Phishing keywords
* AI-generated security advice

---

##  Risk Scoring

| Score  | Risk Level |
| ------ | ---------- |
| 0–24   | Low        |
| 25–59  | Medium     |
| 60–100 | High       |

---

##  Blocked Targets

* Localhost
* Private IP ranges
* Internal networks

---

##  OCR Logic

1. Try **Tesseract OCR**
2. If confidence < 40 → fallback to **OpenAI Vision**
3. Analyze extracted text for phishing patterns

---

##  Graceful Shutdown

* Automatically closes Playwright browser pool
* Prevents memory leaks

---

##  Disclaimer

This tool provides **risk assessment**, not a guarantee of safety.
Always combine with human judgment and additional security tools.

---

##  Author

Built for **advanced cybersecurity analysis**, phishing detection, and AI-assisted threat intelligence.






# main.py - AI Threat Analyzer (Ultimate Max Mode + OCR & Visual Screenshot Analysis)
# Requirements:
# apt install tesseract-ocr
# pip install -r requirements.txt
# requirements.txt should include:
# fastapi uvicorn requests python-whois python-dotenv dnspython pillow openai python-multipart playwright slowapi pytesseract opencv-python-headless

import os, re, io, ssl, socket, base64, hashlib, requests, whois, dns.resolver
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, AnyHttpUrl, field_validator
from PIL import Image, ImageStat
from dotenv import load_dotenv
load_dotenv()

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
limiter = Limiter(key_func=get_remote_address)

# OpenAI
import openai
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

# Playwright async for page fetch
from playwright.async_api import async_playwright

# Optional OCR libs
PYTESSERACT_AVAILABLE = False
try:
    import pytesseract
    TESSERACT_CMD = os.getenv("TESSERACT_CMD")
    if TESSERACT_CMD:
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD
    PYTESSERACT_AVAILABLE = True
except Exception:
    PYTESSERACT_AVAILABLE = False

OPENAI_AVAILABLE = bool(OPENAI_API_KEY)

# Optional API keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFEBROWSING_KEY = os.getenv("GOOGLE_SAFEBROWSING_KEY")
IP_REP_API_KEY = os.getenv("IP_REP_API_KEY")

# FastAPI setup
app = FastAPI(title="AI Threat Analyzer (OCR-enabled)", version="5.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Models
# -------------------------
class URLRequest(BaseModel):
    url: AnyHttpUrl

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        parsed = urlparse(str(v))
        if parsed.hostname in ('localhost', '127.0.0.1') or parsed.hostname.startswith(('10.', '192.168.', '172.')):
            raise ValueError("Private / localhost URLs are blocked")
        return v

class ScreenshotRequest(BaseModel):
    image_base64: str

# -------------------------
# Rules / DB
# -------------------------
PHISHING_KEYWORDS = ["login","signin","verify","password","secure","reset","bank","update","auth","confirm","wallet","account","register","pay","billing","mpesa","m-pesa"]
SUSPICIOUS_TLDS = [".xyz",".top",".click",".live",".rest",".quest",".gq",".ml",".tk",".cf",".vip"]
MALWARE_SIGNATURES = ["eval(base64","bitcoin miner","stealer","trojan","keylogger","token-grabber"]
BLACKLISTED_DOMAINS = {"malicious-site.com":"Known malware","phishing-login.net":"Verified phishing"}

BRAND_KEYWORDS = [
    "facebook","fb","youtube","twitter","whatsapp","m-pesa","mpesa","paypal","google","gmail","amazon",
    "bank","equity","kcb","cooperative","mpower","safaricom","ntv","nation","cbk","stanchart","standard chartered",
    "vodafone","airtel","stripe"
]

# -------------------------
# Helpers
# -------------------------
def hash_url(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()

def safe_get(url: str, timeout=6, headers=None, allow_redirects=True):
    try:
        r = requests.get(url, timeout=timeout, headers=headers or {"User-Agent":"Mozilla/5.0"}, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None

@lru_cache(maxsize=1024)
def real_domain_age_days(domain: str) -> int | None:
    try:
        w = whois.whois(domain)
        dates = [d for d in (getattr(w,a,None) for a in ("creation_date","created","created_date","registered")) if d]
        dates = [d[0] if isinstance(d,list) else d for d in dates]
        dates = [d for d in dates if isinstance(d, datetime)]
        if dates:
            created = min(dates)
            return max(0, (datetime.now() - created).days)
    except Exception:
        pass
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_before = cert.get("notBefore")
                if not_before:
                    for fmt in ("%b %d %H:%M:%S %Y %Z","%b %d %H:%M:%S %Y GMT","%Y-%m-%dT%H:%M:%SZ"):
                        try:
                            dt = datetime.strptime(not_before, fmt)
                            return max(0, (datetime.now() - dt).days)
                        except Exception:
                            continue
    except Exception:
        pass
    return None

def ssl_certificate_dates(domain: str) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {"not_before": cert.get("notBefore"), "not_after": cert.get("notAfter")}
    except Exception:
        return None

def get_redirect_chain(url: str) -> list:
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
        return [h.url for h in r.history] + [r.url]
    except Exception:
        return []

def analyze_page_html(html: str) -> dict:
    h = (html or "").lower()
    return {
        "has_password_field": bool(re.search(r"<input[^>]+type=['\"]password['\"]", h)),
        "login_keywords_found": [kw for kw in PHISHING_KEYWORDS if kw in h],
        "malware_signatures_found": [sig for sig in MALWARE_SIGNATURES if sig in h],
        "scripts_count": len(re.findall(r"<script\b", h)),
        "external_scripts": len(re.findall(r"src=['\"]https?://", h)),
        "obfuscated": bool(re.search(r"(%[0-9a-fA-F]{2}){4,}", h)),
    }

# -------------------------
# Playwright page fetch
# -------------------------
browser_pool = None
playwright_instance = None

async def init_browser_pool():
    global browser_pool, playwright_instance
    if not browser_pool:
        playwright_instance = await async_playwright().start()
        browser_pool = await playwright_instance.chromium.launch(headless=True)

async def close_browser_pool():
    global browser_pool, playwright_instance
    try:
        if browser_pool:
            await browser_pool.close()
        if playwright_instance:
            await playwright_instance.stop()
    except:
        pass

async def fetch_page_content(url: str) -> str:
    try:
        if not browser_pool:
            await init_browser_pool()
        browser = browser_pool
        page = await browser.new_page()
        await page.goto(url, wait_until="networkidle", timeout=15000)
        content = await page.content()
        await page.close()
        content = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', content, flags=re.IGNORECASE | re.DOTALL)
        return content[:30000]
    except Exception:
        return "<Could not fetch page content>"

# -------------------------
# OCR helpers
# -------------------------
def ocr_from_pillow_image(img: Image.Image) -> dict:
    if not PYTESSERACT_AVAILABLE:
        return {"text": "", "words": [], "confidence": 0.0, "error": "pytesseract not installed"}

    try:
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        words = []
        confidences = []
        for i in range(len(data.get("text", []))):
            txt = (data["text"][i] or "").strip()
            conf = None
            try:
                conf = float(data["conf"][i])
            except:
                conf = None
            if txt:
                words.append({"text": txt, "conf": conf})
            if conf is not None and conf > -1:
                confidences.append(conf)
        avg_conf = float(sum(confidences))/len(confidences) if confidences else 0.0
        full_text = " ".join(w["text"] for w in words)
        return {"text": full_text, "words": words, "confidence": avg_conf}
    except Exception as e:
        return {"text": "", "words": [], "confidence": 0.0, "error": str(e)}

async def ocr_with_openai_fallback(img_b64: str) -> dict:
    if not OPENAI_AVAILABLE:
        return {"text":"", "method":"none", "note":"no-openai-key"}
    try:
        if PYTESSERACT_AVAILABLE:
            img = Image.open(io.BytesIO(base64.b64decode(img_b64))).convert("RGB")
            res = ocr_from_pillow_image(img)
            if res.get("confidence",0) >= 40:
                res.update({"method":"pytesseract"})
                return res
        # fallback to OpenAI
        prompt = "Extract all visible text from the image and return only the text."
        res = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role":"user","content": prompt}],
            temperature=0.0,
            max_tokens=600
        )
        text = res['choices'][0]['message']['content'].strip()
        return {"text": text, "words": [{"text": t, "conf": None} for t in text.split()], "confidence": 50.0, "method":"openai"}
    except Exception as e:
        return {"text":"", "words":[], "confidence":0.0, "error":str(e), "method":"openai_failed"}

# -------------------------
# Screenshot analysis helpers
# -------------------------
def detect_logos_from_text(ocr_text: str) -> list:
    found = []
    t = (ocr_text or "").lower()
    for kw in BRAND_KEYWORDS:
        if kw in t:
            found.append(kw)
    return sorted(set(found))

def detect_form_using_text(ocr_text: str) -> bool:
    t = (ocr_text or "").lower()
    indicators = ["password", "username", "email", "sign in", "log in", "login", "enter password", "confirm password"]
    return any(i in t for i in indicators)

def detect_phishing_keywords_in_text(ocr_text: str) -> list:
    t = (ocr_text or "").lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in t]

def generate_screenshot_summary(ocr_text: str, logo_matches: list, form_detected: bool, ocr_conf: float) -> str:
    base = f"Screenshot OCR confidence: {ocr_conf:.1f}. Logos found: {', '.join(logo_matches) or 'none'}. Form detected: {form_detected}."
    short_text = (ocr_text or "").strip()
    if OPENAI_AVAILABLE:
        try:
            prompt = (
                f"You're an assistant analyzing a website screenshot.\n"
                f"{base}\n"
                f"Extracted text (first 600 chars):\n{short_text[:600]}\n\n"
                "Write a concise user-facing summary (1-3 short sentences) explaining if this looks like a phishing/login page, "
                "what brand it might be impersonating (if any), and advice to the user."
            )
            res = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role":"user","content": prompt}],
                temperature=0.4,
                max_tokens=150
            )
            return res['choices'][0]['message']['content'].strip()
        except:
            pass
    if form_detected and logo_matches:
        return f"Screenshot appears to show a login form and references {', '.join(logo_matches)} — possible impersonation. Do not enter credentials."
    if form_detected:
        return "Screenshot shows a login form or password fields — be cautious."
    if logo_matches:
        return f"Detected brand keywords: {', '.join(logo_matches)}; check domain closely for impersonation."
    if short_text:
        return "Screenshot contains text. No obvious login form or known brand detected."
    return "No readable text detected in screenshot."

# -------------------------
# Compute URL score
# -------------------------
async def compute_score_and_details(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path.lower()
    score = 0
    categories = []

    # DNS check
    try:
        dns.resolver.resolve(domain, 'A')
    except Exception:
        score += 10
        categories.append("dns_resolution_failed")

    if domain in BLACKLISTED_DOMAINS:
        score += 60; categories.append("blacklisted_domain")
    if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
        score += 12; categories.append("suspicious_tld")

    cert_info = ssl_certificate_dates(domain)
    if not cert_info:
        score += 20; categories.append("no_ssl")

    age_days = real_domain_age_days(domain)
    if age_days is None:
        score += 8; categories.append("unknown_domain_age")
    elif age_days < 30:
        score += 30; categories.append(f"new_domain ({age_days} days)")
    elif age_days < 90:
        score += 10; categories.append(f"young_domain ({age_days} days)")

    chain = get_redirect_chain(url)
    if len(chain) > 3:
        score += 8; categories.append("redirect_chain_long")

    if re.search(r"/login|/signin|/register|/account|/verify|/checkout|/payment", path):
        score += 12; categories.append("suspicious_login_path")
    if len(parsed.query) > 80:
        score += 6; categories.append("long_query")
    if re.search(r"([a-z0-9]{20,})", url):
        score += 6; categories.append("long_random_token")

    page = await fetch_page_content(url)
    html_analysis = analyze_page_html(page)
    if html_analysis["has_password_field"]:
        score += 15; categories.append("password_field_found")
    if html_analysis["login_keywords_found"]:
        score += 5; categories.append(f"login_keywords:{','.join(html_analysis['login_keywords_found'][:5])}")
    if html_analysis["malware_signatures_found"]:
        score += 20; categories.append("malware_signatures_found")
    if html_analysis["external_scripts"] > 10:
        score += 6; categories.append("many_external_scripts")
    if html_analysis["obfuscated"]:
        score += 10; categories.append("obfuscated_content")

    score = min(max(score, 0), 100)
    risk = "low" if score < 25 else ("medium" if score < 60 else "high")

    summary_text = f"Risk {risk.upper()} ({score}%). Indicators: {', '.join(categories) or 'none'}."
    if OPENAI_AVAILABLE:
        try:
            prompt = (
                f"Analyze the website: {url}\nIndicators: {', '.join(categories) or 'none'}\n"
                "Return a short (1-3 sentence) explanation for a non-technical user and advice."
            )
            res = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role":"user","content": prompt}],
                temperature=0.3,
                max_tokens=150
            )
            summary_text = res['choices'][0]['message']['content'].strip()
        except:
            pass

    return {
        "url": url,
        "domain": domain,
        "risk": risk,
        "score": score / 100.0,
        "score_percent": score,
        "categories": categories,
        "summary_text": summary_text,
        "preview": page[:1200] if page else "<No preview available>",
        "hash": hash_url(url),
        "domain_age_days": age_days,
        "redirect_chain": chain,
        "ssl_cert": cert_info
    }

# -------------------------
# Endpoints
# -------------------------
@app.get("/")
def root():
    return {"status":"ok","message":"AI Threat Analyzer v5.0 (OCR + phishing detection)"}

@app.get("/health")
def health():
    return {"status":"ok"}

@app.post("/scan-url")
@app.post("/scan")
@app.post("/analyze")
@limiter.limit("15/minute")
async def scan(request: Request, payload: URLRequest):
    try:
        return await compute_score_and_details(str(payload.url))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan-screenshot")
async def scan_screenshot(payload: ScreenshotRequest):
    img_b64 = payload.image_base64 or ""
    if not img_b64:
        raise HTTPException(status_code=400, detail="Image required")
    if img_b64.startswith("data:"):
        try:
            img_b64 = img_b64.split(",", 1)[1]
        except:
            pass
    try:
        img_bytes = base64.b64decode(img_b64)
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Image decode failed: {e}")

    ocr_result = {"text":"", "words":[], "confidence":0.0, "method":"none"}
    if PYTESSERACT_AVAILABLE:
        ocr_result = ocr_from_pillow_image(img)
    elif OPENAI_AVAILABLE:
        ocr_result = await ocr_with_openai_fallback(img_b64)

    text = ocr_result.get("text","")
    conf = ocr_result.get("confidence",0.0)
    logos = detect_logos_from_text(text)
    form_detected = detect_form_using_text(text)
    keywords = detect_phishing_keywords_in_text(text)
    summary = generate_screenshot_summary(text, logos, form_detected, conf)

    return {
        "ocr_result": ocr_result,
        "logos_detected": logos,
        "form_detected": form_detected,
        "phishing_keywords_found": keywords,
        "summary": summary
    }

# -------------------------
# Shutdown
# -------------------------
@app.on_event("shutdown")
async def shutdown_event():
    await close_browser_pool()

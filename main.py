# main.py - AI Threat Analyzer (Ultimate Max Mode + JS Previews + AI Visual Analysis)
# Requirements:
# pip install fastapi uvicorn requests python-whois python-dotenv dnspython pillow openai python-multipart playwright
# And run: playwright install chromium

import os, re, io, ssl, socket, base64, hashlib, requests, whois, dns.resolver
from datetime import datetime
from urllib.parse import urlparse
from functools import lru_cache

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image, ImageStat
from dotenv import load_dotenv
load_dotenv()

import openai
from playwright.sync_api import sync_playwright

# -------------------------
# OpenAI setup
# -------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

# -------------------------
# Optional API keys
# -------------------------
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")          
GOOGLE_SAFEBROWSING_KEY = os.getenv("GOOGLE_SAFEBROWSING_KEY")
IP_REP_API_KEY = os.getenv("IP_REP_API_KEY")

# -------------------------
# FastAPI setup
# -------------------------
app = FastAPI(title="AI Threat Analyzer (Ultimate Max Mode)", version="4.0")
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
    url: str

class ScreenshotRequest(BaseModel):
    image_base64: str

# -------------------------
# Rules / Signatures
# -------------------------
PHISHING_KEYWORDS = ["login","signin","verify","password","secure","reset","bank","update","auth","confirm","wallet","account","register","pay","billing"]
SUSPICIOUS_TLDS = [".xyz",".top",".click",".live",".rest",".quest",".gq",".ml",".tk",".cf",".vip"]
MALWARE_SIGNATURES = ["eval(base64","bitcoin miner","stealer","trojan","keylogger","token-grabber"]
BLACKLISTED_DOMAINS = {"malicious-site.com":"Known malware","phishing-login.net":"Verified phishing"}

# -------------------------
# Helpers
# -------------------------
def hash_url(url:str) -> str: return hashlib.sha256(url.encode()).hexdigest()

@lru_cache(maxsize=1024)
def real_domain_age_days(domain:str) -> int | None:
    try:
        w = whois.whois(domain)
        dates = [d for d in [getattr(w, a, None) for a in ("creation_date","created","created_date","registered")] if d]
        dates = [d[0] if isinstance(d,list) else d for d in dates]
        dates = [d for d in dates if isinstance(d, datetime)]
        if dates: return max(0,(datetime.now()-min(dates)).days)
    except: pass
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=4) as sock:
            with ctx.wrap_socket(sock,server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                nb = cert.get("notBefore")
                if nb:
                    for fmt in ("%b %d %H:%M:%S %Y %Z","%b %d %H:%M:%S %Y GMT","%Y-%m-%dT%H:%M:%SZ"):
                        try: return max(0,(datetime.now()-datetime.strptime(nb,fmt)).days)
                        except: continue
    except: pass
    return None

def ssl_certificate_dates(domain:str) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=4) as sock:
            with ctx.wrap_socket(sock,server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {"not_before":cert.get("notBefore"),"not_after":cert.get("notAfter")}
    except: return None

def get_redirect_chain(url:str) -> list:
    try:
        r = requests.get(url,timeout=10,allow_redirects=True,headers={"User-Agent":"Mozilla/5.0"})
        return [h.url for h in r.history]+[r.url]
    except: return []

# -------------------------
# Fetch page (JS-supported)
# -------------------------
def fetch_page_content(url:str) -> str:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url,wait_until="networkidle",timeout=10000)
            content = page.content()
            browser.close()
            return content[:30000]
    except: return "<Could not fetch page content>"

def analyze_page_html(html:str) -> dict:
    h = (html or "").lower()
    return {
        "has_password_field":bool(re.search(r"<input[^>]+type=['\"]password['\"]",h)),
        "login_keywords_found":[kw for kw in PHISHING_KEYWORDS if kw in h],
        "malware_signatures_found":[sig for sig in MALWARE_SIGNATURES if sig in h],
        "scripts_count":len(re.findall(r"<script\b",h)),
        "external_scripts":len(re.findall(r"src=['\"]https?://",h)),
        "obfuscated":bool(re.search(r"(%[0-9a-fA-F]{2}){4,}",h))
    }

# -------------------------
# AI summary generator
# -------------------------
def generate_ai_summary(url:str,categories:list,score:float,age:int) -> str:
    if not OPENAI_API_KEY: return ""
    prompt = f"""
Analyze the website: {url}
Risk categories detected: {', '.join(categories) or 'None'}
Risk score: {score*100:.1f}%
Domain age: {age} days
Write a concise, human-readable summary explaining why this site is risky or safe. Include advice for the user.
"""
    try:
        res = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role":"user","content":prompt}],
            temperature=0.5,max_tokens=200
        )
        return res['choices'][0]['message']['content'].strip()
    except: return "AI summary could not be generated."

# -------------------------
# Scoring Engine
# -------------------------
def compute_score_and_details(url:str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path.lower()
    score=0
    categories=[]

    if domain in BLACKLISTED_DOMAINS: score+=60; categories.append("blacklisted_domain")
    if any(domain.endswith(t) for t in SUSPICIOUS_TLDS): score+=12; categories.append("suspicious_tld")
    cert_info = ssl_certificate_dates(domain)
    if not cert_info: score+=20; categories.append("no_ssl")
    age_days = real_domain_age_days(domain)
    if age_days is None: score+=8; categories.append("unknown_domain_age")
    elif age_days<30: score+=30; categories.append(f"new_domain ({age_days} days)")
    elif age_days<90: score+=10; categories.append(f"young_domain ({age_days} days)")

    chain = get_redirect_chain(url)
    if len(chain)>3: score+=8; categories.append("redirect_chain_long")

    if re.search(r"/login|/signin|/register|/account|/verify|/checkout|/payment",path): score+=12; categories.append("suspicious_login_path")
    if len(parsed.query)>80: score+=6; categories.append("long_query")
    if re.search(r"([a-z0-9]{20,})",url): score+=6; categories.append("long_random_token")

    page = fetch_page_content(url)
    html_analysis = analyze_page_html(page)
    if html_analysis["has_password_field"]: score+=15; categories.append("password_field_found")
    if html_analysis["login_keywords_found"]: score+=5; categories.append(f"login_keywords:{','.join(html_analysis['login_keywords_found'][:5])}")
    if html_analysis["malware_signatures_found"]: score+=20; categories.append("malware_signatures_found")
    if html_analysis["external_scripts"]>10: score+=6; categories.append("many_external_scripts")
    if html_analysis["obfuscated"]: score+=10; categories.append("obfuscated_content")

    score = min(max(score,0),100)
    risk = "low" if score<25 else ("medium" if score<60 else "high")
    summary_text = generate_ai_summary(url,categories,score/100.0,age_days or 0)

    return {
        "url":url,
        "domain":domain,
        "risk":risk,
        "score":score/100.0,
        "score_percent":score,
        "categories":categories,
        "summary_text":summary_text or f"Risk {risk.upper()} ({score}%). Indicators: {', '.join(categories) or 'none'}.",
        "preview":page[:1200] if page else "<No preview available>",
        "hash":hash_url(url),
        "domain_age_days":age_days,
        "redirect_chain":chain,
        "ssl_cert":cert_info
    }

# -------------------------
# Endpoints
# -------------------------
@app.get("/")
def root(): return {"status":"ok","message":"AI Threat Analyzer (Ultimate Max Mode)"}

@app.get("/health")
def health(): return {"status":"ok"}

@app.post("/scan-url")
@app.post("/scan")
@app.post("/analyze")
def scan(payload:URLRequest):
    url = payload.url.strip()
    if not url: raise HTTPException(status_code=400,detail="URL required")
    if not url.startswith("http"): url="http://"+url
    try: return compute_score_and_details(url)
    except Exception as e: raise HTTPException(status_code=500,detail=str(e))

@app.post("/scan-screenshot")
def scan_screenshot(payload:ScreenshotRequest):
    img_b64 = payload.image_base64
    if not img_b64: raise HTTPException(status_code=400,detail="Image required")
    if img_b64.startswith("data:"): img_b64=img_b64.split(",",1)[1]
    try:
        img_bytes = base64.b64decode(img_b64)
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        stat = ImageStat.Stat(img)
        w,h = img.size
        mean_brightness = sum(stat.mean)/3
        var = sum(stat.var)/3
        indicators=[]
        if mean_brightness<40: indicators.append("very_dark")
        if mean_brightness>220: indicators.append("very_bright")
        if var<100: indicators.append("low_variance_visuals")
        score=0; cats=[]
        for ind in indicators:
            if ind in ("very_dark","very_bright"): score+=20; cats.append("suspicious_appearance")
            if ind=="low_variance_visuals": score+=10; cats.append("low_visual_variance")
        risk = "low" if score<25 else ("medium" if score<60 else "high")
        # AI Visual Summary
        summary=""
        if OPENAI_API_KEY:
            try:
                prompt=f"Analyze an image for potential risk indicators. Indicators: {', '.join(indicators) or 'none'}. Risk: {risk.upper()}."
                res = openai.ChatCompletion.create(model="gpt-4",messages=[{"role":"user","content":prompt}],temperature=0.5,max_tokens=150)
                summary=res['choices'][0]['message']['content'].strip()
            except: summary=""
        return {"risk":risk,"score":min(score/100.0,1.0),"categories":list(set(cats)),"meta":{"width":w,"height":h,"brightness":mean_brightness,"variance":var,"indicators":indicators},"summary_text":summary}
    except Exception as e:
        raise HTTPException(status_code=400,detail=f"Image decode failed: {e}")

import json
import os
import re
import datetime
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, HTMLResponse
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from sqlalchemy import func
from dotenv import load_dotenv

load_dotenv()

# Rate limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    SLOWAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback for minimal deployments
    SLOWAPI_AVAILABLE = False

    class RateLimitExceeded(Exception):
        pass

    def _rate_limit_exceeded_handler(request, exc):
        raise exc

    def get_remote_address(request):
        return request.client.host if request.client else "unknown"

    class Limiter:
        def __init__(self, key_func=None):
            self.key_func = key_func

        def limit(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

# DB imports
from .database import engine, Base, get_db
from .models import User, ScanHistory
from .schemas import (
    EmailPredictRequest, PredictResponse, StatsResponse,
    UrlAnalyzeRequest, UrlAnalyzeResponse,
    VirusTotalResult, WhoisResult, EmailAuthResult, AttachmentInfo, LlmAnalysisResult
)
from .classifier import PhishingClassifier
from .utils import (
    parse_eml, scan_image_for_qr, extract_text_from_image,
    check_virustotal, get_whois_info, check_url_reputation,
    analyze_attachment, get_extension_zip_bytes, sanitize_html
)
from .llm import generate_llm_explanation

# Initialize Limiter for rate limiting
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI
app = FastAPI(
    title="AI-Powered Phishing Email Detector Enterprise API",
    description="SaaS Backend API for detecting phishing emails, URLs, and attachments using ML and Threat Intelligence",
    version="2.0.0"
)

raw_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,https://*.vercel.app,https://*.onrender.com,https://*.netlify.app")
ALLOWED_ORIGINS = []
ALLOWED_ORIGIN_REGEXES = []
for raw_origin in raw_cors_origins.split(","):
    origin = raw_origin.strip()
    if not origin:
        continue
    if origin == "https://*.vercel.app":
        ALLOWED_ORIGIN_REGEXES.append(r"https://([a-z0-9-]+\.)*vercel\.app")
    elif origin == "*":
        ALLOWED_ORIGIN_REGEXES.append(r".*")
    else:
        ALLOWED_ORIGINS.append(origin)


def is_allowed_origin(origin: Optional[str]) -> bool:
    if not origin:
        return False
    if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        return True
    if origin.startswith("https://") and origin.endswith(".vercel.app"):
        return True
    return origin in ALLOWED_ORIGINS

# Register Rate Limit Exception Handler
app.state.limiter = limiter
if SLOWAPI_AVAILABLE:
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex="|".join(ALLOWED_ORIGIN_REGEXES) if ALLOWED_ORIGIN_REGEXES else None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Custom Security Headers & Dynamic CORS Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    origin = request.headers.get("origin", "")
    
    # Handle preflight OPTIONS requests dynamically
    if request.method == "OPTIONS":
        response = Response()
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
        return response

    response = await call_next(request)

    if origin and is_allowed_origin(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    elif origin:
        response.headers["Access-Control-Allow-Origin"] = ""
        
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Dynamically resolve current host for CSP
    host = request.headers.get("host", "")
    scheme = "https" if request.url.is_secure or request.headers.get("x-forwarded-proto") == "https" else "http"
    current_host_url = f"{scheme}://{host}" if host else ""
    
    csp_connect = f"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' {current_host_url} {origin} http://localhost:8000 http://localhost:5173 http://127.0.0.1:8000;"
    response.headers["Content-Security-Policy"] = csp_connect
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Initialize Database tables
Base.metadata.create_all(bind=engine)
print("Database connected successfully")

# Initialize Classifier
classifier = PhishingClassifier()

# Limit file size for enterprise scans
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(10 * 1024 * 1024)))

# Optional Authentication Dependency (Disabled)
def get_optional_current_user() -> Optional[Any]:
    return None


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL. Use http:// or https://")
    return url


def validate_email_text(text: str) -> str:
    sanitized_text = sanitize_html(text)
    if not sanitized_text or len(sanitized_text.strip()) < 3:
        raise HTTPException(status_code=400, detail="Invalid or empty email text.")
    return sanitized_text


@app.get("/")
def root() -> Dict[str, str]:
    return {"status": "healthy"}


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# --- Core Scanner Routes (V2 SaaS Version) ---

@app.post("/api/predict", response_model=PredictResponse)
@limiter.limit("30/minute")
async def predict_email(
    request: Request, 
    payload: EmailPredictRequest, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    sanitized_text = validate_email_text(payload.text)
        
    # 1. Core ML Text Scan (Sync CPU bound - run in threadpool)
    result = await run_in_threadpool(classifier.predict, sanitized_text)
    
    # 2. Extract URLs from text to run VirusTotal and WHOIS
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', sanitized_text)
    vt_result = None
    whois_result = None
    domain = None
    
    if urls:
        first_url = urls[0]
        domain = re.sub(r'^https?://', '', first_url).split('/')[0].split(':')[0].lower()
        
        # Async parallel fetch for WHOIS and VirusTotal
        vt_task = run_in_threadpool(check_virustotal, first_url)
        whois_task = run_in_threadpool(get_whois_info, domain)
        
        vt_result_dict, whois_result_dict = await asyncio.gather(vt_task, whois_task)
        vt_result = VirusTotalResult(**vt_result_dict)
        whois_result = WhoisResult(**whois_result_dict)
        
        # Increase risk score if URL is dangerous
        if vt_result.malicious > 0 or whois_result.is_new_domain:
            result["risk_score"] = min(result["risk_score"] + 20.0, 100.0)
            if result["classification"] == "Safe":
                result["classification"] = "Suspicious"
                
    # 3. LLM Security Analysis & MITRE ATT&CK (Concurrently with other logic if needed, or run now)
    llm_res_dict = await run_in_threadpool(
        generate_llm_explanation, 
        sanitized_text, 
        result["classification"], 
        result["detected_indicators"]
    )
    llm_analysis = LlmAnalysisResult(**llm_res_dict)
    
    # 4. Save to Database
    db_history = ScanHistory(
        user_id=current_user.id if current_user else None,
        subject="Raw Text Scan",
        sender="Unknown",
        body_preview=sanitized_text[:200],
        classification=result["classification"],
        confidence_score=result["confidence_score"],
        risk_score=result["risk_score"],
        explanation=result["explanation"],
        detected_indicators=json.dumps(result["detected_indicators"]),
        
        # V2 Columns
        threat_type=llm_analysis.mitre_mappings[0].name if llm_analysis.mitre_mappings else "Phishing",
        virustotal_results=json.dumps(vt_result.dict()) if vt_result else None,
        whois_results=json.dumps(whois_result.dict()) if whois_result else None,
        email_auth_results=json.dumps({"spf": "None", "dkim": "None", "dmarc": "None", "is_authenticated": True}),
        attachment_analysis=json.dumps([]),
        llm_analysis=json.dumps(llm_analysis.dict()),
        
        domain=domain,
        file_type="TXT"
    )
    db.add(db_history)
    db.commit()
    db.refresh(db_history)
    
    # 5. Build Final Response
    result.update({
        "id": db_history.id,
        "user_id": db_history.user_id,
        "subject": db_history.subject,
        "sender": db_history.sender,
        "created_at": db_history.created_at,
        "threat_type": db_history.threat_type,
        "virustotal_results": vt_result,
        "whois_results": whois_result,
        "email_auth_results": EmailAuthResult(),
        "attachment_analysis": [],
        "llm_analysis": llm_analysis
    })
    
    return result

@app.post("/api/upload", response_model=PredictResponse)
@limiter.limit("20/minute")
async def upload_email(
    request: Request,
    file: UploadFile = File(...), 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    filename = (file.filename or "").strip()
    if not filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid file name.")

    ext = os.path.splitext(filename)[1].lower()
    if ext not in [".txt", ".eml"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only .txt and .eml supported.")
        
    contents = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        contents += chunk
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds the 10MB limit.")
            
    subject = "Uploaded File Scan"
    sender = "Unknown"
    body = ""
    attachments = []
    raw_attachments = []
    email_auth = EmailAuthResult()
    ocr_text = ""
    
    # 1. Parse File
    if ext == ".eml":
        parsed = parse_eml(contents)
        subject = parsed["subject"] or "No Subject"
        sender = parsed["sender"] or "Unknown Sender"
        body = parsed["body"]
        attachments = parsed["attachments"]
        raw_attachments = parsed["raw_attachments"]
        email_auth = EmailAuthResult(**parsed["email_auth_results"])
        
        # 2. Run OCR on Image Attachments in Parallel
        if parsed["image_attachments"]:
            ocr_tasks = [run_in_threadpool(extract_text_from_image, img_bytes) for name, img_bytes in parsed["image_attachments"]]
            ocr_results = await asyncio.gather(*ocr_tasks)
            ocr_text = "\n".join([t for t in ocr_results if t])
            if ocr_text:
                body += f"\n\n[OCR Extracted Text from Attachments]:\n{ocr_text}"
    else:
        body = contents.decode("utf-8", errors="ignore")
        subject = file.filename or "Uploaded Text File"
        
    body = sanitize_html(body)
    if not body:
        raise HTTPException(status_code=400, detail="Email body is empty or invalid.")
        
    # 3. Analyze Attachments (Risk levels, reasons)
    attachment_analysis_list = []
    if raw_attachments:
        for att_name, att_bytes in raw_attachments:
            att_analysis = analyze_attachment(att_name, att_bytes)
            attachment_analysis_list.append(AttachmentInfo(**att_analysis))
            
    # 4. QR Code scanning inside attachments
    qr_urls = []
    if ext == ".eml" and parsed["image_attachments"]:
        for img_name, img_bytes in parsed["image_attachments"]:
            found_urls = scan_image_for_qr(img_bytes)
            qr_urls.extend(found_urls)
            
    # 5. Core ML Predict
    result = await run_in_threadpool(classifier.predict, body, sender=sender, subject=subject, attachments=attachments)
    
    # 6. Gather URL Intel (VirusTotal, WHOIS)
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body) + qr_urls
    vt_result = None
    whois_result = None
    domain = None
    
    if urls:
        first_url = urls[0]
        domain = re.sub(r'^https?://', '', first_url).split('/')[0].split(':')[0].lower()
        
        vt_task = run_in_threadpool(check_virustotal, first_url)
        whois_task = run_in_threadpool(get_whois_info, domain)
        
        vt_result_dict, whois_result_dict = await asyncio.gather(vt_task, whois_task)
        vt_result = VirusTotalResult(**vt_result_dict)
        whois_result = WhoisResult(**whois_result_dict)
        
        # Risk Score Adjustments
        if vt_result.malicious > 0:
            result["risk_score"] = min(result["risk_score"] + 25.0, 100.0)
            result["classification"] = "Phishing"
            
    # Boost risk if email auth (SPF/DKIM/DMARC) fails
    if not email_auth.is_authenticated:
        result["risk_score"] = min(result["risk_score"] + 15.0, 100.0)
        if result["classification"] == "Safe":
            result["classification"] = "Suspicious"
            
    # Boost risk if dangerous attachments are present
    has_high_risk_att = any(a.risk_level == "High" for a in attachment_analysis_list)
    if has_high_risk_att:
        result["risk_score"] = min(result["risk_score"] + 30.0, 100.0)
        result["classification"] = "Phishing"

    # 7. LLM Threat Analysis
    llm_res_dict = await run_in_threadpool(
        generate_llm_explanation, 
        body, 
        result["classification"], 
        result["detected_indicators"]
    )
    llm_analysis = LlmAnalysisResult(**llm_res_dict)
    
    # 8. Save to Database
    db_history = ScanHistory(
        user_id=current_user.id if current_user else None,
        subject=subject,
        sender=sender,
        body_preview=body[:200],
        classification=result["classification"],
        confidence_score=result["confidence_score"],
        risk_score=result["risk_score"],
        explanation=result["explanation"],
        detected_indicators=json.dumps(result["detected_indicators"]),
        
        # V2 Columns
        threat_type=llm_analysis.mitre_mappings[0].name if llm_analysis.mitre_mappings else "Phishing",
        virustotal_results=json.dumps(vt_result.dict()) if vt_result else None,
        whois_results=json.dumps(whois_result.dict()) if whois_result else None,
        email_auth_results=json.dumps(email_auth.dict()),
        attachment_analysis=json.dumps([a.dict() for a in attachment_analysis_list]),
        llm_analysis=json.dumps(llm_analysis.dict()),
        
        domain=domain,
        file_type="EML" if ext == ".eml" else "TXT"
    )
    db.add(db_history)
    db.commit()
    db.refresh(db_history)
    
    # 9. Build Final Response
    result.update({
        "id": db_history.id,
        "user_id": db_history.user_id,
        "subject": db_history.subject,
        "sender": db_history.sender,
        "created_at": db_history.created_at,
        "threat_type": db_history.threat_type,
        "virustotal_results": vt_result,
        "whois_results": whois_result,
        "email_auth_results": email_auth,
        "attachment_analysis": attachment_analysis_list,
        "llm_analysis": llm_analysis,
        "ocr_extracted_text": ocr_text if ocr_text else None
    })
    
    return result

@app.post("/api/analyze-url", response_model=UrlAnalyzeResponse)
@limiter.limit("30/minute")
async def analyze_url_endpoint(
    request: Request, 
    payload: UrlAnalyzeRequest, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    sanitized_url = validate_url(payload.url.strip())
        
    # 1. Core Heuristic Reputation Check
    result = check_url_reputation(sanitized_url)
    
    # 2. Parallel VirusTotal and WHOIS fetching
    vt_task = run_in_threadpool(check_virustotal, sanitized_url)
    whois_task = run_in_threadpool(get_whois_info, result["domain"])
    
    vt_result_dict, whois_result_dict = await asyncio.gather(vt_task, whois_task)
    vt_result = VirusTotalResult(**vt_result_dict)
    whois_result = WhoisResult(**whois_result_dict)
    
    # Boost risk score based on VirusTotal results
    if vt_result.malicious > 0:
        result["risk_score"] = min(result["risk_score"] + 30.0, 100.0)
        result["status"] = "Dangerous"
    if whois_result.is_new_domain:
        result["risk_score"] = min(result["risk_score"] + 15.0, 100.0)
        if result["status"] == "Safe":
            result["status"] = "Suspicious"
            
    db_class = "Phishing" if result["status"] == "Dangerous" else result["status"]
    
    # 3. Save to History
    db_history = ScanHistory(
        user_id=current_user.id if current_user else None,
        subject=f"URL Scan: {result['domain']}",
        sender="System URL Analyzer",
        body_preview=f"URL: {result['url']}\nThreat: {result['threat_type']}\nAdvice: {result['advice']}",
        classification=db_class,
        confidence_score=95.0,
        risk_score=result["risk_score"],
        explanation=f"Threat Type: {result['threat_type']}. {result['advice']}",
        detected_indicators=json.dumps({
            "urgent_language": False,
            "suspicious_urls": result["status"] != "Safe",
            "fake_login": any(kw in result["domain"] for kw in ["login", "signin", "secure", "verify"]),
            "password_request": False,
            "banking_scam": any(kw in result["domain"] for kw in ["chase", "bank"]),
            "financial_fraud": False,
            "crypto_scam": any(kw in result["domain"] for kw in ["coinbase", "metamask"]),
            "grammar_issues": False,
            "spoofed_sender": False,
            "dangerous_attachments": False
        }),
        threat_type=result["threat_type"],
        virustotal_results=json.dumps(vt_result.dict()),
        whois_results=json.dumps(whois_result.dict()),
        email_auth_results=json.dumps({"spf": "None", "dkim": "None", "dmarc": "None", "is_authenticated": True}),
        attachment_analysis=json.dumps([]),
        llm_analysis=json.dumps({
            "danger_explanation": result["advice"],
            "social_engineering_techniques": ["URL redirection / Obfuscation"],
            "indicators_of_compromise": [result["url"]],
            "safety_recommendations": ["Avoid entering passwords", "Verify the SSL certificate"],
            "mitre_mappings": [{"id": "T1566.002", "name": "Phishing: Spearphishing Link", "description": "Luring victims to click malicious links."}]
        }),
        domain=result["domain"],
        file_type="URL"
    )
    db.add(db_history)
    db.commit()
    db.refresh(db_history)
    
    result.update({
        "id": db_history.id,
        "created_at": db_history.created_at,
        "virustotal_results": vt_result,
        "whois_results": whois_result
    })
    
    return result

@app.get("/api/history", response_model=List[PredictResponse])
def get_history(
    limit: int = 50, 
    skip: int = 0, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    # If logged in, show user's scans. If admin, show all scans. If anonymous, show all public scans.
    query = db.query(ScanHistory)
    if current_user and current_user.role != "admin":
        query = query.filter(ScanHistory.user_id == current_user.id)
        
    history_items = query.order_by(ScanHistory.created_at.desc()).offset(skip).limit(limit).all()
    
    response = []
    for item in history_items:
        # Reconstruct JSON fields
        indicators = json.loads(item.detected_indicators)
        vt = VirusTotalResult(**json.loads(item.virustotal_results)) if item.virustotal_results else None
        whois_res = WhoisResult(**json.loads(item.whois_results)) if item.whois_results else None
        email_auth = EmailAuthResult(**json.loads(item.email_auth_results)) if item.email_auth_results else EmailAuthResult()
        attachments = [AttachmentInfo(**a) for a in json.loads(item.attachment_analysis)] if item.attachment_analysis else []
        llm = LlmAnalysisResult(**json.loads(item.llm_analysis)) if item.llm_analysis else None
        
        # Run a quick local predict to get highlighted text and keywords
        reconstructed = classifier.predict(item.body_preview, sender=item.sender, subject=item.subject)
        
        response.append(PredictResponse(
            id=item.id,
            user_id=item.user_id,
            subject=item.subject,
            sender=item.sender,
            classification=item.classification,
            confidence_score=item.confidence_score,
            risk_score=item.risk_score,
            explanation=item.explanation,
            detected_indicators=indicators,
            highlighted_text=reconstructed["highlighted_text"],
            xai_keywords=reconstructed["xai_keywords"],
            created_at=item.created_at,
            
            threat_type=item.threat_type,
            virustotal_results=vt,
            whois_results=whois_res,
            email_auth_results=email_auth,
            attachment_analysis=attachments,
            llm_analysis=llm
        ))
        
    return response

@app.get("/api/stats", response_model=StatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    # Query filters: standard users only see their own telemetry
    filter_user = ScanHistory.user_id == current_user.id if (current_user and current_user.role != "admin") else True
    
    total = db.query(ScanHistory).filter(filter_user).count()
    safe = db.query(ScanHistory).filter(filter_user, ScanHistory.classification == "Safe").count()
    suspicious = db.query(ScanHistory).filter(filter_user, ScanHistory.classification == "Suspicious").count()
    phishing = db.query(ScanHistory).filter(filter_user, ScanHistory.classification == "Phishing").count()
    
    avg_conf = 0.0
    if total > 0:
        avg_conf_query = db.query(ScanHistory).filter(filter_user).with_entities(ScanHistory.confidence_score).all()
        avg_conf = sum(c[0] for c in avg_conf_query) / total
        
    # Risk distribution
    distribution = {
        "0-20": db.query(ScanHistory).filter(filter_user, ScanHistory.risk_score <= 20).count(),
        "21-40": db.query(ScanHistory).filter(filter_user, (ScanHistory.risk_score > 20) & (ScanHistory.risk_score <= 40)).count(),
        "41-60": db.query(ScanHistory).filter(filter_user, (ScanHistory.risk_score > 40) & (ScanHistory.risk_score <= 60)).count(),
        "61-80": db.query(ScanHistory).filter(filter_user, (ScanHistory.risk_score > 60) & (ScanHistory.risk_score <= 80)).count(),
        "81-100": db.query(ScanHistory).filter(filter_user, ScanHistory.risk_score > 80).count(),
    }
    
    # 1. Daily/Weekly Scans (Last 7 days)
    daily_data = []
    for i in range(7):
        date = (datetime.datetime.utcnow() - datetime.timedelta(days=i)).date()
        count = db.query(ScanHistory).filter(
            filter_user, 
            func.date(ScanHistory.created_at) == date
        ).count()
        daily_data.append({"date": date.strftime("%b %d"), "count": count})
    daily_data.reverse()
    
    # 2. Most Impersonated Brands
    brand_counts: Dict[str, int] = {}
    brands_in_db = db.query(ScanHistory.domain).filter(filter_user, ScanHistory.classification == "Phishing", ScanHistory.domain.isnot(None)).all()
    brand_keywords = ["paypal", "chase", "netflix", "microsoft", "google", "apple", "amazon", "coinbase", "metamask", "docusign", "dhl", "fedex"]
    
    for (dom,) in brands_in_db:
        for b in brand_keywords:
            if b in dom.lower():
                brand_counts[b] = brand_counts.get(b, 0) + 1
    most_impersonated = [{"brand": k.title(), "count": v} for k, v in sorted(brand_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    # 3. Top Phishing Keywords
    keyword_counts = {
        "urgent": 0, "password": 0, "login": 0, "verify": 0, "bank": 0, "crypto": 0, "link": 0, "immediately": 0
    }
    phish_bodies = db.query(ScanHistory.body_preview).filter(filter_user, ScanHistory.classification == "Phishing").all()
    for (body,) in phish_bodies:
        for kw in keyword_counts:
            if kw in body.lower():
                keyword_counts[kw] += 1
    top_keywords = [{"word": k, "count": v} for k, v in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:5] if v > 0]

    # 4. Most Dangerous Domains
    danger_domains_query = db.query(ScanHistory.domain, func.max(ScanHistory.risk_score)).filter(
        filter_user, 
        ScanHistory.domain.isnot(None),
        ScanHistory.classification == "Phishing"
    ).group_by(ScanHistory.domain).order_by(func.max(ScanHistory.risk_score).desc()).limit(5).all()
    danger_domains = [{"domain": dom, "risk": r} for dom, r in danger_domains_query]

    # 5. Country Distribution
    countries_query = db.query(ScanHistory.country, func.count(ScanHistory.id)).filter(
        filter_user, 
        ScanHistory.country.isnot(None)
    ).group_by(ScanHistory.country).all()
    country_distribution = {c or "Unknown": count for c, count in countries_query}
    
    # 6. File Type Distribution
    file_types_query = db.query(ScanHistory.file_type, func.count(ScanHistory.id)).filter(filter_user).group_by(ScanHistory.file_type).all()
    file_type_distribution = {ft or "TXT": count for ft, count in file_types_query}

    # 7. Recent Scans
    recent_items = db.query(ScanHistory).filter(filter_user).order_by(ScanHistory.created_at.desc()).limit(5).all()
    recent_scans = []
    for item in recent_items:
        indicators = json.loads(item.detected_indicators)
        recent_scans.append(PredictResponse(
            id=item.id,
            user_id=item.user_id,
            subject=item.subject,
            sender=item.sender,
            classification=item.classification,
            confidence_score=item.confidence_score,
            risk_score=item.risk_score,
            explanation=item.explanation,
            detected_indicators=indicators,
            highlighted_text="",
            xai_keywords=[],
            created_at=item.created_at,
            threat_type=item.threat_type
        ))
        
    return StatsResponse(
        total_scans=total,
        safe_count=safe,
        suspicious_count=suspicious,
        phishing_count=phishing,
        average_confidence=round(avg_conf, 1),
        risk_distribution=distribution,
        daily_scans=daily_data,
        weekly_scans=[], # Placeholder/unused for graph
        most_impersonated_brands=most_impersonated,
        top_phishing_keywords=top_keywords,
        most_dangerous_domains=danger_domains,
        country_distribution=country_distribution,
        file_type_distribution=file_type_distribution,
        recent_scans=recent_scans
    )

print("API started successfully")

# --- Browser Extension Download Route ---

@app.get("/api/extension/download")
def download_extension():
    """Returns the packaged browser extension as a ZIP file."""
    try:
        zip_data = get_extension_zip_bytes()
        return Response(
            content=zip_data,
            media_type="application/zip",
            headers={
                "Content-Disposition": "attachment; filename=ai_phishing_detector_extension.zip"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to package extension: {e}")

# --- Serve Built Frontend in Production ---
from fastapi.staticfiles import StaticFiles

frontend_dist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "dist")
if os.path.exists(frontend_dist_path):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist_path, "assets")), name="assets")
    
    @app.get("/{full_path:path}", response_class=HTMLResponse)
    async def serve_frontend(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            raise HTTPException(status_code=404, detail="Not Found")
        index_file = os.path.join(frontend_dist_path, "index.html")
        if os.path.exists(index_file):
            with open(index_file, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="Frontend build index.html not found.", status_code=404)

from pydantic import BaseModel, Field, EmailStr
from typing import List, Dict, Optional, Any
from datetime import datetime

# --- User & Auth Schemas ---

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class TokenData(BaseModel):
    email: Optional[str] = None

# --- Threat Intelligence Sub-Schemas ---

class VirusTotalResult(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    reputation: int = 0
    community_votes_harmless: int = 0
    community_votes_malicious: int = 0
    raw_response: Optional[str] = None

class WhoisResult(BaseModel):
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = "Unknown"
    registration_date: Optional[str] = "Unknown"
    expiration_date: Optional[str] = "Unknown"
    updated_date: Optional[str] = "Unknown"
    country: Optional[str] = "Unknown"
    name_servers: Optional[str] = "Unknown"
    is_new_domain: bool = False

class DnsResult(BaseModel):
    ip_address: Optional[str] = "Unknown"
    a_records: List[str] = []
    aaaa_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []
    ns_records: List[str] = []
    cname_records: List[str] = []

class SslResult(BaseModel):
    has_ssl: bool = False
    issuer: Optional[str] = "Unknown"
    subject: Optional[str] = "Unknown"
    valid_from: Optional[str] = "Unknown"
    valid_to: Optional[str] = "Unknown"
    signature_algorithm: Optional[str] = "Unknown"
    is_expired: bool = True
    days_remaining: int = 0
    is_self_signed: bool = False

class EmailAuthResult(BaseModel):
    spf: str = "None"      # "Pass", "Fail", "None", "Neutral"
    dkim: str = "None"     # "Pass", "Fail", "None"
    dmarc: str = "None"    # "Pass", "Fail", "None"
    is_authenticated: bool = True

class AttachmentInfo(BaseModel):
    filename: str
    risk_level: str        # "Low", "Medium", "High"
    reason: str
    action: str

class MitreMapping(BaseModel):
    id: str                # e.g. "T1566"
    name: str              # e.g. "Phishing"
    description: str

class LlmAnalysisResult(BaseModel):
    danger_explanation: str
    social_engineering_techniques: List[str]
    indicators_of_compromise: List[str]
    safety_recommendations: List[str]
    mitre_mappings: List[MitreMapping]

# --- Main API Responses ---

class EmailPredictRequest(BaseModel):
    text: str = Field(..., min_length=1, description="The raw email body text to analyze")

class KeywordImportance(BaseModel):
    word: str
    weight: float
    type: str  # "danger" or "safe"

class PredictResponse(BaseModel):
    id: Optional[int] = None
    user_id: Optional[int] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    classification: str  # "Safe", "Suspicious", "Phishing"
    confidence_score: float
    risk_score: float
    explanation: str
    detected_indicators: Dict[str, Any]
    highlighted_text: str
    xai_keywords: List[KeywordImportance] = []
    created_at: Optional[datetime] = None
    
    # V2 Upgrades
    threat_type: Optional[str] = "Unknown"
    virustotal_results: Optional[VirusTotalResult] = None
    whois_results: Optional[WhoisResult] = None
    dns_results: Optional[DnsResult] = None
    ssl_results: Optional[SslResult] = None
    email_auth_results: Optional[EmailAuthResult] = None
    attachment_analysis: List[AttachmentInfo] = []
    llm_analysis: Optional[LlmAnalysisResult] = None
    
    # OCR Preview (Extracted text if scanned)
    ocr_extracted_text: Optional[str] = None

    class Config:
        from_attributes = True

class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, description="The URL to analyze for security threats")

class UrlAnalyzeResponse(BaseModel):
    id: Optional[int] = None
    url: str
    domain: str
    risk_score: float
    status: str  # "Safe", "Suspicious", "Dangerous"
    reasons: List[str]
    threat_type: str
    advice: str
    created_at: Optional[datetime] = None
    
    # V2 Upgrades
    virustotal_results: Optional[VirusTotalResult] = None
    whois_results: Optional[WhoisResult] = None
    dns_results: Optional[DnsResult] = None
    ssl_results: Optional[SslResult] = None

class StatsResponse(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    average_confidence: float
    risk_distribution: Dict[str, int]
    
    # V2 Threat Intel Advanced Metrics
    daily_scans: List[Dict[str, Any]]              # e.g., [{"date": "2026-06-29", "count": 10}]
    weekly_scans: List[Dict[str, Any]]
    most_impersonated_brands: List[Dict[str, Any]] # e.g., [{"brand": "paypal", "count": 4}]
    top_phishing_keywords: List[Dict[str, Any]]    # e.g., [{"word": "urgent", "count": 15}]
    most_dangerous_domains: List[Dict[str, Any]]   # e.g., [{"domain": "netflix-update.com", "risk": 95}]
    country_distribution: Dict[str, int]
    file_type_distribution: Dict[str, int]         # e.g., {"EML": 12, "TXT": 8, "URL": 20}
    
    recent_scans: List[PredictResponse]

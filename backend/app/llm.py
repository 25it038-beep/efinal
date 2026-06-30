import os
import json
import re
import requests
from typing import Dict, Any, List

# MITRE ATT&CK Reference Database (Common Phishing-related Techniques)
MITRE_DB = {
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "description": "Adversaries send spearphishing emails containing malicious links to lure victims into clicking them, leading to credential harvesting or malware execution."
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "description": "Adversaries send spearphishing emails containing malicious attachments (e.g., zip, pdf, docm) designed to execute code when opened by the user."
    },
    "T1566.003": {
        "name": "Phishing: Spearphishing Service",
        "description": "Adversaries use third-party services (e.g., social media, webmail, chat apps) to send phishing links or attachments to targets."
    },
    "T1114": {
        "name": "Email Collection",
        "description": "Adversaries target user emails to collect sensitive business intelligence, credentials, or contacts for subsequent campaigns."
    },
    "T1204.001": {
        "name": "User Execution: Malicious Link",
        "description": "Adversaries rely on a user clicking a malicious link within an email to execute code, download malware, or visit a credential harvesting portal."
    },
    "T1204.002": {
        "name": "User Execution: Malicious Attachment",
        "description": "Adversaries rely on a user opening a malicious attachment to trigger exploit code or macro execution."
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "description": "Adversaries capture session cookies to bypass Multi-Factor Authentication (MFA) and hijack active login sessions."
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Adversaries use compromised credentials harvested via phishing to log into legitimate services, bypassing perimeter security."
    }
}

def generate_local_analysis(email_text: str, classification: str, indicators: Dict[str, bool]) -> Dict[str, Any]:
    """
    Highly sophisticated local expert system that generates a detailed, 
    structured security report matching the LLM schema.
    """
    text_lower = email_text.lower()
    
    # 1. Determine Social Engineering Techniques
    social_techniques = []
    if indicators.get("urgent_language"):
        social_techniques.append("Urgency & Coercion: Creating a false sense of time-pressure (e.g., 'suspend in 24 hours') to bypass rational thinking.")
    if indicators.get("fake_login") or indicators.get("password_request"):
        social_techniques.append("Authority & Impersonation: Mimicking trusted service portals (Microsoft, PayPal) to exploit user trust.")
    if indicators.get("banking_scam") or indicators.get("financial_fraud"):
        social_techniques.append("Financial Greed/Fear: Using monetary rewards (tax refunds, wire transfers) or financial loss threats to prompt action.")
    if indicators.get("crypto_scam"):
        social_techniques.append("FOMO (Fear Of Missing Out): Leveraging cryptocurrency hype, smart contract upgrades, or wallet restriction threats to steal seed phrases.")
    if not social_techniques:
        social_techniques.append("Pretexting: Presenting a fabricated scenario (like a routine meeting or document share) to establish trust before executing an exploit.")

    # 2. Extract Indicators of Compromise (IOCs)
    iocs = []
    # Extract URLs
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    for url in urls:
        domain = url.split("//")[-1].split("/")[0]
        iocs.append(f"Suspicious URL: {url}")
        iocs.append(f"Malicious Domain: {domain}")
    # Extract Email Addresses if present in text
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email_text)
    for email in emails:
        iocs.append(f"Sender/Target Email: {email}")
        
    iocs = list(set(iocs))[:6] # Limit to top 6
    if not iocs:
        iocs.append("No specific external network indicators detected.")

    # 3. Formulate MITRE ATT&CK Mappings
    mitre_mappings = []
    
    # Default Phishing mapping
    if indicators.get("dangerous_attachments"):
        mitre_mappings.append({
            "id": "T1566.001",
            "name": MITRE_DB["T1566.001"]["name"],
            "description": MITRE_DB["T1566.001"]["description"]
        })
        mitre_mappings.append({
            "id": "T1204.002",
            "name": MITRE_DB["T1204.002"]["name"],
            "description": MITRE_DB["T1204.002"]["description"]
        })
    else:
        # Default to link phishing if URLs found
        if urls:
            mitre_mappings.append({
                "id": "T1566.002",
                "name": MITRE_DB["T1566.002"]["name"],
                "description": MITRE_DB["T1566.002"]["description"]
            })
            mitre_mappings.append({
                "id": "T1204.001",
                "name": MITRE_DB["T1204.001"]["name"],
                "description": MITRE_DB["T1204.001"]["description"]
            })
        else:
            # General phishing
            mitre_mappings.append({
                "id": "T1566.003",
                "name": MITRE_DB["T1566.003"]["name"],
                "description": MITRE_DB["T1566.003"]["description"]
            })

    if indicators.get("fake_login") or indicators.get("password_request"):
        mitre_mappings.append({
            "id": "T1114",
            "name": MITRE_DB["T1114"]["name"],
            "description": MITRE_DB["T1114"]["description"]
        })
        mitre_mappings.append({
            "id": "T1078",
            "name": MITRE_DB["T1078"]["name"],
            "description": MITRE_DB["T1078"]["description"]
        })

    # 4. Safety Recommendations
    recommendations = [
        "DO NOT click on any links, scan QR codes, or download attachments from this email.",
        "Verify the sender's identity through an alternative, trusted channel (e.g., call them or visit the official website manually).",
        "Report this email to your organization's security operations center (SOC) or IT department."
    ]
    if indicators.get("password_request"):
        recommendations.append("If you entered your password, change it immediately on the official service portal and enable Multi-Factor Authentication (MFA).")
    if indicators.get("banking_scam") or indicators.get("financial_fraud"):
        recommendations.append("If you provided banking details or credit card numbers, contact your financial institution immediately to freeze your accounts.")

    # 5. Explanations
    if classification == "Phishing":
        danger_explanation = (
            "This email represents a critical threat. The sender is attempting to deceive you into "
            "taking action that will compromise your credentials or financial accounts. The language "
            "exhibits classic social engineering triggers designed to bypass security awareness."
        )
    elif classification == "Suspicious":
        danger_explanation = (
            "This email exhibits several anomalies (e.g. urgent tone, generic domains, or unverified links) "
            "that are highly characteristic of phishing campaigns. While not definitively confirmed, it should "
            "be treated with extreme caution."
        )
    else:
        danger_explanation = (
            "No significant threats were detected. The email appears to be normal correspondence. "
            "Always maintain basic security vigilance."
        )

    return {
        "danger_explanation": danger_explanation,
        "social_engineering_techniques": social_techniques,
        "indicators_of_compromise": iocs,
        "safety_recommendations": recommendations,
        "mitre_mappings": mitre_mappings
    }

def generate_llm_explanation(email_text: str, classification: str, indicators: Dict[str, bool]) -> Dict[str, Any]:
    """
    Attempts to call Google Gemini or OpenAI to perform threat analysis.
    Falls back to a highly detailed local rule-based generator if no keys are found.
    """
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    prompt = f"""
    You are an expert Cybersecurity Incident Responder. Analyze this email and classify it.
    Email Text:
    ---
    {email_text}
    ---
    Threat Classification: {classification}
    Triggered Indicators: {json.dumps([k for k, v in indicators.items() if v])}

    Provide a detailed security analysis in JSON format matching this schema:
    {{
        "danger_explanation": "A detailed paragraph explaining why this email is dangerous.",
        "social_engineering_techniques": ["Technique 1 with description", "Technique 2 with description"],
        "indicators_of_compromise": ["IOC 1 (URL/Domain/IP)", "IOC 2"],
        "safety_recommendations": ["Recommendation 1", "Recommendation 2"],
        "mitre_mappings": [
            {{
                "id": "MITRE ATT&CK ID (e.g. T1566.002)",
                "name": "Technique Name",
                "description": "Short description of how it applies here."
            }}
        ]
    }}
    Do not output any markdown formatting outside of the JSON. Return raw JSON only.
    """

    # 1. Try Gemini API (Free, fast, direct HTTP call)
    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json"
                }
            }
            response = requests.post(url, headers=headers, json=payload, timeout=8)
            if response.status_code == 200:
                res_data = response.json()
                text_response = res_data["candidates"][0]["content"]["parts"][0]["text"]
                # Clean up any potential markdown wrap
                text_response = re.sub(r'^```json\s*|```$', '', text_response.strip(), flags=re.MULTILINE)
                return json.loads(text_response)
        except Exception as e:
            print(f"Gemini API call failed: {e}. Falling back to local analysis.")

    # 2. Try OpenAI API
    if openai_key:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {openai_key}"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a helpful cybersecurity assistant that outputs structured JSON."},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2
            }
            response = requests.post(url, headers=headers, json=payload, timeout=8)
            if response.status_code == 200:
                res_data = response.json()
                text_response = res_data["choices"][0]["message"]["content"]
                return json.loads(text_response)
        except Exception as e:
            print(f"OpenAI API call failed: {e}. Falling back to local analysis.")

    # 3. Fallback to Local Expert System
    return generate_local_analysis(email_text, classification, indicators)


def generate_local_url_analysis(
    url: str,
    domain: str,
    classification: str,
    risk_score: float,
    lexical_results: Dict[str, Any],
    whois_results: Dict[str, Any],
    dns_results: Dict[str, Any],
    ssl_results: Dict[str, Any],
    virustotal_results: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Deterministic rule-based backup to generate the structured URL threat report.
    """
    techniques = [f"Risk Level: {classification}"]
    
    # Identify legitimate indicators
    leg_ind = []
    if ssl_results.get("has_ssl") and not ssl_results.get("is_expired"):
        leg_ind.append(f"Valid SSL Certificate (Issuer: {ssl_results.get('issuer')})")
    if whois_results.get("domain_age_days", 0) and whois_results["domain_age_days"] > 365:
        leg_ind.append(f"Established Domain Age ({whois_results['domain_age_days']} days)")
    if dns_results.get("mx_records"):
        leg_ind.append("Configured Mail Servers (MX records present)")
        
    if leg_ind:
        techniques.append(f"Legitimate Indicators: {', '.join(leg_ind)}")
    else:
        techniques.append("Legitimate Indicators: None detected")
        
    recommendations = []
    iocs = [url]
    if dns_results.get("ip_address") and dns_results["ip_address"] != "Unknown":
        iocs.append(f"IP: {dns_results['ip_address']}")
        
    if classification == "Dangerous":
        exec_summary = f"This URL is classified as Dangerous with a critical risk score of {risk_score}/100. It exhibits multiple high-risk indicators commonly associated with active phishing or credential theft campaigns."
        tech_explanation = (
            f"Technical Analysis:\n"
            f"- Reputation: VirusTotal flagged this domain with {virustotal_results.get('malicious', 0)} malicious reports.\n"
            f"- SSL Status: {'Missing or invalid SSL certificate' if not ssl_results.get('has_ssl') else 'Certificate is expired or self-signed' if ssl_results.get('is_expired') else 'Valid SSL certificate present'}.\n"
            f"- Domain Age: Registered domain is {whois_results.get('domain_age_days', 'Unknown')} days old (Registrar: {whois_results.get('registrar')}).\n"
            f"- DNS Status: Resolved to IP {dns_results.get('ip_address')}. Mail servers: {'Configured' if dns_results.get('mx_records') else 'None'}.\n"
            f"- Lexical Checks: {', '.join(lexical_results.get('reasons', [])) or 'No lexical anomalies'}."
        )
        recommendations.extend([
            "DO NOT enter any credentials, passwords, or personal details on this page.",
            "Close the browser tab immediately.",
            "Report this URL to your organization's IT Security Team."
        ])
    elif classification == "Suspicious":
        exec_summary = f"This URL is classified as Suspicious ({risk_score}/100). It exhibits some anomalies that do not align with trusted business domains."
        tech_explanation = (
            f"Technical Analysis:\n"
            f"- SSL Status: {'No SSL encryption (HTTP)' if not ssl_results.get('has_ssl') else 'SSL present but has warnings' if ssl_results.get('is_expired') else 'Valid SSL present'}.\n"
            f"- Domain Age: {whois_results.get('domain_age_days', 'Unknown')} days.\n"
            f"- DNS Status: Resolved to IP {dns_results.get('ip_address')}.\n"
            f"- Lexical Checks: {', '.join(lexical_results.get('reasons', [])) or 'No lexical anomalies'}."
        )
        recommendations.extend([
            "Avoid entering sensitive information or credentials.",
            "Inspect the address bar carefully to ensure it is not a typosquatted domain.",
            "Verify the source that sent you this URL."
        ])
    else:
        exec_summary = f"This URL is classified as Safe ({risk_score}/100). No significant threats or phishing indicators were detected."
        tech_explanation = (
            f"Technical Analysis:\n"
            f"- SSL Status: Secured via valid SSL certificate (Issuer: {ssl_results.get('issuer')}).\n"
            f"- Domain Age: Established domain ({whois_results.get('domain_age_days', 'Unknown')} days old).\n"
            f"- DNS Status: Resolved to IP {dns_results.get('ip_address')} with valid Name Servers."
        )
        recommendations.append("Always verify the address bar before entering sensitive information.")

    danger_explanation = f"### Executive Summary\n{exec_summary}\n\n### Technical Explanation\n{tech_explanation}"
    
    return {
        "danger_explanation": danger_explanation,
        "social_engineering_techniques": techniques,
        "indicators_of_compromise": iocs,
        "safety_recommendations": recommendations,
        "mitre_mappings": [{"id": "T1566.002", "name": "Phishing: Spearphishing Link", "description": "Luring victims to click malicious links."}]
    }


def generate_url_llm_explanation(
    url: str,
    domain: str,
    classification: str,
    risk_score: float,
    lexical_results: Dict[str, Any],
    whois_results: Dict[str, Any],
    dns_results: Dict[str, Any],
    ssl_results: Dict[str, Any],
    virustotal_results: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generates a highly structured threat explanation using Gemini or OpenAI.
    Falls back to deterministic local rules if API keys are missing.
    """
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    prompt = f"""
    You are an expert Cybersecurity Threat Analyst. Analyze the collected features of the URL and classify it.
    
    URL: {url}
    Domain: {domain}
    Threat Classification: {classification}
    Overall Risk Score: {risk_score}/100
    
    Collected Technical Features:
    - Lexical Analysis: {json.dumps(lexical_results.get('reasons', []))}
    - WHOIS: Registrar: {whois_results.get('registrar')}, Age: {whois_results.get('domain_age_days')} days, Country: {whois_results.get('country')}, New Domain: {whois_results.get('is_new_domain')}
    - DNS: Resolved IP: {dns_results.get('ip_address')}, MX Records: {json.dumps(dns_results.get('mx_records', []))}, NS Records: {json.dumps(dns_results.get('ns_records', []))}, CNAME: {json.dumps(dns_results.get('cname_records', []))}
    - SSL: Has SSL: {ssl_results.get('has_ssl')}, Issuer: {ssl_results.get('issuer')}, Subject: {ssl_results.get('subject')}, Valid To: {ssl_results.get('valid_to')}, Expired: {ssl_results.get('is_expired')}, Days Remaining: {ssl_results.get('days_remaining')}, Self-Signed: {ssl_results.get('is_self_signed')}
    - Reputation: VirusTotal Malicious: {virustotal_results.get('malicious', 0)}, Harmless: {virustotal_results.get('harmless', 0)}

    Provide a detailed security analysis in JSON format matching this schema:
    {{
        "danger_explanation": "### Executive Summary\\n[Provide a clear executive summary paragraph]\\n\\n### Technical Explanation\\n[Provide a detailed paragraph explaining the technical reasons based on WHOIS, DNS, SSL, and Reputation]",
        "social_engineering_techniques": [
            "Risk Level: [Safe | Suspicious | Dangerous]",
            "Legitimate Indicators: [List any positive/legitimate indicators like valid SSL, old domain, etc.]",
            "[Any other social engineering/luring techniques observed]"
        ],
        "indicators_of_compromise": ["[List all indicators of compromise found, e.g. malicious URLs, IPs, domains]"],
        "safety_recommendations": ["[List recommended actions for the user]"],
        "mitre_mappings": [
            {{
                "id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "description": "Adversaries send spearphishing emails containing malicious links to lure victims."
            }}
        ]
    }}
    Do not output any markdown formatting outside of the JSON. Return raw JSON only.
    """

    # 1. Try Gemini
    if gemini_key:
        try:
            url_api = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json"
                }
            }
            response = requests.post(url_api, headers=headers, json=payload, timeout=8)
            if response.status_code == 200:
                res_data = response.json()
                text_response = res_data["candidates"][0]["content"]["parts"][0]["text"]
                text_response = re.sub(r'^```json\s*|```$', '', text_response.strip(), flags=re.MULTILINE)
                return json.loads(text_response)
        except Exception as e:
            print(f"Gemini URL API call failed: {e}. Falling back to local analysis.")

    # 2. Try OpenAI
    if openai_key:
        try:
            url_api = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {openai_key}"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are a helpful cybersecurity assistant that outputs structured JSON."},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2
            }
            response = requests.post(url_api, headers=headers, json=payload, timeout=8)
            if response.status_code == 200:
                res_data = response.json()
                text_response = res_data["choices"][0]["message"]["content"]
                return json.loads(text_response)
        except Exception as e:
            print(f"OpenAI URL API call failed: {e}. Falling back to local analysis.")

    # 3. Fallback to Local Rule-based analysis
    return generate_local_url_analysis(
        url, domain, classification, risk_score,
        lexical_results, whois_results, dns_results, ssl_results, virustotal_results
    )

import os
import re
import html
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
import joblib
import numpy as np
from typing import Dict, List, Any, Tuple
from .indicators import analyze_indicators

# Ensure NLTK resources are downloaded
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)

# File paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.getenv("MODEL_PATH") or os.path.join(BASE_DIR, "models", "model.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH") or os.path.join(BASE_DIR, "models", "vectorizer.pkl")

# Preprocessing function (must match train.py)
def preprocess_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'^(subject|from|to|cc|date):\s*', '', text, flags=re.IGNORECASE)
    text = re.sub(r'https?://\S+|www\.\S+', 'httpurl', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    
    words = text.split()
    stop_words = set(stopwords.words('english'))
    stemmer = PorterStemmer()
    cleaned_words = [stemmer.stem(word) for word in words if word not in stop_words]
    return " ".join(cleaned_words)

class PhishingClassifier:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.load_model()
        
    def load_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.vectorizer = joblib.load(VECTORIZER_PATH)
                print("✓ Model loaded")
                print("✓ Vectorizer loaded")
            except Exception as e:
                print(f"⚠ Model load failed: {e}. Falling back to rule-based analysis.")
        else:
            print("⚠ Model files missing. Falling back to rule-based analysis.")

    def get_fallback_prediction(self, indicators: Dict[str, Any]) -> Tuple[str, float, float]:
        """Fallback rule-based classification if ML model is not loaded."""
        triggered_count = sum(1 for k, v in indicators.items() if v["triggered"])
        
        # Determine class
        if indicators["password_request"]["triggered"] or indicators["banking_scam"]["triggered"] or indicators["crypto_scam"]["triggered"]:
            classification = "Phishing"
            confidence = 80.0 + (triggered_count * 4.0)
            risk_score = 75.0 + (triggered_count * 5.0)
        elif triggered_count >= 3:
            classification = "Phishing"
            confidence = 70.0 + (triggered_count * 5.0)
            risk_score = 65.0 + (triggered_count * 6.0)
        elif triggered_count >= 1:
            classification = "Suspicious"
            confidence = 60.0 + (triggered_count * 8.0)
            risk_score = 35.0 + (triggered_count * 10.0)
        else:
            classification = "Safe"
            confidence = 90.0
            risk_score = 10.0
            
        confidence = min(confidence, 99.0)
        risk_score = min(risk_score, 100.0)
        
        return classification, confidence, risk_score

    def predict(self, text: str, sender: str = "", subject: str = "", attachments: List[str] = None) -> Dict[str, Any]:
        # Clean text for HTML rendering and extract indicators
        clean_display_text = html.escape(text)
        indicators = analyze_indicators(text, sender, subject, attachments)
        
        classification = "Safe"
        confidence = 0.0
        risk_score = 0.0
        xai_keywords = []
        explanation_parts = []
        
        # Use ML Model if available
        if self.model is not None and self.vectorizer is not None:
            cleaned_text = preprocess_text(text)
            vec_text = self.vectorizer.transform([cleaned_text])
            
            # Predict probabilities
            probs = self.model.predict_proba(vec_text)[0]  # [prob_safe, prob_suspicious, prob_phishing]
            pred_class_idx = np.argmax(probs)
            
            classes = ["Safe", "Suspicious", "Phishing"]
            classification = classes[pred_class_idx]
            confidence = float(probs[pred_class_idx] * 100)
            
            # Base risk score calculation based on probabilities
            # Phishing prob contributes heavily to risk, Suspicious moderately
            risk_score = float((probs[2] * 100) + (probs[1] * 45))
            
            # Adjust risk score based on critical heuristic indicators
            critical_indicators = ["suspicious_urls", "password_request", "banking_scam", "crypto_scam", "dangerous_attachments", "spoofed_sender"]
            triggered_critical = [ind for ind in critical_indicators if indicators[ind]["triggered"]]
            
            if triggered_critical:
                # Boost risk if critical indicators are triggered, even if ML missed it
                risk_score += len(triggered_critical) * 12.0
                if classification == "Safe" and len(triggered_critical) >= 2:
                    classification = "Suspicious"
            
            risk_score = min(max(risk_score, 0.0), 100.0)
            
            # Explainable AI (XAI) - Extract word importances
            feature_names = self.vectorizer.get_feature_names_out()
            coefficients = self.model.coef_  # shape: (3, n_features)
            
            # Get words that actually appear in this email after preprocessing
            stemmer = PorterStemmer()
            stop_words = set(stopwords.words('english'))
            
            # Map of original word -> stemmed word
            words_in_email = {}
            for word in re.findall(r'\b[a-zA-Z]+\b', text.lower()):
                if word not in stop_words:
                    stemmed = stemmer.stem(word)
                    words_in_email[word] = stemmed
            
            # Find coefficients for words in the email
            word_weights = []
            seen_stems = set()
            
            for orig_word, stemmed in words_in_email.items():
                if stemmed in seen_stems:
                    continue
                
                # Find if the stemmed word (or bigram) is in our vocabulary
                if stemmed in self.vectorizer.vocabulary_:
                    vocab_idx = self.vectorizer.vocabulary_[stemmed]
                    
                    # We look at the coefficient for Phishing (idx 2) or Suspicious (idx 1)
                    # depending on which is higher, or just Phishing vs Safe.
                    phish_coef = coefficients[2][vocab_idx]
                    safe_coef = coefficients[0][vocab_idx]
                    susp_coef = coefficients[1][vocab_idx]
                    
                    # Weight contribution: TF-IDF value * coefficient
                    tfidf_val = vec_text[0, vocab_idx]
                    
                    if phish_coef > 0.1:
                        word_weights.append({
                            "word": orig_word,
                            "weight": float(phish_coef * tfidf_val * 10),
                            "type": "danger"
                        })
                        seen_stems.add(stemmed)
                    elif safe_coef > 0.1:
                        word_weights.append({
                            "word": orig_word,
                            "weight": float(safe_coef * tfidf_val * 10),
                            "type": "safe"
                        })
                        seen_stems.add(stemmed)
            
            # Sort weights by absolute value
            word_weights.sort(key=lambda x: abs(x["weight"]), reverse=True)
            xai_keywords = word_weights[:10]  # Top 10 words
            
        else:
            # Fallback to rule-based if ML not loaded
            classification, confidence, risk_score = self.get_fallback_prediction(indicators)
            
            # Simple XAI keywords based on regex matches
            danger_words = ["urgent", "action required", "immediate", "suspended", "password", "bank", "routing", "ssn", "bitcoin", "metamask", "gift card"]
            for word in danger_words:
                if word in text.lower():
                    xai_keywords.append({
                        "word": word,
                        "weight": 5.0,
                        "type": "danger"
                    })
        
        # Highlight dangerous words in HTML
        highlighted_text = clean_display_text
        danger_words_to_highlight = set()
        
        # Collect words from triggered indicators and XAI keywords
        for kw in xai_keywords:
            if kw["type"] == "danger" and len(kw["word"]) > 2:
                danger_words_to_highlight.add(kw["word"])
                
        # Add common phishing terms to highlight list if they exist in text
        phish_triggers = ["urgent", "suspend", "block", "verify", "password", "login", "signin", "bank", "routing", "ssn", "wire", "gift card", "bitcoin", "ethereum", "wallet", "seed phrase"]
        for trigger in phish_triggers:
            if trigger in text.lower():
                # Find the actual case-preserved word in the text
                matches = re.findall(rf'\b{trigger}\w*\b', text, re.IGNORECASE)
                for match in matches:
                    danger_words_to_highlight.add(match)
        
        # Replace words in the HTML text with a highlighted span
        # Sort by length descending so we don't replace parts of longer words first
        sorted_highlights = sorted(list(danger_words_to_highlight), key=len, reverse=True)
        for word in sorted_highlights:
            escaped_word = html.escape(word)
            # Use regex to replace only whole words, ignoring case
            pattern = re.compile(rf'\b{re.escape(escaped_word)}\b', re.IGNORECASE)
            highlighted_text = pattern.sub(f'<span class="bg-red-500/20 text-red-400 border border-red-500/30 px-1 rounded font-semibold animate-pulse">{escaped_word}</span>', highlighted_text)
            
        # Formulate Explanation
        triggered_names = [k.replace('_', ' ').title() for k, v in indicators.items() if v["triggered"]]
        
        if classification == "Phishing":
            explanation_parts.append(f"This email has been classified as **Phishing** with a risk score of **{risk_score:.1f}/100**.")
            if triggered_names:
                explanation_parts.append(f"Key threat indicators detected: **{', '.join(triggered_names)}**.")
            if xai_keywords:
                danger_kws = [k["word"] for k in xai_keywords if k["type"] == "danger"]
                if danger_kws:
                    explanation_parts.append(f"High-risk keywords such as **{', '.join(danger_kws[:4])}** contributed significantly to this warning.")
            explanation_parts.append("We strongly advise **against** clicking any links, opening attachments, or replying to this sender.")
            
        elif classification == "Suspicious":
            explanation_parts.append(f"This email has been classified as **Suspicious** with a risk score of **{risk_score:.1f}/100**.")
            if triggered_names:
                explanation_parts.append(f"It contains indicators of concern: **{', '.join(triggered_names)}**.")
            explanation_parts.append("Exercise caution. Verify the sender's identity through an alternative channel before taking action.")
            
        else:
            explanation_parts.append(f"This email appears to be **Safe** (Risk score: **{risk_score:.1f}/100**).")
            explanation_parts.append("No major phishing indicators were detected, and the language pattern matches normal, non-threatening correspondence.")
            
        explanation = " ".join(explanation_parts)
        
        return {
            "classification": classification,
            "confidence_score": round(confidence, 1),
            "risk_score": round(risk_score, 1),
            "explanation": explanation,
            "detected_indicators": {k: v["triggered"] for k, v in indicators.items()},
            "highlighted_text": highlighted_text,
            "xai_keywords": xai_keywords
        }

import re
import math
import os
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import joblib

from app.schemas.analysis import EvidenceItem, AnalysisResponse
from app.services.risk_engine import risk_engine
from app.services.explanation_engine import explanation_engine

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../../ml/models/phishing_model.joblib")

SUSPICIOUS_KEYWORDS = [
    "verify", "account", "login", "signin", "banking", "secure", "update",
    "password", "auth", "confirm", "billing", "suspended", "token", "service",
    "security", "support", "chase", "paypal", "microsoft", "apple", "google"
]

class PhishingService:
    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def extract_url_features(self, url: str) -> Tuple[Dict[str, Any], List[EvidenceItem]]:
        evidence: List[EvidenceItem] = []
        parsed = urlparse(url if "://" in url else f"http://{url}")
        
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        url_len = len(url)
        domain_len = len(hostname)
        has_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0
        has_https = 1 if parsed.scheme == "https" else 0
        has_at = 1 if "@" in url else 0
        has_double_slash = 1 if "//" in path else 0
        subdomain_count = max(0, len(hostname.split(".")) - 2)
        hyphen_count = hostname.count("-")
        digit_count = sum(c.isdigit() for c in url)
        special_char_count = sum(not c.isalnum() and c not in [":", "/", "."] for c in url)
        
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
        has_suspicious_keyword = len(matched_keywords)
        entropy = round(self.calculate_entropy(hostname), 2)

        # Build evidence indicators
        if has_ip:
            evidence.append(EvidenceItem(
                indicator="ip_address_host",
                description=f"Direct IP address ({hostname}) used as host instead of legitimate domain",
                weight=18
            ))
            
        if hyphen_count >= 2:
            evidence.append(EvidenceItem(
                indicator="domain_hyphen_spoofing",
                description=f"Hostname contains {hyphen_count} hyphens, commonly used in typosquatting / brand spoofing",
                weight=12
            ))
            
        if subdomain_count >= 2:
            evidence.append(EvidenceItem(
                indicator="excessive_subdomains",
                description=f"Found {subdomain_count} nested subdomains obscuring actual top-level destination",
                weight=10
            ))
            
        if matched_keywords:
            evidence.append(EvidenceItem(
                indicator="credential_harvesting_keywords",
                description=f"Target URL contains high-risk authentication keywords: {', '.join(matched_keywords[:4])}",
                weight=14
            ))
            
        if not has_https:
            evidence.append(EvidenceItem(
                indicator="insecure_transport_http",
                description="Plain HTTP transport without TLS/SSL encryption for sensitive endpoint",
                weight=8
            ))

        if url_len > 75:
            evidence.append(EvidenceItem(
                indicator="abnormal_url_length",
                description=f"Abnormally long URL string ({url_len} characters) hiding tracking tokens or redirects",
                weight=8
            ))

        if entropy > 3.8:
            evidence.append(EvidenceItem(
                indicator="high_entropy_domain",
                description=f"High domain randomness/entropy ({entropy}), typical of Domain Generation Algorithms (DGA)",
                weight=10
            ))

        features = {
            "url_length": url_len,
            "domain_length": domain_len,
            "has_ip": has_ip,
            "has_https": has_https,
            "has_at_symbol": has_at,
            "has_double_slash": has_double_slash,
            "subdomain_count": subdomain_count,
            "hyphen_count": hyphen_count,
            "digit_count": digit_count,
            "special_character_count": special_char_count,
            "suspicious_keywords_count": has_suspicious_keyword,
            "entropy": entropy
        }

        return features, evidence

    def analyze_url(self, url: str) -> AnalysisResponse:
        features, evidence = self.extract_url_features(url)
        
        # Calculate ML probability
        if self.model is not None:
            # Model inference when trained
            try:
                feature_vals = [list(features.values())]
                proba = float(self.model.predict_proba(feature_vals)[0][1])
            except Exception:
                proba = self._heuristic_probability(features, evidence)
        else:
            proba = self._heuristic_probability(features, evidence)

        risk_score, severity = risk_engine.calculate_risk(proba, evidence)
        prediction = "malicious" if risk_score >= 60 else ("suspicious" if risk_score >= 40 else "clean")

        # Response recommendations
        actions = []
        if severity in ["CRITICAL", "HIGH"]:
            actions = ["block_url", "quarantine_message", "notify_soc_team", "revoke_sender_trust"]
        elif severity == "MEDIUM":
            actions = ["warn_recipient", "log_perimeter_firewall", "deep_sandbox_analysis"]
        else:
            actions = ["allow_traffic", "add_reputation_whitelist"]

        explanation = explanation_engine.generate_explanation(
            threat_type="phishing",
            risk_score=risk_score,
            severity=severity,
            evidence=evidence,
            target_reference=url
        )

        return AnalysisResponse(
            threat_type="phishing",
            prediction=prediction,
            confidence=round(proba, 2),
            risk_score=risk_score,
            severity=severity,
            evidence=evidence,
            recommended_actions=actions,
            explanation=explanation,
            mitre_technique="T1566",
            mitre_name="Phishing: Spearphishing Link",
            features=features
        )

    def _heuristic_probability(self, features: Dict[str, Any], evidence: List[EvidenceItem]) -> float:
        # Base benign domain check
        url_lower = str(features)
        total_weight = sum(e.weight for e in evidence)
        
        if total_weight == 0:
            return 0.04
        
        # Normalize into probability
        prob = min(0.98, max(0.05, 0.15 + (total_weight / 60.0)))
        return round(prob, 2)

phishing_service = PhishingService()

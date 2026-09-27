import re
import math
import os
import logging
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import joblib
import httpx

from app.schemas.analysis import EvidenceItem, AnalysisResponse
from app.services.risk_engine import risk_engine
from app.services.explanation_engine import explanation_engine
from app.config import settings

logger = logging.getLogger("cyberguard.phishing")

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
        self.safe_browsing_key = settings.GOOGLE_SAFE_BROWSING_API_KEY or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None

    # ── Google Safe Browsing API v4 (free: 10,000 req/day) ──────────────
    def _check_safe_browsing(self, url: str) -> Tuple[bool, str]:
        """
        Query Google Safe Browsing API for real-time threat match.
        Returns (is_flagged: bool, threat_type: str).
        """
        if not self.safe_browsing_key:
            return False, ""
        try:
            payload = {
                "client": {"clientId": "cyberguard", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safe_browsing_key}",
                    json=payload
                )
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "UNKNOWN")
                    logger.info(f"Google Safe Browsing MATCH: {url} → {threat_type}")
                    return True, threat_type
        except Exception as e:
            logger.warning(f"Google Safe Browsing lookup failed: {e}")
        return False, ""

    # ── WHOIS Domain Age Check (free, unlimited) ────────────────────────
    def _check_domain_age(self, hostname: str) -> Tuple[int, str]:
        """
        Query WHOIS for domain creation date. Returns (age_days, registrar).
        New domains (< 30 days) are highly suspicious for phishing.
        """
        try:
            import whois
            from datetime import datetime
            # Strip subdomains to get the registerable domain
            parts = hostname.split(".")
            if len(parts) > 2:
                domain = ".".join(parts[-2:])
            else:
                domain = hostname

            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.utcnow() - creation_date).days
                registrar = str(w.registrar or "Unknown")
                return age_days, registrar
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {hostname}: {e}")
        return -1, ""

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

        # ── NEW: Google Safe Browsing live threat match ──────────────────
        sb_flagged, sb_threat = self._check_safe_browsing(url)
        if sb_flagged:
            threat_label = sb_threat.replace("_", " ").title()
            evidence.append(EvidenceItem(
                indicator="google_safe_browsing_match",
                description=f"Google Safe Browsing API confirmed active threat: {threat_label}",
                weight=25
            ))
        elif self.safe_browsing_key:
            # API was called successfully but URL is clean
            evidence.append(EvidenceItem(
                indicator="safe_browsing_clean",
                description="Google Safe Browsing API returned no active threat matches",
                weight=0
            ))

        # ── NEW: WHOIS domain age intelligence ───────────────────────────
        domain_age_days = -1
        if hostname and not has_ip:
            domain_age_days, registrar = self._check_domain_age(hostname)
            if domain_age_days >= 0:
                if domain_age_days < 30:
                    evidence.append(EvidenceItem(
                        indicator="newly_registered_domain",
                        description=f"Domain registered only {domain_age_days} days ago (Registrar: {registrar}). Over 80% of phishing domains are under 30 days old.",
                        weight=16
                    ))
                elif domain_age_days < 90:
                    evidence.append(EvidenceItem(
                        indicator="young_domain_registration",
                        description=f"Domain registered {domain_age_days} days ago (Registrar: {registrar}). Relatively new.",
                        weight=6
                    ))
                else:
                    evidence.append(EvidenceItem(
                        indicator="established_domain_age",
                        description=f"Domain has been registered for {domain_age_days} days ({domain_age_days // 365} years). Established domain.",
                        weight=0
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
            "entropy": entropy,
            "safe_browsing_flagged": sb_flagged,
            "domain_age_days": domain_age_days
        }

        return features, evidence

    def analyze_url(self, url: str) -> AnalysisResponse:
        features, evidence = self.extract_url_features(url)
        
        # Calculate ML probability
        if self.model is not None:
            # Model inference when trained
            try:
                # Use only the original 12 features for the trained model
                model_feature_keys = [
                    "url_length", "domain_length", "has_ip", "has_https",
                    "has_at_symbol", "has_double_slash", "subdomain_count",
                    "hyphen_count", "digit_count", "special_character_count",
                    "suspicious_keywords_count", "entropy"
                ]
                feature_vals = [[features[k] for k in model_feature_keys]]
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

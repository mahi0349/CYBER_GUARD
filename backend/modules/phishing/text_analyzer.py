import re
from typing import Any, Dict, List, Tuple
from ...models.schemas import ThreatIndicator

# Target high-profile brands frequently targeted by phishing attacks
KNOWN_TARGET_BRANDS = [
    "microsoft", "office 365", "paypal", "netflix", "amazon", "google", 
    "apple", "chase", "bank of america", "wells fargo", "irs", "usps", 
    "fedex", "dhl", "workday", "metamask", "coinbase", "binance", "docuSign"
]

# Patterns representing urgency and fear tactics
URGENCY_PATTERNS = [
    (r"\b(urgent|urgently|immediate|immediately|action required)\b", "High Urgency Cue", 0.35),
    (r"\b(within \d+ (hours|mins|minutes|days)|today only|expires in)\b", "Artificial Deadline Pressure", 0.4),
    (r"\b(suspend(ed|ion)?|deactivat(ed|ion)?|terminat(ed|ion)?|block(ed)?|restrict(ed)?)\b", "Account Suspension / Coercion Threat", 0.45),
    (r"\b(unauthorized|suspicious activity|security breach|compromised|fraud alert)\b", "Manufactured Security Alarm", 0.35),
    (r"\b(last warning|final notice|permanently disabled)\b", "High Severity Ultimatum", 0.4),
]

# Patterns representing credential harvesting and sensitive data requests
CREDENTIAL_PATTERNS = [
    (r"\b(password|passcode|secret phrase|seed phrase|private key)\b", "Explicit Credential Solicitation", 0.6),
    (r"\b(credit card|card number|cvv|expiry date|debit card)\b", "Payment Card Data Harvesting", 0.6),
    (r"\b(social security|ssn|tax id|national id)\b", "Government Identity Theft Indicator", 0.65),
    (r"\b(verify (your )?(login|account|identity|credentials)|confirm (your )?identity)\b", "Credential Verification Lure", 0.5),
    (r"\b(routing number|bank account details|wire transfer|overseas wiring)\b", "Financial Account / Wire Phishing", 0.55),
    (r"\b(one-time password|otp|verification code)\b", "2FA / OTP Interception Phishing", 0.5),
]

# Suspicious generic greetings
GENERIC_GREETINGS = [
    (r"^(dear (customer|user|valued client|member|employee|sir/madam)|hello customer)\b", "Generic Impersonal Greeting", 0.25),
]

# Malicious payload / executable lures
MALICIOUS_PAYLOAD_PATTERNS = [
    (r"\b(\.exe|\.scr|\.bat|\.vbs|\.iso|\.zip|\.rar|patch\.exe|security-patch)\b", "Executable Attachment / Malware Lure", 0.7),
    (r"\b(download and run|install update|run security patch)\b", "Forced Download / Execution Prompt", 0.55),
]

class TextAnalyzer:
    def __init__(self):
        pass

    def analyze(self, text: str, subject: str = "", sender: str = "") -> Dict[str, Any]:
        combined_text = f"{subject}\n{text}".strip()
        indicators: List[ThreatIndicator] = []
        
        urgency_score = 0.0
        credential_score = 0.0
        malware_score = 0.0
        generic_greeting_detected = False
        
        matched_urgency_cues = []
        matched_credential_cues = []
        matched_brands = []
        
        # 1. Evaluate Urgency & Coercion Patterns
        for pattern, label, weight in URGENCY_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                matched_str = matches[0] if isinstance(matches[0], str) else matches[0][0]
                matched_urgency_cues.append(matched_str)
                urgency_score = min(1.0, urgency_score + weight)
                indicators.append(ThreatIndicator(
                    name=label,
                    category="Social Engineering & Urgency",
                    weight=weight,
                    value=matched_str,
                    description=f"Message uses psychological pressure: '{matched_str}'"
                ))

        # 2. Evaluate Credential Solicitation Patterns
        for pattern, label, weight in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                matched_str = matches[0] if isinstance(matches[0], str) else matches[0][0]
                matched_credential_cues.append(matched_str)
                credential_score = min(1.0, credential_score + weight)
                indicators.append(ThreatIndicator(
                    name=label,
                    category="Credential Harvesting",
                    weight=weight,
                    value=matched_str,
                    description=f"Message requests sensitive/confidential information: '{matched_str}'"
                ))

        # 3. Evaluate Malicious Executable / Malware Lures
        for pattern, label, weight in MALICIOUS_PAYLOAD_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                matched_str = matches[0] if isinstance(matches[0], str) else matches[0][0]
                malware_score = min(1.0, malware_score + weight)
                indicators.append(ThreatIndicator(
                    name=label,
                    category="Malware Delivery",
                    weight=weight,
                    value=matched_str,
                    description=f"Message references high-risk executable or payload: '{matched_str}'"
                ))

        # 4. Check for Generic Impersonal Greetings
        for pattern, label, weight in GENERIC_GREETINGS:
            if re.search(pattern, combined_text, re.IGNORECASE | re.MULTILINE):
                generic_greeting_detected = True
                indicators.append(ThreatIndicator(
                    name=label,
                    category="Communication Pattern",
                    weight=weight,
                    value="Impersonal Salutation",
                    description="Attacker uses broad generic salutation rather than addressing target by name"
                ))

        # 5. Check for Targeted Brand Mention
        lower_combined = combined_text.lower()
        for brand in KNOWN_TARGET_BRANDS:
            if brand in lower_combined:
                matched_brands.append(brand)

        # 6. Check Caps Lock ratio & Exclamation Count
        caps_count = sum(1 for c in combined_text if c.isupper())
        total_letters = sum(1 for c in combined_text if c.isalpha())
        caps_ratio = (caps_count / max(1, total_letters))
        exclamation_count = combined_text.count("!")

        if caps_ratio > 0.25 and total_letters > 20:
            indicators.append(ThreatIndicator(
                name="Abnormal Capitalization Ratio",
                category="Linguistic Anomaly",
                weight=0.2,
                value=f"{caps_ratio * 100:.1f}% uppercase",
                description="Excessive uppercase phrasing used to induce panic or urgency"
            ))

        # Calculate composite text threat score (0 to 1)
        text_threat_score = min(1.0, (
            urgency_score * 0.35 +
            credential_score * 0.45 +
            malware_score * 0.40 +
            (0.15 if generic_greeting_detected else 0.0) +
            (0.1 if len(matched_brands) > 0 and (urgency_score > 0 or credential_score > 0) else 0.0)
        ))

        return {
            "text_threat_score": round(text_threat_score, 3),
            "urgency_score": round(urgency_score, 3),
            "credential_score": round(credential_score, 3),
            "malware_score": round(malware_score, 3),
            "matched_urgency_cues": matched_urgency_cues,
            "matched_credential_cues": matched_credential_cues,
            "matched_brands": matched_brands,
            "generic_greeting": generic_greeting_detected,
            "indicators": indicators,
        }

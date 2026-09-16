import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from ...models.schemas import ThreatIndicator

# Authoritative legitimate domains for high-target services
LEGITIMATE_TARGET_DOMAINS = [
    "microsoft.com", "office.com", "live.com", "outlook.com",
    "paypal.com", "paypal-community.com",
    "netflix.com",
    "amazon.com", "amazon.co.uk", "amazon.in",
    "google.com", "accounts.google.com", "drive.google.com", "meet.google.com",
    "apple.com", "icloud.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "github.com", "slack.com", "atlassian.net", "auth0.com", "digitalocean.com",
    "irs.gov", "usps.com", "fedex.com", "dhl.com", "workday.com", "metamask.io"
]

# High-risk / high-abuse TLDs often favored in disposable phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "work", "tk", "ml", "ga", "cf", "gq", 
    "cam", "icu", "loan", "click", "rest", "support", "vip", "cfd"
}

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly"
}

# Suspicious keywords commonly seen in phishing paths/queries
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", 
    "banking", "update", "dispute", "recover", "wallet", "seed", "claim", 
    "refund", "patch.exe", "trojan", "direct-deposit"
]

def calculate_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return calculate_levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to detect random/DGA domain names."""
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in prob_dict.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class UrlAnalyzer:
    def __init__(self):
        pass

    def extract_urls(self, text: str) -> List[str]:
        """Extracts all HTTP/HTTPS and bare URLs from text."""
        url_pattern = r"(https?://[^\s<>\"'{}|\\^`]+|[a-zA-Z0-9.-]+\.(?:com|org|net|xyz|top|gov|io|edu|info|me)[^\s<>\"'{}|\\^`]*)"
        raw_matches = re.findall(url_pattern, text)
        cleaned = []
        for m in raw_matches:
            if not m.startswith("http://") and not m.startswith("https://"):
                m = "http://" + m
            cleaned.append(m)
        return list(dict.fromkeys(cleaned))

    def analyze_url(self, raw_url: str) -> Dict[str, Any]:
        """Performs deep heuristic and structural forensic analysis of a single URL."""
        if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
            raw_url = "http://" + raw_url
        
        parsed = urlparse(raw_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        scheme = parsed.scheme.lower()
        
        indicators: List[ThreatIndicator] = []
        risk_subscores = []
        
        # 1. IP Address as Hostname Detection
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        is_raw_ip = bool(re.match(ip_pattern, hostname))
        if is_raw_ip:
            risk_subscores.append(0.85)
            indicators.append(ThreatIndicator(
                name="Direct IP Address in URL",
                category="Infrastructure Obfuscation",
                weight=0.85,
                value=hostname,
                description=f"URL uses a bare IP address ({hostname}) rather than a registered domain name, typical of disposable attack infrastructure."
            ))

        # 2. Suspicious TLD Detection
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            risk_subscores.append(0.55)
            indicators.append(ThreatIndicator(
                name="High-Abuse Disposable TLD",
                category="Domain Reputation",
                weight=0.55,
                value=f".{tld}",
                description=f"Top-level domain '.{tld}' has a statistically high correlation with disposable phishing campaigns."
            ))

        # 3. URL Shortener Detection
        if hostname in URL_SHORTENERS:
            risk_subscores.append(0.40)
            indicators.append(ThreatIndicator(
                name="URL Shortening Service",
                category="Destination Obfuscation",
                weight=0.40,
                value=hostname,
                description=f"Destination URL is obscured behind shortener service '{hostname}'."
            ))

        # 4. Brand Typo-Squatting / Look-Alike Domain Analysis
        # Normalize homoglyphs/common leetspeak: 0->o, 1->l, vv->w
        normalized_host = (
            hostname.replace("0", "o")
                    .replace("1", "l")
                    .replace("vv", "w")
                    .replace("-", "")
        )
        
        best_match_legit = None
        min_edit_dist = 999
        is_exact_legit = hostname in LEGITIMATE_TARGET_DOMAINS or any(hostname.endswith("." + d) for d in LEGITIMATE_TARGET_DOMAINS)
        
        if not is_exact_legit and not is_raw_ip:
            for legit_domain in LEGITIMATE_TARGET_DOMAINS:
                legit_clean = legit_domain.replace(".", "").replace("-", "")
                dist = calculate_levenshtein_distance(normalized_host, legit_clean)
                if dist < min_edit_dist:
                    min_edit_dist = dist
                    best_match_legit = legit_domain
            
            # Check if domain closely imitates a known brand (e.g. edit distance 1 or 2, or contains brand name in normalized host)
            matched_spoofed_brand = None
            for legit_domain in LEGITIMATE_TARGET_DOMAINS:
                b_name = legit_domain.split(".")[0]
                if len(b_name) >= 3 and b_name in normalized_host and not hostname.endswith(f".{legit_domain}") and not hostname == legit_domain:
                    matched_spoofed_brand = legit_domain
                    break

            if (min_edit_dist <= 2 and len(hostname) >= 6) or matched_spoofed_brand:
                spoofed_target = matched_spoofed_brand or best_match_legit
                risk_subscores.append(0.90)
                indicators.append(ThreatIndicator(
                    name="Look-Alike / Typo-Squatted Domain",
                    category="Brand Spoofing",
                    weight=0.90,
                    value=f"Spoofs {spoofed_target} via '{hostname}'",
                    description=f"Domain '{hostname}' closely mimics legitimate authoritative domain '{spoofed_target}' using character substitution, typo-squatting, or deceptive hyphenation."
                ))

        # 5. Deceptive Subdomain Stacking
        # E.g., login.microsoft.com.evil-server.net
        parts = hostname.split(".")
        if len(parts) >= 4:
            for legit in ["microsoft", "google", "paypal", "apple", "chase", "netflix"]:
                if legit in parts[:-2]:
                    risk_subscores.append(0.80)
                    indicators.append(ThreatIndicator(
                        name="Deceptive Brand Subdomain Stacking",
                        category="Brand Spoofing",
                        weight=0.80,
                        value=hostname,
                        description=f"Legitimate brand name '{legit}' is embedded as a misleading subdomain to disguise the true host domain '{'.'.join(parts[-2:])}'."
                    ))

        # 6. Shannon Entropy (Random string / DGA detection)
        entropy = calculate_shannon_entropy(hostname.split(".")[0])
        if entropy > 3.8 and len(hostname.split(".")[0]) > 8:
            risk_subscores.append(0.45)
            indicators.append(ThreatIndicator(
                name="High Domain Entropy (DGA Pattern)",
                category="Infrastructure Anomaly",
                weight=0.45,
                value=f"Entropy: {entropy:.2f} bits",
                description="Domain name exhibits unusually high algorithmic randomness, consistent with Domain Generation Algorithms (DGAs)."
            ))

        # 7. Suspicious Path & Query Keywords
        matched_path_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path.lower() or kw in raw_url.lower()]
        if matched_path_keywords:
            weight = 0.35 if is_exact_legit else 0.65
            risk_subscores.append(weight)
            indicators.append(ThreatIndicator(
                name="Credential Harvesting Path Pattern",
                category="Attack Intent",
                weight=weight,
                value=", ".join(matched_path_keywords[:3]),
                description=f"URL path targets authentication and credential endpoints: '{', '.join(matched_path_keywords)}'."
            ))

        # 8. Unencrypted HTTP on Sensitive Endpoints
        if scheme == "http" and matched_path_keywords:
            risk_subscores.append(0.40)
            indicators.append(ThreatIndicator(
                name="Unencrypted HTTP Credential Form",
                category="Transport Security",
                weight=0.40,
                value="Insecure HTTP",
                description="Login or verification endpoint operates over unencrypted HTTP without valid TLS encryption."
            ))

        # If it's a confirmed legitimate domain and no spoofing detected, lower risk
        if is_exact_legit and not risk_subscores:
            url_threat_score = 0.05
        else:
            url_threat_score = min(1.0, max(risk_subscores) if risk_subscores else 0.1)

        return {
            "url": raw_url,
            "hostname": hostname,
            "scheme": scheme,
            "is_raw_ip": is_raw_ip,
            "is_exact_legitimate": is_exact_legit,
            "url_threat_score": round(url_threat_score, 3),
            "indicators": indicators
        }

    def analyze_all(self, urls: List[str]) -> Dict[str, Any]:
        """Analyzes a list of URLs and aggregates scores."""
        if not urls:
            return {
                "max_url_threat_score": 0.0,
                "analyzed_urls": [],
                "indicators": []
            }
        
        results = [self.analyze_url(u) for u in urls]
        max_score = max(r["url_threat_score"] for r in results)
        all_indicators: List[ThreatIndicator] = []
        for r in results:
            all_indicators.extend(r["indicators"])
        
        return {
            "max_url_threat_score": round(max_score, 3),
            "analyzed_urls": results,
            "indicators": all_indicators
        }

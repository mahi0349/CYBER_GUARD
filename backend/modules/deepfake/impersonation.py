"""
Impersonation Detector — Authority-figure spoofing and organizational identity fraud detection.

Uses rule-based heuristics + NLP-style pattern matching to detect:
- CEO/executive title spoofing
- Organization name similarity attacks
- Communication style anomalies (urgency + authority combo)
- Metadata inconsistencies (sender domain vs claimed org)
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from ...models.schemas import ThreatIndicator


class ImpersonationDetector:
    """Detects text-based authority-figure impersonation and organizational identity fraud."""

    # Known authority titles that attackers frequently impersonate
    AUTHORITY_TITLES = [
        "ceo", "cfo", "cto", "coo", "ciso", "cio",
        "chief executive", "chief financial", "chief technology", "chief operating",
        "chief information security", "chief information",
        "president", "vice president", "vp",
        "director", "managing director", "executive director",
        "senior vice president", "svp", "evp",
        "general manager", "gm",
        "head of", "department head",
        "chairman", "chairperson", "board member",
        "partner", "senior partner", "managing partner",
        "secretary", "treasurer",
        "superintendent", "commissioner",
    ]

    # Well-known organizations frequently impersonated
    KNOWN_ORGANIZATIONS = {
        # Banks & Financial
        "state bank of india": ["sbi", "state bank"],
        "reserve bank of india": ["rbi", "reserve bank"],
        "hdfc bank": ["hdfc"],
        "icici bank": ["icici"],
        "axis bank": ["axis"],
        "punjab national bank": ["pnb"],
        "bank of baroda": ["bob", "baroda"],
        "jpmorgan chase": ["jpmorgan", "chase"],
        "bank of america": ["bofa", "boa"],
        "wells fargo": ["wells"],
        "citibank": ["citi"],
        "hsbc": [],
        "barclays": [],
        # Tech
        "microsoft": ["msft"],
        "google": ["alphabet"],
        "apple": ["apple inc"],
        "amazon": ["aws"],
        "meta": ["facebook", "fb"],
        "netflix": [],
        "paypal": [],
        # Government
        "income tax department": ["income tax", "it department"],
        "central bureau of investigation": ["cbi"],
        "ministry of finance": [],
        "internal revenue service": ["irs"],
        "federal bureau of investigation": ["fbi"],
        "social security administration": ["ssa", "social security"],
        # Telecom / Services
        "reliance jio": ["jio"],
        "airtel": ["bharti airtel"],
        "vodafone": ["vi", "vodafone idea"],
    }

    # Urgency + authority pressure phrases
    AUTHORITY_PRESSURE_PHRASES = [
        r"this is (?:the |your )?(?:ceo|cfo|cto|director|president|chairman|head)",
        r"i(?:'m| am) (?:the |your )?(?:ceo|cfo|cto|director|president|chairman)",
        r"speaking on behalf of (?:the )?(?:ceo|board|management|director)",
        r"direct(?:ly)? from (?:the )?(?:ceo|board|management|leadership)",
        r"(?:personal|direct|confidential) (?:request|instruction|order|directive) from",
        r"do not (?:share|discuss|forward|tell|inform) (?:this |anyone)",
        r"keep this (?:confidential|between us|private|secret)",
        r"bypass (?:normal|standard|regular|usual) (?:process|procedure|protocol|channel)",
        r"override (?:normal|standard|existing) (?:approval|authorization)",
        r"this (?:is |must be )?(?:handled |done |completed )?(?:urgently|immediately|right away|asap|now)",
        r"(?:wire|transfer|send|move) (?:the )?(?:funds|money|payment|amount)",
        r"update (?:the |your )?(?:bank|account|payment|billing) (?:details|information|records)",
        r"new (?:bank|account|wire|payment) (?:details|information|instructions)",
        r"do(?:n't| not) (?:verify|check|confirm|validate) (?:with|through)",
    ]

    # Suspicious salutation patterns
    GENERIC_AUTHORITY_SALUTATIONS = [
        r"^dear (?:employee|staff|team member|colleague|valued (?:employee|member))",
        r"^(?:attention|notice to) (?:all )?(?:employees|staff|team|department)",
        r"^(?:important|urgent|critical|immediate) (?:notice|announcement|update|action required)",
    ]

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compiles regex patterns for performance."""
        self._authority_pressure_re = [
            re.compile(p, re.IGNORECASE) for p in self.AUTHORITY_PRESSURE_PHRASES
        ]
        self._salutation_re = [
            re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.GENERIC_AUTHORITY_SALUTATIONS
        ]

    def analyze(
        self,
        text_content: Optional[str] = None,
        claimed_identity: Optional[str] = None,
        claimed_organization: Optional[str] = None,
        channel: str = "Email",
        urgency_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyzes text content for authority-figure impersonation signals.

        Returns dict with:
            - impersonation_score (float 0-1)
            - title_spoofing (dict)
            - org_similarity (dict)
            - authority_pressure (dict)
            - communication_anomalies (dict)
            - indicators (List[ThreatIndicator])
        """
        text = (text_content or "").strip()
        identity = (claimed_identity or "").strip()
        org = (claimed_organization or "").strip()
        urgency = (urgency_context or "").strip()
        combined_text = f"{text} {identity} {org} {urgency}".strip()

        indicators: List[ThreatIndicator] = []

        # 1. Title spoofing detection
        title_result = self._detect_title_spoofing(combined_text, identity)
        if title_result["detected"]:
            indicators.append(ThreatIndicator(
                name="Authority Title Spoofing",
                category="Impersonation / Social Engineering",
                weight=round(title_result["score"], 2),
                value=f"Claimed title: {title_result['matched_titles'][0]}" if title_result["matched_titles"] else "Title pattern detected",
                description=f"The communication claims authority through executive title impersonation ({', '.join(title_result['matched_titles'][:3])}). "
                            "This is a hallmark of Business Email Compromise (BEC) and CEO fraud attacks."
            ))

        # 2. Organization name similarity
        org_result = self._detect_org_similarity(org, text)
        if org_result["detected"]:
            indicators.append(ThreatIndicator(
                name="Organization Identity Spoofing",
                category="Impersonation / Identity Fraud",
                weight=round(org_result["score"], 2),
                value=f"Claims affiliation with: {org_result['matched_org']}" if org_result["matched_org"] else "Org reference detected",
                description=f"The message references {org_result['matched_org'] or 'a known organization'} "
                            f"(similarity: {org_result['similarity']:.0%}). "
                            "Verify the sender's actual organizational affiliation through independent channels."
            ))

        # 3. Authority pressure pattern detection
        pressure_result = self._detect_authority_pressure(combined_text)
        if pressure_result["detected"]:
            indicators.append(ThreatIndicator(
                name="Coercive Authority Pressure Tactics",
                category="Social Engineering / Manipulation",
                weight=round(pressure_result["score"], 2),
                value=f"{len(pressure_result['matched_phrases'])} pressure tactics detected",
                description=f"The communication employs {len(pressure_result['matched_phrases'])} psychological pressure tactics "
                            f"including: {'; '.join(pressure_result['matched_phrases'][:3])}. "
                            "This combination of authority claims with urgency is a strong BEC/impersonation indicator."
            ))

        # 4. Communication style anomalies
        style_result = self._detect_style_anomalies(text, identity, channel)
        if style_result["detected"]:
            indicators.append(ThreatIndicator(
                name="Communication Style Anomaly",
                category="Behavioral Analysis",
                weight=round(style_result["score"], 2),
                value=f"{len(style_result['anomalies'])} style anomalies",
                description=f"Unusual communication patterns detected: {'; '.join(style_result['anomalies'][:3])}."
            ))

        # 5. Generic salutation + authority combo
        salutation_result = self._detect_generic_authority_salutation(text)
        if salutation_result["detected"]:
            indicators.append(ThreatIndicator(
                name="Generic Authority Salutation",
                category="Impersonation Pattern",
                weight=round(salutation_result["score"], 2),
                value=salutation_result["matched_pattern"],
                description="Uses a generic mass-targeting salutation combined with authority claims — "
                            "inconsistent with genuine executive-to-individual communication."
            ))

        # Compute composite impersonation score
        component_scores = [
            title_result["score"] * 0.30,
            org_result["score"] * 0.20,
            pressure_result["score"] * 0.30,
            style_result["score"] * 0.10,
            salutation_result["score"] * 0.10,
        ]
        raw_score = sum(component_scores)

        # Multi-signal boost: if 3+ distinct signals fire, increase confidence
        signals_fired = sum(1 for r in [title_result, org_result, pressure_result, style_result, salutation_result] if r["detected"])
        if signals_fired >= 3:
            raw_score = min(1.0, raw_score * 1.3)
        elif signals_fired >= 4:
            raw_score = min(1.0, raw_score * 1.5)

        impersonation_score = round(min(1.0, max(0.0, raw_score)), 4)

        return {
            "impersonation_score": impersonation_score,
            "signals_fired": signals_fired,
            "title_spoofing": title_result,
            "org_similarity": org_result,
            "authority_pressure": pressure_result,
            "communication_anomalies": style_result,
            "salutation_analysis": salutation_result,
            "indicators": indicators,
        }

    # ── Detection Sub-Methods ────────────────────────────────────────────

    def _detect_title_spoofing(self, text: str, claimed_identity: str) -> Dict[str, Any]:
        """Detects claims of executive/authority titles in text."""
        text_lower = text.lower()
        identity_lower = claimed_identity.lower()
        matched = []

        for title in self.AUTHORITY_TITLES:
            if title in text_lower or title in identity_lower:
                matched.append(title)

        score = min(1.0, len(matched) * 0.35) if matched else 0.0
        return {
            "detected": len(matched) > 0,
            "score": round(score, 4),
            "matched_titles": matched,
        }

    def _detect_org_similarity(self, claimed_org: str, text: str) -> Dict[str, Any]:
        """Checks claimed organization against known-org database using Levenshtein distance."""
        if not claimed_org:
            # Try to extract org references from text
            claimed_org = self._extract_org_from_text(text)
            if not claimed_org:
                return {"detected": False, "score": 0.0, "matched_org": None, "similarity": 0.0}

        claimed_lower = claimed_org.lower().strip()
        best_match = None
        best_similarity = 0.0

        for org_name, aliases in self.KNOWN_ORGANIZATIONS.items():
            # Check exact and alias matches
            all_names = [org_name] + aliases
            for name in all_names:
                sim = self._string_similarity(claimed_lower, name.lower())
                if sim > best_similarity:
                    best_similarity = sim
                    best_match = org_name

        # Score based on similarity
        if best_similarity >= 0.85:
            score = 0.9  # Very high match — likely impersonating
        elif best_similarity >= 0.65:
            score = 0.6  # Moderate match — suspicious
        elif best_similarity >= 0.45:
            score = 0.3  # Loose match — worth flagging
        else:
            score = 0.0

        return {
            "detected": score > 0.0,
            "score": round(score, 4),
            "matched_org": best_match if score > 0 else None,
            "similarity": round(best_similarity, 4),
        }

    def _detect_authority_pressure(self, text: str) -> Dict[str, Any]:
        """Detects coercive authority pressure tactics."""
        matched_phrases = []
        for pattern in self._authority_pressure_re:
            matches = pattern.findall(text)
            if matches:
                # Get the matched text for display
                for m in pattern.finditer(text):
                    matched_phrases.append(m.group(0).strip())

        score = min(1.0, len(matched_phrases) * 0.25) if matched_phrases else 0.0

        # Boost if financial action + secrecy combo detected
        has_financial = any("fund" in p.lower() or "transfer" in p.lower() or "payment" in p.lower() or "wire" in p.lower() for p in matched_phrases)
        has_secrecy = any("confidential" in p.lower() or "secret" in p.lower() or "share" in p.lower() or "discuss" in p.lower() for p in matched_phrases)
        if has_financial and has_secrecy:
            score = min(1.0, score * 1.5)

        return {
            "detected": len(matched_phrases) > 0,
            "score": round(score, 4),
            "matched_phrases": matched_phrases,
            "financial_action_detected": has_financial,
            "secrecy_request_detected": has_secrecy,
        }

    def _detect_style_anomalies(self, text: str, identity: str, channel: str) -> Dict[str, Any]:
        """Detects communication style anomalies inconsistent with claimed identity."""
        anomalies = []
        score = 0.0

        if not text:
            return {"detected": False, "score": 0.0, "anomalies": []}

        text_lower = text.lower()

        # Check for excessive urgency markers
        urgency_count = len(re.findall(r'[!]{2,}|URGENT|ASAP|IMMEDIATELY|RIGHT NOW', text, re.IGNORECASE))
        if urgency_count >= 2:
            anomalies.append(f"Excessive urgency markers ({urgency_count} instances)")
            score += 0.2

        # Check for grammar/spelling inconsistencies unusual for executives
        # (very basic heuristic: all-caps sections mixed with normal text)
        caps_ratio = sum(1 for c in text if c.isupper()) / (len(text) + 1)
        if 0.3 < caps_ratio < 0.7:
            anomalies.append("Inconsistent capitalization pattern (mixed ALL-CAPS and normal text)")
            score += 0.15

        # Check for personal email indicators when claiming corporate identity
        personal_email_indicators = ["gmail", "yahoo", "hotmail", "outlook.com", "aol", "protonmail"]
        if any(ind in text_lower for ind in personal_email_indicators) and identity:
            anomalies.append("References personal email service while claiming corporate authority")
            score += 0.25

        # Check for unusual request patterns
        if re.search(r'(?:send|give|provide|share).{0,20}(?:password|credential|login|access|pin|otp)', text_lower):
            anomalies.append("Direct credential solicitation from claimed authority figure")
            score += 0.3

        # Check for pressure to use non-standard channels
        if re.search(r'(?:text|call|whatsapp|telegram|signal|personal).{0,15}(?:me|number|phone|cell)', text_lower):
            anomalies.append("Pressures recipient to switch to unmonitored communication channel")
            score += 0.2

        return {
            "detected": len(anomalies) > 0,
            "score": round(min(1.0, score), 4),
            "anomalies": anomalies,
        }

    def _detect_generic_authority_salutation(self, text: str) -> Dict[str, Any]:
        """Detects generic salutations inconsistent with genuine executive communication."""
        for pattern in self._salutation_re:
            match = pattern.search(text)
            if match:
                return {
                    "detected": True,
                    "score": 0.4,
                    "matched_pattern": match.group(0).strip(),
                }
        return {"detected": False, "score": 0.0, "matched_pattern": None}

    # ── Utility Methods ──────────────────────────────────────────────────

    def _extract_org_from_text(self, text: str) -> Optional[str]:
        """Attempts to extract organization name from text content."""
        text_lower = text.lower()
        for org_name, aliases in self.KNOWN_ORGANIZATIONS.items():
            all_names = [org_name] + aliases
            for name in all_names:
                if name.lower() in text_lower:
                    return org_name
        return None

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Computes normalized Levenshtein similarity between two strings."""
        if not s1 or not s2:
            return 0.0
        if s1 == s2:
            return 1.0

        len1, len2 = len(s1), len(s2)
        max_len = max(len1, len2)

        # Create distance matrix
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )

        distance = matrix[len1][len2]
        return 1.0 - (distance / max_len)

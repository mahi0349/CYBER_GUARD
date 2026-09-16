from typing import Any, Dict, List
from ...models.enums import RiskLevel, ThreatCategory
from ...models.schemas import ThreatIndicator

class PhishingExplainer:
    def __init__(self):
        pass

    def generate_explanation(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        text_result: Dict[str, Any],
        url_result: Dict[str, Any],
        ml_proba: float,
        top_keywords: List[Any],
        indicators: List[ThreatIndicator]
    ) -> str:
        """Generates a plain-English, SOC-analyst quality threat rationale explaining the decision factors."""
        if risk_level == RiskLevel.SAFE:
            return (
                "Safe: Analysis reveals standard communication patterns with no indicators of credential solicitation, "
                "psychological urgency pressure, or domain spoofing. Embedded links point to recognized authoritative domains "
                "with valid transport security."
            )

        explanation_parts = []
        explanation_parts.append(f"{risk_level.value} Risk ({threat_classification}):")

        # 1. Domain / URL evidence
        spoofed_domains = [ind for ind in indicators if ind.name == "Look-Alike / Typo-Squatted Domain"]
        ip_urls = [ind for ind in indicators if ind.name == "Direct IP Address in URL"]
        subdomain_stack = [ind for ind in indicators if ind.name == "Deceptive Brand Subdomain Stacking"]
        disposable_tlds = [ind for ind in indicators if ind.name == "High-Abuse Disposable TLD"]

        if spoofed_domains:
            explanation_parts.append(
                f"The embedded link employs a look-alike / typo-squatted domain ({spoofed_domains[0].value}) designed to spoof legitimate corporate infrastructure."
            )
        elif ip_urls:
            explanation_parts.append(
                f"The destination address routes to an unverified bare IP host ({ip_urls[0].value}) avoiding standard domain registration oversight."
            )
        elif subdomain_stack:
            explanation_parts.append(
                f"The link uses deceptive brand subdomain stacking ({subdomain_stack[0].value}) to camouflage the actual destination server."
            )
        elif disposable_tlds:
            explanation_parts.append(
                f"The URL utilizes a high-abuse disposable top-level domain ({disposable_tlds[0].value}) commonly associated with short-lived phishing sites."
            )

        # 2. Text / Linguistic evidence
        urgency_cues = text_result.get("matched_urgency_cues", [])
        credential_cues = text_result.get("matched_credential_cues", [])
        malware_score = text_result.get("malware_score", 0.0)

        if credential_cues:
            cues_str = ", ".join(f"'{c}'" for c in credential_cues[:3])
            explanation_parts.append(
                f"The communication explicitly solicits sensitive credentials or financial details ({cues_str})."
            )

        if urgency_cues:
            urg_str = ", ".join(f"'{u}'" for u in urgency_cues[:2])
            explanation_parts.append(
                f"The message applies coercive psychological pressure ({urg_str}) to force immediate action before verification."
            )

        if malware_score > 0.4:
            explanation_parts.append(
                "The message contains references prompting the victim to download and execute untrusted software binaries."
            )

        # 3. ML Model confidence attribution
        if ml_proba > 0.75:
            explanation_parts.append(
                f"Machine learning NLP classifier affirms high anomaly confidence ({ml_proba * 100:.1f}%) based on syntactic and structural patterns."
            )

        return " ".join(explanation_parts)

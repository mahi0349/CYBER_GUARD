import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from ...database import save_threat_event
from ...models.enums import ActionType, EventSource, IncidentStatus, RiskLevel, ThreatCategory
from ...models.schemas import (
    PhishingAnalysisRequest,
    RecommendedAction,
    ThreatDetectionResult,
    ThreatIndicator,
)
from .classifier import PhishingMLClassifier
from .explainer import PhishingExplainer
from .text_analyzer import TextAnalyzer
from .url_analyzer import UrlAnalyzer

class PhishingDetector:
    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.url_analyzer = UrlAnalyzer()
        self.ml_classifier = PhishingMLClassifier()
        self.explainer = PhishingExplainer()

    def analyze(self, request: PhishingAnalysisRequest) -> ThreatDetectionResult:
        raw_text = request.text or ""
        subject = request.subject or ""
        sender = request.sender or ""
        
        # 1. Extract URLs from text if not explicitly provided
        urls = list(request.urls)
        extracted = self.url_analyzer.extract_urls(raw_text)
        for u in extracted:
            if u not in urls:
                urls.append(u)

        # 2. Run Text NLP Analysis
        text_result = self.text_analyzer.analyze(raw_text, subject=subject, sender=sender)
        
        # 3. Run URL & Domain Forensics
        url_result = self.url_analyzer.analyze_all(urls)
        
        # 4. Run Machine Learning Classifier
        ml_proba, top_keywords = self.ml_classifier.predict_proba(raw_text, subject=subject, urls=urls)

        # 5. Aggregate All Feature Indicators
        all_indicators: List[ThreatIndicator] = []
        all_indicators.extend(text_result["indicators"])
        all_indicators.extend(url_result["indicators"])
        
        if ml_proba > 0.65:
            all_indicators.append(ThreatIndicator(
                name="ML Classification Confidence",
                category="Machine Learning Inference",
                weight=round(ml_proba, 2),
                value=f"{ml_proba * 100:.1f}% Phishing Probability",
                description=f"TF-IDF feature weights driven by terms: {', '.join([k[0] for k in top_keywords[:3]])}"
            ))

        # 6. Calculate Unified Composite Risk Score (0 - 100)
        text_score = text_result["text_threat_score"]  # 0 to 1
        url_score = url_result["max_url_threat_score"]  # 0 to 1
        
        # Weighted combination with non-linear boost for multi-vector threats
        base_risk = (text_score * 0.45) + (url_score * 0.40) + (ml_proba * 0.15)
        
        # Boost if both severe urgency AND malicious URL detected
        if text_result["urgency_score"] > 0.4 and url_score > 0.6:
            base_risk = min(1.0, base_risk * 1.25)
            
        # Boost if credential harvesting pattern matches look-alike domain
        if text_result["credential_score"] > 0.4 and url_score > 0.7:
            base_risk = min(1.0, base_risk * 1.30)

        risk_score = round(base_risk * 100.0, 1)

        # 7. Map Risk Score to Risk Level
        if risk_score >= 85.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 65.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40.0:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 20.0:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.SAFE

        # 8. Determine Threat Classification Sub-Type
        threat_classification = self._classify_threat(text_result, url_result, risk_level)

        # 9. Map MITRE ATT&CK Techniques
        mitre_techniques = self._map_mitre_techniques(text_result, url_result, risk_level)

        # 10. Generate Recommended Response Actions
        recommended_actions = self._generate_recommended_actions(risk_level, threat_classification, urls, sender)

        # 11. Generate Human-Readable Natural-Language Explanation
        human_explanation = self.explainer.generate_explanation(
            risk_level=risk_level,
            threat_classification=threat_classification,
            text_result=text_result,
            url_result=url_result,
            ml_proba=ml_proba,
            top_keywords=top_keywords,
            indicators=all_indicators
        )

        # Create Detection Result Event
        result = ThreatDetectionResult(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=request.source_type,
            category=ThreatCategory.PHISHING if risk_level != RiskLevel.SAFE else ThreatCategory.BENIGN,
            threat_classification=threat_classification,
            risk_score=risk_score,
            risk_level=risk_level,
            human_explanation=human_explanation,
            indicators=all_indicators,
            recommended_actions=recommended_actions,
            mitre_attack_techniques=mitre_techniques,
            target_identity=sender if sender else "Unknown Recipient",
            origin_ip=url_result["analyzed_urls"][0]["hostname"] if url_result["analyzed_urls"] else None,
            raw_content_summary=(subject or raw_text[:120]).strip(),
            metadata={
                "ml_probability": ml_proba,
                "top_keywords": top_keywords,
                "urls_count": len(urls),
                "text_score": text_score,
                "url_score": url_score,
                "urgency_score": text_result["urgency_score"],
                "credential_score": text_result["credential_score"]
            },
            incident_status=IncidentStatus.DETECTED if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else IncidentStatus.RESOLVED
        )

        # Persist event to SQLite
        try:
            save_threat_event(result)
        except Exception as e:
            print(f"Warning: Failed to save event to SQLite: {e}")

        return result

    def _classify_threat(self, text_result: Dict[str, Any], url_result: Dict[str, Any], risk_level: RiskLevel) -> str:
        if risk_level == RiskLevel.SAFE:
            return "Legitimate Communication / Benign"
        
        if text_result.get("malware_score", 0) > 0.5:
            return "Malware Delivery Lure / Malicious Payload"
        if url_result.get("max_url_threat_score", 0) > 0.75 and text_result.get("credential_score", 0) > 0.4:
            return "Credential Harvesting via Look-Alike Domain"
        if text_result.get("credential_score", 0) > 0.5:
            return "Credential Solicitation & Account Takeover Attempt"
        if url_result.get("max_url_threat_score", 0) > 0.6:
            return "Malicious URL / Look-Alike Phishing Domain"
        if text_result.get("urgency_score", 0) > 0.5:
            return "Social Engineering / Coercive Ultimatum Attack"
        
        return "Social Engineering / Phishing Threat"

    def _map_mitre_techniques(self, text_result: Dict[str, Any], url_result: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        if risk_level == RiskLevel.SAFE:
            return []
        
        techniques = ["T1566 - Phishing"]
        if url_result.get("analyzed_urls"):
            techniques.append("T1566.002 - Phishing: Spearphishing Link")
            techniques.append("T1598.003 - Phishing for Information: Spearphishing Link")
        if text_result.get("credential_score", 0) > 0.3:
            techniques.append("T1078 - Valid Accounts")
        if text_result.get("malware_score", 0) > 0.4:
            techniques.append("T1204.002 - User Execution: Malicious File")
        if "Deceptive Brand Subdomain Stacking" in [i.name for i in url_result.get("indicators", [])]:
            techniques.append("T1036.007 - Masquerading: Double File Extension / Subdomain Stacking")
        
        return techniques

    def _generate_recommended_actions(
        self, 
        risk_level: RiskLevel, 
        threat_classification: str, 
        urls: List[str], 
        sender: str
    ) -> List[RecommendedAction]:
        actions: List[RecommendedAction] = []
        
        if risk_level == RiskLevel.SAFE:
            actions.append(RecommendedAction(
                action_type=ActionType.ALLOW,
                title="Permit Delivery",
                description="No malicious indicators found. Allow message to proceed to user inbox.",
                priority=5,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc)
            ))
            return actions

        # For High / Critical Threats:
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            actions.append(RecommendedAction(
                action_type=ActionType.QUARANTINE_EMAIL,
                title="Quarantine Message Across Mailboxes",
                description=f"Isolate message from recipient inbox and initiate retroactive search for sender '{sender or 'origin'}' across all mailboxes.",
                priority=1,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc)
            ))

            if urls:
                actions.append(RecommendedAction(
                    action_type=ActionType.BLOCK_URL,
                    title="Block Malicious URLs at Perimeter Firewall & DNS",
                    description=f"Add {len(urls)} domain(s) ({', '.join(urls[:2])}) to perimeter DNS sinkhole and firewall egress blocklist.",
                    priority=1,
                    is_automated=True,
                    executed=True,
                    executed_at=datetime.now(timezone.utc)
                ))

            actions.append(RecommendedAction(
                action_type=ActionType.REVOKE_SESSION,
                title="Force Step-Up Authentication / Session Invalidation",
                description="Invalidate active tokens if any user clicked the embedded link within the last 15 minutes.",
                priority=2,
                is_automated=False,
                executed=False
            ))

            actions.append(RecommendedAction(
                action_type=ActionType.NOTIFY_ADMIN,
                title="Dispatch High-Priority Alert to SOC Analysts",
                description="Forward incident IOCs to SOC Slack/Webhook channel for incident case file creation.",
                priority=2,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc)
            ))

            if risk_level == RiskLevel.CRITICAL:
                actions.append(RecommendedAction(
                    action_type=ActionType.ESCALATE_INCIDENT,
                    title="Escalate to Major Security Incident Playbook",
                    description="Trigger tier-3 incident escalation for credential harvesting targeting corporate users.",
                    priority=1,
                    is_automated=False,
                    executed=False
                ))

        # For Low / Medium Threats:
        else:
            actions.append(RecommendedAction(
                action_type=ActionType.WARN_USER,
                title="Display Warning Banner to Recipient",
                description="Inject an external untrusted sender warning banner into the email header.",
                priority=2,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc)
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.FLAG_MANUAL_REVIEW,
                title="Flag for SOC Analyst Triage",
                description="Route suspicious communication into analyst queue for secondary verification.",
                priority=3,
                is_automated=False,
                executed=False
            ))

        return actions

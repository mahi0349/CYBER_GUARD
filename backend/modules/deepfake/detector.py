"""
Deepfake & Impersonation Detection Orchestrator.

Main entry point that coordinates image forensics, impersonation detection,
risk scoring, MITRE ATT&CK mapping, and response action generation.
Mirrors the phishing/detector.py pattern.
"""

import base64
import io
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ...database import save_threat_event
from ...models.enums import (
    ActionType,
    EventSource,
    IncidentStatus,
    RiskLevel,
    ThreatCategory,
)
from ...models.schemas import (
    RecommendedAction,
    ThreatDetectionResult,
    ThreatIndicator,
)
from .explainer import DeepfakeExplainer
from .image_forensics import ImageForensicsAnalyzer
from .impersonation import ImpersonationDetector


class DeepfakeDetector:
    """Orchestrates deepfake image forensics and text-based impersonation detection."""

    def __init__(self):
        self.image_analyzer = ImageForensicsAnalyzer()
        self.impersonation_detector = ImpersonationDetector()
        self.explainer = DeepfakeExplainer()

    def analyze_image(self, image_bytes: bytes, filename: str = "uploaded_image") -> ThreatDetectionResult:
        """
        Runs full image forensics pipeline (ELA + DCT) on uploaded image bytes.
        Returns a complete ThreatDetectionResult.
        """
        # Run image forensics
        forensics_result = self.image_analyzer.analyze(image_bytes)

        # Compute risk score from combined forensics score
        combined_score = forensics_result["combined_score"]
        risk_score = round(combined_score * 100.0, 1)

        # Map to risk level
        risk_level = self._score_to_risk_level(risk_score)

        # Determine threat classification
        threat_classification = self._classify_image_threat(forensics_result, risk_level)

        # Map MITRE ATT&CK techniques
        mitre_techniques = self._map_image_mitre_techniques(forensics_result, risk_level)

        # Generate recommended actions
        recommended_actions = self._generate_image_actions(risk_level, threat_classification, filename)

        # Build indicators list
        all_indicators = list(forensics_result["indicators"])

        # Add ELA/DCT summary indicators
        ela_score = forensics_result["ela_score"]
        dct_score = forensics_result["dct_score"]

        if ela_score > 0.25:
            all_indicators.append(ThreatIndicator(
                name="ELA Compression Anomaly",
                category="Image Forensics / Error Level Analysis",
                weight=round(ela_score, 2),
                value=f"ELA Score: {ela_score:.1%} — {forensics_result['ela_details']['hotspot_count']} hotspot region(s)",
                description=f"Error Level Analysis detected compression inconsistencies across "
                            f"{forensics_result['ela_details']['hotspot_count']} image region(s). "
                            f"Coefficient of variation: {forensics_result['ela_details']['coefficient_of_variation']:.3f}."
            ))

        if dct_score > 0.25:
            all_indicators.append(ThreatIndicator(
                name="DCT Frequency Artifact",
                category="Image Forensics / Frequency Analysis",
                weight=round(dct_score, 2),
                value=f"DCT Score: {dct_score:.1%} — Periodicity: {forensics_result['dct_details']['periodicity_score']:.3f}",
                description=f"DCT frequency-domain analysis detected spectral anomalies consistent with "
                            f"{'double-JPEG compression' if forensics_result['dct_details']['double_compression_indicators'] else 'non-standard image processing'}. "
                            f"Blocks analyzed: {forensics_result['dct_details']['blocks_analyzed']}."
            ))

        # Generate human-readable explanation
        human_explanation = self.explainer.generate_image_explanation(
            risk_level=risk_level,
            threat_classification=threat_classification,
            ela_result=forensics_result,
            dct_result=forensics_result,
            combined_score=combined_score,
            indicators=all_indicators,
        )

        # Build result
        result = ThreatDetectionResult(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=EventSource.IMAGE,
            category=ThreatCategory.DEEPFAKE if risk_level != RiskLevel.SAFE else ThreatCategory.BENIGN,
            threat_classification=threat_classification,
            risk_score=risk_score,
            risk_level=risk_level,
            human_explanation=human_explanation,
            indicators=all_indicators,
            recommended_actions=recommended_actions,
            mitre_attack_techniques=mitre_techniques,
            target_identity=filename,
            origin_ip=None,
            raw_content_summary=f"Image forensics analysis: {filename} ({forensics_result['image_dimensions']['width']}x{forensics_result['image_dimensions']['height']})",
            metadata={
                "analysis_type": "image_forensics",
                "ela_score": ela_score,
                "dct_score": dct_score,
                "combined_score": combined_score,
                "image_dimensions": forensics_result["image_dimensions"],
                "image_format": forensics_result["image_format_info"],
                "ela_heatmap_base64": forensics_result["ela_heatmap_base64"],
                "dct_spectrum_base64": forensics_result["dct_spectrum_base64"],
                "ela_details": forensics_result["ela_details"],
                "dct_details": forensics_result["dct_details"],
            },
            incident_status=IncidentStatus.DETECTED if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else IncidentStatus.RESOLVED,
        )

        # Persist to SQLite
        try:
            save_threat_event(result)
        except Exception as e:
            print(f"Warning: Failed to save deepfake event to SQLite: {e}")

        return result

    def analyze_impersonation(
        self,
        text_content: Optional[str] = None,
        claimed_identity: Optional[str] = None,
        claimed_organization: Optional[str] = None,
        channel: str = "Email",
        urgency_context: Optional[str] = None,
    ) -> ThreatDetectionResult:
        """
        Runs text-based impersonation detection pipeline.
        Returns a complete ThreatDetectionResult.
        """
        # Run impersonation detection
        imp_result = self.impersonation_detector.analyze(
            text_content=text_content,
            claimed_identity=claimed_identity,
            claimed_organization=claimed_organization,
            channel=channel,
            urgency_context=urgency_context,
        )

        # Compute risk score
        imp_score = imp_result["impersonation_score"]
        risk_score = round(imp_score * 100.0, 1)

        # Map to risk level
        risk_level = self._score_to_risk_level(risk_score)

        # Determine threat classification
        threat_classification = self._classify_impersonation_threat(imp_result, risk_level)

        # Map MITRE ATT&CK techniques
        mitre_techniques = self._map_impersonation_mitre_techniques(imp_result, risk_level)

        # Generate recommended actions
        recommended_actions = self._generate_impersonation_actions(
            risk_level, threat_classification, claimed_identity, claimed_organization
        )

        # Build indicators
        all_indicators = list(imp_result["indicators"])

        # Generate explanation
        human_explanation = self.explainer.generate_impersonation_explanation(
            risk_level=risk_level,
            threat_classification=threat_classification,
            impersonation_result=imp_result,
            indicators=all_indicators,
        )

        # Determine source type
        source_map = {
            "Email": EventSource.EMAIL,
            "SMS / Message": EventSource.SMS,
            "SMS": EventSource.SMS,
        }
        source = source_map.get(channel, EventSource.EMAIL)

        # Build result
        result = ThreatDetectionResult(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=source,
            category=ThreatCategory.DIGITAL_IMPERSONATION if risk_level != RiskLevel.SAFE else ThreatCategory.BENIGN,
            threat_classification=threat_classification,
            risk_score=risk_score,
            risk_level=risk_level,
            human_explanation=human_explanation,
            indicators=all_indicators,
            recommended_actions=recommended_actions,
            mitre_attack_techniques=mitre_techniques,
            target_identity=claimed_identity or "Unknown",
            origin_ip=None,
            raw_content_summary=(text_content or "")[:150].strip(),
            metadata={
                "analysis_type": "impersonation_detection",
                "impersonation_score": imp_score,
                "signals_fired": imp_result["signals_fired"],
                "claimed_identity": claimed_identity,
                "claimed_organization": claimed_organization,
                "title_spoofing": imp_result["title_spoofing"],
                "org_similarity": imp_result["org_similarity"],
                "authority_pressure": imp_result["authority_pressure"],
                "communication_anomalies": imp_result["communication_anomalies"],
            },
            incident_status=IncidentStatus.DETECTED if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else IncidentStatus.RESOLVED,
        )

        # Persist to SQLite
        try:
            save_threat_event(result)
        except Exception as e:
            print(f"Warning: Failed to save impersonation event to SQLite: {e}")

        return result

    # ── Risk Level Mapping ───────────────────────────────────────────────

    def _score_to_risk_level(self, risk_score: float) -> RiskLevel:
        if risk_score >= 85.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 65.0:
            return RiskLevel.HIGH
        elif risk_score >= 40.0:
            return RiskLevel.MEDIUM
        elif risk_score >= 20.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    # ── Threat Classification ────────────────────────────────────────────

    def _classify_image_threat(self, forensics_result: Dict[str, Any], risk_level: RiskLevel) -> str:
        if risk_level == RiskLevel.SAFE:
            return "Authentic Image / No Manipulation Detected"

        ela_score = forensics_result.get("ela_score", 0)
        dct_score = forensics_result.get("dct_score", 0)
        dct_details = forensics_result.get("dct_details", {})

        if ela_score > 0.6 and dct_score > 0.5:
            return "High-Confidence Image Manipulation / Content Splicing"
        if dct_details.get("double_compression_indicators") and ela_score > 0.4:
            return "Double-Compressed Image with Localized Edits"
        if ela_score > 0.5:
            return "Suspected Image Tampering / Region Editing"
        if dct_details.get("double_compression_indicators"):
            return "Double JPEG Compression Detected"
        if dct_details.get("spectral_anomaly_detected"):
            return "Spectral Anomaly / Non-Standard Processing"

        return "Suspected Image Manipulation"

    def _classify_impersonation_threat(self, imp_result: Dict[str, Any], risk_level: RiskLevel) -> str:
        if risk_level == RiskLevel.SAFE:
            return "Legitimate Communication / No Impersonation Detected"

        title_info = imp_result.get("title_spoofing", {})
        pressure_info = imp_result.get("authority_pressure", {})
        org_info = imp_result.get("org_similarity", {})

        if title_info.get("detected") and pressure_info.get("financial_action_detected"):
            return "Business Email Compromise (BEC) / CEO Fraud Attack"
        if title_info.get("detected") and pressure_info.get("secrecy_request_detected"):
            return "Executive Impersonation with Secrecy Directive"
        if org_info.get("detected") and pressure_info.get("detected"):
            return "Organizational Identity Fraud with Coercive Pressure"
        if title_info.get("detected"):
            return "Authority-Figure Impersonation Attempt"
        if org_info.get("detected"):
            return "Organizational Identity Spoofing"
        if pressure_info.get("detected"):
            return "Social Engineering via Authority Pressure Tactics"

        return "Digital Impersonation / Identity Fraud"

    # ── MITRE ATT&CK Mapping ────────────────────────────────────────────

    def _map_image_mitre_techniques(self, forensics_result: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        if risk_level == RiskLevel.SAFE:
            return []

        techniques = ["T1583.001 - Acquire Infrastructure: Domains"]

        ela_score = forensics_result.get("ela_score", 0)
        if ela_score > 0.4:
            techniques.append("T1565.002 - Data Manipulation: Transmitted Data Manipulation")
            techniques.append("T1491 - Defacement")

        if forensics_result.get("dct_details", {}).get("double_compression_indicators"):
            techniques.append("T1027 - Obfuscated Files or Information")

        return techniques

    def _map_impersonation_mitre_techniques(self, imp_result: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        if risk_level == RiskLevel.SAFE:
            return []

        techniques = ["T1656 - Impersonation"]

        if imp_result.get("title_spoofing", {}).get("detected"):
            techniques.append("T1534 - Internal Spearphishing")
            techniques.append("T1566.001 - Phishing: Spearphishing Attachment")

        if imp_result.get("authority_pressure", {}).get("financial_action_detected"):
            techniques.append("T1657 - Financial Theft")

        if imp_result.get("org_similarity", {}).get("detected"):
            techniques.append("T1598 - Phishing for Information")

        if imp_result.get("authority_pressure", {}).get("secrecy_request_detected"):
            techniques.append("T1078 - Valid Accounts")

        return techniques

    # ── Response Actions ─────────────────────────────────────────────────

    def _generate_image_actions(
        self, risk_level: RiskLevel, threat_classification: str, filename: str
    ) -> List[RecommendedAction]:
        actions: List[RecommendedAction] = []

        if risk_level == RiskLevel.SAFE:
            actions.append(RecommendedAction(
                action_type=ActionType.ALLOW,
                title="Permit Content",
                description="No manipulation indicators found. Image appears authentic and unmodified.",
                priority=5,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            return actions

        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            actions.append(RecommendedAction(
                action_type=ActionType.FLAG_MANUAL_REVIEW,
                title="Flag Image for Digital Forensics Review",
                description=f"Route '{filename}' to Tier-2 SOC digital forensics queue for in-depth analysis "
                            "using advanced tools (FotoForensics, Amped Authenticate).",
                priority=1,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.REPORT_IMPERSONATION,
                title="File Manipulation/Deepfake Report",
                description="Submit manipulated media report to platform abuse team and document for legal evidence chain.",
                priority=2,
                is_automated=False,
                executed=False,
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.NOTIFY_ADMIN,
                title="Alert Security Team — Manipulated Media Detected",
                description="Dispatch high-priority alert to SOC with forensic evidence (ELA heatmap, DCT analysis).",
                priority=1,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            if risk_level == RiskLevel.CRITICAL:
                actions.append(RecommendedAction(
                    action_type=ActionType.ESCALATE_INCIDENT,
                    title="Escalate to Major Incident — Deepfake Campaign",
                    description="Trigger tier-3 incident response for potential coordinated deepfake/disinformation campaign.",
                    priority=1,
                    is_automated=False,
                    executed=False,
                ))
        else:
            actions.append(RecommendedAction(
                action_type=ActionType.WARN_USER,
                title="Display Unverified Media Warning",
                description="Inject a visual warning banner indicating the image may have been digitally altered.",
                priority=2,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.FLAG_MANUAL_REVIEW,
                title="Queue for Analyst Review",
                description="Route to analyst queue for secondary verification of image authenticity.",
                priority=3,
                is_automated=False,
                executed=False,
            ))

        return actions

    def _generate_impersonation_actions(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        claimed_identity: Optional[str],
        claimed_org: Optional[str],
    ) -> List[RecommendedAction]:
        actions: List[RecommendedAction] = []

        if risk_level == RiskLevel.SAFE:
            actions.append(RecommendedAction(
                action_type=ActionType.ALLOW,
                title="Permit Communication",
                description="No impersonation indicators detected. Communication appears legitimate.",
                priority=5,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            return actions

        identity_str = claimed_identity or "unknown identity"

        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            actions.append(RecommendedAction(
                action_type=ActionType.QUARANTINE_EMAIL,
                title="Quarantine Impersonation Message",
                description=f"Isolate message claiming to be from '{identity_str}' and initiate retroactive search "
                            "across all mailboxes for similar patterns.",
                priority=1,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.REPORT_IMPERSONATION,
                title="File Impersonation Abuse Report",
                description=f"Report identity fraud attempt impersonating '{identity_str}'"
                            f"{f' from {claimed_org}' if claimed_org else ''} to platform abuse team.",
                priority=1,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.NOTIFY_ADMIN,
                title="Alert SOC — BEC/Impersonation Attack",
                description="Dispatch high-priority alert with impersonation evidence to SOC Slack/webhook channel.",
                priority=1,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            if risk_level == RiskLevel.CRITICAL:
                actions.append(RecommendedAction(
                    action_type=ActionType.ESCALATE_INCIDENT,
                    title="Escalate BEC Incident to Tier-3",
                    description="Trigger major incident playbook for Business Email Compromise targeting financial operations.",
                    priority=1,
                    is_automated=False,
                    executed=False,
                ))
        else:
            actions.append(RecommendedAction(
                action_type=ActionType.WARN_USER,
                title="Display Impersonation Warning Banner",
                description=f"Inject warning banner indicating potential identity spoofing of '{identity_str}'.",
                priority=2,
                is_automated=True,
                executed=True,
                executed_at=datetime.now(timezone.utc),
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.FLAG_MANUAL_REVIEW,
                title="Flag for SOC Analyst Verification",
                description="Route suspected impersonation to analyst queue for sender identity verification.",
                priority=3,
                is_automated=False,
                executed=False,
            ))

        return actions

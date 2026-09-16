"""
Deepfake & Impersonation Explainer — Natural-language explanation generator.

Produces SOC-analyst quality, evidence-driven explanations for deepfake
and impersonation detection results. Mirrors the phishing explainer pattern.
"""

from typing import Any, Dict, List

from ...models.enums import RiskLevel
from ...models.schemas import ThreatIndicator


class DeepfakeExplainer:
    """Generates human-readable, evidence-driven threat explanations for deepfake/impersonation analysis."""

    def generate_image_explanation(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        ela_result: Dict[str, Any],
        dct_result: Dict[str, Any],
        combined_score: float,
        indicators: List[ThreatIndicator],
    ) -> str:
        """Generates explanation for image forensics analysis results."""
        if risk_level == RiskLevel.SAFE:
            return (
                "Safe: Image forensic analysis reveals consistent compression artifacts across all regions, "
                "uniform error level distribution, and no spectral anomalies in DCT frequency domain. "
                "The image exhibits characteristics consistent with single-capture, unmodified origin."
            )

        parts = [f"{risk_level.value} Risk ({threat_classification}):"]

        # ELA findings
        ela_score = ela_result.get("ela_score", 0)
        ela_details = ela_result.get("ela_details", {})
        hotspot_count = ela_details.get("hotspot_count", 0)

        if ela_score > 0.5:
            parts.append(
                f"Error Level Analysis reveals significant compression inconsistencies "
                f"(ELA score: {ela_score:.1%}) with {hotspot_count} anomalous region(s) "
                f"showing error levels that deviate substantially from the image baseline. "
                f"This pattern is characteristic of localized post-capture editing or content splicing."
            )
        elif ela_score > 0.3:
            parts.append(
                f"Error Level Analysis detected moderate compression variance "
                f"(ELA score: {ela_score:.1%}) with {hotspot_count} region(s) of interest. "
                f"The error level distribution suggests possible re-saving or minor modifications."
            )

        # DCT findings
        dct_score = dct_result.get("dct_score", 0)
        dct_details = dct_result.get("dct_details", {})

        if dct_details.get("double_compression_indicators"):
            parts.append(
                f"DCT frequency-domain analysis detected periodic artifacts in the block energy distribution "
                f"(periodicity score: {dct_details.get('periodicity_score', 0):.2f}) consistent with "
                f"double-JPEG compression — a strong indicator that the image was decoded, modified, and re-encoded."
            )
        elif dct_score > 0.3:
            parts.append(
                f"Spectral analysis reveals anomalous high-frequency energy distribution "
                f"(DCT score: {dct_score:.1%}) suggesting non-standard image processing pipeline."
            )

        # Additional indicator evidence
        for ind in indicators:
            if ind.name not in ("ELA Compression Anomaly", "DCT Frequency Artifact"):
                parts.append(f"{ind.description}")

        return " ".join(parts)

    def generate_impersonation_explanation(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        impersonation_result: Dict[str, Any],
        indicators: List[ThreatIndicator],
    ) -> str:
        """Generates explanation for text-based impersonation detection results."""
        if risk_level == RiskLevel.SAFE:
            return (
                "Safe: Communication analysis reveals no authority-figure impersonation indicators, "
                "no organizational identity spoofing patterns, and no coercive pressure tactics. "
                "The message presents standard communication patterns consistent with legitimate correspondence."
            )

        parts = [f"{risk_level.value} Risk ({threat_classification}):"]

        # Title spoofing
        title_info = impersonation_result.get("title_spoofing", {})
        if title_info.get("detected"):
            titles = ", ".join(title_info.get("matched_titles", [])[:3])
            parts.append(
                f"The communication claims authority through executive title impersonation "
                f"({titles}). This is a hallmark pattern of Business Email Compromise (BEC) "
                f"and CEO fraud campaigns targeting organizational trust hierarchies."
            )

        # Org similarity
        org_info = impersonation_result.get("org_similarity", {})
        if org_info.get("detected"):
            parts.append(
                f"The sender claims affiliation with '{org_info.get('matched_org', 'a known organization')}' "
                f"(similarity match: {org_info.get('similarity', 0):.0%}). "
                f"Verify organizational affiliation through independent, pre-established contact channels."
            )

        # Authority pressure
        pressure_info = impersonation_result.get("authority_pressure", {})
        if pressure_info.get("detected"):
            phrase_count = len(pressure_info.get("matched_phrases", []))
            parts.append(
                f"The message employs {phrase_count} coercive psychological pressure tactic(s) "
                f"combining authority claims with urgency demands."
            )
            if pressure_info.get("financial_action_detected"):
                parts.append(
                    "CRITICAL: Financial action requested (fund transfer, payment, or account update) — "
                    "this combination with authority impersonation is the primary BEC attack vector."
                )
            if pressure_info.get("secrecy_request_detected"):
                parts.append(
                    "The communication explicitly requests secrecy or bypass of standard verification procedures — "
                    "a strong indicator of fraudulent intent."
                )

        # Style anomalies
        style_info = impersonation_result.get("communication_anomalies", {})
        if style_info.get("detected"):
            anomalies = "; ".join(style_info.get("anomalies", [])[:2])
            parts.append(
                f"Communication style analysis flagged anomalies: {anomalies}."
            )

        return " ".join(parts)

    def generate_combined_explanation(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        image_result: Dict[str, Any] | None,
        impersonation_result: Dict[str, Any] | None,
        indicators: List[ThreatIndicator],
    ) -> str:
        """Generates combined explanation when both image and text analysis are present."""
        if risk_level == RiskLevel.SAFE:
            return (
                "Safe: Multi-modal analysis (image forensics + communication content) reveals no manipulation "
                "artifacts, impersonation indicators, or coercive pressure tactics. Content appears authentic."
            )

        parts = [f"{risk_level.value} Risk ({threat_classification}) — Multi-Modal Analysis:"]

        if image_result:
            ela_score = image_result.get("ela_score", 0)
            dct_score = image_result.get("dct_score", 0)
            if ela_score > 0.3 or dct_score > 0.3:
                parts.append(
                    f"Image forensics detected manipulation indicators "
                    f"(ELA: {ela_score:.1%}, DCT: {dct_score:.1%})."
                )

        if impersonation_result:
            imp_score = impersonation_result.get("impersonation_score", 0)
            signals = impersonation_result.get("signals_fired", 0)
            if imp_score > 0.2:
                parts.append(
                    f"Impersonation detection triggered {signals} independent signal(s) "
                    f"(confidence: {imp_score:.1%})."
                )

        # Add top indicator descriptions
        for ind in indicators[:3]:
            parts.append(ind.description)

        return " ".join(parts)

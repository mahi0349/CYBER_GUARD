import os
import logging
from typing import List
from app.schemas.analysis import EvidenceItem
from app.config import settings

logger = logging.getLogger("quantumvault.explanation")

class ExplanationEngine:
    """
    QuantumVault Dual-Mode Explainability Engine.
    Leverages Gemini 3.8 / 2.0 Flash for structured cybersecurity narrative,
    with an intelligent offline fallback when API key is not configured.
    """

    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
        self.model_name = settings.GEMINI_MODEL
        self.client = None
        
        if self.api_key:
            try:
                from google import genai
                # Configure 6-second timeout so API calls never hang FastAPI worker threads
                self.client = genai.Client(api_key=self.api_key, http_options={"timeout": 6000})
                logger.info("Gemini AI Client initialized successfully for Threat Explanations.")
            except Exception as e:
                logger.warning(f"Could not initialize Gemini Client: {e}")

    def generate_explanation(
        self,
        threat_type: str,
        risk_score: int,
        severity: str,
        evidence: List[EvidenceItem],
        target_reference: str = ""
    ) -> str:
        # Try Gemini if client is ready
        if self.client:
            try:
                from google.genai import types
                prompt = f"""You are a Lead Tier-3 SOC Analyst at QuantumVault.
Provide a concise, authoritative 2-3 sentence threat explanation for an analyst dashboard.

Context:
- Threat Category: {threat_type.upper()}
- Severity: {severity} (Risk Score: {risk_score}/100)
- Target: {target_reference}
- Evidence Indicators Detected:
{chr(10).join(f"  * {e.indicator}: {e.description}" for e in evidence)}

Explain:
1. Why this is classified as {severity}.
2. The specific tactical risk posed to the organization.
3. Recommended immediate containment stance.

Keep the response strictly factual, direct, and under 90 words without markdown headers."""

                # Disable AFC to prevent AFC warnings and unnecessary roundtrips
                gen_config = types.GenerateContentConfig(
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)
                )

                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=gen_config
                )
                if response and response.text:
                    return response.text.strip()
            except Exception as e:
                logger.warning(f"Gemini AI explanation unavailable ({e}), using deterministic explanation.")

        # Fallback SOC Template Engine
        return self._generate_fallback(threat_type, risk_score, severity, evidence, target_reference)

    def _generate_fallback(
        self,
        threat_type: str,
        risk_score: int,
        severity: str,
        evidence: List[EvidenceItem],
        target: str
    ) -> str:
        if severity == "SAFE":
            return (
                f"Automated threat inspection verified {target or 'the input'} as legitimate. "
                "No malicious heuristics, domain impersonation patterns, or unauthorized anomalies were observed. "
                "Confidence score confirms safe state."
            )

        indicator_names = [e.indicator.replace("_", " ").title() for e in evidence[:3]]
        indicators_str = ", ".join(indicator_names) if indicator_names else "structural heuristics"

        if threat_type == "phishing":
            return (
                f"{severity} phishing risk detected (Score: {risk_score}/100). "
                f"The target exhibits deceptive characteristics including {indicators_str}. "
                "The domain mimics legitimate authentication endpoints to facilitate credential harvesting. "
                "Immediate URL perimeter blocking and recipient quarantine recommended."
            )
        elif threat_type == "deepfake":
            return (
                f"{severity} synthetic media manipulation identified (Score: {risk_score}/100). "
                f"Analysis detected visual inconsistencies and high-frequency noise artifacts ({indicators_str}). "
                "The biometric signature indicates artificial facial synthesis or unauthorized voice cloning. "
                "Manual identity verification must be mandated prior to privileged access."
            )
        elif threat_type == "account_takeover":
            return (
                f"{severity} unauthorized access attempt flagged (Score: {risk_score}/100). "
                f"Behavioral telemetry triggered alerts for {indicators_str}, deviating sharply from baseline activity. "
                "High probability of credential stuffing or hijacked session tokens. "
                "Active sessions should be revoked and MFA challenge enforced immediately."
            )
        
        return (
            f"{severity} security event recorded with composite risk score of {risk_score}/100 based on {indicators_str}. "
            "Automated containment procedures have been staged for SOC review."
        )

explanation_engine = ExplanationEngine()

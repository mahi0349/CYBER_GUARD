from typing import List, Dict, Tuple
from app.schemas.analysis import EvidenceItem
from app.config import settings

class RiskEngine:
    """
    CYBERGUARD Deterministic Risk Scoring Engine.
    
    Formula:
      Risk Score = min(100, max(0, Base ML Confidence Contribution + Sum(Rule Penalty Weights)))
      
    Policy Severity:
      0 - 19  : SAFE
      20 - 39 : LOW
      40 - 59 : MEDIUM
      60 - 79 : HIGH
      80 - 100: CRITICAL
    """

    @staticmethod
    def calculate_risk(
        ml_probability: float,
        evidence: List[EvidenceItem],
        base_threat_weight: int = 70
    ) -> Tuple[int, str]:
        # 1. Base ML contribution (scaled up to base_threat_weight, e.g. 0.95 * 70 = 66.5)
        base_score = ml_probability * base_threat_weight
        
        # 2. Rule penalty additions from observed indicators
        rule_penalties = sum(item.weight for item in evidence)
        
        # 3. Final composite score clamped to [0, 100]
        raw_score = round(base_score + rule_penalties)
        final_score = max(0, min(100, raw_score))
        
        # 4. Severity classification based on configurable policy thresholds
        if final_score >= settings.RISK_THRESHOLD_CRITICAL:
            severity = "CRITICAL"
        elif final_score >= settings.RISK_THRESHOLD_HIGH:
            severity = "HIGH"
        elif final_score >= settings.RISK_THRESHOLD_MEDIUM:
            severity = "MEDIUM"
        elif final_score >= settings.RISK_THRESHOLD_LOW:
            severity = "LOW"
        else:
            severity = "SAFE"
            
        return final_score, severity

risk_engine = RiskEngine()

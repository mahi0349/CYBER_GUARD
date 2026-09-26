# CYBERGUARD Architecture Specification

## 1. Threat Ingestion & Orchestration Layer
The Threat Orchestrator routes inputs based on asset type:
- **URL / Email / SMS** -> Phishing Analysis Engine
- **Image / Profile Media** -> Deepfake Assessment Engine
- **Authentication Logs** -> Behavioral Anomaly Detector

## 2. Deterministic Risk Engine Formula
Unlike uninterpretable black-box scores, CYBERGUARD uses an additive deterministic scoring system:

$$\text{RiskScore} = \min(100, \max(0, \text{BaseScore} + \sum \text{RulePenalties}))$$

### Severity Policy Thresholds:
- **0–19**: SAFE
- **20–39**: LOW
- **40–59**: MEDIUM
- **60–79**: HIGH
- **80–100**: CRITICAL

## 3. Explainability Layer (Dual Engine)
- **Primary**: Google Gemini 3.8 Flash with structured JSON output schema.
- **Fallback**: Deterministic rule-based template engine (activates if offline or if no API key is supplied).

## 4. Response & Containment Engine
All containment operations in this prototype are non-destructive and simulated:
- Incident status transitions to `CONTAINED`
- Simulated actions recorded to `response_actions` audit log
- MITRE ATT&CK technique tagging for SIEM export

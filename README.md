# QuantumVault — AI Cyber Threat Detection & Response Platform

QuantumVault is an AI-driven Security Operations Center (SOC) threat detection, explainability, and automated response platform. It unifies multi-vector threat detection (Phishing, Deepfake/Impersonation, and Account Takeover/Behavior Anomalies) with deterministic risk scoring, Gemini-powered explainability, and simulated incident containment mapped to the MITRE ATT&CK framework.

---

## 🏛️ System Architecture

```
                         QuantumVault
                             │
              ┌──────────────┴──────────────┐
              │       React Dashboard       │  (Vite, Tailwind, Recharts, Lucide)
              └──────────────┬──────────────┘
                             │ REST API
                         FastAPI
                             │
                 ┌───────────┴───────────┐
                 │   Threat Orchestrator │
                 └───────────┬───────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   PHISHING              DEEPFAKE             BEHAVIOR
   DETECTOR              DETECTOR             DETECTOR
  (Random Forest)     (Visual Artifacts)  (Isolation Forest)
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ▼
                       RISK ENGINE (0-100 Score & Policy)
                             │
                             ▼
                    EXPLANATION ENGINE (Gemini 3.8 Flash)
                             │
                             ▼
                   RESPONSE RECOMMENDER (MITRE ATT&CK & Actions)
                             │
                             ▼
                 PostgreSQL / SQLite Database
```

---

## ⚡ Quick Start

### 1. Backend Setup
```bash
cd backend
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API Documentation: `http://localhost:8000/docs`

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend Dashboard: `http://localhost:5173`

### 3. Database (Optional Docker PostgreSQL)
```bash
docker-compose up -d
```
*Note: If PostgreSQL is not running, QuantumVault automatically falls back to local SQLite (`quantumvault.db`), requiring zero setup!*

---

## 🎯 Hackathon Demo Scenarios

1. **Scenario 1 — Phishing Detection**
   - Input: Urgent banking suspension URL (`https://secure-bank-login-verify.com/auth`)
   - Detection: Lexical analysis + Random Forest ML (96% phishing probability)
   - Risk: 94/100 (CRITICAL)
   - Response: Quarantine URL, Alert SOC, Notify Recipient

2. **Scenario 2 — Deepfake / Impersonation Assessment**
   - Input: Manipulated executive image / profile photo
   - Detection: Visual frequency artifact & facial consistency analysis
   - Risk: 87/100 (SUSPICIOUS)
   - Response: Flag for manual SOC verification, restrict privileged actions

3. **Scenario 3 — Account Takeover / Behavioral Anomaly**
   - Input: Login audit logs with 14 failed attempts, impossible travel, and new device
   - Detection: Isolation Forest behavioral anomaly detector
   - Risk: 91/100 (CRITICAL)
   - Response: Revoke Session, Require MFA, Block Attacker IP

# CYBERGUARD 🛡️
> **AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System**

CYBERGUARD is an advanced multi-layered cybersecurity platform that detects, analyzes, and provides automated response strategies for modern AI-era cyber threats across both the **human layer** (phishing, social engineering, deepfakes, brand impersonation) and the **technology layer** (account takeover, credential stuffing, anomalous behavioral patterns).

---

## 🚀 Key Modules & Capabilities

### 1. Phishing & Social Engineering Engine (Scenario A)
- **Multi-Vector Threat Analysis**: Analyzes email/SMS content, subject lines, header metadata, sender spoofing, and embedded hyperlinks.
- **Explainable Indicators**: Highlights suspicious lexical cues, urgency pressure words, zero-trust credential harvesting indicators, and typo-squatted domains.
- **Domain & URL Reputation Scoring**: Evaluates suspicious TLDs, entropy, domain impersonation, and multi-redirect behavior.

### 2. Deepfake & Digital Impersonation Engine (Scenario B)
- **Image & Media Forensics**: Performs Error Level Analysis (ELA), frequency domain artifact detection, and compression anomaly detection on uploaded identity assets.
- **Executive / VIP Impersonation Detection**: Identifies communication patterns mimicking corporate authority or IT security personas to coerce wire transfers or credential sharing.
- **Multimodal Risk Aggregation**: Synthesizes visual and linguistic markers into a unified risk confidence score.

### 3. Account Takeover & Anomaly Detection (Scenario C)
- **Behavioral Anomaly Detection**: Uses unsupervised machine learning (Isolation Forest) alongside deterministic security policies to flag impossible travel, velocity spikes, and brute force login attempts.
- **MITRE ATT&CK Mapping**: Maps detected event chains directly to industry-standard MITRE ATT&CK tactics and techniques (e.g., T1110, T1078).
- **Automated Response Playbooks**: Recommends immediate containment actions (session invalidation, forced step-up MFA, IP blocking).

### 4. Interactive Cybersecurity Command Dashboard
- Real-time threat visualizer with dynamic charts (Recharts), indicator severity breakdowns, and interactive playbooks.
- Incident log history with SQLite backend.

---

## 🏗️ Architecture & Tech Stack

- **Backend**: Python 3.10+, [FastAPI](https://fastapi.tiangolo.com/), [Scikit-learn](https://scikit-learn.org/), NumPy, Pandas, Pillow, OpenCV, SQLite.
- **Frontend**: [React 19](https://react.dev/), [Vite](https://vitejs.dev/), [Tailwind/Vanilla CSS](https://developer.mozilla.org/en-US/docs/Web/CSS), [Lucide React Icons](https://lucide.dev/), [Recharts](https://recharts.org/).

---

## 📦 Getting Started

### Prerequisites
- Python 3.10 or higher
- Node.js 18 or higher & npm

### 1. Backend Setup
```bash
cd backend
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Backend API will be accessible at: `http://localhost:8000` (Swagger docs at `http://localhost:8000/docs`).

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend dashboard will be accessible at: `http://localhost:5173`.

---

## 🔒 Security & Privacy Notice

CYBERGUARD is designed with security-first practices:
- Local database storage and sandbox execution.
- Sensitive environment files (`.env`), private keys, and runtime databases are strictly excluded from version control via `.gitignore`.

---

## 📄 License
MIT License.

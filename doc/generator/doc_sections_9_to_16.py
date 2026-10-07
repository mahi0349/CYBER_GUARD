"""
Sections 9 to 16 of QuantumVault Documentation
"""
def add_sections_9_to_16(b):
    # -------------------------------------------------------------
    # SECTION 9: TECHNOLOGY STACK
    # -------------------------------------------------------------
    b.add_h1("9. Technology Stack")
    b.add_p("The table below details all core technologies, runtime environments, frameworks, and third-party libraries utilized across Quantum Vault, verified directly against backend/requirements.txt and frontend/package.json.")

    b.add_table(
        ["Category", "Technology", "Verified Version", "Implementation Role & Purpose in Quantum Vault"],
        [
            ["Backend Framework", "FastAPI", ">=0.110.0", "Asynchronous ASGI web framework powering REST APIs and high-throughput WebSockets."],
            ["ASGI Web Server", "Uvicorn (Standard)", ">=0.28.0", "High-performance event-loop server for async concurrency and WebSocket lifecycle."],
            ["Data Validation", "Pydantic & Settings", ">=2.6.0 / >=2.2.0", "Type enforcement, request body validation, and environment configuration loading."],
            ["ORM & Database", "SQLAlchemy", ">=2.0.28", "Enterprise relational database object mapper with dual SQLite/PostgreSQL dialect support."],
            ["Database Driver", "psycopg2-binary", ">=2.9.9", "Production C-extension PostgreSQL database driver."],
            ["Machine Learning", "Scikit-Learn", ">=1.4.0", "Random Forest URL classifier, Isolation Forest anomaly detector, and metric evaluators."],
            ["Data Processing", "Pandas & NumPy", ">=2.2.0 / >=1.26.0", "Feature array manipulation, spectral matrix calculations, and log stream parsing."],
            ["Model Serializer", "Joblib", ">=1.3.2", "Serialization and zero-latency loading of pre-trained binary models (.joblib)."],
            ["AI Reasoning", "Google GenAI SDK", ">=0.1.1", "Gemini 3.8 Flash SDK for automated SOC analyst threat explanations."],
            ["Image Forensics", "Pillow (PIL)", ">=10.2.0", "Image decoding, EXIF metadata inspection, and RGB channel array extraction."],
            ["Domain Intel", "python-whois", ">=0.9.4", "Automated WHOIS queries for domain creation date and registrar verification."],
            ["DNS Forensics", "dnspython", ">=2.6.0", "DNS resolution of TXT records for SPF and DMARC email authentication validation."],
            ["Audio Forensics", "Librosa & Soundfile", ">=0.10.0 / >=0.12.0", "Digital audio signal processing, Mel-spectrogram calculation, and spectral flatness."],
            ["Endpoint Telemetry", "psutil (Agent)", ">=5.9.0 / >=6.0.0", "Non-invasive retrieval of process trees, CPU, memory, disks, and network sockets."],
            ["Frontend Framework", "React", "^19.2.8", "Modern declarative UI framework rendering real-time reactive security dashboards."],
            ["Type System", "TypeScript", "~6.0.2", "Strict static typing across all UI components, state stores, and API clients."],
            ["Build & Bundler", "Vite", "^8.3.0", "High-speed frontend development server and optimized ES-module production builder."],
            ["Styling & CSS", "TailwindCSS", "^3.4.19", "Utility-first CSS framework styled with custom dark-mode cybersecurity palette."],
            ["UI Visualization", "Recharts & Lucide", "^3.10.1 / ^1.47.0", "SVG charting (radar, timeline, bar) and comprehensive security icon set."],
            ["Containerization", "Docker & Compose", "Engine 24+ / v2", "Multi-stage production containerization with Alpine PostgreSQL and Nginx proxy."]
        ],
        [1.3, 1.4, 1.1, 2.7]
    )

    # -------------------------------------------------------------
    # SECTION 10: SYSTEM ARCHITECTURE
    # -------------------------------------------------------------
    b.add_h1("10. System Architecture")
    b.add_p("Quantum Vault follows an asynchronous layered architecture separating endpoint sensor collection, API gateway routing, forensic detection pipelines, persistent storage, and reactive user interfaces.")

    b.add_h2("10.1 Layered Decomposition")
    b.add_bullet("1. Sensor & Endpoint Agent Layer (Local OS):", "Runs on the protected Windows workstation. Executes non-invasive probes every 3 to 15 seconds, aggregating system vitals, running processes, sockets, Windows Defender state, and firewall profiles.")
    b.add_bullet("2. Ingestion & Concurrency Guard Layer:", "Exposed via WebSocket (/api/v1/command-center/agent-ws) and fallback HTTP (/ingest). Enforces single-device licensing: validates device identity, locks the active connection, and broadcasts updates to SOC browsers.")
    b.add_bullet("3. Forensic Detection & Analysis Engine Layer:", "Stateless micro-services evaluating external threat submissions: Phishing Service (lexical + RF), Email Analyzer (SPF/DMARC + NLP), Deepfake Engine (2D FFT + Laplacian), Audio Forensics (Librosa), and Behavior Service (Isolation Forest).")
    b.add_bullet("4. Cognitive AI & Explanation Layer:", "Consumes threat evidence from detection engines, formatting structured prompts to Gemini 3.8 Flash to produce concise tactical explanations. Operates an integrated deterministic rule engine for offline failover.")
    b.add_bullet("5. Incident Orchestration & Response Layer:", "Automatically binds HIGH/CRITICAL threats to formal Incident records with unique tracking codes (e.g. QV-1021), MITRE ATT&CK technique tags, and simulated response playbooks.")
    b.add_bullet("6. Persistence & Diagnostics Layer:", "Maintains 13 relational tables in PostgreSQL or SQLite. Houses an active diagnostic watcher that checks port 5432 and manages dynamic database reconnection.")
    b.add_bullet("7. Presentation & Operator Layer:", "React 19 single-page application providing an interactive dark-mode command center, live charts, process inspection modals, and incident triage queues.")

    b.add_h2("10.2 Architectural Communication Flow")
    b.add_code(
"""[ Windows Endpoint ]                        [ FastAPI Backend ]                    [ React SOC Frontend ]
        |                                           |                                         |
        |--- 1. WS Connect (Token, DeviceID) ------>|                                         |
        |    (Validates Single-Device Lock)         |                                         |
        |<-- 2. Accept WebSocket Connection --------|                                         |
        |                                           |                                         |
        |--- 3. Stream Telemetry (JSON every 3s) -->|--- 4. Broadcast to Browser WS ---------->|
        |    (CPU, RAM, Procs, Firewall, Defender)  |    (Real-time State Update)             |
        |                                           |                                         |
        |                                           |<-- 5. Trigger Scan (/scans/run) --------|
        |<-- 6. Forward Scan Command (ScanType) ----|                                         |
        |--- 7. Scan Findings Returned ------------>|--- 8. Update DB & Broadcast Findings -->|
        |                                           |                                         |
        |                                           |<-- 9. External Threat Submission -------|
        |                                           |    (URL / Email / Image / Audio)        |
        |                                           |-- 10. Run Forensic ML & SafeBrowsing ->|
        |                                           |-- 11. Request Gemini XAI Explanation ->|
        |                                           |-- 12. Create Threat & Incident in DB ->|
        |                                           |--- 13. Return Structured Analysis ----->|
"""
    )

    # -------------------------------------------------------------
    # SECTION 11: PROJECT/FOLDERS STRUCTURE
    # -------------------------------------------------------------
    b.add_h1("11. Project/Folders Structure")
    b.add_p("The Quantum Vault codebase is organized into a clean multi-tier structure separating agent collectors, backend microservices, machine learning models, frontend single-page application, and deployment assets.")

    b.add_code(
"""d:/BPUT Project/
├── .gitignore                      # Git exclusion rules (safeguards .env, *.db, cache)
├── Dockerfile                      # Root / deployment build configuration
├── docker-compose.yml              # Local Docker Compose (PostgreSQL service)
├── docker-compose.prod.yml         # Full-stack production Compose (DB + Backend + Nginx)
├── README.md                       # Repository overview and quickstart instructions
├── run_agent.bat                   # 1-Click Windows Batch Endpoint Agent Launcher
├── agent_launcher.py               # Python entrypoint for endpoint agent execution
├── QuantumVault-Agent.spec         # PyInstaller compilation specification for agent
│
├── agent/                          # WINDOWS ENDPOINT SECURITY AGENT
│   ├── __init__.py                 # Agent package marker
│   ├── config.py                   # Agent configuration, URL resolution & intervals
│   ├── main.py                     # Main agent telemetry loop & background scheduler
│   ├── transport.py                # WebSocket client with auto-reconnect & HTTP fallback
│   ├── collectors/                 # OS telemetry collection modules
│   │   ├── __init__.py
│   │   ├── defender.py             # Windows Defender status & signature age inspector
│   │   ├── firewall.py             # Windows Firewall multi-profile status inspector
│   │   ├── network.py              # Active TCP/UDP socket & listener probe (psutil)
│   │   ├── processes.py            # Running process inspector & anomaly classifier
│   │   ├── services.py             # Windows service inventory & state inspector
│   │   ├── software.py             # Installed software registry harvester (HKLM/HKCU)
│   │   ├── startup.py              # Windows Run registry key persistence harvester
│   │   ├── system.py               # CPU, RAM, disk usage, uptime, and host metadata
│   │   ├── files.py                # File creation monitor for Downloads, Startup, Temp
│   │   └── windows_events.py       # Windows Event Log security auditor (wevtutil)
│   └── detection/                  # Agent-side detection rules
│       └── rules.py                # Heuristic rules for high-risk processes & paths
│
├── backend/                        # FASTAPI THREAT ORCHESTRATION BACKEND
│   ├── Dockerfile                  # Production container recipe for FastAPI backend
│   ├── requirements.txt            # Python dependencies (FastAPI, SQLAlchemy, ML)
│   ├── .env.example                # Safe environment variable configuration template
│   └── app/
│       ├── __init__.py
│       ├── main.py                 # FastAPI application, CORS, routers & lifespan
│       ├── config.py               # Pydantic BaseSettings loading environment config
│       ├── seed.py                 # Database initialization & default user seeder
│       ├── api/                    # API route controllers mounted under /api/v1
│       │   ├── analyze.py          # Threat analysis endpoints (URL, Email, Media, Log)
│       │   ├── auth.py             # Analyst authentication & session verification
│       │   ├── command_center.py   # Agent WebSocket, devices, telemetry & scan triggers
│       │   ├── dashboard.py        # SOC telemetry stats, trends & ML model metrics
│       │   ├── email_auth.py       # Raw .eml file authenticity & forensic analysis
│       │   ├── incidents.py        # Incident management queue & response actions
│       │   ├── settings.py         # Risk policy thresholds & PostgreSQL diagnostics
│       │   └── threats.py          # Threat query, filter, and detail endpoints
│       ├── models/                 # SQLAlchemy 2.0 ORM database models
│       │   ├── database.py         # Engine factory, session generator & DB diagnostics
│       │   ├── endpoint.py         # EndpointDevice, Scan, Alert, Event tables
│       │   ├── incident.py         # Incident and ResponseAction tables
│       │   ├── settings.py         # SystemPolicy configuration table
│       │   ├── threat.py           # Threat, ThreatEvidence, Scan, ModelPrediction
│       │   └── user.py             # User and LoginEvent tables
│       ├── schemas/                # Pydantic request & response data models
│       │   ├── analysis.py         # EvidenceItem, AnalysisResponse schemas
│       │   ├── command_center.py   # Telemetry, process, network, scan DTO schemas
│       │   ├── dashboard.py        # Dashboard stats and incident DTO schemas
│       │   └── settings.py         # Policy and database diagnostic schemas
│       ├── services/               # Core forensic & detection business logic
│       │   ├── audio_forensics.py  # Spectral flatness & acoustic deepfake forensics
│       │   ├── behavior_service.py # Isolation Forest login anomaly detector
│       │   ├── deepfake_service.py # 2D FFT & Laplacian image forensic pipeline
│       │   ├── email_analyzer.py   # NLP & DNS SPF/DMARC email analyzer
│       │   ├── email_auth.py       # In-depth RFC-822 header parser & homoglyph engine
│       │   ├── endpoint_risk_engine.py # Deterministic host risk scoring engine (0-100)
│       │   ├── endpoint_security.py    # Singleton managing devices, WS & single-device lock
│       │   ├── explanation_engine.py   # Gemini 3.8 Flash XAI & rule-based fallback
│       │   ├── phishing_service.py     # 12-feature Random Forest & Google SafeBrowsing
│       │   ├── response_engine.py      # MITRE ATT&CK mapper & simulated playbooks
│       │   └── risk_engine.py          # Unified threat risk weighting engine
│       └── tests/                  # Automated Pytest suite
│           ├── test_api.py         # Threat analysis & risk engine integration tests
│           ├── test_command_center.py # Endpoint risk engine & status route tests
│           └── test_email_auth.py  # Comprehensive RFC-822 email parser unit tests
│
├── frontend/                       # REACT 19 / TYPESCRIPT SOC FRONTEND
│   ├── Dockerfile                  # Multi-stage Nginx container recipe for frontend
│   ├── nginx.conf                  # Nginx production reverse proxy configuration
│   ├── package.json                # Frontend dependencies & npm script commands
│   ├── tsconfig.json               # TypeScript project compiler configuration
│   ├── vite.config.ts              # Vite configuration (proxy & alias settings)
│   ├── index.html                  # Single-page application HTML entrypoint
│   └── src/
│       ├── main.tsx                # React DOM root bootstrapping
│       ├── App.tsx                 # Root layout, navigation router & sidebar state
│       ├── index.css               # Global styles, cyber-grid animations & theme
│       ├── components/
│       │   ├── command-center/     # Endpoint modals (AgentDownload, Process, Scan, Alert)
│       │   ├── common/             # Reusable Header and Sidebar components
│       │   └── dashboard/          # StatCards, EvidenceList, MitreBadge, RiskMeter
│       ├── pages/                  # Top-level route views
│       │   ├── Dashboard.tsx       # Live Endpoint Command Center (Single-Device)
│       │   ├── ThreatScanner.tsx   # Unified multi-vector threat scanner
│       │   ├── PhishingScanner.tsx # URL & Email forensic analysis interface
│       │   ├── DeepfakeScanner.tsx # Image & Audio synthetic media forensic lab
│       │   ├── BehaviorAnalyzer.tsx# Login anomaly stream & CSV forensic lab
│       │   ├── Incidents.tsx       # SOC incident response queue & playbook trigger
│       │   ├── Analytics.tsx       # Historical telemetry trends & ML confusion matrices
│       │   └── Settings.tsx        # Risk policy threshold sliders & DB diagnostics
│       ├── services/               # HTTP & WebSocket API client services
│       │   ├── api.ts              # Core Axios client for /api/v1 endpoints
│       │   └── commandCenterApi.ts # Command center endpoints & WebSocket helpers
│       └── types/                  # TypeScript interface declarations
│           ├── index.ts            # Threat, Evidence, Analysis, Incident interfaces
│           └── commandCenter.ts    # Device, Process, Telemetry, Scan interfaces
│
├── ml/                             # MACHINE LEARNING MODELS & TRAINING
│   ├── models/
│   │   ├── phishing_model.joblib   # Trained Random Forest URL phishing classifier
│   │   └── behavior_model.joblib   # Trained Isolation Forest behavior model
│   ├── training/
│   │   ├── train_phishing.py       # Training pipeline for 12-feature URL classifier
│   │   └── train_behavior.py       # Training pipeline for 5000-sample Isolation Forest
│   └── evaluation/
│       ├── phishing_evaluation.json# Evaluation metrics (Accuracy, F1, Confusion Matrix)
│       └── behavior_evaluation.json# Anomaly detection rates & contamination settings
│
├── data/                           # STATIC DATA & EVALUATION BENCHMARKS
│   └── phishing/samples.json       # Curated corpus of benchmark phishing & clean URLs
│
└── samples/                        # FORENSIC SAMPLE CORPUS
    └── emails/                     # Raw RFC-822 sample email files (.eml)
        ├── 01_clean_google_report.eml
        ├── 02_spoofed_registrar.eml
        ├── 03_lookalike_bank.eml
        └── 04_government_impersonation.eml
"""
    )

    # -------------------------------------------------------------
    # SECTION 12: FUNCTIONAL MODULES
    # -------------------------------------------------------------
    b.add_h1("12. Functional Modules")
    b.add_p("This section documents the 10 core functional modules comprising Quantum Vault. Each module is specified according to its responsibilities, data contracts, and implementation state.")

    modules = [
        {
            "name": "Module 1: Endpoint Security Collector Agent",
            "purpose": "Harvests real-time OS telemetry from the local Windows workstation without kernel drivers.",
            "responsibilities": "Executes modular collectors for system vitals, running processes, sockets, Windows Defender, Firewall, software inventory, services, startup registry hooks, and Windows event logs.",
            "inputs": "Local OS APIs (psutil, winreg, netsh, PowerShell Get-MpComputerStatus).",
            "processing": "Aggregates raw system states every 3-15 seconds, packages JSON payloads, and monitors file creation events.",
            "outputs": "Framed JSON telemetry packets transmitted over WebSocket or HTTP /ingest.",
            "apis": "WebSocket connection to /api/v1/command-center/agent-ws; fallback POST to /api/v1/command-center/ingest.",
            "status": "Fully Implemented (Windows 10/11 native)."
        },
        {
            "name": "Module 2: Command Center & Concurrency Lock Manager",
            "purpose": "Maintains active device state and strictly enforces single-device session exclusivity.",
            "responsibilities": "Tracks connected WebSockets, registers active_device_id, rejects concurrent machines with code 4003, and dispatches on-demand scan requests.",
            "inputs": "Agent WebSocket telemetry and browser client control messages.",
            "processing": "Evaluates connection eligibility (can_agent_connect), registers state in memory, persists metadata to DB, and broadcasts updates to UI.",
            "outputs": "Live device status, aggregated process/network lists, and real-time risk scores.",
            "apis": "/api/v1/command-center/status, /processes, /network, /protection, /scans/run, /device/disconnect.",
            "status": "Fully Implemented."
        },
        {
            "name": "Module 3: Deterministic Endpoint Risk Engine",
            "purpose": "Calculates an explainable 0-100 composite risk score for the connected workstation.",
            "responsibilities": "Computes risk penalties across 5 categories: Security Config, Process Anomalies, Network Sockets, Persistence Hooks, and File Events.",
            "inputs": "Defender state, Firewall profile states, running processes, open network connections, startup items, and security logs.",
            "processing": "Applies penalty additions (e.g. +35 if Defender disabled, +20 per suspicious process) and credits (-10 if Defender and Firewall active). Clamps score between 0 and 100.",
            "outputs": "Composite risk score (0-100), categorical risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL), category breakdown, and list of contributing factors.",
            "apis": "Called internally by DeviceState.get_risk() and exposed via /api/v1/command-center/risk.",
            "status": "Fully Implemented."
        },
        {
            "name": "Module 4: URL Phishing Analysis Engine",
            "purpose": "Detects deceptive, credential-harvesting, and typosquatted web URLs.",
            "responsibilities": "Extracts 12 lexical features, runs Random Forest classification, checks Google Safe Browsing API v4, and queries WHOIS for domain age.",
            "inputs": "Target URL string via HTTP POST request.",
            "processing": "Computes Shannon entropy, IP address host patterns, excessive subdomains, and suspicious authentication keywords. Combines model probability with weighted evidence.",
            "outputs": "AnalysisResponse containing risk_score, severity, confidence, evidence items, and MITRE technique T1566.",
            "apis": "POST /api/v1/analyze/url.",
            "status": "Fully Implemented."
        },
        {
            "name": "Module 5: Email Forensic & Authenticity Engine",
            "purpose": "Validates authenticity of incoming emails and identifies spear-phishing / spoofing campaigns.",
            "responsibilities": "Parses RFC-822 headers, extracts Authentication-Results (SPF, DKIM, DMARC), detects sender/reply-to mismatches, checks homoglyph lookalikes, and runs urgency NLP regex.",
            "inputs": "Raw .eml file multipart upload or structured sender/subject/body fields.",
            "processing": "Calculates Levenshtein edit distance and homoglyph substitutions against 36 trusted institutions; performs live DNS TXT SPF/DMARC resolution.",
            "outputs": "Structured authenticity breakdown, SPF/DKIM/DMARC statuses, impersonation flags, risk score, and evidence list.",
            "apis": "POST /api/v1/analyze/email and POST /api/v1/email/analyze.",
            "status": "Fully Implemented."
        },
        {
            "name": "Module 6: Deepfake Visual Forensic Lab",
            "purpose": "Identifies AI-generated or synthetic photographic media and face swaps.",
            "responsibilities": "Analyzes EXIF camera sensor tags, calculates 2D Fast Fourier Transform (FFT) high-frequency lattice anomaly ratio, and measures Laplacian micro-texture variance.",
            "inputs": "Uploaded image file (JPEG, PNG, WEBP) in binary format.",
            "processing": "Greyscale conversion, 2D FFT shift, azimuthal frequency power distribution, and Laplacian edge filtering. Optional EfficientNet-B0 neural feature extraction if PyTorch is present.",
            "outputs": "Synthetic likelihood score, frequency anomaly metric, texture variance metric, and MITRE T1566 technique tag.",
            "apis": "POST /api/v1/analyze/image.",
            "status": "Fully Implemented (FFT/Laplacian production-active; PyTorch optional)."
        },
        {
            "name": "Module 7: Audio Deepfake & Cloned Voice Lab",
            "purpose": "Detects neural text-to-speech, voice cloning, and synthetic speech.",
            "responsibilities": "Performs digital signal processing via Librosa/Soundfile, calculating Mel-spectrogram spectral flatness, zero-crossing rate variance, and pitch stability.",
            "inputs": "Uploaded audio file (WAV, MP3, OGG) in binary format.",
            "processing": "Acoustic waveform framing, short-time Fourier transform (STFT), Mel-frequency filterbank application, and harmonic-to-noise ratio estimation.",
            "outputs": "Acoustic anomaly metrics, cloned speech probability, risk score, and evidence items.",
            "apis": "POST /api/v1/analyze/audio.",
            "status": "Fully Implemented (Librosa signal processing active)."
        },
        {
            "name": "Module 8: Behavioral Anomaly & Account Takeover Engine",
            "purpose": "Detects automated credential stuffing, brute force spikes, and unauthorized session hijackings.",
            "responsibilities": "Processes authentication event streams, identifies rapid failure bursts, flags headless script User-Agents (curl, python), and evaluates Isolation Forest anomaly scores.",
            "inputs": "Structured login event records or uploaded authentication CSV log files.",
            "processing": "Aggregates failure velocity, extracts User-Agent attributes, evaluates geographic velocity (impossible travel), and infers Isolation Forest outlier predictions.",
            "outputs": "Anomaly score, threat classification (account_takeover), evidence indicators, and MITRE T1078 tag.",
            "apis": "POST /api/v1/analyze/login-log.",
            "status": "Fully Implemented."
        },
        {
            "name": "Module 9: Cognitive Explainability (XAI) Engine",
            "purpose": "Translates complex multi-vector evidence into clear, actionable natural language SOC reports.",
            "responsibilities": "Constructs structured prompts with evidence indicators and risk metrics; queries Google Gemini 3.8 Flash; falls back to deterministic heuristic rules if offline.",
            "inputs": "Threat category, risk score, severity level, evidence items, and target reference.",
            "processing": "Formats GenAI request with 6-second timeout and AFC disabled; parses Gemini narrative response; falls back to rule-based synthesis if key missing.",
            "outputs": "Concise 2-3 sentence threat explanation detailing root cause, tactical risk, and containment advice.",
            "apis": "Integrated service invoked across all /api/v1/analyze controllers.",
            "status": "Fully Implemented."
        },
        {
            "name": "Module 10: Incident Response & Remediation Orchestrator",
            "purpose": "Tracks high-risk threats as formal SOC incidents and executes containment playbooks.",
            "responsibilities": "Generates unique incident tracking codes (e.g. QV-1021), maintains incident status lifecycle (OPEN, INVESTIGATING, CONTAINED, RESOLVED), and logs response action audits.",
            "inputs": "Incident ID and selected action playbook (block_url, revoke_session, require_mfa, block_ip).",
            "processing": "Simulates containment execution, records audit row in response_actions table, updates Incident status to CONTAINED, and marks Threat as contained.",
            "outputs": "Remediation confirmation, action execution record, and updated incident object.",
            "apis": "GET /api/v1/incidents, GET /api/v1/incidents/{id}, POST /api/v1/incidents/{id}/action.",
            "status": "Fully Implemented."
        }
    ]

    for m in modules:
        b.add_h2(m["name"])
        b.add_bullet("Purpose:", m["purpose"])
        b.add_bullet("Responsibilities:", m["responsibilities"])
        b.add_bullet("Inputs:", m["inputs"])
        b.add_bullet("Processing:", m["processing"])
        b.add_bullet("Outputs:", m["outputs"])
        b.add_bullet("APIs Used:", m["apis"])
        b.add_bullet("Current Status:", m["status"])

    # -------------------------------------------------------------
    # SECTION 13: USER INTERFACE DOCUMENTATION
    # -------------------------------------------------------------
    b.add_h1("13. User Interface Documentation")
    b.add_p("The Quantum Vault frontend is engineered as a high-density, dark-themed SOC operations cockpit built in React 19. All views provide live data bindings, loading states, and error resilience.")

    screens = [
        {
            "name": "1. Endpoint Command Center (Dashboard.tsx)",
            "route": "Default View ('dashboard' tab)",
            "purpose": "Real-time command center for the connected Windows workstation, showing health vitals, active protection states, and security posture.",
            "components": "Header with device indicator, Agent Status banner, Single-Device Lock badge, Health Stat Cards (CPU, RAM, Disk, Uptime), Protection Status (Defender & Firewall), Threat Alerts panel, Process Table, Network Connections list, and Interactive Action Bar.",
            "actions": "Trigger Quick/Full scan, view process inspection modal, view network connection inspection, open Agent Download/Run guidance modal, disconnect device.",
            "apis": "GET /command-center/status, /system, /protection, /processes, /network, /risk, /device/mode; WS /command-center/ws."
        },
        {
            "name": "2. Unified Threat Scanner (ThreatScanner.tsx)",
            "route": "'scanner' tab",
            "purpose": "Centralized threat analysis portal allowing analysts to submit URLs, emails, images, audio, or logs from a unified interface.",
            "components": "Vector selection tabs (URL, Email, Media, Log), input form with drag-and-drop file upload, quick test-sample loaders, RiskScoreMeter component, EvidenceList component, and Gemini explanation box.",
            "actions": "Submit target for analysis, load benchmark samples, view forensic breakdown, trigger automated incident response.",
            "apis": "POST /api/v1/analyze/url, /email, /image, /audio, /login-log."
        },
        {
            "name": "3. Phishing Intelligence Lab (PhishingScanner.tsx)",
            "route": "'phishing' tab",
            "purpose": "Specialized laboratory for analyzing suspicious web URLs and raw email message structures.",
            "components": "Dual URL/Email tabs, live lexical feature radar chart, homoglyph lookalike warning cards, SPF/DKIM/DMARC status pills, and WHOIS domain age metadata display.",
            "actions": "Input URL, paste email source, load sample phishing emails, inspect lexical breakdown.",
            "apis": "POST /api/v1/analyze/url, POST /api/v1/email/analyze."
        },
        {
            "name": "4. Deepfake Forensic Media Lab (DeepfakeScanner.tsx)",
            "route": "'deepfake' tab",
            "purpose": "Forensic examination portal for detecting manipulated imagery and synthesized voice recordings.",
            "components": "Image/Audio mode toggle, visual spectrum preview canvas, EXIF tag table, 2D FFT anomaly indicator, audio waveform visualization, and spectral flatness meter.",
            "actions": "Upload image or audio, run forensic examination, view high-frequency anomaly metrics.",
            "apis": "POST /api/v1/analyze/image, POST /api/v1/analyze/audio."
        },
        {
            "name": "5. Behavioral Anomaly Lab (BehaviorAnalyzer.tsx)",
            "route": "'behavior' tab",
            "purpose": "Forensic analysis of user authentication streams to detect credential stuffing and account takeover.",
            "components": "Log event timeline chart, geographic source map indicator, failure burst velocity gauge, User-Agent anomaly card, and CSV upload zone.",
            "actions": "Upload CSV auth log, run automated credential-stuffing simulation, review anomaly scores.",
            "apis": "POST /api/v1/analyze/login-log."
        },
        {
            "name": "6. Incident Response Center (Incidents.tsx)",
            "route": "'incidents' tab",
            "purpose": "SOC incident triage queue for investigating elevated threats and executing containment playbooks.",
            "components": "Incident list table with severity badges, MITRE technique tags, incident detail drawer, audit timeline of response actions, and Playbook Action buttons.",
            "actions": "Filter incidents by severity/status, select incident, execute containment playbooks (Block URL, Revoke Session, Force MFA, Block IP).",
            "apis": "GET /api/v1/incidents, GET /api/v1/incidents/{id}, POST /api/v1/incidents/{id}/action."
        },
        {
            "name": "7. Analytics & ML Metrics (Analytics.tsx)",
            "route": "'analytics' tab",
            "purpose": "Operational telemetry visualization and empirical machine learning model performance evaluation.",
            "components": "7-day threat trend timeline chart, threat type distribution pie chart, severity breakdown bars, and live ML model evaluation cards (Random Forest & Isolation Forest metrics).",
            "actions": "Filter timeframes, inspect model confusion matrices, review precision/recall/F1 metrics.",
            "apis": "GET /api/v1/dashboard/stats, GET /api/v1/dashboard/ml-metrics."
        },
        {
            "name": "8. Platform Settings & DB Diagnostics (Settings.tsx)",
            "route": "'settings' tab",
            "purpose": "Configuration of deterministic risk policy thresholds and real-time database container diagnostics.",
            "components": "Risk threshold sliders (Low, Medium, High, Critical) with strict monotonic order validation, Gemini model selector, Database connection diagnostic card, and Docker PostgreSQL reconnect button.",
            "actions": "Adjust scoring thresholds, change AI model, trigger database reconnection attempt.",
            "apis": "GET /api/v1/settings/policy, PUT /api/v1/settings/policy, POST /api/v1/settings/db-reconnect."
        }
    ]

    for s in screens:
        b.add_h2(s["name"])
        b.add_bullet("Route / View:", s["route"])
        b.add_bullet("Purpose:", s["purpose"])
        b.add_bullet("Key Components:", s["components"])
        b.add_bullet("User Actions:", s["actions"])
        b.add_bullet("API Endpoints:", s["apis"])

    # -------------------------------------------------------------
    # SECTION 14: COMMAND CENTER / SECURITY MONITORING
    # -------------------------------------------------------------
    b.add_h1("14. Command Center / Security Monitoring")
    b.add_p("The Quantum Vault Command Center is the operational nerve center for endpoint monitoring. Telemetry flows continuously from the Windows agent across 9 distinct collection domains.")

    b.add_h2("14.1 End-to-End Telemetry Pipeline")
    b.add_p("Every telemetry data point follows a deterministic six-stage lifecycle: Data Source -> Collection -> Normalization -> Risk Calculation -> UI Display -> Alert / Remediation.")
    
    b.add_table(
        ["Monitoring Domain", "Data Source / Tool", "Collection Frequency", "Risk Calculation Impact & Evaluation"],
        [
            ["System Vitals", "psutil (CPU, RAM, Disks, Uptime)", "Every 3 seconds", "High CPU/RAM sustained loads contribute to host stress alerts."],
            ["Windows Defender", "PowerShell Get-MpComputerStatus", "Every 15 seconds", "Penalties (+35) if real-time protection is disabled; (+15) if signatures > 7 days old; credit (-10) if active."],
            ["Windows Firewall", "netsh advfirewall / PowerShell", "Every 15 seconds", "Penalty (+25) if any profile (Domain, Private, Public) is disabled; credit (-10) if all profiles active."],
            ["Processes", "psutil.process_iter() with path audit", "Every 5 seconds", "Flags binaries executing from Temp/Downloads, high CPU/RAM usage, and known malicious command-line flags (+20 each)."],
            ["Network Sockets", "psutil.net_connections()", "Every 4 seconds", "Monitors LISTEN and ESTABLISHED sockets; flags unknown listening ports and non-standard outbound connections (+15 each)."],
            ["Software Inventory", "Windows Registry Uninstall keys", "Every 60 seconds", "Maintains audit of installed software packages, publishers, versions, and installation dates."],
            ["Windows Services", "psutil.win_service_iter()", "Every 30 seconds", "Monitors service states (running, stopped) and startup types; flags unauthorized services."],
            ["Startup Persistence", "Registry Run keys & Startup folders", "Every 30 seconds", "Audits persistence hooks; flags entries executing out of temporary or user-writable paths (+20 each)."],
            ["File Creation", "Polling directory watcher (Downloads/Startup)", "Real-time / 5 seconds", "Monitors monitored folders for executable and script creations (.exe, .bat, .ps1, .vbs) (+8 each)."],
            ["Windows Event Log", "wevtutil / Windows Security Log", "Every 10 seconds", "Audits logon failures (Event 4625), privilege escalation (Event 4672), and audit log clearing (Event 1102) (+15 each)."]
        ],
        [1.5, 1.8, 1.2, 2.5]
    )

    b.add_h2("14.2 Single-Device Concurrency Enforcement")
    b.add_p("To guarantee dedicated protection and prevent rogue probe spoofing, the backend enforces a single active machine lock:")
    b.add_bullet("Device Registration:", "When the agent connects, it transmits its unique hostname/device_id. If no device is currently active, the agent is registered and assigned exclusive telemetry rights.")
    b.add_bullet("Conflict Rejection:", "If a second machine attempts to connect via WebSocket while another is active, the backend immediately closes the connection with code 4003 (SINGLE_DEVICE_LIMIT_EXCEEDED) and returns a structured rejection payload.")
    b.add_bullet("Explicit Handover:", "The active endpoint can be disconnected manually via the Command Center UI (POST /api/v1/command-center/device/disconnect) or automatically upon heartbeat timeout (> 30 seconds), allowing reassignment.")

    # -------------------------------------------------------------
    # SECTION 15: SECURITY ARCHITECTURE
    # -------------------------------------------------------------
    b.add_h1("15. Security Architecture")
    b.add_p("Quantum Vault enforces defense-in-depth principles across all platform layers. Security controls are implemented to protect confidentiality, integrity, and operational availability.")

    b.add_table(
        ["Security Domain", "Actual Implemented Control", "Implementation Status & Verification"],
        [
            ["Authentication", "Analyst login returning structured bearer token; User schema with password_hash.", "Implemented in Prototype Mode; mock bearer token validated; production Argon2 hashing planned."],
            ["Authorization & RBAC", "Role assignment in user payload (tier3_analyst, admin).", "Implemented at schema level; endpoint guards enforce analyst profile."],
            ["Agent Authorization", "Pre-shared token header (QUANTUMVAULT_API_TOKEN) required for WebSocket and /ingest.", "Implemented; unauthorized agents rejected with HTTP 401 or WS 1008."],
            ["Concurrency Security", "Single-device active machine lock preventing concurrent probe hijacking.", "Implemented; verified with active_device_id lock and code 4003 rejections."],
            ["Input Validation", "Strict Pydantic models for all API request bodies with explicit type checks.", "Implemented; invalid payloads rejected with HTTP 422 Unprocessable Entity."],
            ["Policy Validation", "Strict ascending order validation on risk cutoffs (0 <= Low < Med < High < Crit <= 100).", "Implemented; non-monotonic updates rejected with HTTP 400 Bad Request."],
            ["Output Sanitization", "Regex masking of database passwords in all status responses (mask_connection_url).", "Implemented; connection URLs sanitized with :***@ masking."],
            ["CORS Protection", "Configured CORSMiddleware with explicit origin bindings and allowed methods.", "Implemented in main.py; supports localhost:5173 and configured origins."],
            ["Secrets Management", "Environment variables loaded via Pydantic BaseSettings; sensitive keys excluded from git.", "Implemented; .env excluded via .gitignore; .env.example provided with safe placeholders."],
            ["Audit Logging", "Structured Python logging across all service modules with timestamp and level.", "Implemented; logs written to console and standard error."]
        ],
        [1.6, 2.6, 2.8]
    )

    # -------------------------------------------------------------
    # SECTION 16: THREAT DETECTION / SECURITY SCANNING
    # -------------------------------------------------------------
    b.add_h1("16. Threat Detection / Security Scanning")
    b.add_p("Quantum Vault incorporates multi-modal artificial intelligence, signal processing algorithms, and deterministic heuristic rule engines across each specialized threat domain.")

    b.add_h2("16.1 Phishing URL Detection Engine")
    b.add_p("The phishing engine evaluates URLs across 12 lexical dimensions and checks external threat databases:")
    b.add_bullet("1. Shannon Entropy:", "H(X) = -sum(P(x) * log2(P(x))). Detects randomized algorithmic subdomains typical of Domain Generation Algorithms (DGA). Values > 3.8 trigger penalties.")
    b.add_bullet("2. IP Host Indicator:", "Regex matching direct IPv4 hosts (e.g. http://192.168.1.1/login) used to bypass DNS reputation filters.")
    b.add_bullet("3. Structural Features:", "URL length, domain length, hyphen count (brand spoofing), subdomain count, digit count, and special characters.")
    b.add_bullet("4. Authentication Keywords:", "Presence of sensitive keywords ('verify', 'account', 'banking', 'signin', 'suspended', 'update').")
    b.add_bullet("5. Random Forest Model:", "Pre-trained ensemble classifier (100 estimators) trained on UCI Phishing & PhiUSIIL benchmarks, outputting malicious probability.")
    b.add_bullet("6. Google Safe Browsing v4:", "Live lookup against Google Safe Browsing API querying MALWARE, SOCIAL_ENGINEERING, and UNWANTED_SOFTWARE threat lists.")
    b.add_bullet("7. WHOIS Domain Age:", "Queries domain registration date; domains registered < 30 days ago trigger high-risk brand impersonation alerts.")

    b.add_h2("16.2 Email Authenticity & Forensic Engine")
    b.add_p("The email engine parses RFC-822 message structures and performs cryptographic and linguistic checks:")
    b.add_bullet("1. Header Authentication Parsing:", "Extracts Authentication-Results header, validating SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication) pass/fail/softfail statuses.")
    b.add_bullet("2. Domain Alignment Audit:", "Cross-references the header 'From' address against 'Reply-To' and 'Return-Path'. Misalignments indicate mail forwarding deception or sender spoofing.")
    b.add_bullet("3. Homoglyph & Lookalike Detection:", "Normalizes Cyrillic, Greek, and numeric homoglyphs (e.g., 'pаypal' with Cyrillic 'а', '0' for 'o', '1' for 'l') and calculates Levenshtein edit distances against 36 trusted financial and government entities.")
    b.add_bullet("4. DNS Live Verification:", "Queries authoritative DNS TXT records to confirm SPF and DMARC deployment on sender domains.")
    b.add_bullet("5. Urgency NLP Heuristics:", "Scans email bodies for coercive social engineering language ('urgent', 'immediately', 'account suspended', '24 hours').")

    b.add_h2("16.3 Deepfake Visual Forensics")
    b.add_bullet("1. EXIF Sensor Provenance:", "Checks for authentic camera hardware tags (Make, Model, Software, DateTimeOriginal). AI-generated images typically lack camera sensor hardware tags.")
    b.add_bullet("2. 2D Fast Fourier Transform (FFT):", "Applies 2D FFT to convert spatial pixels into frequency spectrum. AI generative models (GANs and Latent Diffusion) produce distinctive high-frequency periodic lattice artifacts due to convolutional upsampling.")
    b.add_bullet("3. Laplacian Noise Variance:", "Applies Laplacian convolution filter to measure micro-texture edge sharpness and noise distribution uniformity. Synthetic faces display unnatural noise smoothness.")
    b.add_bullet("4. EfficientNet-B0 Classifier (Optional):", "When PyTorch and timm are available, extracts deep feature activations from penultimate layers, measuring kurtosis and sparsity anomalies.")

    b.add_h2("16.4 Audio Voice Clone Forensics")
    b.add_bullet("1. Mel-Spectrogram Analysis:", "Transforms acoustic waveform into 128 Mel-frequency bands using Librosa, inspecting harmonic frequency consistency.")
    b.add_bullet("2. Spectral Flatness:", "Measures the ratio of geometric mean to arithmetic mean of the power spectrum. AI voice synthesis exhibits abnormal spectral flatness due to vocoder quantization noise.")
    b.add_bullet("3. Zero-Crossing Rate & Pitch Stability:", "Measures vocal tract vibration consistency. Cloned voices exhibit unnatural pitch regularity or robotic phase transitions.")

    b.add_h2("16.5 Behavioral Anomaly & Account Takeover Detection")
    b.add_bullet("1. Isolation Forest Model:", "Unsupervised anomaly detection algorithm (contamination=0.08) isolating outlier login attempts based on failure velocity, hour of day, and location changes.")
    b.add_bullet("2. Credential Stuffing Bursts:", "Flags clusters of >= 3 failed logins or sudden bursts of >= 10 attempts prior to a successful authentication.")
    b.add_bullet("3. Automated Client Detection:", "Inspects HTTP User-Agent headers, flagging script engines (curl, python-urllib, requests, headless bots).")
    b.page_break()

print("Loaded Section 9-16 module.")

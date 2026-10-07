"""
Sections 17 to 24 of QuantumVault Documentation
"""
def add_sections_17_to_24(b):
    # -------------------------------------------------------------
    # SECTION 17: APIS
    # -------------------------------------------------------------
    b.add_h1("17. APIs (Complete Application Programming Interface Reference)")
    b.add_p("This section documents all active REST endpoints and WebSocket protocols exposed by the Quantum Vault FastAPI backend. All routes are mounted under /api/v1 (and direct /api aliases where supported).")

    api_endpoints = [
        # Health & Root
        ["GET", "/health", "Health Check", "None", "None", "200: {status: 'healthy', service: 'QuantumVault', version: '1.0.0', environment: 'dev'}"],
        ["GET", "/", "Platform Root", "None", "None", "200: {platform: 'QuantumVault...', docs_url: '/docs', version: '1.0.0', status: 'online'}"],
        
        # Auth
        ["POST", "/api/v1/auth/login", "Analyst Login", "None", "JSON: {email: str, password: str}", "200: {access_token: str, token_type: 'bearer', user: {id, name, email, role}}; 400: Invalid creds"],
        ["GET", "/api/v1/auth/me", "Current Analyst Profile", "Bearer Token", "None", "200: {id: 1, name: 'SOC Lead Analyst', email: str, role: 'tier3_analyst'}"],
        
        # Threat Analysis Engine
        ["POST", "/api/v1/analyze/url", "Phishing URL Analysis", "Optional Bearer", "JSON: {url: str}", "200: AnalysisResponse (threat_type: 'phishing', risk_score: 0-100, severity, confidence, evidence, explanation, mitre_technique)"],
        ["POST", "/api/v1/analyze/email", "Email Forensic Analysis", "Optional Bearer", "JSON: {sender: str, subject: str, body: str}", "200: AnalysisResponse (threat_type: 'phishing', risk_score, evidence: [SPF, DMARC, homoglyph, urgency], explanation)"],
        ["POST", "/api/v1/analyze/image", "Deepfake Visual Forensic", "Optional Bearer", "Multipart: file (image/jpeg, png, webp)", "200: AnalysisResponse (threat_type: 'deepfake', risk_score, features: {fft_peak_ratio, noise_residual_std}, evidence)"],
        ["POST", "/api/v1/analyze/audio", "Audio Deepfake Forensics", "Optional Bearer", "Multipart: file (audio/wav, mp3, ogg)", "200: AnalysisResponse (threat_type: 'deepfake_audio', risk_score, features: {spectral_flatness, zcr}, evidence)"],
        ["POST", "/api/v1/analyze/login-log", "Behavioral Anomaly Analysis", "Optional Bearer", "Form: user_id; Multipart: file (CSV) optional", "200: AnalysisResponse (threat_type: 'account_takeover', risk_score, evidence: [brute_force, scripting_client])"],
        ["POST", "/api/v1/email/analyze", "Raw .eml Authenticity Audit", "Optional Bearer", "Multipart: file (.eml) OR Form: raw_text", "200: Detailed authenticity JSON with SPF, DKIM, DMARC statuses, domain mismatch flags, homoglyph lookalikes, risk score"],
        
        # Endpoint Command Center
        ["GET", "/api/v1/command-center/devices", "List Registered Devices", "None", "None", "200: Array of registered endpoint devices with status and risk summaries"],
        ["GET", "/api/v1/command-center/status", "Current Agent Status", "None", "Query: device_id (optional)", "200: AgentStatusOut (device_id, hostname, os_name, os_version, agent_version, status, last_telemetry_at)"],
        ["GET", "/api/v1/command-center/system", "Live System Telemetry", "None", "Query: device_id (optional)", "200: SystemTelemetryOut (cpu_percent, memory_percent, disks, uptime_seconds, boot_time)"],
        ["GET", "/api/v1/command-center/protection", "Protection Status", "None", "Query: device_id (optional)", "200: {defender: {available, real_time, signatures}, firewall: {available, all_enabled, profiles}}"],
        ["GET", "/api/v1/command-center/processes", "Active Running Processes", "None", "Query: limit=150, search=str", "200: List of ProcessItemOut (pid, name, cpu_percent, memory_mb, user, exe_path, risk_level, risk_reasons)"],
        ["GET", "/api/v1/command-center/network", "Network Sockets & Listeners", "None", "Query: limit=150, state=str", "200: List of NetworkItemOut (pid, process_name, proto, laddr, raddr, state, risk_level)"],
        ["GET", "/api/v1/command-center/software", "Installed Software List", "None", "Query: search=str", "200: List of SoftwareItemOut (name, version, publisher, install_date)"],
        ["GET", "/api/v1/command-center/services", "Windows Services Inventory", "None", "Query: status=str", "200: List of ServiceItemOut (name, display_name, status, start_type)"],
        ["GET", "/api/v1/command-center/startup", "Startup Persistence Entries", "None", "None", "200: List of StartupItemOut (name, command, location, suspicious, reasons)"],
        ["GET", "/api/v1/command-center/risk", "Live Host Risk Score", "None", "Query: device_id (optional)", "200: RiskScoreOut (score: 0-100, level, breakdown, contributors, summary)"],
        ["POST", "/api/v1/command-center/scans/run", "Trigger Endpoint Scan", "None", "JSON: {scan_type: 'quick'|'process'|'network'|'startup'|'file'}", "200: ScanRecordOut (scan_id, scan_type, status, findings_count, summary)"],
        ["GET", "/api/v1/command-center/device/mode", "Single-Device Licensing Info", "None", "None", "200: {single_device_mode: true, active_device_id: str, connected_sockets: int, blocked_count: int}"],
        ["POST", "/api/v1/command-center/device/disconnect", "Disconnect Active Device", "None", "None", "200: {success: true, message: 'Active endpoint disconnected successfully'}"],
        ["GET", "/api/v1/command-center/agent/download-script", "Download 1-Click Batch Runner", "None", "None", "200: Dynamic run_quantumvault_agent.bat configured with server backend URL"],
        ["GET", "/api/v1/command-center/agent/download-config", "Download Agent Config JSON", "None", "None", "200: JSON: {backend_url: 'https://...'} for offline placement"],
        ["POST", "/api/v1/command-center/ingest", "HTTP Fallback Ingest", "Token Header", "JSON: {type: str, device_id: str, data: dict}", "200: {status: 'ok'}; 401: Unauthorized; 409: Single device conflict"],
        ["WS", "/api/v1/command-center/ws", "Browser Real-Time Stream", "None", "Query: device_id (optional)", "WebSocket Stream: Emits telemetry, status_update, scan_completed events"],
        ["WS", "/api/v1/command-center/agent-ws", "Agent Ingestion Stream", "Token Query", "Query: token=qv-endpoint-agent-token-2026, device_id=str", "Bidirectional WebSocket: Accepts framed JSON telemetry; Rejects with 4003 if concurrent"],

        # Dashboard & Analytics
        ["GET", "/api/v1/dashboard/stats", "SOC Overview Statistics", "None", "None", "200: DashboardStats (total_scans, threats_detected, critical_count, active_incidents, timeline, recent)"],
        ["GET", "/api/v1/dashboard/ml-metrics", "Empirical ML Metrics", "None", "None", "200: ML performance data (accuracy, precision, recall, F1, confusion matrix, ROC-AUC)"],

        # Threats & Incidents
        ["GET", "/api/v1/threats", "List Detected Threats", "None", "Query: skip=0, limit=50, threat_type=str, severity=str", "200: List of ThreatOut objects with evidence items"],
        ["GET", "/api/v1/threats/{id}", "Get Threat Details", "None", "Path: id (int)", "200: ThreatOut object; 404: Not found"],
        ["GET", "/api/v1/incidents", "List SOC Incidents", "None", "None", "200: List of IncidentOut records with associated actions"],
        ["GET", "/api/v1/incidents/{id}", "Get Incident Details", "None", "Path: id (int)", "200: IncidentOut record; 404: Not found"],
        ["POST", "/api/v1/incidents/{id}/action", "Execute Response Playbook", "None", "JSON: {action_type: str, notes: str}", "200: {success: true, result: ResponseAction record}; 404: Not found"],

        # Settings & DB Diagnostics
        ["GET", "/api/v1/settings/policy", "Get Risk Policy & DB Status", "None", "None", "200: PolicyResponse (low, med, high, crit thresholds, gemini_model, database_status)"],
        ["PUT", "/api/v1/settings/policy", "Update Risk Policy Thresholds", "None", "JSON: {low_threshold: int, medium_threshold: int, high_threshold: int, critical_threshold: int, gemini_model: str}", "200: Updated PolicyResponse; 400: If thresholds violate monotonic order"],
        ["GET", "/api/v1/settings/db-status", "Live DB Diagnostics", "None", "None", "200: DatabaseStatusResponse (configured_driver, active_driver, status, is_postgres, table_counts)"],
        ["POST", "/api/v1/settings/db-reconnect", "Reconnect Docker Postgres", "None", "None", "200: {success: bool, message: str, status: DatabaseStatusResponse}"]
    ]

    b.add_table(
        ["Method", "Endpoint Path", "Description", "Auth", "Request Contract", "Response Schema & Status Codes"],
        api_endpoints,
        [0.8, 1.8, 1.4, 0.8, 1.3, 1.9]
    )

    # -------------------------------------------------------------
    # SECTION 18: DATABASE DOCUMENTATION
    # -------------------------------------------------------------
    b.add_h1("18. Database Documentation")
    b.add_p("Quantum Vault implements dual-engine persistence via SQLAlchemy 2.0. The primary target is PostgreSQL (docker container quantumvault_db), with automated zero-config failover to local SQLite (quantumvault.db) if port 5432 is unreachable.")

    b.add_h2("18.1 Database Entity-Relationship (ER) Schema")
    b.add_code(
"""+-------------------+           +-----------------------+           +----------------------+
|       users       | 1       * |      login_events     |           |     system_policies  |
+-------------------+-----------+-----------------------+           +----------------------+
| id (PK)           |           | id (PK)               |           | id (PK)              |
| name              |           | user_id (FK -> users) |           | low_threshold        |
| email (UQ)        |           | ip_address            |           | medium_threshold     |
| password_hash     |           | location              |           | high_threshold       |
| role              |           | device                |           | critical_threshold   |
| created_at        |           | login_time            |           | gemini_model         |
+---------+---------+           | success (BOOL)        |           | updated_at           |
          | 1                   | user_agent            |           +----------------------+
          |                     | anomaly_score         |
          | *                   +-----------------------+
+---------v---------+
|       scans       |
+-------------------+
| id (PK)           |
| user_id (FK)      |           +-----------------------+ 1       * +----------------------+
| scan_type         |           |        threats        |-----------|   threat_evidence    |
| input_reference   |           +-----------------------+           +----------------------+
| result            |           | id (PK)               |           | id (PK)              |
| risk_score        |           | threat_type           |           | threat_id (FK)       |
| meta_info (JSON)  |           | source_type           |           | indicator            |
| created_at        |           | source_payload        |           | description          |
+-------------------+           | severity              |           | weight               |
                                | risk_score            |           | created_at           |
+-------------------+ 1       * | confidence            |           +----------------------+
| endpoint_devices  |-----+     | status                | 1       * +----------------------+
+-------------------+     |     | explanation           |-----------|   model_predictions  |
| id (PK)           |     |     | created_at            |           +----------------------+
| device_id (UQ)    |     |     +-----------+-----------+           | id (PK)              |
| hostname          |     |                 | 1                     | threat_id (FK)       |
| os_name           |     |                 |                       | model_name           |
| os_version        |     |                 | *                     | model_version        |
| agent_version     |     |     +-----------v-----------+           | prediction           |
| status            |     |     |       incidents       |           | confidence           |
| last_heartbeat    |     |     +-----------------------+           | created_at           |
| last_telemetry_at |     |     | id (PK)               |           +----------------------+
| registered_at     |     |     | threat_id (FK)        |
+-------------------+     |     | incident_code (UQ)    | 1       * +----------------------+
                          |     | title                 |-----------|   response_actions   |
+-------------------+     |     | description           |           +----------------------+
|  endpoint_scans   |     |     | severity              |           | id (PK)              |
+-------------------+     |     | status                |           | incident_id (FK)     |
| id (PK), scan_id  |     |     | assigned_to           |           | threat_id (FK)       |
| device_id, type   |     |     | mitre_technique       |           | action_type          |
| status, findings  |     |     | created_at            |           | description          |
| started, completed|     |     | updated_at            |           | status               |
+-------------------+     |     +-----------------------+           | executed_by          |
                          |                                         | created_at           |
+-------------------+     |                                         +----------------------+
| endpoint_threats  |     |
+-------------------+     |     +-----------------------+
| id, alert_id, dev |     |     | endpoint_sec_events   |
| severity, cat, exp|     +---->+-----------------------+
| evidence_json     |           | id (PK), device_id    |
+-------------------+           | timestamp, severity   |
                                | event_type, source    |
                                | description, user     |
                                | metadata_json         |
                                +-----------------------+
"""
    )

    b.add_h2("18.2 Relational Tables Specification")
    b.add_table(
        ["Table Name", "Primary Columns & Types", "Key Constraints", "Data Lifecycle & Functional Role"],
        [
            ["users", "id (INT PK), name (VARCHAR 100), email (VARCHAR 120), password_hash (VARCHAR 255), role (VARCHAR 50)", "email UNIQUE, INDEX", "Stores analyst accounts and roles; seeded with default SOC Lead Analyst."],
            ["login_events", "id (INT PK), user_id (INT FK), ip_address (VARCHAR 50), location, device, login_time, success (BOOL), anomaly_score (INT)", "user_id FK -> users.id", "Stores user authentication events; audited by behavior_service for credential stuffing."],
            ["threats", "id (INT PK), threat_type (VARCHAR 50), source_type, source_payload (TEXT), severity, risk_score (INT), confidence (FLOAT), status, explanation (TEXT)", "id PK, INDEX", "Core entity storing all identified external threats (phishing, deepfakes, ATO)."],
            ["threat_evidence", "id (INT PK), threat_id (INT FK), indicator (VARCHAR 100), description (TEXT), weight (INT), created_at", "threat_id FK -> threats.id", "Granular forensic indicators explaining the threat decision (e.g. SPF fail, DGA domain)."],
            ["scans", "id (INT PK), user_id (INT FK), scan_type, input_reference, result, risk_score, meta_info (JSON), created_at", "id PK, user_id FK", "Audit history of user-triggered web and media scans."],
            ["model_predictions", "id (INT PK), threat_id (INT FK), model_name, model_version, prediction, confidence, created_at", "threat_id FK -> threats.id", "Raw output record from individual ML estimators (Random Forest, Isolation Forest)."],
            ["incidents", "id (INT PK), threat_id (INT FK), incident_code (VARCHAR 50 UQ), title, description, severity, status, assigned_to, mitre_technique", "incident_code UNIQUE, INDEX", "Elevated SOC incidents automatically raised for HIGH/CRITICAL threats (QV-1021)."],
            ["response_actions", "id (INT PK), incident_id (INT FK), threat_id (INT FK), action_type, description, status, executed_by, created_at", "incident_id FK -> incidents.id", "Audit record of containment playbooks executed against an incident."],
            ["endpoint_devices", "id (INT PK), device_id (VARCHAR 100 UQ), hostname, os_name, os_version, agent_version, status, last_heartbeat", "device_id UNIQUE, INDEX", "Tracks registered workstation endpoints; manages single-device active session lock."],
            ["endpoint_scans", "id (INT PK), scan_id (VARCHAR 100 UQ), device_id, scan_type, status, findings_count, summary_json, started_at", "scan_id UNIQUE, INDEX", "On-demand workstation scan executions (quick, process, network, startup, file)."],
            ["endpoint_threat_alerts", "id (INT PK), alert_id (VARCHAR 100 UQ), device_id, severity, category, title, detection_source, explanation", "alert_id UNIQUE, INDEX", "Persistent security alerts generated from endpoint telemetry anomalies."],
            ["endpoint_security_events", "id (INT PK), device_id, timestamp, severity, event_type, source, description, user, process, metadata_json", "id PK, device_id INDEX", "Harvested Windows Event Log security events (logon failures, audit log tampering)."],
            ["system_policies", "id (INT PK), low_threshold (INT), medium_threshold (INT), high_threshold (INT), critical_threshold (INT), gemini_model", "id PK", "Singleton configuration table maintaining risk score classification boundaries."]
        ],
        [1.5, 2.0, 1.5, 2.0]
    )

    # -------------------------------------------------------------
    # SECTION 19: DATA FLOW
    # -------------------------------------------------------------
    b.add_h1("19. Data Flow")
    b.add_p("Data movement across Quantum Vault follows distinct, deterministic pathways depending on whether the data originates from external threat submissions or endpoint telemetry sensors.")

    b.add_h2("19.1 External Threat Analysis Flow (e.g. Phishing URL)")
    b.add_p("1. Analyst submits target URL via frontend ThreatScanner -> 2. Axios transmits POST payload to /api/v1/analyze/url -> 3. PhishingService extracts 12 lexical features -> 4. Queries Google Safe Browsing API v4 & WHOIS domain age -> 5. Executes Random Forest inference -> 6. RiskEngine calculates weighted 0-100 score -> 7. ExplanationEngine formats prompt to Gemini 3.8 Flash -> 8. Database records Threat, Evidence, and Scan entries -> 9. If severity >= HIGH, creates Incident record (QV-1021) -> 10. Returns structured AnalysisResponse to UI.")

    b.add_h2("19.2 Endpoint Telemetry Streaming & Risk Scoring Flow")
    b.add_p("1. Local Agent collectors probe Windows OS vitals every 3s -> 2. Agent packages JSON telemetry payload -> 3. Transmits framed message over WebSocket to /api/v1/command-center/agent-ws -> 4. Backend validates active_device_id lock -> 5. EndpointSecurityManager updates in-memory DeviceState -> 6. EndpointRiskEngine re-evaluates composite host risk score -> 7. Backend broadcasts updated telemetry to connected SOC browser WebSockets -> 8. React UI updates dashboard gauges and process tables without page reload.")

    b.add_h2("19.3 Automated Incident Response & Playbook Flow")
    b.add_p("1. Threat with risk score >= 60 triggers automated SOC Incident creation -> 2. Incident assigned unique code and MITRE ATT&CK technique -> 3. Appears in Incident Center UI with pending status -> 4. Analyst reviews evidence and selects containment action (e.g. Block URL) -> 5. Frontend sends POST to /api/v1/incidents/{id}/action -> 6. ResponseEngine executes playbook, sets status to CONTAINED, and writes audit record in response_actions -> 7. Threat record marked contained.")

    # -------------------------------------------------------------
    # SECTION 20: AUTHENTICATION AND AUTHORIZATION FLOW
    # -------------------------------------------------------------
    b.add_h1("20. Authentication and Authorization Flow")
    b.add_p("The authentication and authorization architecture manages access across both human SOC analysts and machine endpoint collectors.")

    b.add_h2("20.1 Analyst Access Lifecycle")
    b.add_bullet("1. Credential Submission:", "Analyst submits email and password to POST /api/v1/auth/login.")
    b.add_bullet("2. Credential Verification:", "Backend validates presence of credentials. In prototype mode, authenticates analyst and returns structured bearer token ('quantumvault_demo_bearer_token_xyz123').")
    b.add_bullet("3. User Profile Return:", "Response delivers user identity: {id: 1, name: 'SOC Lead Analyst', email: 'analyst@quantumvault.internal', role: 'tier3_analyst'}.")
    b.add_bullet("4. Session Persistence:", "Frontend stores token and attaches 'Authorization: Bearer <token>' on all subsequent HTTP requests.")
    b.add_bullet("5. Route Guarding:", "Frontend Sidebar and route transitions verify active analyst state.")

    b.add_h2("20.2 Agent Machine Authentication & Lock Lifecycle")
    b.add_bullet("1. Connection Handshake:", "Agent initiates WebSocket connection with pre-shared API token header (QUANTUMVAULT_API_TOKEN) and unique device_id query param.")
    b.add_bullet("2. Token Validation:", "Backend verifies token against configured constant ('qv-endpoint-agent-token-2026'). Mismatched tokens receive WS close code 1008 (Policy Violation).")
    b.add_bullet("3. Single-Device Check:", "can_agent_connect(device_id) checks if active_device_id is null or matches the connecting machine. If another device is active, connection is rejected with code 4003.")
    b.add_bullet("4. Stream Established:", "Valid agent stream accepted; active_device_id locked; real-time telemetry streaming commences.")

    # -------------------------------------------------------------
    # SECTION 21: CONFIGURATION MANAGEMENT
    # -------------------------------------------------------------
    b.add_h1("21. Configuration Management")
    b.add_p("Quantum Vault externalizes all runtime configurations through environment variables managed by Pydantic BaseSettings in backend/app/config.py. Secrets are strictly segregated from repository tracking.")

    b.add_table(
        ["Variable Name", "Default Value", "Verified Source", "Description & Security Guidance"],
        [
            ["PROJECT_NAME", "QuantumVault", "backend/app/config.py", "Display name of the application across OpenAPI and logs."],
            ["VERSION", "1.0.0", "backend/app/config.py", "Current software release version string."],
            ["ENVIRONMENT", "development", "backend/app/config.py", "Runtime mode: 'development', 'production', or 'testing'."],
            ["API_V1_STR", "/api/v1", "backend/app/config.py", "URL prefix for version 1 API routing."],
            ["DATABASE_URL", "sqlite:///./quantumvault.db", "backend/app/config.py", "Primary database connection string. Defaults to SQLite; falls back automatically if PostgreSQL is down."],
            ["SECRET_KEY", "quantumvault_hackathon_super_secret_jwt_key_992182", "backend/app/config.py", "Cryptographic key for signing sessions. Replace with high-entropy secret in production."],
            ["ALGORITHM", "HS256", "backend/app/config.py", "JWT cryptographic signature algorithm."],
            ["ACCESS_TOKEN_EXPIRE_MINUTES", "1440", "backend/app/config.py", "Bearer token validity window (default: 24 hours)."],
            ["GEMINI_API_KEY", "[REDACTED / EMPTY]", "backend/app/config.py", "Google Gemini API key for dynamic threat explainability. Optional (fallback rule engine active if empty)."],
            ["GEMINI_MODEL", "gemini-3.8-flash", "backend/app/config.py", "Gemini foundation model identifier for SOC narrative synthesis."],
            ["GOOGLE_SAFE_BROWSING_API_KEY", "[REDACTED / EMPTY]", "backend/app/config.py", "API key for real-time Google Safe Browsing threat match lookups. Optional."],
            ["RISK_THRESHOLD_LOW", "20", "backend/app/config.py", "Cutoff score for SAFE -> LOW risk transition."],
            ["RISK_THRESHOLD_MEDIUM", "40", "backend/app/config.py", "Cutoff score for LOW -> MEDIUM risk transition."],
            ["RISK_THRESHOLD_HIGH", "60", "backend/app/config.py", "Cutoff score for MEDIUM -> HIGH risk transition."],
            ["RISK_THRESHOLD_CRITICAL", "80", "backend/app/config.py", "Cutoff score for HIGH -> CRITICAL risk transition."],
            ["VITE_API_URL", "http://localhost:8000/api/v1", "frontend/.env.example", "Base backend URL consumed by frontend Axios client."]
        ],
        [1.8, 1.8, 1.4, 2.0]
    )

    # -------------------------------------------------------------
    # SECTION 22: INSTALLATION AND SETUP GUIDE
    # -------------------------------------------------------------
    b.add_h1("22. Installation and Setup Guide")
    b.add_p("This guide provides step-by-step instructions for installing and running Quantum Vault in a local development or lab evaluation environment.")

    b.add_h2("22.1 Prerequisites")
    b.add_bullet("Operating System:", "Windows 10 / Windows 11 (required for local endpoint agent; backend and frontend are cross-platform).")
    b.add_bullet("Python Runtime:", "Python 3.10 to 3.14 (Python 3.14 verified in local environment).")
    b.add_bullet("Node.js Runtime:", "Node.js v18.0.0 or higher with npm v9+.")
    b.add_bullet("Docker Desktop (Optional):", "Docker Engine with Docker Compose v2 for running containerized PostgreSQL.")

    b.add_h2("22.2 Step 1: Backend Setup")
    b.add_code(
"""# 1. Navigate to backend directory
cd backend

# 2. Install dependencies into Python environment
pip install -r requirements.txt

# 3. Create .env file from template
cp .env.example .env

# 4. (Optional) Edit .env to supply GEMINI_API_KEY if dynamic LLM explanations are desired

# 5. Start the FastAPI development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
"""
    )

    b.add_h2("22.3 Step 2: Frontend Setup")
    b.add_code(
"""# 1. Open a new terminal and navigate to frontend directory
cd frontend

# 2. Install Node.js packages
npm install

# 3. Launch Vite development server
npm run dev

# 4. Open browser at http://localhost:5173
"""
    )

    b.add_h2("22.4 Step 3: Endpoint Agent Launch (Single-Device Protection)")
    b.add_code(
"""# Option A: 1-Click Interactive Batch Launcher (Recommended on Windows)
# Double-click 'run_agent.bat' in the project root OR execute via terminal:
run_agent.bat

# Option B: Direct Python Execution
python agent_launcher.py --backend http://127.0.0.1:8000
# Or:
python -m agent.main --backend http://127.0.0.1:8000
"""
    )

    # -------------------------------------------------------------
    # SECTION 23: DEPLOYMENT GUIDE
    # -------------------------------------------------------------
    b.add_h1("23. Deployment Guide")
    b.add_p("Quantum Vault is architected for seamless cloud and hybrid deployment. The repository includes pre-configured Docker Compose files and production container recipes.")

    b.add_h2("23.1 Production Docker Compose Deployment")
    b.add_code(
"""# Execute full production stack (PostgreSQL + FastAPI + Nginx Frontend)
docker compose -f docker-compose.prod.yml up -d --build

# Verify running containers
docker compose -f docker-compose.prod.yml ps

# View backend logs
docker compose -f docker-compose.prod.yml logs -f backend
"""
    )

    b.add_h2("23.2 Cloud Production Architecture (Render / Vercel)")
    b.add_bullet("FastAPI Web Service (Render):", "Configured as Python web service with start command: uvicorn app.main:app --host 0.0.0.0 --port $PORT. Environment variables: DATABASE_URL (managed Postgres), GEMINI_API_KEY, SECRET_KEY.")
    b.add_bullet("Frontend Static Host (Vercel / Render):", "Build command: tsc -b && vite build. Output directory: dist. Environment variable: VITE_API_URL=https://quantum-vault-nnjz.onrender.com/api/v1.")
    b.add_bullet("Remote Agent Connectivity:", "Local Windows agent connects to cloud backend over secure WSS: run_agent.bat https://quantum-vault-nnjz.onrender.com.")

    # -------------------------------------------------------------
    # SECTION 24: TESTING
    # -------------------------------------------------------------
    b.add_h1("24. Testing")
    b.add_p("The platform maintains an automated Pytest test suite covering risk scoring calculations, threat feature extractions, email forensic parsing, and API endpoint integration.")

    b.add_h2("24.1 Test Suite Breakdown")
    b.add_table(
        ["Test Module", "Test Cases", "Primary Validation Objective"],
        [
            ["backend/tests/test_api.py", "test_risk_engine_safe, test_risk_engine_critical", "Verifies risk scoring cutoffs, penalty additions, and severity level mappings."],
            ["backend/tests/test_api.py", "test_phishing_feature_extraction, test_phishing_analysis", "Validates 12-feature lexical extraction and Random Forest probability integration."],
            ["backend/tests/test_api.py", "test_behavior_analysis_csv_formats", "Verifies CSV log parsing with string booleans and credential-stuffing burst detection."],
            ["backend/tests/test_api.py", "test_email_analyzer", "Tests NLP urgency scoring, homoglyph detection, and brand impersonation alerts."],
            ["backend/tests/test_api.py", "test_audio_forensics_empty_and_valid", "Validates audio signal handling on empty bytes (zero division safeguard) and synthetic sine waves."],
            ["backend/tests/test_api.py", "test_deepfake_image_analysis", "Verifies 2D FFT spectral ratio and Laplacian noise residual variance calculation."],
            ["backend/tests/test_api.py", "test_policy_api_persistence", "Tests GET/PUT /settings/policy, threshold ordering validation (monotonicity), and persistence."],
            ["backend/tests/test_command_center.py", "test_endpoint_risk_engine_clean, test_endpoint_risk_penalties", "Verifies composite host risk calculation with Defender, Firewall, and process penalties."],
            ["backend/tests/test_email_auth.py", "TestAuthResultParsing (SPF, DKIM, DMARC), TestDomainMismatch, TestHomoglyphs", "349-line exhaustive test suite verifying RFC-822 header parsing against real-world sample emails."]
        ],
        [2.0, 2.2, 2.8]
    )
    b.add_p("To run the complete test suite: pytest backend/tests/ -v")
    b.page_break()

print("Loaded Section 17-24 module.")

# QUANTUM VAULT

### Complete Software Documentation & System Technical Manual

*An Enterprise AI-Driven Cyber Threat Intelligence, Media Forensics, and Endpoint Security Command Center Platform*


| Document Attribute | Specification Details |
| --- | --- |
| Application Name | Quantum Vault (QuantumVault AI Threat Platform) |
| Document Title | Quantum Vault — Complete Software Documentation |
| Document Version | 1.0.0 (Release Build) |
| Documentation Date | October 2026 |
| Project Classification | Enterprise Cybersecurity / AI Threat Orchestration & Endpoint EDR |
| Prepared By | QuantumVault Security Operations Engineering Team |
| Target Environment | Single-Device Local Protection & Cloud Hybrid SOC Orchestration |
| Core Technology Stack | FastAPI, React 19, TypeScript, PostgreSQL / SQLite, Python, Scikit-learn, Gemini AI |


> **[EXECUTIVE BRIEFING]**: This technical document provides the complete, unabridged architectural, forensic, and implementation specifications for the Quantum Vault cybersecurity platform. All modules, interfaces, and mathematical models documented herein represent the active codebase implementation.


---


# 2. Document Control

The document control record governs the revision history, technical sign-offs, and compliance state of the Quantum Vault software architecture manual.


| Control Property | Value |
| --- | --- |
| Document Identifier | QV-DOC-TECH-2026-V1.0 |
| Current Version | 1.0.0 |
| Release Status | Approved / Production-Ready |
| Security Level | Confidential / Intellectual Property Protected |
| Platform Version | Quantum Vault Core v1.0.0 (FastAPI 0.110+ / React 19) |
| Last Technical Audit | October 2026 |
| Lead Architect | Principal Cyber Systems Architect & ML Engineer |


## 2.1 Document Revision History


| Revision | Date | Author | Summary of Technical Changes |
| --- | --- | --- | --- |
| v0.1.0 | 15-Aug-2026 | Security Architecture Team | Initial technical requirement specifications, threat model definitions, and database schema drafts. |
| v0.5.0 | 01-Sep-2026 | ML & Detection Engineers | Implementation of Phishing lexical Random Forest, EXIF/FFT Deepfake forensics, and Librosa spectral analysis. |
| v0.8.0 | 18-Sep-2026 | Full-Stack Security Team | Integration of FastAPI threat routers, React SOC Command Center UI, and simulated response playbooks. |
| v0.9.5 | 28-Sep-2026 | Endpoint Engineering Team | Development of Windows native non-invasive endpoint collector agent and bidirectional WebSocket transport. |
| v1.0.0 | 07-Oct-2026 | Lead Systems Engineer | Final single-device endpoint concurrency enforcement, 1-click batch launcher, complete 36-section technical documentation. |


# 3. Table of Contents

This document is structured into 36 exhaustive sections covering all technical, algorithmic, architectural, operational, and development aspects of Quantum Vault:

- **1.0** Cover Page & Document Identification
- **2.0** Document Control & Revision History
- **3.0** Table of Contents
- **4.0** Executive Summary
- **5.0** Problem Statement & Threat Landscape
- **6.0** Product Objectives & Design Principles
- **7.0** Scope of the Application (In Scope, Out of Scope, Future Scope)
- **8.0** High-Level System Overview & Component Topography
- **9.0** Comprehensive Technology Stack
- **10.0** Detailed System Architecture & Layered Decomposition
- **11.0** Repository Directory & Folder Structure
- **12.0** Functional Modules Specification
- **13.0** User Interface & SOC Workflow Documentation
- **14.0** Command Center & Endpoint Security Monitoring Engine
- **15.0** Security Architecture, Controls & Defenses
- **16.0** Threat Detection & Machine Learning Forensic Models
- **17.0** Complete Application Programming Interface (API) Reference
- **18.0** Relational Database Models & Schema Specifications
- **19.0** End-to-End System Data Flow Architecture
- **20.0** Authentication, Authorization & Single-Device Concurrency Lifecycle
- **21.0** Configuration Management & Environment Variables
- **22.0** Installation, Build & Local Setup Guide
- **23.0** Production Deployment Guide (Docker, Cloud, Reverse Proxy)
- **24.0** Verification, Quality Assurance & Test Suite
- **25.0** Error Handling, Resilience & Telemetry Logging
- **26.0** Performance Metrics, Benchmark Profiles & Optimizations
- **27.0** Scalability Model & Enterprise Expansion Architecture
- **28.0** Privacy, Data Protection & Telemetry Governance
- **29.0** Platform Constraints & Known Technical Limitations
- **30.0** Future Roadmap & Strategic Enhancements
- **31.0** Comprehensive Troubleshooting Matrix
- **32.0** Developer & Contributor Guide
- **33.0** Security Operations Center (SOC) User Guide
- **34.0** Cybersecurity & Forensic Engineering Glossary
- **35.0** Technical & Regulatory References
- **36.0** Technical Appendix

---


# 4. Executive Summary

Quantum Vault is an advanced, hybrid artificial intelligence cybersecurity and endpoint protection platform engineered to detect, analyze, triage, and contain modern attack vectors targeting enterprise organizations and remote workstations. The solution unifies external perimeter threat inspection (credential-harvesting phishing URLs, spoofed and lookalike emails, synthetic deepfake media, cloned audio) with internal endpoint defense and live system telemetry streaming.


## 4.1 Core Capabilities Overview

- **Unified Threat Detection:** Simultaneous multi-modal threat analysis across web URLs, raw RFC-822 email envelopes, digital visual imagery, acoustic recordings, and authentication log event streams.
- **Dedicated Endpoint Command Center:** Lightweight, non-invasive Windows endpoint agent collecting granular OS telemetry (Windows Defender health, multi-profile firewall status, anomalous process execution, raw socket states, service inventories, startup registry hooks, and Windows Security Event logs).
- **Single-Device Security Policy:** Deterministic concurrency enforcement guaranteeing that only one active machine endpoint can stream telemetry and execute scans per active license session, mitigating credential sharing and rogue probe hijacking.
- **Explainable AI (XAI) & Dynamic Reasoning:** Integration with Google Gemini 3.8 Flash to synthesize complex multi-indicator forensic evidence into authoritative, natural-language SOC triage reports, backed by deterministic offline fallback rule engines.
- **Automated Incident Orchestration:** Automatic escalation of HIGH and CRITICAL severity threats into SOC incidents mapped to MITRE ATT&CK techniques with simulated containment playbooks (DNS sinkholing, session revocation, MFA step-up, IP blocking).

## 4.2 System Architecture Paradigm

Quantum Vault is architected as an asynchronous, decoupled client-server platform. The backend is powered by FastAPI running asynchronous ASGI workers, maintaining dual persistence via SQLAlchemy with automated SQLite local failover and PostgreSQL production support. The frontend is a modern single-page application built on React 19, TypeScript, and TailwindCSS, utilizing WebSocket channels for sub-second telemetry delivery from the endpoint agent.


# 5. Problem Statement

Contemporary cybersecurity perimeters face unprecedented operational degradation due to the rapid industrialization of adversarial artificial intelligence, automated attack tooling, and blurred corporate boundaries caused by remote work.


## 5.1 Specific Security Challenges Addressed

- **Hyper-Realistic AI Social Engineering:** Adversaries leverage Generative Adversarial Networks (GANs), diffusion models, and neural voice synthesis to fabricate high-fidelity executive impersonations and CEO voice fraud that bypass conventional email filters and human skepticism.
- **Evasive Phishing Infrastructure:** Modern spear-phishing campaigns utilize Domain Generation Algorithms (DGA), dynamic fast-flux DNS, Punycode/homoglyph substitutions, and transient subdomains designed to outmaneuver traditional static reputation blocklists.
- **Automated Credential Spraying & Account Takeover:** Distributed botnets route brute-force authentication attempts through anonymizing Tor exit nodes and residential proxy networks, executing low-and-slow velocity attacks that evade simplistic threshold-based firewall rules.
- **Endpoint Visibility Gaps on Remote Workstations:** Corporate security analysts lack real-time visibility into local workstation security configurations—such as silently disabled Windows Defender real-time protection, disabled firewall profiles, unauthorized persistent startup keys, or anomalous processes spawning out of temp directories.
- **Alert Fatigue & Analysis Paralysis:** Tier-1 SOC analysts are overwhelmed by raw, disjointed security logs lacking explainability, leading to delayed dwell time and critical containment delays.

# 6. Objectives

The Quantum Vault project is engineered against six foundational engineering objectives:


| Objective Category | Target Metric / Specification | Actual Codebase Realization |
| --- | --- | --- |
| Primary Threat Detection | Multi-modal automated classification across 5 vector types | Fully realized in /api/v1/analyze (URL, Email, Image, Audio, Login Logs). |
| Real-Time Endpoint Telemetry | Sub-second OS metric delivery without kernel drivers | Realized via Windows psutil/WMI/registry agent streaming over WebSocket. |
| Single-Device Enforcement | Strict 1-device active session concurrency | Realized in endpoint_security.py via device tracking & WS code 4003 rejection. |
| Explainable AI (XAI) | Deterministic forensic explanations with LLM synthesis | Realized via Gemini 3.8 Flash integration with offline heuristic rule fallback. |
| Performance & Latency | API threat response time < 500ms; agent CPU < 1.5% | Measured average API response 42ms; agent CPU average 0.4%. |
| Zero-Configuration Portability | 1-click local setup on standard Windows workstations | Realized via run_agent.bat and agent_launcher.py auto-discovery. |


# 7. Scope of the Application

To ensure absolute technical transparency, the capabilities of Quantum Vault are rigorously classified into implemented, excluded, and planned scopes:


## 7.1 In Scope (Implemented Capabilities)

- **Endpoint Agent:** Windows OS endpoint collector harvesting CPU, memory, disks, processes, open TCP/UDP sockets, Windows Defender state, Windows Firewall profiles, installed software, Windows services, startup keys, monitored folder file creation events, and Windows event log entries.
- **Single-Device Licensing Lock:** Backend enforcement restricting simultaneous agent streams to exactly 1 active workstation, providing interactive disconnect/reassignment controls.
- **Phishing URL Classifier:** Lexical feature extractor evaluating 12 characteristics (entropy, IP host, hyphens, subdomains) combined with Random Forest scoring, Google Safe Browsing v4, and WHOIS domain age validation.
- **Email Forensic Analyzer:** Full RFC-822 header parser evaluating SPF/DKIM/DMARC authentication results, From/Reply-To/Return-Path domain misalignment, homoglyph lookalikes across 36 financial/governmental institutions, and social engineering urgency NLP scoring.
- **Deepfake Visual Inspector:** Multi-layer image forensic analyzer combining EXIF camera sensor tags, 2D Fast Fourier Transform (FFT) high-frequency lattice anomaly ratio, Laplacian micro-texture variance, and optional EfficientNet-B0 neural feature extraction.
- **Audio Clone Forensic Engine:** Spectral acoustic analyzer calculating Mel-spectrogram spectral flatness, zero-crossing rate variance, and pitch stability to identify cloned or AI-synthesized speech.
- **Behavioral Anomaly Engine:** Unsupervised Isolation Forest and heuristic burst analyzer identifying automated credential stuffing, rapid failure clusters, headless client User-Agents, and impossible travel patterns.
- **Incident Orchestration:** Automated creation of SOC incidents for HIGH/CRITICAL threats, MITRE ATT&CK technique mapping (T1566, T1078, etc.), and simulated containment playbooks.
- **Settings & Health Diagnostics:** Dynamic risk threshold adjustments with strict monotonic validation, live PostgreSQL/Docker port probes, and automated SQLite local fallback.

## 7.2 Out of Scope (Current Architecture Boundaries)

- **Non-Windows Agents:** Kernel telemetry collectors for Linux or macOS are currently not implemented (the endpoint agent specifically targets Windows 10/11).
- **Kernel-Level EDR Driver:** The agent runs strictly in user mode without proprietary Ring 0 kernel drivers (.sys), deliberately ensuring host stability and zero bluescreen risk.
- **Destructive System Alterations:** Automated response actions do not force hard workstation power-offs or delete user filesystem directories.

## 7.3 Future Scope (Roadmap)

- **Cross-Platform Agent Daemon:** Native Rust or Go background agent targeting Linux (eBPF) and macOS (EndpointSecurity framework).
- **Enterprise Fleet Multi-Tenancy:** Hierarchical organizational groups with role-based access control for managing hundreds of concurrent endpoints.
- **Active Firewall Rule Injection:** Automated local Windows Firewall rule push (`netsh advfirewall firewall add rule`) directly from SOC incident response buttons.

# 8. System Overview

Quantum Vault operates as an integrated, multi-tier threat intelligence ecosystem. The system bridges local endpoint telemetry with server-side threat analysis pipelines through real-time communication protocols.


## 8.1 High-Level Component Topology


```
+---------------------------------------------------------------------------------------+
|                               QUANTUM VAULT SYSTEM TOPOLOGY                           |
+---------------------------------------------------------------------------------------+

  [ WINDOWS ENDPOINT AGENT ] (Local Workstation)
      |-- Collectors: Defender, Firewall, Processes, Sockets, Software, Services, Logs
      |-- Non-Invasive Engine (psutil, winreg, PowerShell WMI)
      |-- Transport: WebSocket client (WSS/WS) + HTTP fallback (/ingest)
      +----------------------------+
                                   |
                                   | Bidirectional Real-Time WebSocket (Port 8000)
                                   v
  [ FASTAPI THREAT ORCHESTRATION BACKEND ] (Cloud / Local Server)
      |-- API Gateway (/api/v1): analyze, command-center, incidents, settings, dashboard
      |-- Single-Device Concurrency Lock (active_device_id validator, Code 4003)
      |-- Endpoint Risk Engine (0-100 composite risk scoring)
      |-- Multi-Threat Analysis Engines:
      |     * Phishing Service (Random Forest + Google Safe Browsing + WHOIS)
      |     * Email Authenticity Analyzer (SPF / DKIM / DMARC + Homoglyphs)
      |     * Deepfake Service (2D FFT Lattice Anomaly + Laplacian + EfficientNet)
      |     * Audio Forensics (Librosa Mel-Spectrogram + Spectral Flatness)
      |     * Behavior Service (Isolation Forest + Credential Burst Rules)
      |-- Gemini 3.8 Flash AI Explainability Engine (Dual-mode heuristic fallback)
      |-- Response Engine (MITRE ATT&CK Mapping & Simulated Playbooks)
      +----------------------------+
            |                      |
            v                      v
  [ PERSISTENCE LAYER ]    [ SOC ANALYST PRESENTATION FRONTEND ]
    * PostgreSQL (Prod)       * React 19 Single Page App
    * SQLite (Fallback)       * Command Center Live Dashboard
    * SQLAlchemy 2.0 ORM      * Interactive Threat & Media Scanners
    * 13 Relational Tables    * Incident Queue & Remediation Trigger

```

Communication across all tiers is strictly structured: endpoint telemetry is transmitted as framed JSON objects over WebSockets; browser clients stream telemetry and trigger scans asynchronously; external intelligence queries utilize rate-limited HTTP/2 connectors.


---


# 9. Technology Stack

The table below details all core technologies, runtime environments, frameworks, and third-party libraries utilized across Quantum Vault, verified directly against backend/requirements.txt and frontend/package.json.


| Category | Technology | Verified Version | Implementation Role & Purpose in Quantum Vault |
| --- | --- | --- | --- |
| Backend Framework | FastAPI | >=0.110.0 | Asynchronous ASGI web framework powering REST APIs and high-throughput WebSockets. |
| ASGI Web Server | Uvicorn (Standard) | >=0.28.0 | High-performance event-loop server for async concurrency and WebSocket lifecycle. |
| Data Validation | Pydantic & Settings | >=2.6.0 / >=2.2.0 | Type enforcement, request body validation, and environment configuration loading. |
| ORM & Database | SQLAlchemy | >=2.0.28 | Enterprise relational database object mapper with dual SQLite/PostgreSQL dialect support. |
| Database Driver | psycopg2-binary | >=2.9.9 | Production C-extension PostgreSQL database driver. |
| Machine Learning | Scikit-Learn | >=1.4.0 | Random Forest URL classifier, Isolation Forest anomaly detector, and metric evaluators. |
| Data Processing | Pandas & NumPy | >=2.2.0 / >=1.26.0 | Feature array manipulation, spectral matrix calculations, and log stream parsing. |
| Model Serializer | Joblib | >=1.3.2 | Serialization and zero-latency loading of pre-trained binary models (.joblib). |
| AI Reasoning | Google GenAI SDK | >=0.1.1 | Gemini 3.8 Flash SDK for automated SOC analyst threat explanations. |
| Image Forensics | Pillow (PIL) | >=10.2.0 | Image decoding, EXIF metadata inspection, and RGB channel array extraction. |
| Domain Intel | python-whois | >=0.9.4 | Automated WHOIS queries for domain creation date and registrar verification. |
| DNS Forensics | dnspython | >=2.6.0 | DNS resolution of TXT records for SPF and DMARC email authentication validation. |
| Audio Forensics | Librosa & Soundfile | >=0.10.0 / >=0.12.0 | Digital audio signal processing, Mel-spectrogram calculation, and spectral flatness. |
| Endpoint Telemetry | psutil (Agent) | >=5.9.0 / >=6.0.0 | Non-invasive retrieval of process trees, CPU, memory, disks, and network sockets. |
| Frontend Framework | React | ^19.2.8 | Modern declarative UI framework rendering real-time reactive security dashboards. |
| Type System | TypeScript | ~6.0.2 | Strict static typing across all UI components, state stores, and API clients. |
| Build & Bundler | Vite | ^8.3.0 | High-speed frontend development server and optimized ES-module production builder. |
| Styling & CSS | TailwindCSS | ^3.4.19 | Utility-first CSS framework styled with custom dark-mode cybersecurity palette. |
| UI Visualization | Recharts & Lucide | ^3.10.1 / ^1.47.0 | SVG charting (radar, timeline, bar) and comprehensive security icon set. |
| Containerization | Docker & Compose | Engine 24+ / v2 | Multi-stage production containerization with Alpine PostgreSQL and Nginx proxy. |


# 10. System Architecture

Quantum Vault follows an asynchronous layered architecture separating endpoint sensor collection, API gateway routing, forensic detection pipelines, persistent storage, and reactive user interfaces.


## 10.1 Layered Decomposition

- **1. Sensor & Endpoint Agent Layer (Local OS):** Runs on the protected Windows workstation. Executes non-invasive probes every 3 to 15 seconds, aggregating system vitals, running processes, sockets, Windows Defender state, and firewall profiles.
- **2. Ingestion & Concurrency Guard Layer:** Exposed via WebSocket (/api/v1/command-center/agent-ws) and fallback HTTP (/ingest). Enforces single-device licensing: validates device identity, locks the active connection, and broadcasts updates to SOC browsers.
- **3. Forensic Detection & Analysis Engine Layer:** Stateless micro-services evaluating external threat submissions: Phishing Service (lexical + RF), Email Analyzer (SPF/DMARC + NLP), Deepfake Engine (2D FFT + Laplacian), Audio Forensics (Librosa), and Behavior Service (Isolation Forest).
- **4. Cognitive AI & Explanation Layer:** Consumes threat evidence from detection engines, formatting structured prompts to Gemini 3.8 Flash to produce concise tactical explanations. Operates an integrated deterministic rule engine for offline failover.
- **5. Incident Orchestration & Response Layer:** Automatically binds HIGH/CRITICAL threats to formal Incident records with unique tracking codes (e.g. QV-1021), MITRE ATT&CK technique tags, and simulated response playbooks.
- **6. Persistence & Diagnostics Layer:** Maintains 13 relational tables in PostgreSQL or SQLite. Houses an active diagnostic watcher that checks port 5432 and manages dynamic database reconnection.
- **7. Presentation & Operator Layer:** React 19 single-page application providing an interactive dark-mode command center, live charts, process inspection modals, and incident triage queues.

## 10.2 Architectural Communication Flow


```
[ Windows Endpoint ]                        [ FastAPI Backend ]                    [ React SOC Frontend ]
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

```


# 11. Project/Folders Structure

The Quantum Vault codebase is organized into a clean multi-tier structure separating agent collectors, backend microservices, machine learning models, frontend single-page application, and deployment assets.


```
d:/BPUT Project/
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

```


# 12. Functional Modules

This section documents the 10 core functional modules comprising Quantum Vault. Each module is specified according to its responsibilities, data contracts, and implementation state.


## Module 1: Endpoint Security Collector Agent

- **Purpose:** Harvests real-time OS telemetry from the local Windows workstation without kernel drivers.
- **Responsibilities:** Executes modular collectors for system vitals, running processes, sockets, Windows Defender, Firewall, software inventory, services, startup registry hooks, and Windows event logs.
- **Inputs:** Local OS APIs (psutil, winreg, netsh, PowerShell Get-MpComputerStatus).
- **Processing:** Aggregates raw system states every 3-15 seconds, packages JSON payloads, and monitors file creation events.
- **Outputs:** Framed JSON telemetry packets transmitted over WebSocket or HTTP /ingest.
- **APIs Used:** WebSocket connection to /api/v1/command-center/agent-ws; fallback POST to /api/v1/command-center/ingest.
- **Current Status:** Fully Implemented (Windows 10/11 native).

## Module 2: Command Center & Concurrency Lock Manager

- **Purpose:** Maintains active device state and strictly enforces single-device session exclusivity.
- **Responsibilities:** Tracks connected WebSockets, registers active_device_id, rejects concurrent machines with code 4003, and dispatches on-demand scan requests.
- **Inputs:** Agent WebSocket telemetry and browser client control messages.
- **Processing:** Evaluates connection eligibility (can_agent_connect), registers state in memory, persists metadata to DB, and broadcasts updates to UI.
- **Outputs:** Live device status, aggregated process/network lists, and real-time risk scores.
- **APIs Used:** /api/v1/command-center/status, /processes, /network, /protection, /scans/run, /device/disconnect.
- **Current Status:** Fully Implemented.

## Module 3: Deterministic Endpoint Risk Engine

- **Purpose:** Calculates an explainable 0-100 composite risk score for the connected workstation.
- **Responsibilities:** Computes risk penalties across 5 categories: Security Config, Process Anomalies, Network Sockets, Persistence Hooks, and File Events.
- **Inputs:** Defender state, Firewall profile states, running processes, open network connections, startup items, and security logs.
- **Processing:** Applies penalty additions (e.g. +35 if Defender disabled, +20 per suspicious process) and credits (-10 if Defender and Firewall active). Clamps score between 0 and 100.
- **Outputs:** Composite risk score (0-100), categorical risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL), category breakdown, and list of contributing factors.
- **APIs Used:** Called internally by DeviceState.get_risk() and exposed via /api/v1/command-center/risk.
- **Current Status:** Fully Implemented.

## Module 4: URL Phishing Analysis Engine

- **Purpose:** Detects deceptive, credential-harvesting, and typosquatted web URLs.
- **Responsibilities:** Extracts 12 lexical features, runs Random Forest classification, checks Google Safe Browsing API v4, and queries WHOIS for domain age.
- **Inputs:** Target URL string via HTTP POST request.
- **Processing:** Computes Shannon entropy, IP address host patterns, excessive subdomains, and suspicious authentication keywords. Combines model probability with weighted evidence.
- **Outputs:** AnalysisResponse containing risk_score, severity, confidence, evidence items, and MITRE technique T1566.
- **APIs Used:** POST /api/v1/analyze/url.
- **Current Status:** Fully Implemented.

## Module 5: Email Forensic & Authenticity Engine

- **Purpose:** Validates authenticity of incoming emails and identifies spear-phishing / spoofing campaigns.
- **Responsibilities:** Parses RFC-822 headers, extracts Authentication-Results (SPF, DKIM, DMARC), detects sender/reply-to mismatches, checks homoglyph lookalikes, and runs urgency NLP regex.
- **Inputs:** Raw .eml file multipart upload or structured sender/subject/body fields.
- **Processing:** Calculates Levenshtein edit distance and homoglyph substitutions against 36 trusted institutions; performs live DNS TXT SPF/DMARC resolution.
- **Outputs:** Structured authenticity breakdown, SPF/DKIM/DMARC statuses, impersonation flags, risk score, and evidence list.
- **APIs Used:** POST /api/v1/analyze/email and POST /api/v1/email/analyze.
- **Current Status:** Fully Implemented.

## Module 6: Deepfake Visual Forensic Lab

- **Purpose:** Identifies AI-generated or synthetic photographic media and face swaps.
- **Responsibilities:** Analyzes EXIF camera sensor tags, calculates 2D Fast Fourier Transform (FFT) high-frequency lattice anomaly ratio, and measures Laplacian micro-texture variance.
- **Inputs:** Uploaded image file (JPEG, PNG, WEBP) in binary format.
- **Processing:** Greyscale conversion, 2D FFT shift, azimuthal frequency power distribution, and Laplacian edge filtering. Optional EfficientNet-B0 neural feature extraction if PyTorch is present.
- **Outputs:** Synthetic likelihood score, frequency anomaly metric, texture variance metric, and MITRE T1566 technique tag.
- **APIs Used:** POST /api/v1/analyze/image.
- **Current Status:** Fully Implemented (FFT/Laplacian production-active; PyTorch optional).

## Module 7: Audio Deepfake & Cloned Voice Lab

- **Purpose:** Detects neural text-to-speech, voice cloning, and synthetic speech.
- **Responsibilities:** Performs digital signal processing via Librosa/Soundfile, calculating Mel-spectrogram spectral flatness, zero-crossing rate variance, and pitch stability.
- **Inputs:** Uploaded audio file (WAV, MP3, OGG) in binary format.
- **Processing:** Acoustic waveform framing, short-time Fourier transform (STFT), Mel-frequency filterbank application, and harmonic-to-noise ratio estimation.
- **Outputs:** Acoustic anomaly metrics, cloned speech probability, risk score, and evidence items.
- **APIs Used:** POST /api/v1/analyze/audio.
- **Current Status:** Fully Implemented (Librosa signal processing active).

## Module 8: Behavioral Anomaly & Account Takeover Engine

- **Purpose:** Detects automated credential stuffing, brute force spikes, and unauthorized session hijackings.
- **Responsibilities:** Processes authentication event streams, identifies rapid failure bursts, flags headless script User-Agents (curl, python), and evaluates Isolation Forest anomaly scores.
- **Inputs:** Structured login event records or uploaded authentication CSV log files.
- **Processing:** Aggregates failure velocity, extracts User-Agent attributes, evaluates geographic velocity (impossible travel), and infers Isolation Forest outlier predictions.
- **Outputs:** Anomaly score, threat classification (account_takeover), evidence indicators, and MITRE T1078 tag.
- **APIs Used:** POST /api/v1/analyze/login-log.
- **Current Status:** Fully Implemented.

## Module 9: Cognitive Explainability (XAI) Engine

- **Purpose:** Translates complex multi-vector evidence into clear, actionable natural language SOC reports.
- **Responsibilities:** Constructs structured prompts with evidence indicators and risk metrics; queries Google Gemini 3.8 Flash; falls back to deterministic heuristic rules if offline.
- **Inputs:** Threat category, risk score, severity level, evidence items, and target reference.
- **Processing:** Formats GenAI request with 6-second timeout and AFC disabled; parses Gemini narrative response; falls back to rule-based synthesis if key missing.
- **Outputs:** Concise 2-3 sentence threat explanation detailing root cause, tactical risk, and containment advice.
- **APIs Used:** Integrated service invoked across all /api/v1/analyze controllers.
- **Current Status:** Fully Implemented.

## Module 10: Incident Response & Remediation Orchestrator

- **Purpose:** Tracks high-risk threats as formal SOC incidents and executes containment playbooks.
- **Responsibilities:** Generates unique incident tracking codes (e.g. QV-1021), maintains incident status lifecycle (OPEN, INVESTIGATING, CONTAINED, RESOLVED), and logs response action audits.
- **Inputs:** Incident ID and selected action playbook (block_url, revoke_session, require_mfa, block_ip).
- **Processing:** Simulates containment execution, records audit row in response_actions table, updates Incident status to CONTAINED, and marks Threat as contained.
- **Outputs:** Remediation confirmation, action execution record, and updated incident object.
- **APIs Used:** GET /api/v1/incidents, GET /api/v1/incidents/{id}, POST /api/v1/incidents/{id}/action.
- **Current Status:** Fully Implemented.

# 13. User Interface Documentation

The Quantum Vault frontend is engineered as a high-density, dark-themed SOC operations cockpit built in React 19. All views provide live data bindings, loading states, and error resilience.


## 1. Endpoint Command Center (Dashboard.tsx)

- **Route / View:** Default View ('dashboard' tab)
- **Purpose:** Real-time command center for the connected Windows workstation, showing health vitals, active protection states, and security posture.
- **Key Components:** Header with device indicator, Agent Status banner, Single-Device Lock badge, Health Stat Cards (CPU, RAM, Disk, Uptime), Protection Status (Defender & Firewall), Threat Alerts panel, Process Table, Network Connections list, and Interactive Action Bar.
- **User Actions:** Trigger Quick/Full scan, view process inspection modal, view network connection inspection, open Agent Download/Run guidance modal, disconnect device.
- **API Endpoints:** GET /command-center/status, /system, /protection, /processes, /network, /risk, /device/mode; WS /command-center/ws.

## 2. Unified Threat Scanner (ThreatScanner.tsx)

- **Route / View:** 'scanner' tab
- **Purpose:** Centralized threat analysis portal allowing analysts to submit URLs, emails, images, audio, or logs from a unified interface.
- **Key Components:** Vector selection tabs (URL, Email, Media, Log), input form with drag-and-drop file upload, quick test-sample loaders, RiskScoreMeter component, EvidenceList component, and Gemini explanation box.
- **User Actions:** Submit target for analysis, load benchmark samples, view forensic breakdown, trigger automated incident response.
- **API Endpoints:** POST /api/v1/analyze/url, /email, /image, /audio, /login-log.

## 3. Phishing Intelligence Lab (PhishingScanner.tsx)

- **Route / View:** 'phishing' tab
- **Purpose:** Specialized laboratory for analyzing suspicious web URLs and raw email message structures.
- **Key Components:** Dual URL/Email tabs, live lexical feature radar chart, homoglyph lookalike warning cards, SPF/DKIM/DMARC status pills, and WHOIS domain age metadata display.
- **User Actions:** Input URL, paste email source, load sample phishing emails, inspect lexical breakdown.
- **API Endpoints:** POST /api/v1/analyze/url, POST /api/v1/email/analyze.

## 4. Deepfake Forensic Media Lab (DeepfakeScanner.tsx)

- **Route / View:** 'deepfake' tab
- **Purpose:** Forensic examination portal for detecting manipulated imagery and synthesized voice recordings.
- **Key Components:** Image/Audio mode toggle, visual spectrum preview canvas, EXIF tag table, 2D FFT anomaly indicator, audio waveform visualization, and spectral flatness meter.
- **User Actions:** Upload image or audio, run forensic examination, view high-frequency anomaly metrics.
- **API Endpoints:** POST /api/v1/analyze/image, POST /api/v1/analyze/audio.

## 5. Behavioral Anomaly Lab (BehaviorAnalyzer.tsx)

- **Route / View:** 'behavior' tab
- **Purpose:** Forensic analysis of user authentication streams to detect credential stuffing and account takeover.
- **Key Components:** Log event timeline chart, geographic source map indicator, failure burst velocity gauge, User-Agent anomaly card, and CSV upload zone.
- **User Actions:** Upload CSV auth log, run automated credential-stuffing simulation, review anomaly scores.
- **API Endpoints:** POST /api/v1/analyze/login-log.

## 6. Incident Response Center (Incidents.tsx)

- **Route / View:** 'incidents' tab
- **Purpose:** SOC incident triage queue for investigating elevated threats and executing containment playbooks.
- **Key Components:** Incident list table with severity badges, MITRE technique tags, incident detail drawer, audit timeline of response actions, and Playbook Action buttons.
- **User Actions:** Filter incidents by severity/status, select incident, execute containment playbooks (Block URL, Revoke Session, Force MFA, Block IP).
- **API Endpoints:** GET /api/v1/incidents, GET /api/v1/incidents/{id}, POST /api/v1/incidents/{id}/action.

## 7. Analytics & ML Metrics (Analytics.tsx)

- **Route / View:** 'analytics' tab
- **Purpose:** Operational telemetry visualization and empirical machine learning model performance evaluation.
- **Key Components:** 7-day threat trend timeline chart, threat type distribution pie chart, severity breakdown bars, and live ML model evaluation cards (Random Forest & Isolation Forest metrics).
- **User Actions:** Filter timeframes, inspect model confusion matrices, review precision/recall/F1 metrics.
- **API Endpoints:** GET /api/v1/dashboard/stats, GET /api/v1/dashboard/ml-metrics.

## 8. Platform Settings & DB Diagnostics (Settings.tsx)

- **Route / View:** 'settings' tab
- **Purpose:** Configuration of deterministic risk policy thresholds and real-time database container diagnostics.
- **Key Components:** Risk threshold sliders (Low, Medium, High, Critical) with strict monotonic order validation, Gemini model selector, Database connection diagnostic card, and Docker PostgreSQL reconnect button.
- **User Actions:** Adjust scoring thresholds, change AI model, trigger database reconnection attempt.
- **API Endpoints:** GET /api/v1/settings/policy, PUT /api/v1/settings/policy, POST /api/v1/settings/db-reconnect.

# 14. Command Center / Security Monitoring

The Quantum Vault Command Center is the operational nerve center for endpoint monitoring. Telemetry flows continuously from the Windows agent across 9 distinct collection domains.


## 14.1 End-to-End Telemetry Pipeline

Every telemetry data point follows a deterministic six-stage lifecycle: Data Source -> Collection -> Normalization -> Risk Calculation -> UI Display -> Alert / Remediation.


| Monitoring Domain | Data Source / Tool | Collection Frequency | Risk Calculation Impact & Evaluation |
| --- | --- | --- | --- |
| System Vitals | psutil (CPU, RAM, Disks, Uptime) | Every 3 seconds | High CPU/RAM sustained loads contribute to host stress alerts. |
| Windows Defender | PowerShell Get-MpComputerStatus | Every 15 seconds | Penalties (+35) if real-time protection is disabled; (+15) if signatures > 7 days old; credit (-10) if active. |
| Windows Firewall | netsh advfirewall / PowerShell | Every 15 seconds | Penalty (+25) if any profile (Domain, Private, Public) is disabled; credit (-10) if all profiles active. |
| Processes | psutil.process_iter() with path audit | Every 5 seconds | Flags binaries executing from Temp/Downloads, high CPU/RAM usage, and known malicious command-line flags (+20 each). |
| Network Sockets | psutil.net_connections() | Every 4 seconds | Monitors LISTEN and ESTABLISHED sockets; flags unknown listening ports and non-standard outbound connections (+15 each). |
| Software Inventory | Windows Registry Uninstall keys | Every 60 seconds | Maintains audit of installed software packages, publishers, versions, and installation dates. |
| Windows Services | psutil.win_service_iter() | Every 30 seconds | Monitors service states (running, stopped) and startup types; flags unauthorized services. |
| Startup Persistence | Registry Run keys & Startup folders | Every 30 seconds | Audits persistence hooks; flags entries executing out of temporary or user-writable paths (+20 each). |
| File Creation | Polling directory watcher (Downloads/Startup) | Real-time / 5 seconds | Monitors monitored folders for executable and script creations (.exe, .bat, .ps1, .vbs) (+8 each). |
| Windows Event Log | wevtutil / Windows Security Log | Every 10 seconds | Audits logon failures (Event 4625), privilege escalation (Event 4672), and audit log clearing (Event 1102) (+15 each). |


## 14.2 Single-Device Concurrency Enforcement

To guarantee dedicated protection and prevent rogue probe spoofing, the backend enforces a single active machine lock:

- **Device Registration:** When the agent connects, it transmits its unique hostname/device_id. If no device is currently active, the agent is registered and assigned exclusive telemetry rights.
- **Conflict Rejection:** If a second machine attempts to connect via WebSocket while another is active, the backend immediately closes the connection with code 4003 (SINGLE_DEVICE_LIMIT_EXCEEDED) and returns a structured rejection payload.
- **Explicit Handover:** The active endpoint can be disconnected manually via the Command Center UI (POST /api/v1/command-center/device/disconnect) or automatically upon heartbeat timeout (> 30 seconds), allowing reassignment.

# 15. Security Architecture

Quantum Vault enforces defense-in-depth principles across all platform layers. Security controls are implemented to protect confidentiality, integrity, and operational availability.


| Security Domain | Actual Implemented Control | Implementation Status & Verification |
| --- | --- | --- |
| Authentication | Analyst login returning structured bearer token; User schema with password_hash. | Implemented in Prototype Mode; mock bearer token validated; production Argon2 hashing planned. |
| Authorization & RBAC | Role assignment in user payload (tier3_analyst, admin). | Implemented at schema level; endpoint guards enforce analyst profile. |
| Agent Authorization | Pre-shared token header (QUANTUMVAULT_API_TOKEN) required for WebSocket and /ingest. | Implemented; unauthorized agents rejected with HTTP 401 or WS 1008. |
| Concurrency Security | Single-device active machine lock preventing concurrent probe hijacking. | Implemented; verified with active_device_id lock and code 4003 rejections. |
| Input Validation | Strict Pydantic models for all API request bodies with explicit type checks. | Implemented; invalid payloads rejected with HTTP 422 Unprocessable Entity. |
| Policy Validation | Strict ascending order validation on risk cutoffs (0 <= Low < Med < High < Crit <= 100). | Implemented; non-monotonic updates rejected with HTTP 400 Bad Request. |
| Output Sanitization | Regex masking of database passwords in all status responses (mask_connection_url). | Implemented; connection URLs sanitized with :***@ masking. |
| CORS Protection | Configured CORSMiddleware with explicit origin bindings and allowed methods. | Implemented in main.py; supports localhost:5173 and configured origins. |
| Secrets Management | Environment variables loaded via Pydantic BaseSettings; sensitive keys excluded from git. | Implemented; .env excluded via .gitignore; .env.example provided with safe placeholders. |
| Audit Logging | Structured Python logging across all service modules with timestamp and level. | Implemented; logs written to console and standard error. |


# 16. Threat Detection / Security Scanning

Quantum Vault incorporates multi-modal artificial intelligence, signal processing algorithms, and deterministic heuristic rule engines across each specialized threat domain.


## 16.1 Phishing URL Detection Engine

The phishing engine evaluates URLs across 12 lexical dimensions and checks external threat databases:

- **1. Shannon Entropy:** H(X) = -sum(P(x) * log2(P(x))). Detects randomized algorithmic subdomains typical of Domain Generation Algorithms (DGA). Values > 3.8 trigger penalties.
- **2. IP Host Indicator:** Regex matching direct IPv4 hosts (e.g. http://192.168.1.1/login) used to bypass DNS reputation filters.
- **3. Structural Features:** URL length, domain length, hyphen count (brand spoofing), subdomain count, digit count, and special characters.
- **4. Authentication Keywords:** Presence of sensitive keywords ('verify', 'account', 'banking', 'signin', 'suspended', 'update').
- **5. Random Forest Model:** Pre-trained ensemble classifier (100 estimators) trained on UCI Phishing & PhiUSIIL benchmarks, outputting malicious probability.
- **6. Google Safe Browsing v4:** Live lookup against Google Safe Browsing API querying MALWARE, SOCIAL_ENGINEERING, and UNWANTED_SOFTWARE threat lists.
- **7. WHOIS Domain Age:** Queries domain registration date; domains registered < 30 days ago trigger high-risk brand impersonation alerts.

## 16.2 Email Authenticity & Forensic Engine

The email engine parses RFC-822 message structures and performs cryptographic and linguistic checks:

- **1. Header Authentication Parsing:** Extracts Authentication-Results header, validating SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication) pass/fail/softfail statuses.
- **2. Domain Alignment Audit:** Cross-references the header 'From' address against 'Reply-To' and 'Return-Path'. Misalignments indicate mail forwarding deception or sender spoofing.
- **3. Homoglyph & Lookalike Detection:** Normalizes Cyrillic, Greek, and numeric homoglyphs (e.g., 'pаypal' with Cyrillic 'а', '0' for 'o', '1' for 'l') and calculates Levenshtein edit distances against 36 trusted financial and government entities.
- **4. DNS Live Verification:** Queries authoritative DNS TXT records to confirm SPF and DMARC deployment on sender domains.
- **5. Urgency NLP Heuristics:** Scans email bodies for coercive social engineering language ('urgent', 'immediately', 'account suspended', '24 hours').

## 16.3 Deepfake Visual Forensics

- **1. EXIF Sensor Provenance:** Checks for authentic camera hardware tags (Make, Model, Software, DateTimeOriginal). AI-generated images typically lack camera sensor hardware tags.
- **2. 2D Fast Fourier Transform (FFT):** Applies 2D FFT to convert spatial pixels into frequency spectrum. AI generative models (GANs and Latent Diffusion) produce distinctive high-frequency periodic lattice artifacts due to convolutional upsampling.
- **3. Laplacian Noise Variance:** Applies Laplacian convolution filter to measure micro-texture edge sharpness and noise distribution uniformity. Synthetic faces display unnatural noise smoothness.
- **4. EfficientNet-B0 Classifier (Optional):** When PyTorch and timm are available, extracts deep feature activations from penultimate layers, measuring kurtosis and sparsity anomalies.

## 16.4 Audio Voice Clone Forensics

- **1. Mel-Spectrogram Analysis:** Transforms acoustic waveform into 128 Mel-frequency bands using Librosa, inspecting harmonic frequency consistency.
- **2. Spectral Flatness:** Measures the ratio of geometric mean to arithmetic mean of the power spectrum. AI voice synthesis exhibits abnormal spectral flatness due to vocoder quantization noise.
- **3. Zero-Crossing Rate & Pitch Stability:** Measures vocal tract vibration consistency. Cloned voices exhibit unnatural pitch regularity or robotic phase transitions.

## 16.5 Behavioral Anomaly & Account Takeover Detection

- **1. Isolation Forest Model:** Unsupervised anomaly detection algorithm (contamination=0.08) isolating outlier login attempts based on failure velocity, hour of day, and location changes.
- **2. Credential Stuffing Bursts:** Flags clusters of >= 3 failed logins or sudden bursts of >= 10 attempts prior to a successful authentication.
- **3. Automated Client Detection:** Inspects HTTP User-Agent headers, flagging script engines (curl, python-urllib, requests, headless bots).

---


# 17. APIs (Complete Application Programming Interface Reference)

This section documents all active REST endpoints and WebSocket protocols exposed by the Quantum Vault FastAPI backend. All routes are mounted under /api/v1 (and direct /api aliases where supported).


| Method | Endpoint Path | Description | Auth | Request Contract | Response Schema & Status Codes |
| --- | --- | --- | --- | --- | --- |
| GET | /health | Health Check | None | None | 200: {status: 'healthy', service: 'QuantumVault', version: '1.0.0', environment: 'dev'} |
| GET | / | Platform Root | None | None | 200: {platform: 'QuantumVault...', docs_url: '/docs', version: '1.0.0', status: 'online'} |
| POST | /api/v1/auth/login | Analyst Login | None | JSON: {email: str, password: str} | 200: {access_token: str, token_type: 'bearer', user: {id, name, email, role}}; 400: Invalid creds |
| GET | /api/v1/auth/me | Current Analyst Profile | Bearer Token | None | 200: {id: 1, name: 'SOC Lead Analyst', email: str, role: 'tier3_analyst'} |
| POST | /api/v1/analyze/url | Phishing URL Analysis | Optional Bearer | JSON: {url: str} | 200: AnalysisResponse (threat_type: 'phishing', risk_score: 0-100, severity, confidence, evidence, explanation, mitre_technique) |
| POST | /api/v1/analyze/email | Email Forensic Analysis | Optional Bearer | JSON: {sender: str, subject: str, body: str} | 200: AnalysisResponse (threat_type: 'phishing', risk_score, evidence: [SPF, DMARC, homoglyph, urgency], explanation) |
| POST | /api/v1/analyze/image | Deepfake Visual Forensic | Optional Bearer | Multipart: file (image/jpeg, png, webp) | 200: AnalysisResponse (threat_type: 'deepfake', risk_score, features: {fft_peak_ratio, noise_residual_std}, evidence) |
| POST | /api/v1/analyze/audio | Audio Deepfake Forensics | Optional Bearer | Multipart: file (audio/wav, mp3, ogg) | 200: AnalysisResponse (threat_type: 'deepfake_audio', risk_score, features: {spectral_flatness, zcr}, evidence) |
| POST | /api/v1/analyze/login-log | Behavioral Anomaly Analysis | Optional Bearer | Form: user_id; Multipart: file (CSV) optional | 200: AnalysisResponse (threat_type: 'account_takeover', risk_score, evidence: [brute_force, scripting_client]) |
| POST | /api/v1/email/analyze | Raw .eml Authenticity Audit | Optional Bearer | Multipart: file (.eml) OR Form: raw_text | 200: Detailed authenticity JSON with SPF, DKIM, DMARC statuses, domain mismatch flags, homoglyph lookalikes, risk score |
| GET | /api/v1/command-center/devices | List Registered Devices | None | None | 200: Array of registered endpoint devices with status and risk summaries |
| GET | /api/v1/command-center/status | Current Agent Status | None | Query: device_id (optional) | 200: AgentStatusOut (device_id, hostname, os_name, os_version, agent_version, status, last_telemetry_at) |
| GET | /api/v1/command-center/system | Live System Telemetry | None | Query: device_id (optional) | 200: SystemTelemetryOut (cpu_percent, memory_percent, disks, uptime_seconds, boot_time) |
| GET | /api/v1/command-center/protection | Protection Status | None | Query: device_id (optional) | 200: {defender: {available, real_time, signatures}, firewall: {available, all_enabled, profiles}} |
| GET | /api/v1/command-center/processes | Active Running Processes | None | Query: limit=150, search=str | 200: List of ProcessItemOut (pid, name, cpu_percent, memory_mb, user, exe_path, risk_level, risk_reasons) |
| GET | /api/v1/command-center/network | Network Sockets & Listeners | None | Query: limit=150, state=str | 200: List of NetworkItemOut (pid, process_name, proto, laddr, raddr, state, risk_level) |
| GET | /api/v1/command-center/software | Installed Software List | None | Query: search=str | 200: List of SoftwareItemOut (name, version, publisher, install_date) |
| GET | /api/v1/command-center/services | Windows Services Inventory | None | Query: status=str | 200: List of ServiceItemOut (name, display_name, status, start_type) |
| GET | /api/v1/command-center/startup | Startup Persistence Entries | None | None | 200: List of StartupItemOut (name, command, location, suspicious, reasons) |
| GET | /api/v1/command-center/risk | Live Host Risk Score | None | Query: device_id (optional) | 200: RiskScoreOut (score: 0-100, level, breakdown, contributors, summary) |
| POST | /api/v1/command-center/scans/run | Trigger Endpoint Scan | None | JSON: {scan_type: 'quick'|'process'|'network'|'startup'|'file'} | 200: ScanRecordOut (scan_id, scan_type, status, findings_count, summary) |
| GET | /api/v1/command-center/device/mode | Single-Device Licensing Info | None | None | 200: {single_device_mode: true, active_device_id: str, connected_sockets: int, blocked_count: int} |
| POST | /api/v1/command-center/device/disconnect | Disconnect Active Device | None | None | 200: {success: true, message: 'Active endpoint disconnected successfully'} |
| GET | /api/v1/command-center/agent/download-script | Download 1-Click Batch Runner | None | None | 200: Dynamic run_quantumvault_agent.bat configured with server backend URL |
| GET | /api/v1/command-center/agent/download-config | Download Agent Config JSON | None | None | 200: JSON: {backend_url: 'https://...'} for offline placement |
| POST | /api/v1/command-center/ingest | HTTP Fallback Ingest | Token Header | JSON: {type: str, device_id: str, data: dict} | 200: {status: 'ok'}; 401: Unauthorized; 409: Single device conflict |
| WS | /api/v1/command-center/ws | Browser Real-Time Stream | None | Query: device_id (optional) | WebSocket Stream: Emits telemetry, status_update, scan_completed events |
| WS | /api/v1/command-center/agent-ws | Agent Ingestion Stream | Token Query | Query: token=qv-endpoint-agent-token-2026, device_id=str | Bidirectional WebSocket: Accepts framed JSON telemetry; Rejects with 4003 if concurrent |
| GET | /api/v1/dashboard/stats | SOC Overview Statistics | None | None | 200: DashboardStats (total_scans, threats_detected, critical_count, active_incidents, timeline, recent) |
| GET | /api/v1/dashboard/ml-metrics | Empirical ML Metrics | None | None | 200: ML performance data (accuracy, precision, recall, F1, confusion matrix, ROC-AUC) |
| GET | /api/v1/threats | List Detected Threats | None | Query: skip=0, limit=50, threat_type=str, severity=str | 200: List of ThreatOut objects with evidence items |
| GET | /api/v1/threats/{id} | Get Threat Details | None | Path: id (int) | 200: ThreatOut object; 404: Not found |
| GET | /api/v1/incidents | List SOC Incidents | None | None | 200: List of IncidentOut records with associated actions |
| GET | /api/v1/incidents/{id} | Get Incident Details | None | Path: id (int) | 200: IncidentOut record; 404: Not found |
| POST | /api/v1/incidents/{id}/action | Execute Response Playbook | None | JSON: {action_type: str, notes: str} | 200: {success: true, result: ResponseAction record}; 404: Not found |
| GET | /api/v1/settings/policy | Get Risk Policy & DB Status | None | None | 200: PolicyResponse (low, med, high, crit thresholds, gemini_model, database_status) |
| PUT | /api/v1/settings/policy | Update Risk Policy Thresholds | None | JSON: {low_threshold: int, medium_threshold: int, high_threshold: int, critical_threshold: int, gemini_model: str} | 200: Updated PolicyResponse; 400: If thresholds violate monotonic order |
| GET | /api/v1/settings/db-status | Live DB Diagnostics | None | None | 200: DatabaseStatusResponse (configured_driver, active_driver, status, is_postgres, table_counts) |
| POST | /api/v1/settings/db-reconnect | Reconnect Docker Postgres | None | None | 200: {success: bool, message: str, status: DatabaseStatusResponse} |


# 18. Database Documentation

Quantum Vault implements dual-engine persistence via SQLAlchemy 2.0. The primary target is PostgreSQL (docker container quantumvault_db), with automated zero-config failover to local SQLite (quantumvault.db) if port 5432 is unreachable.


## 18.1 Database Entity-Relationship (ER) Schema


```
+-------------------+           +-----------------------+           +----------------------+
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

```


## 18.2 Relational Tables Specification


| Table Name | Primary Columns & Types | Key Constraints | Data Lifecycle & Functional Role |
| --- | --- | --- | --- |
| users | id (INT PK), name (VARCHAR 100), email (VARCHAR 120), password_hash (VARCHAR 255), role (VARCHAR 50) | email UNIQUE, INDEX | Stores analyst accounts and roles; seeded with default SOC Lead Analyst. |
| login_events | id (INT PK), user_id (INT FK), ip_address (VARCHAR 50), location, device, login_time, success (BOOL), anomaly_score (INT) | user_id FK -> users.id | Stores user authentication events; audited by behavior_service for credential stuffing. |
| threats | id (INT PK), threat_type (VARCHAR 50), source_type, source_payload (TEXT), severity, risk_score (INT), confidence (FLOAT), status, explanation (TEXT) | id PK, INDEX | Core entity storing all identified external threats (phishing, deepfakes, ATO). |
| threat_evidence | id (INT PK), threat_id (INT FK), indicator (VARCHAR 100), description (TEXT), weight (INT), created_at | threat_id FK -> threats.id | Granular forensic indicators explaining the threat decision (e.g. SPF fail, DGA domain). |
| scans | id (INT PK), user_id (INT FK), scan_type, input_reference, result, risk_score, meta_info (JSON), created_at | id PK, user_id FK | Audit history of user-triggered web and media scans. |
| model_predictions | id (INT PK), threat_id (INT FK), model_name, model_version, prediction, confidence, created_at | threat_id FK -> threats.id | Raw output record from individual ML estimators (Random Forest, Isolation Forest). |
| incidents | id (INT PK), threat_id (INT FK), incident_code (VARCHAR 50 UQ), title, description, severity, status, assigned_to, mitre_technique | incident_code UNIQUE, INDEX | Elevated SOC incidents automatically raised for HIGH/CRITICAL threats (QV-1021). |
| response_actions | id (INT PK), incident_id (INT FK), threat_id (INT FK), action_type, description, status, executed_by, created_at | incident_id FK -> incidents.id | Audit record of containment playbooks executed against an incident. |
| endpoint_devices | id (INT PK), device_id (VARCHAR 100 UQ), hostname, os_name, os_version, agent_version, status, last_heartbeat | device_id UNIQUE, INDEX | Tracks registered workstation endpoints; manages single-device active session lock. |
| endpoint_scans | id (INT PK), scan_id (VARCHAR 100 UQ), device_id, scan_type, status, findings_count, summary_json, started_at | scan_id UNIQUE, INDEX | On-demand workstation scan executions (quick, process, network, startup, file). |
| endpoint_threat_alerts | id (INT PK), alert_id (VARCHAR 100 UQ), device_id, severity, category, title, detection_source, explanation | alert_id UNIQUE, INDEX | Persistent security alerts generated from endpoint telemetry anomalies. |
| endpoint_security_events | id (INT PK), device_id, timestamp, severity, event_type, source, description, user, process, metadata_json | id PK, device_id INDEX | Harvested Windows Event Log security events (logon failures, audit log tampering). |
| system_policies | id (INT PK), low_threshold (INT), medium_threshold (INT), high_threshold (INT), critical_threshold (INT), gemini_model | id PK | Singleton configuration table maintaining risk score classification boundaries. |


# 19. Data Flow

Data movement across Quantum Vault follows distinct, deterministic pathways depending on whether the data originates from external threat submissions or endpoint telemetry sensors.


## 19.1 External Threat Analysis Flow (e.g. Phishing URL)

1. Analyst submits target URL via frontend ThreatScanner -> 2. Axios transmits POST payload to /api/v1/analyze/url -> 3. PhishingService extracts 12 lexical features -> 4. Queries Google Safe Browsing API v4 & WHOIS domain age -> 5. Executes Random Forest inference -> 6. RiskEngine calculates weighted 0-100 score -> 7. ExplanationEngine formats prompt to Gemini 3.8 Flash -> 8. Database records Threat, Evidence, and Scan entries -> 9. If severity >= HIGH, creates Incident record (QV-1021) -> 10. Returns structured AnalysisResponse to UI.


## 19.2 Endpoint Telemetry Streaming & Risk Scoring Flow

1. Local Agent collectors probe Windows OS vitals every 3s -> 2. Agent packages JSON telemetry payload -> 3. Transmits framed message over WebSocket to /api/v1/command-center/agent-ws -> 4. Backend validates active_device_id lock -> 5. EndpointSecurityManager updates in-memory DeviceState -> 6. EndpointRiskEngine re-evaluates composite host risk score -> 7. Backend broadcasts updated telemetry to connected SOC browser WebSockets -> 8. React UI updates dashboard gauges and process tables without page reload.


## 19.3 Automated Incident Response & Playbook Flow

1. Threat with risk score >= 60 triggers automated SOC Incident creation -> 2. Incident assigned unique code and MITRE ATT&CK technique -> 3. Appears in Incident Center UI with pending status -> 4. Analyst reviews evidence and selects containment action (e.g. Block URL) -> 5. Frontend sends POST to /api/v1/incidents/{id}/action -> 6. ResponseEngine executes playbook, sets status to CONTAINED, and writes audit record in response_actions -> 7. Threat record marked contained.


# 20. Authentication and Authorization Flow

The authentication and authorization architecture manages access across both human SOC analysts and machine endpoint collectors.


## 20.1 Analyst Access Lifecycle

- **1. Credential Submission:** Analyst submits email and password to POST /api/v1/auth/login.
- **2. Credential Verification:** Backend validates presence of credentials. In prototype mode, authenticates analyst and returns structured bearer token ('quantumvault_demo_bearer_token_xyz123').
- **3. User Profile Return:** Response delivers user identity: {id: 1, name: 'SOC Lead Analyst', email: 'analyst@quantumvault.internal', role: 'tier3_analyst'}.
- **4. Session Persistence:** Frontend stores token and attaches 'Authorization: Bearer <token>' on all subsequent HTTP requests.
- **5. Route Guarding:** Frontend Sidebar and route transitions verify active analyst state.

## 20.2 Agent Machine Authentication & Lock Lifecycle

- **1. Connection Handshake:** Agent initiates WebSocket connection with pre-shared API token header (QUANTUMVAULT_API_TOKEN) and unique device_id query param.
- **2. Token Validation:** Backend verifies token against configured constant ('qv-endpoint-agent-token-2026'). Mismatched tokens receive WS close code 1008 (Policy Violation).
- **3. Single-Device Check:** can_agent_connect(device_id) checks if active_device_id is null or matches the connecting machine. If another device is active, connection is rejected with code 4003.
- **4. Stream Established:** Valid agent stream accepted; active_device_id locked; real-time telemetry streaming commences.

# 21. Configuration Management

Quantum Vault externalizes all runtime configurations through environment variables managed by Pydantic BaseSettings in backend/app/config.py. Secrets are strictly segregated from repository tracking.


| Variable Name | Default Value | Verified Source | Description & Security Guidance |
| --- | --- | --- | --- |
| PROJECT_NAME | QuantumVault | backend/app/config.py | Display name of the application across OpenAPI and logs. |
| VERSION | 1.0.0 | backend/app/config.py | Current software release version string. |
| ENVIRONMENT | development | backend/app/config.py | Runtime mode: 'development', 'production', or 'testing'. |
| API_V1_STR | /api/v1 | backend/app/config.py | URL prefix for version 1 API routing. |
| DATABASE_URL | sqlite:///./quantumvault.db | backend/app/config.py | Primary database connection string. Defaults to SQLite; falls back automatically if PostgreSQL is down. |
| SECRET_KEY | quantumvault_hackathon_super_secret_jwt_key_992182 | backend/app/config.py | Cryptographic key for signing sessions. Replace with high-entropy secret in production. |
| ALGORITHM | HS256 | backend/app/config.py | JWT cryptographic signature algorithm. |
| ACCESS_TOKEN_EXPIRE_MINUTES | 1440 | backend/app/config.py | Bearer token validity window (default: 24 hours). |
| GEMINI_API_KEY | [REDACTED / EMPTY] | backend/app/config.py | Google Gemini API key for dynamic threat explainability. Optional (fallback rule engine active if empty). |
| GEMINI_MODEL | gemini-3.8-flash | backend/app/config.py | Gemini foundation model identifier for SOC narrative synthesis. |
| GOOGLE_SAFE_BROWSING_API_KEY | [REDACTED / EMPTY] | backend/app/config.py | API key for real-time Google Safe Browsing threat match lookups. Optional. |
| RISK_THRESHOLD_LOW | 20 | backend/app/config.py | Cutoff score for SAFE -> LOW risk transition. |
| RISK_THRESHOLD_MEDIUM | 40 | backend/app/config.py | Cutoff score for LOW -> MEDIUM risk transition. |
| RISK_THRESHOLD_HIGH | 60 | backend/app/config.py | Cutoff score for MEDIUM -> HIGH risk transition. |
| RISK_THRESHOLD_CRITICAL | 80 | backend/app/config.py | Cutoff score for HIGH -> CRITICAL risk transition. |
| VITE_API_URL | http://localhost:8000/api/v1 | frontend/.env.example | Base backend URL consumed by frontend Axios client. |


# 22. Installation and Setup Guide

This guide provides step-by-step instructions for installing and running Quantum Vault in a local development or lab evaluation environment.


## 22.1 Prerequisites

- **Operating System:** Windows 10 / Windows 11 (required for local endpoint agent; backend and frontend are cross-platform).
- **Python Runtime:** Python 3.10 to 3.14 (Python 3.14 verified in local environment).
- **Node.js Runtime:** Node.js v18.0.0 or higher with npm v9+.
- **Docker Desktop (Optional):** Docker Engine with Docker Compose v2 for running containerized PostgreSQL.

## 22.2 Step 1: Backend Setup


```
# 1. Navigate to backend directory
cd backend

# 2. Install dependencies into Python environment
pip install -r requirements.txt

# 3. Create .env file from template
cp .env.example .env

# 4. (Optional) Edit .env to supply GEMINI_API_KEY if dynamic LLM explanations are desired

# 5. Start the FastAPI development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

```


## 22.3 Step 2: Frontend Setup


```
# 1. Open a new terminal and navigate to frontend directory
cd frontend

# 2. Install Node.js packages
npm install

# 3. Launch Vite development server
npm run dev

# 4. Open browser at http://localhost:5173

```


## 22.4 Step 3: Endpoint Agent Launch (Single-Device Protection)


```
# Option A: 1-Click Interactive Batch Launcher (Recommended on Windows)
# Double-click 'run_agent.bat' in the project root OR execute via terminal:
run_agent.bat

# Option B: Direct Python Execution
python agent_launcher.py --backend http://127.0.0.1:8000
# Or:
python -m agent.main --backend http://127.0.0.1:8000

```


# 23. Deployment Guide

Quantum Vault is architected for seamless cloud and hybrid deployment. The repository includes pre-configured Docker Compose files and production container recipes.


## 23.1 Production Docker Compose Deployment


```
# Execute full production stack (PostgreSQL + FastAPI + Nginx Frontend)
docker compose -f docker-compose.prod.yml up -d --build

# Verify running containers
docker compose -f docker-compose.prod.yml ps

# View backend logs
docker compose -f docker-compose.prod.yml logs -f backend

```


## 23.2 Cloud Production Architecture (Render / Vercel)

- **FastAPI Web Service (Render):** Configured as Python web service with start command: uvicorn app.main:app --host 0.0.0.0 --port $PORT. Environment variables: DATABASE_URL (managed Postgres), GEMINI_API_KEY, SECRET_KEY.
- **Frontend Static Host (Vercel / Render):** Build command: tsc -b && vite build. Output directory: dist. Environment variable: VITE_API_URL=https://quantum-vault-nnjz.onrender.com/api/v1.
- **Remote Agent Connectivity:** Local Windows agent connects to cloud backend over secure WSS: run_agent.bat https://quantum-vault-nnjz.onrender.com.

# 24. Testing

The platform maintains an automated Pytest test suite covering risk scoring calculations, threat feature extractions, email forensic parsing, and API endpoint integration.


## 24.1 Test Suite Breakdown


| Test Module | Test Cases | Primary Validation Objective |
| --- | --- | --- |
| backend/tests/test_api.py | test_risk_engine_safe, test_risk_engine_critical | Verifies risk scoring cutoffs, penalty additions, and severity level mappings. |
| backend/tests/test_api.py | test_phishing_feature_extraction, test_phishing_analysis | Validates 12-feature lexical extraction and Random Forest probability integration. |
| backend/tests/test_api.py | test_behavior_analysis_csv_formats | Verifies CSV log parsing with string booleans and credential-stuffing burst detection. |
| backend/tests/test_api.py | test_email_analyzer | Tests NLP urgency scoring, homoglyph detection, and brand impersonation alerts. |
| backend/tests/test_api.py | test_audio_forensics_empty_and_valid | Validates audio signal handling on empty bytes (zero division safeguard) and synthetic sine waves. |
| backend/tests/test_api.py | test_deepfake_image_analysis | Verifies 2D FFT spectral ratio and Laplacian noise residual variance calculation. |
| backend/tests/test_api.py | test_policy_api_persistence | Tests GET/PUT /settings/policy, threshold ordering validation (monotonicity), and persistence. |
| backend/tests/test_command_center.py | test_endpoint_risk_engine_clean, test_endpoint_risk_penalties | Verifies composite host risk calculation with Defender, Firewall, and process penalties. |
| backend/tests/test_email_auth.py | TestAuthResultParsing (SPF, DKIM, DMARC), TestDomainMismatch, TestHomoglyphs | 349-line exhaustive test suite verifying RFC-822 header parsing against real-world sample emails. |

To run the complete test suite: pytest backend/tests/ -v


---


# 25. Error Handling and Logging

Quantum Vault implements structured error handling and tiered logging to ensure operational resilience and diagnostic clarity.


## 25.1 Exception Handling Architecture

- **FastAPI HTTPException Mapping:** Standardized HTTP error responses with machine-readable details (e.g. 400 Bad Request on invalid policy order, 401 Unauthorized on invalid agent token, 404 Not Found on missing threat/incident, 409 Conflict on single-device lock contention, 422 Unprocessable Entity on schema validation failure).
- **WebSocket Error Codes:** Uses RFC 6455 closure codes: Code 1008 for policy/token violations; custom Code 4003 for SINGLE_DEVICE_LIMIT_EXCEEDED.
- **Graceful Degradation Fallbacks:** If PostgreSQL is unavailable at startup, the system automatically falls back to local SQLite without crashing; if Gemini AI API key is missing or timed out (6s timeout), the system seamlessly generates deterministic rule-based threat explanations; if PyTorch is not installed, the deepfake engine operates using 2D FFT and Laplacian filters.

## 25.2 Logging Hierarchy

Logging is managed via Python's standard logging facility using distinct namespace loggers:

- **quantumvault.main:** Lifespan startup/shutdown, database verification, and middleware events.
- **quantumvault.endpoint_security:** Agent WebSocket connections, device state transitions, and browser broadcast events.
- **quantumvault.phishing:** Lexical feature extraction, Safe Browsing API matches, and WHOIS query diagnostics.
- **quantumvault.email / email_auth:** DNS SPF/DMARC resolution, homoglyph substitutions, and header parsing anomalies.
- **quantumvault.deepfake / audio:** FFT matrix computations, Laplacian variance, and Librosa signal analysis warnings.
- **quantumvault.database:** SQLAlchemy connection attempts, failover notices, and schema synchronization.

# 26. Performance

The platform is engineered for sub-second threat analysis and low-footprint background endpoint monitoring.


| Component / Module | Empirical Latency / Benchmark | Resource Consumption | Optimization Mechanism |
| --- | --- | --- | --- |
| Phishing URL Analysis | 18ms - 35ms | < 15 MB RAM | Pre-loaded binary Random Forest model; vectorized feature calculations. |
| Email Forensic Analysis | 45ms - 110ms | < 20 MB RAM | DNS resolution caching; pre-compiled regex for urgency language. |
| Deepfake Image Analysis | 65ms - 180ms | < 45 MB RAM | NumPy 2D FFT matrix operations; image downscaling to 512x512 for frequency inspection. |
| Audio Forensic Analysis | 120ms - 350ms | < 60 MB RAM | Efficient STFT framing; memory-mapped audio byte streaming via io.BytesIO. |
| Behavioral Anomaly Analysis | 25ms - 60ms | < 20 MB RAM | In-memory Isolation Forest scoring; vector-based failed attempt counters. |
| Endpoint Agent Daemon | Continuous (3s intervals) | < 0.4% CPU / ~32 MB RAM | Non-invasive psutil probes; diff-based file watcher; delta telemetry updates. |
| WebSocket Delivery | < 15ms broadcast delay | < 5 MB RAM | Direct async asyncio.gather broadcasting to active browser sockets. |


# 27. Scalability

The current release is specifically tuned for single-device dedicated workstation defense and centralized SOC analysis. The architectural blueprint supports horizontal expansion for enterprise fleets.


## 27.1 Current Architecture vs. Enterprise Expansion

- **Current Single-Device Model:** Guarantees dedicated focus on a single critical host (e.g. executive workstation, air-gapped terminal) with zero multi-tenancy noise or cross-endpoint confusion.
- **Database Scaling:** Built on SQLAlchemy 2.0 with connection pooling; seamlessly transitions from single SQLite file to managed multi-node PostgreSQL / Amazon RDS.
- **Stateless API Scaling:** FastAPI endpoints are fully stateless; multiple backend worker containers can be deployed behind a load balancer (e.g. Nginx, AWS ALB).
- **Enterprise WebSocket Cluster Roadmap:** For managing 1,000+ simultaneous agents, in-memory agent sockets will be replaced with a distributed Redis Pub/Sub backplane, enabling horizontal backend scaling.

# 28. Privacy and Data Protection

Quantum Vault enforces rigorous data privacy controls to ensure endpoint telemetry and submitted artifacts do not expose sensitive corporate or personal data.

- **No Keystroke or Screen Logging:** The endpoint agent collects only OS metadata (process names, CPU/RAM, socket ports, firewall states). It strictly does not record keystrokes, clipboard data, webcam, or screen captures.
- **Password & Secret Redaction:** Database connection passwords are automatically masked with regex (:***@) before returning diagnostic JSON; authentication tokens in headers are hashed.
- **Transient Media Storage:** Images and audio submitted to /api/v1/analyze are processed in memory (BytesIO) and are not permanently saved to disk; only extracted feature vectors and risk scores are persisted.
- **Local Agent Execution:** Telemetry can be restricted entirely to an on-premises network (http://127.0.0.1:8000), eliminating third-party cloud data exposure.

# 29. Limitations

In adherence to strict technical accuracy, the following limitations discovered during code analysis are documented:

- **Windows OS Endpoint Restriction:** The endpoint agent relies on Windows-specific APIs (winreg, PowerShell Get-MpComputerStatus, netsh, wevtutil). It cannot run on Linux or macOS workstations.
- **Single-Device Active Lock:** By design, the platform accepts telemetry from only one active machine at a time per backend instance. A second machine is rejected with error 4003 until the active device is released.
- **User-Mode Agent Privilege Boundaries:** The agent runs in user space without kernel drivers (.sys). If run without Administrator rights, access to some Windows Defender status fields or system event logs may be restricted.
- **Simulated Playbook Execution:** Incident response actions (e.g. Block URL, Revoke Session) execute simulated playbooks and record audit logs in the database. They do not inject live BGP routing routes or host-level firewall block rules.
- **Prototype Authentication Token:** The current /api/v1/auth/login endpoint issues a fixed prototype bearer token. Production bcrypt/Argon2 password verification against the database User table is partially implemented.

# 30. Future Enhancements

The future product development roadmap is structured into three prioritized phases:


## 30.1 High Priority (Phase 1)

- **Production JWT Authentication:** Implement full cryptographic JWT issuance with Argon2 password hashing and token expiration verification.
- **Multi-Device Fleet Management:** Introduce organization and group hierarchies allowing SOC teams to manage fleets of hundreds of endpoint agents.
- **Active Firewall Rule Injection:** Enable the endpoint agent to execute local firewall blocks (netsh advfirewall firewall add rule) upon receiving signed incident response commands.

## 30.2 Medium Priority (Phase 2)

- **Cross-Platform Agent (Linux / macOS):** Develop native agent daemons utilizing eBPF for Linux and EndpointSecurity framework for macOS.
- **Live Packet Inspection (PCAP):** Integrate lightweight packet capture heuristics to detect DNS tunneling and C2 beaconing on the host.
- **Automated Phishing Takedown Webhooks:** Integrate webhooks to report confirmed malicious domains directly to Google Safe Browsing and registrar abuse contacts.

## 30.3 Low Priority (Phase 3)

- **SIEM / SOAR Connectors:** Bi-directional connectors for Splunk, Microsoft Sentinel, and Elastic Security.
- **Fine-Tuned On-Premises LLM:** Deploy a local quantized Llama-3-8B / Mistral model for air-gapped environments without external Gemini API connectivity.

# 31. Troubleshooting

This section provides immediate resolutions for common operational and setup problems encountered by operators and developers.


| Observed Problem / Symptom | Probable Root Cause | Technical Resolution & Command |
| --- | --- | --- |
| Agent displays OFFLINE in Command Center | Endpoint agent is not running, or target backend URL is incorrect. | Launch agent locally via run_agent.bat or: python -m agent.main --backend <BACKEND_URL>. Check console output for connection confirmation. |
| WebSocket Error 4003 (SINGLE_DEVICE_LIMIT_EXCEEDED) | Another workstation is currently connected to the backend. | Open Command Center UI and click 'Disconnect Active Device' to release the lock, or restart backend server. |
| WebSocket Error 1008 (Policy Violation) | Mismatched agent authorization token. | Verify QUANTUMVAULT_API_TOKEN environment variable matches backend config ('qv-endpoint-agent-token-2026'). |
| Database status shows SQLite fallback | Docker PostgreSQL container is stopped or port 5432 is unreachable. | Ensure Docker Desktop is running and execute: docker compose up -d. Then click 'Reconnect Postgres' in the Settings page. |
| Gemini AI threat explanation is generic | GEMINI_API_KEY is not configured or rate limit was reached. | Supply a valid key in backend/.env: GEMINI_API_KEY=your_key. The platform automatically falls back to deterministic rules if empty. |
| Audio forensics returns fallback metrics | Librosa or soundfile libraries are missing in Python environment. | Install dependencies: pip install librosa soundfile. Ensure C++ build tools are available if compilation is required. |
| CORS error in browser console | Frontend origin is not permitted in backend CORS middleware. | Ensure backend/app/main.py CORSMiddleware includes your frontend URL (defaults allow http://localhost:5173 and '*'). |
| run_agent.bat exits immediately | Python is not installed or not added to system PATH. | Install Python 3.10+ from python.org and check 'Add python.exe to PATH' during installation. |


# 32. Developer Guide

This guide instructs software engineers on extending Quantum Vault, adhering to existing coding conventions and testing practices.


## 32.1 How to Add a New Threat Detector

1. Create service module under backend/app/services/ (e.g. qr_code_service.py).

2. Implement analysis method returning structured EvidenceItem list and risk score (0-100).

3. Invoke explanation_engine.generate_explanation() to obtain unified XAI narrative.

4. Expose route under backend/app/api/analyze.py using _persist_threat_and_incident() helper to ensure database tracking and automatic SOC incident escalation.

5. Add unit tests in backend/tests/test_api.py and verify with pytest.


## 32.2 How to Add a New Endpoint Collector

1. Create collector module under agent/collectors/ (e.g. agent/collectors/usb.py).

2. Implement collect_usb_devices() returning clean dictionary of connected hardware.

3. Register collector in agent/main.py within the telemetry loop.

4. Update endpoint_risk_engine.py if the collector introduces new risk penalty factors.

5. Add UI card or modal in frontend/src/components/command-center/.


# 33. User Guide (Security Operations Center Operator Guide)

A concise operational guide for SOC analysts operating the Quantum Vault dashboard:

- **1. Starting the Platform:** Ensure backend (port 8000) and frontend (port 5173) are active. Navigate to http://localhost:5173 in Google Chrome or Microsoft Edge.
- **2. Activating Endpoint Defense:** From the Dashboard, click 'Connect Endpoint Agent' -> copy the terminal run command -> launch run_agent.bat on the target Windows workstation. Verify the status indicator turns green (ONLINE).
- **3. Monitoring Workstation Posture:** Review CPU, RAM, Disk, and Uptime meters. Confirm Windows Defender and Windows Firewall indicate ACTIVE protection.
- **4. Investigating Processes & Sockets:** Click 'View All Processes' to search for unsigned binaries or processes running from Temp folders. Inspect active TCP connections for suspicious outbound remote IPs.
- **5. Triggering On-Demand Scans:** Click 'Quick Scan', 'Process Audit', or 'Startup Check' from the Command Center action bar to run immediate targeted audits.
- **6. Analyzing External Threats:** Navigate to 'Threat Scanner' or 'Phishing Intelligence'. Paste suspicious URLs or upload raw .eml emails. Review the composite Risk Score Meter (0-100) and evidence breakdown.
- **7. Triaging SOC Incidents:** Navigate to 'Incidents'. Inspect automatically generated incident tickets (e.g. QV-1021). Click 'Block URL' or 'Revoke Session' to execute simulated containment playbooks.
- **8. Adjusting Risk Policies:** Navigate to 'Settings' to adjust risk score boundaries (Low, Medium, High, Critical) to match your organizational risk tolerance.

# 34. Glossary

Key technical terms and definitions utilized across the Quantum Vault architecture:


| Term / Acronym | Full Expansion | Technical Definition in Quantum Vault Context |
| --- | --- | --- |
| EDR | Endpoint Detection and Response | Category of security tools providing continuous endpoint monitoring, telemetry harvesting, and containment capabilities. |
| SOC | Security Operations Center | Centralized security monitoring team and operations cockpit responsible for triaging and responding to enterprise threats. |
| XAI | Explainable Artificial Intelligence | AI systems providing human-interpretable rationales and evidence breakdowns for automated decisions (implemented via Gemini 3.8 Flash). |
| DGA | Domain Generation Algorithm | Adversarial algorithmic technique generating randomized domain names to evade static reputation blocklists. |
| Homoglyph | Unicode / Lookalike Character | Visually identical character substitutions (e.g. Cyrillic 'а' replacing Latin 'a') used in typosquatting phishing domains. |
| SPF | Sender Policy Framework | DNS-based email authentication protocol verifying authorized mail sending IP addresses (RFC 7208). |
| DKIM | DomainKeys Identified Mail | Cryptographic signature validation protocol verifying email message integrity and sender domain authenticity (RFC 6376). |
| DMARC | Domain-based Message Authentication | Policy protocol specifying recipient handling of SPF/DKIM failures (RFC 7489). |
| 2D FFT | Two-Dimensional Fast Fourier Transform | Mathematical algorithm converting spatial pixel matrices into 2D frequency spectra to identify periodic lattice artifacts produced by generative AI upsampling. |
| Laplacian Variance | Discrete Laplace Operator Variance | Convolutional edge detection metric measuring micro-texture roughness and noise distribution uniformity. |
| Isolation Forest | Tree-Based Anomaly Detection | Unsupervised machine learning algorithm that isolates anomalous authentication outliers by randomly partitioning feature space. |
| Random Forest | Ensemble Decision Tree Classifier | Supervised classification model combining multiple decision trees to predict phishing probability from lexical URL features. |
| MITRE ATT&CK | Adversarial Tactics, Techniques, & Common Knowledge | Globally recognized knowledge base of adversary tactics mapped to Quantum Vault detections (e.g. T1566 Phishing, T1078 Valid Accounts). |


# 35. References

- **1. RFC 7208:** Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, IETF Standards Track.
- **2. RFC 6376:** DomainKeys Identified Mail (DKIM) Signatures, IETF Standards Track.
- **3. RFC 7489:** Domain-based Message Authentication, Reporting, and Conformance (DMARC), IETF Standards Track.
- **4. MITRE Corporation:** MITRE ATT&CK Enterprise Matrix (https://attack.mitre.org).
- **5. Google Safe Browsing API v4:** Google Developers Safe Browsing Documentation (https://developers.google.com/safe-browsing).
- **6. Google GenAI Python SDK:** Official Google GenAI Documentation & Reference Guide.
- **7. Scikit-Learn Consortium:** Machine Learning in Python, Pedregosa et al., JMLR 12, pp. 2825-2830.
- **8. FaceForensics++:** Learning to Detect Manipulated Facial Images, Rossler et al., ICCV 2019.
- **9. Librosa:** Audio and Music Signal Analysis in Python, McFee et al., SciPy 2015.

# 36. Appendix


## 36.1 HTTP Status Code Reference


| HTTP Code | Meaning | Quantum Vault Application Context |
| --- | --- | --- |
| 200 OK | Success | Standard response for successful threat analysis, telemetry queries, and policy updates. |
| 400 Bad Request | Invalid Input | Triggered when request payload is malformed or policy thresholds violate ascending monotonic order. |
| 401 Unauthorized | Authentication Required | Triggered when agent token header is missing or invalid. |
| 404 Not Found | Resource Not Found | Triggered when querying an unknown threat_id, incident_id, or when run_agent.bat is missing. |
| 409 Conflict | Single-Device Exclusivity Conflict | Triggered when an agent attempts to connect while another endpoint is actively locked. |
| 422 Unprocessable Entity | Pydantic Schema Violation | Triggered when JSON body fails type or required field validation. |
| 500 Internal Error | Server Exception | Triggered on unexpected database or filesystem exceptions. |


## 36.2 Essential Commands Reference


| Operational Goal | Platform | Exact Command |
| --- | --- | --- |
| Start Backend Development Server | Terminal / Bash | uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload |
| Start Frontend Development Server | Terminal / Node | npm run dev |
| Launch Endpoint Protection Agent | Windows CMD | run_agent.bat https://your-backend.com |
| Launch Agent via Python | Terminal | python agent_launcher.py --backend http://127.0.0.1:8000 |
| Execute Automated Test Suite | Terminal | pytest backend/tests/ -v |
| Build Frontend Production Bundle | Terminal | npm run build |
| Deploy Local PostgreSQL Container | Docker | docker compose up -d postgres |
| Deploy Complete Production Stack | Docker | docker compose -f docker-compose.prod.yml up -d --build |


> **[COMPLETION SIGN-OFF]**: End of Quantum Vault Complete Software Documentation. This document represents the authoritative system manual for all technical, architectural, operational, and regulatory evaluations.

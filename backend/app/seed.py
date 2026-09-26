from datetime import datetime, timedelta
from app.models.database import SessionLocal, Base, engine
from app.models.threat import Threat, ThreatEvidence, Scan, ModelPrediction
from app.models.incident import Incident, ResponseAction
from app.models.user import User

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Check if already seeded
        if db.query(Threat).first():
            print("Database already contains records. Skipping seed.")
            return

        print("Seeding initial CYBERGUARD threat intelligence data...")

        # 1. Users
        analyst = User(
            name="SOC Lead Analyst",
            email="analyst@cyberguard.internal",
            password_hash="argon2_demo_hash_92813",
            role="lead_analyst"
        )
        db.add(analyst)
        db.flush()

        # 2. Threats
        t1 = Threat(
            threat_type="phishing",
            source_type="url",
            source_payload="https://secure-chase-online-verify-account.com/auth/login",
            severity="CRITICAL",
            risk_score=94,
            confidence=0.96,
            status="active",
            explanation="Critical phishing risk detected. The target impersonates a recognized banking institution using look-alike domain heuristics and credential extraction endpoints. Immediate DNS containment recommended.",
            created_at=datetime.utcnow() - timedelta(minutes=15)
        )
        db.add(t1)
        db.flush()

        e1 = ThreatEvidence(threat_id=t1.id, indicator="credential_harvesting_keywords", description="Target URL contains authentication keywords 'verify', 'account', 'login'", weight=14)
        e2 = ThreatEvidence(threat_id=t1.id, indicator="domain_hyphen_spoofing", description="Hostname uses 4 consecutive hyphens to simulate genuine subdomain structure", weight=12)
        e3 = ThreatEvidence(threat_id=t1.id, indicator="insecure_transport_http", description="HTTP transport used during initial redirect stage", weight=8)
        db.add_all([e1, e2, e3])

        t2 = Threat(
            threat_type="account_takeover",
            source_type="login_log",
            source_payload="User U1003 authentication event stream",
            severity="CRITICAL",
            risk_score=91,
            confidence=0.94,
            status="active",
            explanation="Critical account takeover anomaly. Rapid cluster of 14 failed logins observed from a Tor exit node in Frankfurt Germany, followed by successful session initialization with an unrecognized user-agent.",
            created_at=datetime.utcnow() - timedelta(minutes=45)
        )
        db.add(t2)
        db.flush()

        e4 = ThreatEvidence(threat_id=t2.id, indicator="brute_force_spike", description="14 failed authentication attempts in under 3 minutes", weight=22)
        e5 = ThreatEvidence(threat_id=t2.id, indicator="geographic_anomaly_impossible_travel", description="Authentication request routed from Tor exit node (Frankfurt)", weight=16)
        e6 = ThreatEvidence(threat_id=t2.id, indicator="automated_scripting_client", description="Client identified as Python-urllib automation tool", weight=18)
        db.add_all([e4, e5, e6])

        t3 = Threat(
            threat_type="deepfake",
            source_type="image",
            source_payload="executive_profile_verification.png",
            severity="HIGH",
            risk_score=87,
            confidence=0.89,
            status="active",
            explanation="High-confidence synthetic media manipulation identified. High-frequency Fourier spectrum reveals checkerboard artifact anomalies and synthetic skin Gaussian smoothing.",
            created_at=datetime.utcnow() - timedelta(hours=2)
        )
        db.add(t3)
        db.flush()

        e7 = ThreatEvidence(threat_id=t3.id, indicator="facial_boundary_blending_artifacts", description="Discontinuous pixel boundary gradient along jawline", weight=20)
        e8 = ThreatEvidence(threat_id=t3.id, indicator="frequency_domain_inconsistency", description="Fourier transform displays GAN upsampling artifact signatures", weight=18)
        db.add_all([e7, e8])

        # 3. Incidents
        inc1 = Incident(
            threat_id=t1.id,
            incident_code="CG-1021",
            title="Credential Phishing Campaign — Banking Lookalike",
            description=t1.explanation,
            severity="CRITICAL",
            status="OPEN",
            assigned_to="SOC Lead Analyst",
            mitre_technique="T1566",
            created_at=datetime.utcnow() - timedelta(minutes=14)
        )

        inc2 = Incident(
            threat_id=t2.id,
            incident_code="CG-1022",
            title="Account Takeover — Credential Stuffing Anomaly",
            description=t2.explanation,
            severity="CRITICAL",
            status="OPEN",
            assigned_to="Incident Response Team",
            mitre_technique="T1078",
            created_at=datetime.utcnow() - timedelta(minutes=44)
        )

        inc3 = Incident(
            threat_id=t3.id,
            incident_code="CG-1023",
            title="Executive Biometric Impersonation Probe",
            description=t3.explanation,
            severity="HIGH",
            status="INVESTIGATING",
            assigned_to="Threat Intelligence Unit",
            mitre_technique="T1586",
            created_at=datetime.utcnow() - timedelta(hours=2)
        )

        db.add_all([inc1, inc2, inc3])
        db.commit()
        print("Database successfully seeded with realistic SOC intelligence data.")

    finally:
        db.close()

if __name__ == "__main__":
    seed_database()

from enum import Enum

class RiskLevel(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ThreatCategory(str, Enum):
    BENIGN = "Benign / Legitimate"
    PHISHING = "Phishing & Social Engineering"
    DIGITAL_IMPERSONATION = "Digital Impersonation"
    DEEPFAKE = "Deepfake & Multimedia Manipulation"
    ACCOUNT_TAKEOVER = "Account Takeover & Anomaly"
    MALICIOUS_URL = "Malicious URL & Look-Alike Domain"
    SUSPICIOUS_NETWORK = "Suspicious Network Activity"
    API_ABUSE = "API Abuse"

class EventSource(str, Enum):
    EMAIL = "Email"
    SMS = "SMS / Message"
    URL = "Web URL"
    IMAGE = "Image / Document"
    AUDIO = "Audio Clip"
    AUTH_LOG = "Authentication Log"
    NETWORK_LOG = "Network Log"
    API_LOG = "API Gateway Log"

class ActionType(str, Enum):
    ALLOW = "Allow Traffic / No Action Required"
    WARN_USER = "Warn User & Display Safety Banner"
    BLOCK_URL = "Block URL at Perimeter Firewall & DNS Sinkhole"
    QUARANTINE_EMAIL = "Quarantine Email & Purge from Inboxes"
    REQUIRE_MFA = "Challenge with Step-Up Multi-Factor Authentication"
    REVOKE_SESSION = "Immediately Revoke Active User Sessions"
    BLOCK_IP = "Temporarily Block Origin IP Address"
    FLAG_MANUAL_REVIEW = "Flag Artifact for Tier-2 SOC Analyst Review"
    REPORT_IMPERSONATION = "File Impersonation Abuse Report to Hosting Authority"
    NOTIFY_ADMIN = "Trigger High-Priority Slack/Email Alert to Security Team"
    ESCALATE_INCIDENT = "Escalate to Major Security Incident Playbook (Tier 3)"

class IncidentStatus(str, Enum):
    DETECTED = "Detected"
    INVESTIGATING = "Investigating"
    MITIGATED = "Mitigated"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"

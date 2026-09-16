from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from ..models.enums import ActionType, IncidentStatus, RiskLevel, ThreatCategory
from ..models.schemas import RecommendedAction

# Action definitions with execution metadata
PLAYBOOK_CATALOG = {
    "quarantine_email": {
        "action_type": ActionType.QUARANTINE_EMAIL,
        "title": "Quarantine Phishing Email & Purge Mailboxes",
        "description": "Purge email message ID across all tenant mailboxes (Exchange/O365 & Google Workspace) and route to quarantine.",
        "simulated_command": "powershell -Command 'Search-Mailbox -Identity * -SearchQuery \"Subject:{subject}\" -DeleteContent -Force'",
        "category": "Messaging Security",
        "default_priority": 1,
    },
    "block_url": {
        "action_type": ActionType.BLOCK_URL,
        "title": "Perimeter DNS Sinkhole & Proxy URL Block",
        "description": "Push malicious domain and URL hashes to Cisco Umbrella DNS Sinkhole and Palo Alto Edge Proxies.",
        "simulated_command": "pan-os-cli -c 'set address fqdn {domain} type sinkhole; commit'",
        "category": "Network & Perimeter",
        "default_priority": 1,
    },
    "block_ip": {
        "action_type": ActionType.BLOCK_IP,
        "title": "Edge Firewall Temporary IP Blacklist",
        "description": "Enforce dynamic IP block rule across Cloudflare WAF and ingress gateway routers for 72 hours.",
        "simulated_command": "iptables -A INPUT -s {origin_ip} -j DROP && cloudflare-waf block --ip {origin_ip}",
        "category": "Edge Security",
        "default_priority": 2,
    },
    "force_mfa": {
        "action_type": ActionType.REQUIRE_MFA,
        "title": "Enforce Step-Up Hardware/FIDO2 MFA Challenge",
        "description": "Invalidate existing push-based MFA sessions and enforce FIDO2 or hardware token re-verification.",
        "simulated_command": "okta-cli user mfa challenge --id {target_identity} --factor-type webauthn",
        "category": "Identity & Access",
        "default_priority": 1,
    },
    "revoke_session": {
        "action_type": ActionType.REVOKE_SESSION,
        "title": "Immediate Revocation of Active Tokens & Sessions",
        "description": "Purge all active refresh tokens, SSO sessions, and cookie keys for compromised account.",
        "simulated_command": "azure-ad-cli revoke-user-sessions --user-principal-name {target_identity}",
        "category": "Identity & Access",
        "default_priority": 1,
    },
    "report_impersonation": {
        "action_type": ActionType.REPORT_IMPERSONATION,
        "title": "Submit Brand Abuse & Takedown Notice",
        "description": "Dispatch automated RFC-compliant abuse report to domain registrar, hosting CDN, and antiphishing working groups.",
        "simulated_command": "curl -X POST https://api.abuseipdb.com/api/v2/report -d \"ip={origin_ip}&categories=phishing,impersonation\"",
        "category": "Legal & Brand Protection",
        "default_priority": 3,
    },
    "notify_soc": {
        "action_type": ActionType.NOTIFY_ADMIN,
        "title": "Dispatch Priority SOC Incident Notification",
        "description": "Send high-priority alert payload to SOC PagerDuty on-call and designated #security-ops channel.",
        "simulated_command": "pagerduty-cli incident create --title \"[CRITICAL] {threat_classification}\" --urgency high",
        "category": "Incident Response",
        "default_priority": 2,
    },
    "escalate_incident": {
        "action_type": ActionType.ESCALATE_INCIDENT,
        "title": "Escalate to Major Security Incident (Tier 3 IR)",
        "description": "Activate corporate Computer Incident Response Team (CIRT) War Room and begin digital forensics triage.",
        "simulated_command": "cirt-playbook activate --incident-id {event_id} --severity tier-3",
        "category": "Incident Response",
        "default_priority": 1,
    }
}

def generate_playbook_actions(
    category: str,
    risk_level: RiskLevel,
    threat_classification: str,
    target_identity: Optional[str] = None,
    origin_ip: Optional[str] = None
) -> List[RecommendedAction]:
    """Generates prioritized recommended response actions based on threat profile."""
    actions = []
    category_str = str(category).lower()
    is_critical = risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)

    # 1. Category-specific actions
    if "phishing" in category_str or "url" in category_str:
        actions.append(RecommendedAction(
            action_type=ActionType.BLOCK_URL,
            title=PLAYBOOK_CATALOG["block_url"]["title"],
            description=PLAYBOOK_CATALOG["block_url"]["description"],
            priority=1,
            is_automated=is_critical
        ))
        actions.append(RecommendedAction(
            action_type=ActionType.QUARANTINE_EMAIL,
            title=PLAYBOOK_CATALOG["quarantine_email"]["title"],
            description=PLAYBOOK_CATALOG["quarantine_email"]["description"],
            priority=1 if is_critical else 2,
            is_automated=is_critical
        ))
        actions.append(RecommendedAction(
            action_type=ActionType.WARN_USER,
            title="Display Suspicious Sender Banner",
            description="Inject cautionary banner on external inbound emails warning recipients not to open attachments.",
            priority=3,
            is_automated=True
        ))

    elif "deepfake" in category_str or "impersonation" in category_str:
        actions.append(RecommendedAction(
            action_type=ActionType.REPORT_IMPERSONATION,
            title=PLAYBOOK_CATALOG["report_impersonation"]["title"],
            description=PLAYBOOK_CATALOG["report_impersonation"]["description"],
            priority=2,
            is_automated=False
        ))
        actions.append(RecommendedAction(
            action_type=ActionType.FLAG_MANUAL_REVIEW,
            title="Escalate Media Artifact to Forensic Analyst",
            description="Submit suspect image/audio and ELA discrepancy map to senior digital forensics team for verification.",
            priority=2,
            is_automated=True
        ))
        if is_critical:
            actions.append(RecommendedAction(
                action_type=ActionType.NOTIFY_ADMIN,
                title=PLAYBOOK_CATALOG["notify_soc"]["title"],
                description="Alert Executive Protection and Public Relations team regarding active impersonation campaign.",
                priority=1,
                is_automated=True
            ))

    elif "account" in category_str or "anomaly" in category_str:
        actions.append(RecommendedAction(
            action_type=ActionType.REVOKE_SESSION,
            title=PLAYBOOK_CATALOG["revoke_session"]["title"],
            description=PLAYBOOK_CATALOG["revoke_session"]["description"],
            priority=1,
            is_automated=is_critical
        ))
        actions.append(RecommendedAction(
            action_type=ActionType.REQUIRE_MFA,
            title=PLAYBOOK_CATALOG["force_mfa"]["title"],
            description=PLAYBOOK_CATALOG["force_mfa"]["description"],
            priority=1 if is_critical else 2,
            is_automated=True
        ))
        if origin_ip:
            actions.append(RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                title=PLAYBOOK_CATALOG["block_ip"]["title"],
                description=f"Block malicious origin IP {origin_ip} at edge gateway.",
                priority=2,
                is_automated=is_critical
            ))

    # Fallback / General actions for High & Critical events
    if is_critical and not any(a.action_type == ActionType.NOTIFY_ADMIN for a in actions):
        actions.append(RecommendedAction(
            action_type=ActionType.NOTIFY_ADMIN,
            title=PLAYBOOK_CATALOG["notify_soc"]["title"],
            description=PLAYBOOK_CATALOG["notify_soc"]["description"],
            priority=2,
            is_automated=True
        ))

    if risk_level == RiskLevel.CRITICAL and not any(a.action_type == ActionType.ESCALATE_INCIDENT for a in actions):
        actions.append(RecommendedAction(
            action_type=ActionType.ESCALATE_INCIDENT,
            title=PLAYBOOK_CATALOG["escalate_incident"]["title"],
            description=PLAYBOOK_CATALOG["escalate_incident"]["description"],
            priority=1,
            is_automated=False
        ))

    return actions

def execute_simulated_action(
    event: Dict[str, Any],
    action_key: str,
    operator: str = "SOC_AUTOMATION_ENGINE",
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a simulated response playbook action against an event.
    Returns a comprehensive execution audit record.
    """
    action_meta = PLAYBOOK_CATALOG.get(action_key, {
        "action_type": ActionType.FLAG_MANUAL_REVIEW,
        "title": f"Custom Action: {action_key}",
        "description": "Executing manual analyst containment procedure.",
        "simulated_command": f"soc-runner --action {action_key} --target {event.get('id')}",
        "category": "Manual Response",
        "default_priority": 2
    })

    # Hydrate template variables
    cmd_template = action_meta.get("simulated_command", "echo 'Action executed'")
    hydrated_cmd = cmd_template.format(
        event_id=event.get("id", "N/A"),
        target_identity=event.get("target_identity") or "target_user",
        origin_ip=event.get("origin_ip") or "0.0.0.0",
        domain=event.get("metadata", {}).get("domain") or "suspicious-domain.com",
        subject=event.get("metadata", {}).get("subject") or "Security Alert",
        threat_classification=event.get("threat_classification", "Cyber Threat")
    )

    action_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "id": action_id,
        "event_id": event.get("id"),
        "action_key": action_key,
        "action_title": action_meta["title"],
        "category": action_meta.get("category", "Remediation"),
        "simulated_command": hydrated_cmd,
        "status": "SUCCESS",
        "operator": operator,
        "notes": notes or "Automated containment playbook initiated by analyst.",
        "executed_at": now_iso,
        "audit_verification": f"SHA256:{uuid.uuid4().hex[:16]}...VERIFIED",
        "impact": "Threat blast-radius contained. Traffic/session revoked."
    }

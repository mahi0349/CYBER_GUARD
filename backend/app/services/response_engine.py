from sqlalchemy.orm import Session
from datetime import datetime
from typing import Dict, Any

from app.models.incident import Incident, ResponseAction
from app.models.threat import Threat

class ResponseEngine:
    """
    CYBERGUARD Response & Automated Containment Engine.
    Executes safe simulated response playbooks for SOC containment:
    - URL quarantine
    - Session revocation & MFA enforcement
    - Perimeter IP blocking
    - Incident status transition to CONTAINED
    """

    @staticmethod
    def execute_action(
        db: Session,
        incident_id: int,
        action_type: str,
        notes: str = ""
    ) -> Dict[str, Any]:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with id {incident_id} not found")

        # Map action descriptions
        action_descriptions = {
            "block_url": "DNS Sinkhole policy pushed to border firewalls; target URL blocked.",
            "quarantine_message": "Email quarantined from user inboxes across mail gateway.",
            "revoke_session": "Active JWT bearer tokens revoked; active sessions terminated.",
            "require_mfa": "Step-up Multi-Factor Authentication policy forced on account.",
            "block_ip": "Attacker source IP added to automated perimeter drop rules.",
            "flag_impersonation": "Synthetic identity warning applied to executive directory."
        }

        desc = action_descriptions.get(action_type, f"Executed automated security playbook: {action_type}")
        if notes:
            desc += f" (Notes: {notes})"

        # Create audit record
        action_record = ResponseAction(
            incident_id=incident.id,
            threat_id=incident.threat_id,
            action_type=action_type,
            description=desc,
            status="SIMULATED_SUCCESS",
            executed_by="CYBERGUARD Automated Orchestrator",
            created_at=datetime.utcnow()
        )
        db.add(action_record)

        # Update Incident status
        incident.status = "CONTAINED"
        incident.updated_at = datetime.utcnow()

        # Update Threat status if associated
        if incident.threat_id:
            threat = db.query(Threat).filter(Threat.id == incident.threat_id).first()
            if threat:
                threat.status = "contained"

        db.commit()
        db.refresh(incident)
        db.refresh(action_record)

        return {
            "action_id": action_record.id,
            "incident_id": incident.id,
            "incident_code": incident.incident_code,
            "action_type": action_record.action_type,
            "status": action_record.status,
            "description": action_record.description,
            "new_incident_status": incident.status,
            "timestamp": action_record.created_at.isoformat()
        }

response_engine = ResponseEngine()

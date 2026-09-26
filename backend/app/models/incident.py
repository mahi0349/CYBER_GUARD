from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.models.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True)
    incident_code = Column(String(50), unique=True, index=True, nullable=False) # e.g. CG-1021
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)     # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(50), default="OPEN")       # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    assigned_to = Column(String(100), default="SOC Lead Analyst")
    mitre_technique = Column(String(50), default="T1566") # MITRE ATT&CK technique (e.g. T1566, T1078)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    threat = relationship("Threat", back_populates="incidents")
    actions = relationship("ResponseAction", back_populates="incident", cascade="all, delete-orphan")

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    action_type = Column(String(100), nullable=False) # block_url, revoke_session, require_mfa, block_ip, quarantine_message
    description = Column(Text, nullable=False)
    status = Column(String(50), default="SIMULATED_SUCCESS") # SIMULATED_SUCCESS, PENDING, FAILED
    executed_by = Column(String(100), default="Automated Orchestrator")
    created_at = Column(DateTime, default=datetime.utcnow)

    threat = relationship("Threat", back_populates="response_actions")
    incident = relationship("Incident", back_populates="actions")

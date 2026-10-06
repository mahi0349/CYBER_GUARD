import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON
from app.models.database import Base

class EndpointDevice(Base):
    __tablename__ = "endpoint_devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), unique=True, index=True, nullable=False)
    hostname = Column(String(150), nullable=False)
    os_name = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    agent_version = Column(String(50), nullable=True)
    status = Column(String(30), default="OFFLINE") # ONLINE, DEGRADED, OFFLINE
    last_heartbeat = Column(DateTime, default=datetime.datetime.utcnow)
    last_telemetry_at = Column(DateTime, nullable=True)
    registered_at = Column(DateTime, default=datetime.datetime.utcnow)

class EndpointScan(Base):
    __tablename__ = "endpoint_scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, index=True, nullable=False)
    device_id = Column(String(100), index=True, nullable=False)
    scan_type = Column(String(50), nullable=False) # quick, process, startup, network, file, config
    status = Column(String(30), default="QUEUED") # QUEUED, RUNNING, COMPLETED, FAILED, UNAVAILABLE
    findings_count = Column(Integer, default=0)
    summary_json = Column(Text, nullable=True)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

class EndpointThreatAlert(Base):
    __tablename__ = "endpoint_threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(100), unique=True, index=True, nullable=False)
    device_id = Column(String(100), index=True, nullable=False)
    severity = Column(String(20), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, SAFE
    category = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    detection_source = Column(String(100), nullable=False)
    evidence_json = Column(Text, nullable=True)
    explanation = Column(Text, nullable=False)
    affected_object = Column(String(255), nullable=True)
    recommended_action = Column(Text, nullable=False)
    status = Column(String(30), default="ACTIVE") # ACTIVE, RESOLVED, IGNORED
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class EndpointSecurityEvent(Base):
    __tablename__ = "endpoint_security_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    severity = Column(String(20), default="LOW")
    event_type = Column(String(100), nullable=False)
    source = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    user = Column(String(100), nullable=True)
    process = Column(String(150), nullable=True)
    metadata_json = Column(Text, nullable=True)

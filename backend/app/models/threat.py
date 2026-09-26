from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.models.database import Base

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(50), nullable=False)  # phishing, deepfake, account_takeover
    source_type = Column(String(50), nullable=False)  # url, email, image, audio, login_log
    source_payload = Column(Text, nullable=True)      # original URL, filename, or context
    severity = Column(String(20), nullable=False)     # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Integer, nullable=False)      # 0 to 100
    confidence = Column(Float, nullable=False)        # 0.0 to 1.0
    status = Column(String(50), default="active")     # active, contained, resolved, false_positive
    explanation = Column(Text, nullable=True)         # Gemini / LLM explanation
    created_at = Column(DateTime, default=datetime.utcnow)

    evidence = relationship("ThreatEvidence", back_populates="threat", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="threat")
    predictions = relationship("ModelPrediction", back_populates="threat", cascade="all, delete-orphan")
    response_actions = relationship("ResponseAction", back_populates="threat")

class ThreatEvidence(Base):
    __tablename__ = "threat_evidence"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False)
    indicator = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    weight = Column(Integer, default=5)
    created_at = Column(DateTime, default=datetime.utcnow)

    threat = relationship("Threat", back_populates="evidence")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    scan_type = Column(String(50), nullable=False)     # url, email, image, login_log
    input_reference = Column(Text, nullable=False)     # target URL or filename
    result = Column(String(50), nullable=False)        # malicious, suspicious, clean
    risk_score = Column(Integer, default=0)
    meta_info = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")

class ModelPrediction(Base):
    __tablename__ = "model_predictions"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False)
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(50), default="1.0.0")
    prediction = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    threat = relationship("Threat", back_populates="predictions")

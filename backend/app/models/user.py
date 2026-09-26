from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.models.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")  # analyst, admin, responder
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="user")
    login_events = relationship("LoginEvent", back_populates="user")

class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    ip_address = Column(String(50), nullable=False)
    location = Column(String(100), nullable=False)
    device = Column(String(100), nullable=False)
    login_time = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=True)
    user_agent = Column(Text, nullable=True)
    anomaly_score = Column(Integer, default=0)

    user = relationship("User", back_populates="login_events")

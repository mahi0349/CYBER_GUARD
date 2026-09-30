from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from app.models.database import Base

class SystemPolicy(Base):
    __tablename__ = "system_policies"

    id = Column(Integer, primary_key=True, index=True)
    low_threshold = Column(Integer, default=20, nullable=False)
    medium_threshold = Column(Integer, default=40, nullable=False)
    high_threshold = Column(Integer, default=60, nullable=False)
    critical_threshold = Column(Integer, default=80, nullable=False)
    gemini_model = Column(String(50), default="gemini-3.8-flash", nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

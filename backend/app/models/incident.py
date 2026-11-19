import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(50), nullable=False, default="DETECTED", index=True)  # DETECTED, AUTO_MITIGATED, INVESTIGATING, MITIGATED, RESOLVED, FALSE_POSITIVE
    primary_attack_vector = Column(String(100), nullable=False, index=True)  # DOS_DDOS, PORTSCAN, BRUTE_FORCE, WEB_ATTACK, BOTNET
    risk_score = Column(Float, nullable=False)
    
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False)
    
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    alerts = relationship("Alert", back_populates="incident", cascade="all, delete-orphan")
    mitigations = relationship("MitigationAction", back_populates="incident", cascade="all, delete-orphan")

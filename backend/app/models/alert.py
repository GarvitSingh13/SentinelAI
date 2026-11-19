import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    flow_id = Column(UUID(as_uuid=True), ForeignKey("network_flows.id", ondelete="SET NULL"), nullable=True)
    
    attack_class = Column(String(100), nullable=False)
    confidence = Column(Float, nullable=False)
    shap_values = Column(JSON, nullable=True)  # Key-value map of top feature attributions
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    incident = relationship("Incident", back_populates="alerts")

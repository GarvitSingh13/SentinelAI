import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base

class MitigationAction(Base):
    __tablename__ = "mitigation_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    
    action_type = Column(String(50), nullable=False)  # BLOCK_IP, RATE_LIMIT, ISOLATE_HOST
    target_value = Column(String(255), nullable=False)  # e.g., IP address 192.168.1.100
    executed_by = Column(String(100), nullable=False, default="AUTOMATION_POLICY")  # AUTOMATION_POLICY or analyst email
    status = Column(String(50), nullable=False, default="APPLIED")  # APPLIED, REVOKED
    
    executed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    incident = relationship("Incident", back_populates="mitigations")

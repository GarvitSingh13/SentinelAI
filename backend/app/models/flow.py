import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
from app.core.database import Base

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    src_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_ip = Column(String(45), nullable=False, index=True)
    dst_port = Column(Integer, nullable=False, index=True)
    protocol = Column(String(10), nullable=False)
    
    flow_duration_ms = Column(Float, nullable=False)
    total_fwd_packets = Column(Integer, nullable=False)
    total_bwd_packets = Column(Integer, nullable=False)
    flow_bytes_per_sec = Column(Float, nullable=False)
    flow_packets_per_sec = Column(Float, nullable=False)
    flow_iat_mean = Column(Float, default=0.0)
    flow_iat_std = Column(Float, default=0.0)
    fwd_packet_length_mean = Column(Float, default=0.0)
    bwd_packet_length_mean = Column(Float, default=0.0)
    packet_length_std = Column(Float, default=0.0)
    syn_flag_count = Column(Integer, default=0)
    fin_flag_count = Column(Integer, default=0)
    rst_flag_count = Column(Integer, default=0)
    psh_flag_count = Column(Integer, default=0)
    ack_flag_count = Column(Integer, default=0)
    
    attack_class = Column(String(50), default="BENIGN", nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    is_attack = Column(Boolean, default=False, nullable=False, index=True)
    is_anomaly = Column(Boolean, default=False, nullable=False)
    anomaly_score = Column(Float, default=0.0, nullable=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    captured_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

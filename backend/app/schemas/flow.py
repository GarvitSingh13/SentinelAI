from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

class FlowIngestRequest(BaseModel):
    src_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = "TCP"
    
    flow_duration_ms: float = 100.0
    total_fwd_packets: int = 1
    total_bwd_packets: int = 0
    flow_bytes_per_sec: float = 1000.0
    flow_packets_per_sec: float = 10.0
    flow_iat_mean: float = 50.0
    flow_iat_std: float = 10.0
    fwd_packet_length_mean: float = 250.0
    bwd_packet_length_mean: float = 350.0
    packet_length_std: float = 40.0
    syn_flag_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    ack_flag_count: int = 1

class FlowBatchIngestRequest(BaseModel):
    flows: List[FlowIngestRequest]

class FlowIngestResult(BaseModel):
    flow_id: UUID
    src_ip: str
    dst_ip: str
    dst_port: int
    attack_class: str
    confidence: float
    is_attack: bool
    is_anomaly: bool
    anomaly_score: float
    incident_id: Optional[UUID] = None
    shap_explanation: Optional[Dict[str, Any]] = None

class BatchIngestResponse(BaseModel):
    total_processed: int
    threats_detected: int
    anomalies_detected: int
    results: List[FlowIngestResult]

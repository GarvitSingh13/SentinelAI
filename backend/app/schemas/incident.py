from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    attack_class: str
    confidence: float
    shap_values: Optional[Dict[str, Any]] = None
    created_at: datetime

class MitigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action_type: str
    target_value: str
    executed_by: str
    status: str
    executed_at: datetime

class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    severity: str
    status: str
    primary_attack_vector: str
    risk_score: float
    src_ip: str
    dst_ip: str
    assigned_to: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime

class IncidentDetailResponse(IncidentResponse):
    alerts: List[AlertResponse] = []
    mitigations: List[MitigationResponse] = []

class IncidentStatusUpdate(BaseModel):
    status: str  # DETECTED, AUTO_MITIGATED, INVESTIGATING, MITIGATED, RESOLVED, FALSE_POSITIVE

class MitigationCreate(BaseModel):
    action_type: str = "BLOCK_IP"  # BLOCK_IP, RATE_LIMIT, ISOLATE_HOST
    target_value: Optional[str] = None

class ThreatStatsResponse(BaseModel):
    total_flows: int
    total_threats: int
    active_incidents: int
    mitigated_incidents: int
    threat_level: str  # LOW, ELEVATED, HIGH, SEVERE
    attack_vector_breakdown: Dict[str, int]

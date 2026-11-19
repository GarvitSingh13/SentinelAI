from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_db
from app.models.flow import NetworkFlow
from app.models.incident import Incident
from app.schemas.incident import ThreatStatsResponse

router = APIRouter(prefix="/stats", tags=["Security Analytics & Telemetry"])

@router.get("", response_model=ThreatStatsResponse)
async def get_threat_stats(db: AsyncSession = Depends(get_db)):
    # 1. Total flows
    total_flows = (await db.execute(select(func.count(NetworkFlow.id)))).scalar() or 0

    # 2. Total threats (Incidents)
    total_threats = (await db.execute(select(func.count(Incident.id)))).scalar() or 0

    # 3. Active incidents (DETECTED, INVESTIGATING)
    active_stmt = select(func.count(Incident.id)).where(Incident.status.in_(["DETECTED", "INVESTIGATING"]))
    active_incidents = (await db.execute(active_stmt)).scalar() or 0

    # 4. Mitigated incidents
    mitigated_stmt = select(func.count(Incident.id)).where(Incident.status == "MITIGATED")
    mitigated_incidents = (await db.execute(mitigated_stmt)).scalar() or 0

    # 5. Attack vector breakdown
    breakdown_stmt = select(Incident.primary_attack_vector, func.count(Incident.id)).group_by(Incident.primary_attack_vector)
    breakdown_rows = (await db.execute(breakdown_stmt)).all()
    attack_breakdown = {row[0]: row[1] for row in breakdown_rows}

    # 6. Compute composite Threat Level
    if active_incidents == 0:
        threat_level = "LOW"
    elif active_incidents <= 3:
        threat_level = "ELEVATED"
    elif active_incidents <= 10:
        threat_level = "HIGH"
    else:
        threat_level = "SEVERE"

    return ThreatStatsResponse(
        total_flows=total_flows,
        total_threats=total_threats,
        active_incidents=active_incidents,
        mitigated_incidents=mitigated_incidents,
        threat_level=threat_level,
        attack_vector_breakdown=attack_breakdown
    )

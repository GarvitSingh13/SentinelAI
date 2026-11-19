from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from typing import List, Optional
from uuid import UUID
import redis.asyncio as aioredis

from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.mitigation import MitigationAction
from app.models.user import User
from app.schemas.incident import (
    IncidentResponse, IncidentDetailResponse, IncidentStatusUpdate,
    MitigationCreate, MitigationResponse, ThreatStatsResponse
)

router = APIRouter(prefix="/incidents", tags=["Security Incidents & Response"])

@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity_filter: Optional[str] = Query(None, alias="severity"),
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(Incident).order_by(desc(Incident.created_at)).offset(offset).limit(limit)
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter.upper())
    if severity_filter:
        stmt = stmt.where(Incident.severity == severity_filter.upper())

    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = (
        select(Incident)
        .options(selectinload(Incident.alerts), selectinload(Incident.mitigations))
        .where(Incident.id == incident_id)
    )
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: UUID,
    req: IncidentStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    valid_statuses = ["DETECTED", "AUTO_MITIGATED", "INVESTIGATING", "MITIGATED", "RESOLVED", "FALSE_POSITIVE"]
    new_status = req.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    stmt = select(Incident).where(Incident.id == incident_id)
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = new_status
    if incident.assigned_to is None:
        incident.assigned_to = current_user.id
    
    await db.commit()
    await db.refresh(incident)
    return incident

@router.post("/{incident_id}/mitigate", response_model=MitigationResponse)
async def trigger_mitigation(
    incident_id: UUID,
    req: MitigationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["ADMIN", "ANALYST"]))
):
    stmt = select(Incident).where(Incident.id == incident_id)
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    target = req.target_value or incident.src_ip

    # Record mitigation in database
    mitigation = MitigationAction(
        incident_id=incident.id,
        action_type=req.action_type.upper(),
        target_value=target,
        executed_by=current_user.email,
        status="APPLIED"
    )
    db.add(mitigation)
    incident.status = "MITIGATED"

    # Push to Redis blacklist with TTL
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        await r.setex(f"blacklist:{target}", 3600, f"incident:{incident.id}")
        await r.aclose()
    except Exception as e:
        # Graceful degradation if Redis is temporarily unreachable
        pass

    await db.commit()
    await db.refresh(mitigation)
    return mitigation

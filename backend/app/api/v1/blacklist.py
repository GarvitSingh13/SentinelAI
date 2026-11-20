from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from app.core.redis_client import ThreatStateStore
from app.services.websocket_manager import ws_manager

router = APIRouter()

class BlacklistRequest(BaseModel):
    ip: str
    duration_seconds: int = 3600
    reason: str = "Manual SOC Analyst Blacklist"
    attack_class: str = "MANUAL_BLOCK"

@router.get("", summary="List All Active Blacklisted IPs")
async def list_blacklisted_ips() -> List[Dict[str, Any]]:
    return await ThreatStateStore.get_all_blacklisted()

@router.post("", summary="Add IP to Real-Time Blacklist")
async def add_to_blacklist(req: BlacklistRequest) -> Dict[str, Any]:
    res = await ThreatStateStore.blacklist_ip(
        ip=req.ip,
        duration_seconds=req.duration_seconds,
        reason=req.reason,
        attack_class=req.attack_class
    )
    await ws_manager.broadcast_mitigation({
        "target_ip": req.ip,
        "action": "FIREWALL_BLOCK",
        "status": "APPLIED",
        "reason": req.reason
    })
    return res

@router.delete("/{ip}", summary="Remove IP from Blacklist")
async def remove_from_blacklist(ip: str) -> Dict[str, Any]:
    await ThreatStateStore.unblacklist_ip(ip)
    await ws_manager.broadcast_mitigation({
        "target_ip": ip,
        "action": "FIREWALL_UNBLOCK",
        "status": "REMOVED",
        "reason": f"Removed from blacklist by SOC analyst"
    })
    return {"status": "SUCCESS", "unblocked_ip": ip}

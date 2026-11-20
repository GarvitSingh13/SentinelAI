from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from typing import Dict, Any

from app.services.traffic_generator import traffic_generator
from app.services.websocket_manager import ws_manager
from app.core.redis_client import ThreatStateStore

router = APIRouter()

@router.get("/status", summary="Get Traffic Streaming Status")
async def get_stream_status() -> Dict[str, Any]:
    return traffic_generator.get_status()

@router.post("/start", summary="Start Synthetic Flow Streaming into Kafka")
async def start_stream(rate: int = Query(20, ge=1, le=500, description="Flows per second")) -> Dict[str, Any]:
    await traffic_generator.start(rate_per_second=rate)
    return {
        "status": "STARTED",
        "rate_per_second": rate,
        "message": f"Streaming network flows to Redpanda topic 'network-flows' at {rate} flows/sec"
    }

@router.post("/stop", summary="Stop Flow Streaming")
async def stop_stream() -> Dict[str, Any]:
    await traffic_generator.stop()
    return {
        "status": "STOPPED",
        "total_generated": traffic_generator.total_generated,
        "total_attacks": traffic_generator.total_attacks
    }

@router.websocket("/ws/threats")
async def websocket_threats_endpoint(websocket: WebSocket):
    """Real-time bi-directional WebSocket stream for SOC analysts."""
    await ws_manager.connect(websocket)
    try:
        # Send initial handshake state
        blacklisted = await ThreatStateStore.get_all_blacklisted()
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "data": {
                "active_blacklist_count": len(blacklisted),
                "stream_status": traffic_generator.get_status()
            }
        })

        while True:
            # Keepalive receiver
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)

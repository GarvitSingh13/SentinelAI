import asyncio
import json
from typing import List, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect

class WebSocketManager:
    """Manages live WebSocket subscriptions from SOC analyst dashboards."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a JSON message to all active WebSocket clients."""
        if not self.active_connections:
            return

        payload = json.dumps(message)
        dead_connections = []

        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_text(payload)
                except Exception:
                    dead_connections.append(connection)

            for dead in dead_connections:
                if dead in self.active_connections:
                    self.active_connections.remove(dead)

    async def broadcast_threat(self, threat_data: Dict[str, Any]):
        await self.broadcast({
            "type": "THREAT_ALERT",
            "data": threat_data
        })

    async def broadcast_mitigation(self, mitigation_data: Dict[str, Any]):
        await self.broadcast({
            "type": "MITIGATION_APPLIED",
            "data": mitigation_data
        })

    async def broadcast_stats(self, stats_data: Dict[str, Any]):
        await self.broadcast({
            "type": "STREAM_METRICS",
            "data": stats_data
        })

# Global singleton instance
ws_manager = WebSocketManager()

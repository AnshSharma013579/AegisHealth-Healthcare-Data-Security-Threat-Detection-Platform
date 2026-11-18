import json
from typing import List
from fastapi import WebSocket

class WebSocketHub:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, alert_data: dict):
        """Broadcasts a newly detected security alert to all connected SOC clients."""
        payload = {
            "type": "SECURITY_ALERT",
            "data": alert_data
        }
        await self._broadcast(payload)

    async def broadcast_audit(self, audit_data: dict):
        """Broadcasts a newly chained audit event to the live audit log explorer."""
        payload = {
            "type": "AUDIT_EVENT",
            "data": audit_data
        }
        await self._broadcast(payload)

    async def _broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                self.disconnect(connection)

ws_hub = WebSocketHub()


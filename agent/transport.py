import asyncio
import json
import logging
import httpx
import websockets
from typing import Dict, Any, Callable, Optional

logger = logging.getLogger("quantumvault.agent.transport")

class AgentTransport:
    def __init__(self, http_url: str, ws_url: str, token: str, device_id: str):
        self.http_url = http_url
        self.ws_url = ws_url
        self.token = token
        self.device_id = device_id
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.is_connected = False
        self.on_command_callback: Optional[Callable[[Dict[str, Any]], Any]] = None

    async def connect_ws(self):
        """Establish WebSocket connection to backend with auth headers."""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Device-ID": self.device_id
        }
        try:
            full_ws_url = f"{self.ws_url}?token={self.token}&device_id={self.device_id}"
            self.ws = await websockets.connect(full_ws_url, ping_interval=20, ping_timeout=15)
            self.is_connected = True
            logger.info("Connected to QuantumVault backend WebSocket.")
            return True
        except Exception as e:
            self.is_connected = False
            self.ws = None
            logger.warning(f"WebSocket connection failed: {e}. Will fallback to HTTP.")
            return False

    async def send_payload(self, message_type: str, data: Any):
        """Send message via WebSocket if connected, otherwise fallback to HTTP."""
        payload = {
            "type": message_type,
            "device_id": self.device_id,
            "data": data
        }

        if self.is_connected and self.ws:
            try:
                await self.ws.send(json.dumps(payload))
                return True
            except Exception as e:
                logger.warning(f"Error sending over WebSocket: {e}. Falling back to HTTP.")
                self.is_connected = False
                self.ws = None

        # Fallback to HTTP POST
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(
                    f"{self.http_url}/ingest",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.token}", "X-Device-ID": self.device_id}
                )
                return res.status_code == 200
        except Exception as e:
            logger.debug(f"HTTP fallback ingest failed: {e}")
            return False

    async def listen_for_commands(self):
        """Listen for incoming scan triggers or configuration commands from backend."""
        while True:
            if not self.is_connected or not self.ws:
                await asyncio.sleep(3)
                await self.connect_ws()
                continue
            try:
                msg = await self.ws.recv()
                data = json.loads(msg)
                if data.get("error") == "SINGLE_DEVICE_LIMIT_EXCEEDED":
                    logger.error(f"🛑 [SINGLE-DEVICE POLICY] {data.get('message')}")
                    self.is_connected = False
                    self.ws = None
                    await asyncio.sleep(10)
                    continue
                if self.on_command_callback:
                    asyncio.create_task(self.on_command_callback(data))
            except websockets.ConnectionClosed as cc:
                if cc.code == 4003:
                    logger.error("🛑 [SINGLE-DEVICE POLICY] Connection refused: Another device is currently active on QuantumVault.")
                    self.is_connected = False
                    self.ws = None
                    await asyncio.sleep(10)
                else:
                    logger.info("WebSocket disconnected from backend.")
                    self.is_connected = False
                    self.ws = None
                    await asyncio.sleep(2)
            except Exception as e:
                logger.warning(f"Error reading from WebSocket: {e}")
                self.is_connected = False
                self.ws = None
                await asyncio.sleep(2)

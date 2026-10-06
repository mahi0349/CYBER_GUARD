import json
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query, Header
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.services.endpoint_security import endpoint_security_mgr
from app.schemas.command_center import (
    AgentStatusOut,
    SystemTelemetryOut,
    ProcessItemOut,
    NetworkItemOut,
    ProtectionStatusOut,
    SoftwareItemOut,
    ServiceItemOut,
    StartupItemOut,
    TrackedFileOut,
    SecurityEventOut,
    ThreatAlertOut,
    RiskScoreOut,
    ScanTriggerRequest,
    ScanRecordOut
)

logger = logging.getLogger("quantumvault.api.command_center")

router = APIRouter(prefix="/command-center", tags=["Endpoint Command Center"])

AGENT_TOKEN = "qv-endpoint-agent-token-2026"

# ----------------- Status & Telemetry -----------------
@router.get("/status", response_model=AgentStatusOut)
def get_agent_status():
    return endpoint_security_mgr.get_agent_status()

@router.get("/system")
def get_system_telemetry():
    telemetry = endpoint_security_mgr.system_telemetry
    if not telemetry:
        status = endpoint_security_mgr.get_agent_status()
        return {
            "status": "UNAVAILABLE",
            "message": "Endpoint telemetry not yet received from Windows agent.",
            "agent_status": status
        }
    return telemetry

@router.get("/telemetry-history")
def get_telemetry_history():
    return endpoint_security_mgr.telemetry_history[-40:]

@router.get("/risk", response_model=RiskScoreOut)
def get_risk_score():
    return endpoint_security_mgr.get_current_risk()

# ----------------- Protection Status -----------------
@router.get("/protection")
def get_protection_status():
    return {
        "defender": endpoint_security_mgr.defender_status,
        "firewall": endpoint_security_mgr.firewall_status
    }

# ----------------- Processes & Network -----------------
@router.get("/processes", response_model=List[ProcessItemOut])
def get_processes(limit: int = 150, search: Optional[str] = None):
    procs = endpoint_security_mgr.processes
    if search:
        search_lower = search.lower()
        procs = [p for p in procs if search_lower in p.get("name", "").lower() or search_lower in str(p.get("pid"))]
    return procs[:limit]

@router.get("/network", response_model=List[NetworkItemOut])
def get_network(limit: int = 150, state: Optional[str] = None):
    conns = endpoint_security_mgr.network_conns
    if state and state.upper() != "ALL":
        conns = [c for c in conns if c.get("state") == state.upper()]
    return conns[:limit]

# ----------------- Inventory & Persistence -----------------
@router.get("/software", response_model=List[SoftwareItemOut])
def get_software(search: Optional[str] = None):
    sw = endpoint_security_mgr.software_inventory
    if search:
        s_lower = search.lower()
        sw = [item for item in sw if s_lower in item.get("name", "").lower() or s_lower in item.get("publisher", "").lower()]
    return sw

@router.get("/services", response_model=List[ServiceItemOut])
def get_services(status: Optional[str] = None):
    svcs = endpoint_security_mgr.services_inventory
    if status and status.lower() != "all":
        svcs = [s for s in svcs if s.get("status") == status.lower()]
    return svcs

@router.get("/startup", response_model=List[StartupItemOut])
def get_startup():
    return endpoint_security_mgr.startup_inventory

# ----------------- Files & Events -----------------
@router.get("/files", response_model=List[TrackedFileOut])
def get_tracked_files():
    return endpoint_security_mgr.tracked_files

@router.get("/file-events")
def get_file_events():
    return endpoint_security_mgr.file_events[:50]

@router.get("/events")
def get_security_events(limit: int = 50, severity: Optional[str] = None):
    evts = endpoint_security_mgr.security_events
    if severity and severity.upper() != "ALL":
        evts = [e for e in evts if e.get("severity") == severity.upper()]
    return evts[:limit]

@router.get("/threats", response_model=List[ThreatAlertOut])
def get_threats():
    return endpoint_security_mgr.threat_alerts

# ----------------- Scans -----------------
@router.get("/scans", response_model=List[ScanRecordOut])
def get_scans():
    return endpoint_security_mgr.scans

@router.post("/scans/run", response_model=ScanRecordOut)
async def run_scan(payload: ScanTriggerRequest):
    return await endpoint_security_mgr.trigger_scan(payload.scan_type)

# ----------------- Agent Ingestion Endpoint (HTTP fallback) -----------------
@router.post("/ingest")
async def ingest_agent_payload(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None)
):
    # Verify token
    token = (authorization or "").replace("Bearer ", "")
    if token != AGENT_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized agent token")

    msg_type = payload.get("type", "unknown")
    device_id = payload.get("device_id") or x_device_id or "unknown"
    data = payload.get("data")

    await endpoint_security_mgr.process_agent_message(msg_type, device_id, data)
    return {"status": "ok"}

# ----------------- Browser WebSocket Stream -----------------
@router.websocket("/ws")
async def browser_websocket(websocket: WebSocket):
    await endpoint_security_mgr.register_browser(websocket)
    try:
        while True:
            # Keepalive / ping handling
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        endpoint_security_mgr.unregister_browser(websocket)
    except Exception as e:
        logger.warning(f"Browser websocket error: {e}")
        endpoint_security_mgr.unregister_browser(websocket)

# ----------------- Agent Bidirectional WebSocket -----------------
@router.websocket("/agent-ws")
async def agent_websocket(websocket: WebSocket, token: Optional[str] = Query(None), device_id: Optional[str] = Query(None)):
    if token != AGENT_TOKEN:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    endpoint_security_mgr.agent_ws = websocket
    endpoint_security_mgr.agent_device_id = device_id
    logger.info(f"Endpoint Agent connected via WebSocket: device_id={device_id}")

    try:
        while True:
            msg_text = await websocket.receive_text()
            try:
                payload = json.loads(msg_text)
                msg_type = payload.get("type", "unknown")
                dev_id = payload.get("device_id") or device_id or "unknown"
                data = payload.get("data")
                await endpoint_security_mgr.process_agent_message(msg_type, dev_id, data)
            except Exception as e:
                logger.error(f"Error handling agent payload: {e}")
    except WebSocketDisconnect:
        logger.info(f"Endpoint Agent disconnected: {device_id}")
        endpoint_security_mgr.agent_ws = None
        # Notify browser of agent offline / degradation
        await endpoint_security_mgr.broadcast_to_browsers({
            "type": "status_update",
            "status": endpoint_security_mgr.get_agent_status()
        })
    except Exception as e:
        logger.warning(f"Agent websocket exception: {e}")
        endpoint_security_mgr.agent_ws = None

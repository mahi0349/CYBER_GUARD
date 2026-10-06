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

# ----------------- Multi-Device Discovery -----------------
@router.get("/devices")
def get_devices():
    """Return all registered/discovered devices with status and risk summary."""
    return endpoint_security_mgr.get_devices_list()

# ----------------- Status & Telemetry -----------------
@router.get("/status", response_model=AgentStatusOut)
def get_agent_status(device_id: Optional[str] = Query(None)):
    return endpoint_security_mgr.get_agent_status(device_id)

@router.get("/system")
def get_system_telemetry(device_id: Optional[str] = Query(None)):
    telemetry = endpoint_security_mgr.get_system_telemetry(device_id)
    if not telemetry:
        status = endpoint_security_mgr.get_agent_status(device_id)
        return {
            "status": "UNAVAILABLE",
            "message": "Endpoint telemetry not yet received from Windows agent.",
            "agent_status": status
        }
    return telemetry

@router.get("/telemetry-history")
def get_telemetry_history(device_id: Optional[str] = Query(None)):
    return endpoint_security_mgr.get_telemetry_history(device_id)

@router.get("/risk", response_model=RiskScoreOut)
def get_risk_score(device_id: Optional[str] = Query(None)):
    return endpoint_security_mgr.get_current_risk(device_id)

# ----------------- Protection Status -----------------
@router.get("/protection")
def get_protection_status(device_id: Optional[str] = Query(None)):
    dev = endpoint_security_mgr.get_device(device_id)
    return {
        "defender": dev.defender_status,
        "firewall": dev.firewall_status
    }

# ----------------- Processes & Network -----------------
@router.get("/processes", response_model=List[ProcessItemOut])
def get_processes(device_id: Optional[str] = Query(None), limit: int = 150, search: Optional[str] = None):
    dev = endpoint_security_mgr.get_device(device_id)
    procs = dev.processes
    if search:
        search_lower = search.lower()
        procs = [p for p in procs if search_lower in p.get("name", "").lower() or search_lower in str(p.get("pid"))]
    return procs[:limit]

@router.get("/network", response_model=List[NetworkItemOut])
def get_network(device_id: Optional[str] = Query(None), limit: int = 150, state: Optional[str] = None):
    dev = endpoint_security_mgr.get_device(device_id)
    conns = dev.network_conns
    if state and state.upper() != "ALL":
        conns = [c for c in conns if c.get("state") == state.upper()]
    return conns[:limit]

# ----------------- Inventory & Persistence -----------------
@router.get("/software", response_model=List[SoftwareItemOut])
def get_software(device_id: Optional[str] = Query(None), search: Optional[str] = None):
    dev = endpoint_security_mgr.get_device(device_id)
    sw = dev.software_inventory
    if search:
        s_lower = search.lower()
        sw = [item for item in sw if s_lower in item.get("name", "").lower() or s_lower in item.get("publisher", "").lower()]
    return sw

@router.get("/services", response_model=List[ServiceItemOut])
def get_services(device_id: Optional[str] = Query(None), status: Optional[str] = None):
    dev = endpoint_security_mgr.get_device(device_id)
    svcs = dev.services_inventory
    if status and status.lower() != "all":
        svcs = [s for s in svcs if s.get("status") == status.lower()]
    return svcs

@router.get("/startup", response_model=List[StartupItemOut])
def get_startup(device_id: Optional[str] = Query(None)):
    dev = endpoint_security_mgr.get_device(device_id)
    return dev.startup_inventory

# ----------------- Files & Events -----------------
@router.get("/files", response_model=List[TrackedFileOut])
def get_tracked_files(device_id: Optional[str] = Query(None)):
    dev = endpoint_security_mgr.get_device(device_id)
    return dev.tracked_files

@router.get("/file-events")
def get_file_events(device_id: Optional[str] = Query(None)):
    dev = endpoint_security_mgr.get_device(device_id)
    return dev.file_events[:50]

@router.get("/events")
def get_security_events(device_id: Optional[str] = Query(None), limit: int = 50, severity: Optional[str] = None):
    dev = endpoint_security_mgr.get_device(device_id)
    evts = dev.security_events
    if severity and severity.upper() != "ALL":
        evts = [e for e in evts if e.get("severity") == severity.upper()]
    return evts[:limit]

@router.get("/threats", response_model=List[ThreatAlertOut])
def get_threats(device_id: Optional[str] = Query(None)):
    dev = endpoint_security_mgr.get_device(device_id)
    return dev.threat_alerts

# ----------------- Scans -----------------
@router.get("/scans", response_model=List[ScanRecordOut])
def get_scans(device_id: Optional[str] = Query(None)):
    dev = endpoint_security_mgr.get_device(device_id)
    return dev.scans

@router.post("/scans/run", response_model=ScanRecordOut)
async def run_scan(payload: ScanTriggerRequest, device_id: Optional[str] = Query(None)):
    return await endpoint_security_mgr.trigger_scan(payload.scan_type, device_id)

# ----------------- Agent Ingestion Endpoint (HTTP fallback) -----------------
@router.post("/ingest")
async def ingest_agent_payload(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None)
):
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
async def browser_websocket(websocket: WebSocket, device_id: Optional[str] = Query(None)):
    await endpoint_security_mgr.register_browser(websocket, device_id)
    try:
        while True:
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

    dev_id = device_id or "unknown"
    await websocket.accept()
    endpoint_security_mgr.agent_sockets[dev_id] = websocket
    logger.info(f"Endpoint Agent connected via WebSocket: device_id={dev_id}")

    try:
        while True:
            msg_text = await websocket.receive_text()
            try:
                payload = json.loads(msg_text)
                msg_type = payload.get("type", "unknown")
                payload_dev_id = payload.get("device_id") or dev_id
                data = payload.get("data")
                await endpoint_security_mgr.process_agent_message(msg_type, payload_dev_id, data)
            except Exception as e:
                logger.error(f"Error handling agent payload: {e}")
    except WebSocketDisconnect:
        logger.info(f"Endpoint Agent disconnected: {dev_id}")
        endpoint_security_mgr.agent_sockets.pop(dev_id, None)
        dev = endpoint_security_mgr.get_device(dev_id)
        await endpoint_security_mgr.broadcast_to_browsers({
            "type": "status_update",
            "status": dev.get_status()
        }, device_id=dev_id)
    except Exception as e:
        logger.warning(f"Agent websocket exception: {e}")
        endpoint_security_mgr.agent_sockets.pop(dev_id, None)

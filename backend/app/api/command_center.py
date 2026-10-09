import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query, Header, Request, Response
from fastapi.responses import FileResponse
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

@router.post("/scans/run-all", response_model=List[ScanRecordOut])
async def run_all_scans(device_id: Optional[str] = Query(None)):
    """Execute all diagnostic and endpoint scan methods simultaneously."""
    return await endpoint_security_mgr.trigger_all_scans(device_id)


# ----------------- Single-Device Licensing & State -----------------
@router.get("/device/mode")
def get_device_mode():
    """Return single-device licensing and active machine lock state."""
    return endpoint_security_mgr.get_device_mode_info()

@router.post("/device/disconnect")
async def disconnect_active_device():
    """Manually disconnect/release the active endpoint so another device can connect."""
    return await endpoint_security_mgr.disconnect_device()

# ----------------- Agent Runner & Config Endpoints -----------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent

@router.get("/agent/download-script")
def download_agent_script(request: Request):
    """Download the 1-click batch launcher pre-configured with this deployment's backend URL."""
    bat_path = PROJECT_ROOT / "run_agent.bat"
    if not bat_path.exists():
        raise HTTPException(status_code=404, detail="run_agent.bat not found on server.")

    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "127.0.0.1:8000"))
    public_url = f"{proto}://{host}".rstrip("/")

    content = bat_path.read_text(encoding="utf-8")
    content = content.replace("set \"FALLBACK_URL=http://127.0.0.1:8000\"", f'set "FALLBACK_URL={public_url}"')

    return Response(
        content=content,
        media_type="application/x-bat",
        headers={"Content-Disposition": 'attachment; filename="run_quantumvault_agent.bat"'}
    )

@router.get("/agent/download-config")
def download_agent_config(request: Request):
    """Download pre-configured agent_config.json for this deployment."""
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "127.0.0.1:8000"))
    public_url = f"{proto}://{host}".rstrip("/")
    cfg_json = json.dumps({"backend_url": public_url}, indent=2)
    return Response(
        content=cfg_json,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="agent_config.json"'}
    )

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

    # Enforce Single-Device policy
    can_connect, reason = endpoint_security_mgr.can_agent_connect(device_id)
    if not can_connect:
        raise HTTPException(status_code=409, detail=reason)

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

    # Enforce Single-Device mode: only 1 machine at a time!
    can_connect, reason = endpoint_security_mgr.can_agent_connect(dev_id)
    if not can_connect:
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "error": "SINGLE_DEVICE_LIMIT_EXCEEDED",
            "message": reason,
            "active_device": endpoint_security_mgr.active_device_id
        })
        await websocket.close(code=4003, reason="SINGLE_DEVICE_LIMIT_EXCEEDED")
        return

    await websocket.accept()
    endpoint_security_mgr.agent_sockets[dev_id] = websocket
    logger.info(f"Endpoint Agent connected via WebSocket: device_id={dev_id} [Single-Device Mode Active]")

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


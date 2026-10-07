import asyncio
import json
import logging
import uuid
import datetime
from typing import Dict, Any, List, Set, Optional
from fastapi import WebSocket

from app.services.endpoint_risk_engine import endpoint_risk_engine
from app.models.database import SessionLocal
from app.models.endpoint import EndpointDevice, EndpointScan, EndpointThreatAlert, EndpointSecurityEvent

logger = logging.getLogger("quantumvault.endpoint_security")


class DeviceState:
    """Encapsulates full real-time telemetry state for a single endpoint device."""
    def __init__(self, device_id: str, hostname: str = "Unknown Host", os_name: str = "Windows", os_version: str = "Unknown"):
        self.device_id = device_id
        self.device_info: Dict[str, Any] = {
            "device_id": device_id,
            "hostname": hostname,
            "os_name": os_name,
            "os_version": os_version,
            "agent_version": "1.0.0",
            "status": "OFFLINE",
            "registered_at": datetime.datetime.utcnow().isoformat(),
            "last_telemetry_at": None
        }
        self.last_telemetry_time: Optional[datetime.datetime] = None
        self.system_telemetry: Optional[Dict[str, Any]] = None
        self.telemetry_history: List[Dict[str, Any]] = []

        self.processes: List[Dict[str, Any]] = []
        self.network_conns: List[Dict[str, Any]] = []
        self.defender_status: Dict[str, Any] = {"available": False, "status": "UNAVAILABLE"}
        self.firewall_status: Dict[str, Any] = {"available": False, "status": "UNAVAILABLE", "profiles": {}}

        self.software_inventory: List[Dict[str, Any]] = []
        self.services_inventory: List[Dict[str, Any]] = []
        self.startup_inventory: List[Dict[str, Any]] = []
        self.tracked_files: List[Dict[str, Any]] = []
        self.file_events: List[Dict[str, Any]] = []
        self.security_events: List[Dict[str, Any]] = []
        self.threat_alerts: List[Dict[str, Any]] = []
        self.scans: List[Dict[str, Any]] = []

    def get_status(self) -> Dict[str, Any]:
        now = datetime.datetime.utcnow()
        if not self.last_telemetry_time:
            status = "OFFLINE"
            age = None
        else:
            age = int((now - self.last_telemetry_time).total_seconds())
            if age <= 10:
                status = "ONLINE"
            elif age <= 30:
                status = "DEGRADED"
            else:
                status = "OFFLINE"

        self.device_info["status"] = status
        return {
            "device_id": self.device_id,
            "hostname": self.device_info.get("hostname", "Unknown Host"),
            "os_name": self.device_info.get("os_name", "Windows"),
            "os_version": self.device_info.get("os_version", "Unknown"),
            "agent_version": self.device_info.get("agent_version", "1.0.0"),
            "status": status,
            "last_telemetry_at": self.last_telemetry_time.isoformat() if self.last_telemetry_time else None,
            "telemetry_age_seconds": age,
            "registered_at": self.device_info.get("registered_at")
        }

    def get_risk(self) -> Dict[str, Any]:
        return endpoint_risk_engine.evaluate(
            defender_data=self.defender_status,
            firewall_data=self.firewall_status,
            processes=self.processes,
            network_conns=self.network_conns,
            startup_items=self.startup_inventory,
            file_events=self.file_events,
            security_events=self.security_events
        )


class EndpointSecurityManager:
    def __init__(self):
        # Connected browser clients
        self.browser_clients: Dict[WebSocket, Optional[str]] = {}
        # Connected agent WebSockets: map device_id -> WebSocket (at most 1 in single-device mode)
        self.agent_sockets: Dict[str, WebSocket] = {}

        # Single-device state
        self.single_device_mode: bool = True
        self.devices: Dict[str, DeviceState] = {}
        self.active_device_id: Optional[str] = None
        self.blocked_attempts: List[Dict[str, Any]] = []

        # Pre-populate known devices from DB
        self._load_known_devices_from_db()

    def can_agent_connect(self, incoming_device_id: str) -> tuple[bool, str]:
        """
        Enforce Single-Device Policy:
        Only 1 active machine is permitted at a time.
        If an agent is already active and online from a different device_id, reject the incoming connection.
        """
        if not self.single_device_mode:
            return True, ""

        if not self.active_device_id or self.active_device_id == incoming_device_id:
            return True, ""

        # Check if the current active device is holding an active socket OR recently sent telemetry
        existing_ws = self.agent_sockets.get(self.active_device_id)
        existing_dev = self.devices.get(self.active_device_id)
        is_active = False
        if existing_ws is not None:
            is_active = True
        elif existing_dev:
            st = existing_dev.get_status()
            if st.get("status") in ("ONLINE", "DEGRADED"):
                is_active = True

        if is_active:
            active_host = existing_dev.device_info.get("hostname", self.active_device_id) if existing_dev else self.active_device_id
            msg = (
                f"SINGLE-DEVICE POLICY ENFORCED: Endpoint '{active_host}' is already active. "
                f"Concurrent connections are prohibited (no 2 devices at a time). "
                f"Please terminate the agent on '{active_host}' or disconnect it before connecting another machine."
            )
            self.record_blocked_attempt(incoming_device_id, msg)
            return False, msg

        # If previous device has gone offline or dropped socket, allow the new device to take over
        return True, ""

    def record_blocked_attempt(self, attempted_device_id: str, reason: str):
        attempt_record = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "attempted_device_id": attempted_device_id,
            "active_device_id": self.active_device_id,
            "reason": reason
        }
        self.blocked_attempts.append(attempt_record)
        if len(self.blocked_attempts) > 10:
            self.blocked_attempts = self.blocked_attempts[-10:]
        logger.warning(f"Single-Device Violation: {reason}")

    async def disconnect_device(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        """Disconnect and release the current active device slot so a new machine can bind."""
        target_id = device_id or self.active_device_id
        if not target_id:
            return {"status": "no_active_device"}

        ws = self.agent_sockets.pop(target_id, None)
        if ws:
            try:
                await ws.close(code=1000, reason="DISCONNECTED_BY_OPERATOR")
            except Exception:
                pass

        if target_id in self.devices:
            self.devices[target_id].device_info["status"] = "OFFLINE"
            self.devices[target_id].last_telemetry_time = None

        prev_id = self.active_device_id
        self.active_device_id = None

        await self.broadcast_to_browsers({
            "type": "device_disconnected",
            "message": f"Endpoint '{prev_id}' was disconnected. Slot is ready for local agent connection."
        })
        return {"status": "ok", "disconnected_device_id": prev_id}

    def get_device_mode_info(self) -> Dict[str, Any]:
        active_dev = self.devices.get(self.active_device_id) if self.active_device_id else None
        st = active_dev.get_status() if active_dev else None
        return {
            "mode": "SINGLE_DEVICE",
            "max_allowed": 1,
            "is_locked": self.active_device_id is not None and len(self.agent_sockets) > 0,
            "active_device_id": self.active_device_id,
            "active_hostname": st.get("hostname") if st else None,
            "active_status": st.get("status") if st else "OFFLINE",
            "blocked_attempts_count": len(self.blocked_attempts),
            "recent_blocked_attempts": self.blocked_attempts[-5:]
        }

    def _load_known_devices_from_db(self):
        try:
            with SessionLocal() as db:
                records = db.query(EndpointDevice).all()
                for rec in records:
                    if rec.device_id not in self.devices:
                        dev = DeviceState(
                            device_id=rec.device_id,
                            hostname=rec.hostname,
                            os_name=rec.os_name or "Windows",
                            os_version=rec.os_version or "Unknown"
                        )
                        dev.device_info["status"] = "OFFLINE"
                        self.devices[rec.device_id] = dev
                        if not self.active_device_id:
                            self.active_device_id = rec.device_id
        except Exception as e:
            logger.warning(f"Could not preload devices from database: {e}")

    def get_device(self, device_id: Optional[str] = None) -> DeviceState:
        """Resolve DeviceState for device_id, active_device_id, or first available."""
        if device_id and device_id in self.devices:
            return self.devices[device_id]
        if self.active_device_id and self.active_device_id in self.devices:
            return self.devices[self.active_device_id]
        if self.devices:
            dev = next(iter(self.devices.values()))
            self.active_device_id = dev.device_id
            return dev
        
        # Default placeholder device
        default_dev = DeviceState("default", "Pending Device Connection")
        self.devices["default"] = default_dev
        self.active_device_id = "default"
        return default_dev

    def get_or_create_device(self, device_id: str, hostname: str = "Unknown Host", os_name: str = "Windows", os_version: str = "Unknown") -> DeviceState:
        if device_id not in self.devices:
            self.devices[device_id] = DeviceState(device_id, hostname, os_name, os_version)
        self.active_device_id = device_id
        return self.devices[device_id]

    def get_devices_list(self) -> List[Dict[str, Any]]:
        """List all known endpoint devices with their live connection status."""
        result = []
        for dev_id, dev in self.devices.items():
            st = dev.get_status()
            risk = dev.get_risk()
            result.append({
                "device_id": dev_id,
                "hostname": st.get("hostname", "Unknown"),
                "os_name": st.get("os_name", "Windows"),
                "os_version": st.get("os_version", ""),
                "status": st.get("status", "OFFLINE"),
                "telemetry_age_seconds": st.get("telemetry_age_seconds"),
                "risk_score": risk.get("score", 0),
                "risk_level": risk.get("level", "SAFE")
            })
        return result

    # ---------------- Backward Compatibility Accessors ----------------
    @property
    def agent_ws(self) -> Optional[WebSocket]:
        if self.active_device_id and self.active_device_id in self.agent_sockets:
            return self.agent_sockets[self.active_device_id]
        if self.agent_sockets:
            return next(iter(self.agent_sockets.values()))
        return None

    @property
    def agent_device_id(self) -> Optional[str]:
        return self.active_device_id

    @property
    def system_telemetry(self) -> Optional[Dict[str, Any]]:
        return self.get_device().system_telemetry

    @property
    def telemetry_history(self) -> List[Dict[str, Any]]:
        return self.get_device().telemetry_history

    @property
    def processes(self) -> List[Dict[str, Any]]:
        return self.get_device().processes

    @property
    def network_conns(self) -> List[Dict[str, Any]]:
        return self.get_device().network_conns

    @property
    def defender_status(self) -> Dict[str, Any]:
        return self.get_device().defender_status

    @property
    def firewall_status(self) -> Dict[str, Any]:
        return self.get_device().firewall_status

    @property
    def software_inventory(self) -> List[Dict[str, Any]]:
        return self.get_device().software_inventory

    @property
    def services_inventory(self) -> List[Dict[str, Any]]:
        return self.get_device().services_inventory

    @property
    def startup_inventory(self) -> List[Dict[str, Any]]:
        return self.get_device().startup_inventory

    @property
    def tracked_files(self) -> List[Dict[str, Any]]:
        return self.get_device().tracked_files

    @property
    def file_events(self) -> List[Dict[str, Any]]:
        return self.get_device().file_events

    @property
    def security_events(self) -> List[Dict[str, Any]]:
        return self.get_device().security_events

    @property
    def threat_alerts(self) -> List[Dict[str, Any]]:
        return self.get_device().threat_alerts

    @property
    def scans(self) -> List[Dict[str, Any]]:
        return self.get_device().scans

    def get_agent_status(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        return self.get_device(device_id).get_status()

    def get_current_risk(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        return self.get_device(device_id).get_risk()

    def get_system_telemetry(self, device_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.get_device(device_id).system_telemetry

    def get_telemetry_history(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.get_device(device_id).telemetry_history[-40:]

    # ---------------- Browser WebSockets ----------------
    async def register_browser(self, ws: WebSocket, target_device_id: Optional[str] = None):
        await ws.accept()
        self.browser_clients[ws] = target_device_id
        await self.send_browser_init(ws, target_device_id)

    def unregister_browser(self, ws: WebSocket):
        self.browser_clients.pop(ws, None)

    async def broadcast_to_browsers(self, message: Dict[str, Any], device_id: Optional[str] = None):
        """Broadcast an event to connected browsers (targeted or global)."""
        dead_clients = []
        if device_id:
            message["device_id"] = device_id

        for ws, client_device_id in list(self.browser_clients.items()):
            # Send if browser client has no target filter or filter matches device_id
            if not client_device_id or not device_id or client_device_id == device_id:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead_clients.append(ws)

        for ws in dead_clients:
            self.unregister_browser(ws)

    async def send_browser_init(self, ws: WebSocket, device_id: Optional[str] = None):
        """Send complete baseline state to newly connected browser client."""
        try:
            dev = self.get_device(device_id)
            payload = {
                "type": "init_state",
                "device_id": dev.device_id,
                "status": dev.get_status(),
                "telemetry": dev.system_telemetry,
                "telemetry_history": dev.telemetry_history[-35:],
                "risk": dev.get_risk(),
                "protection": {
                    "defender": dev.defender_status,
                    "firewall": dev.firewall_status
                },
                "processes": dev.processes[:150],
                "network": dev.network_conns[:150],
                "threats": dev.threat_alerts[:25],
                "events": dev.security_events[:30],
                "file_events": dev.file_events[:20],
                "software_count": len(dev.software_inventory),
                "services_count": len(dev.services_inventory),
                "startup_count": len(dev.startup_inventory),
                "scans": dev.scans[:10],
                "available_devices": self.get_devices_list()
            }
            await ws.send_json(payload)
        except Exception as e:
            logger.warning(f"Error sending init state to browser: {e}")

    # ---------------- Agent Ingestion ----------------
    async def process_agent_message(self, msg_type: str, device_id: str, data: Any):
        dev = self.get_or_create_device(device_id)
        dev.last_telemetry_time = datetime.datetime.utcnow()
        self.active_device_id = device_id

        if msg_type == "device_register":
            dev.device_info.update(data)
            dev.device_info["device_id"] = device_id
            dev.device_info["registered_at"] = datetime.datetime.utcnow().isoformat()
            self._save_device_record(data)
            await self.broadcast_to_browsers({
                "type": "status_update",
                "status": dev.get_status(),
                "devices": self.get_devices_list()
            }, device_id=device_id)

        elif msg_type == "system_telemetry":
            dev.system_telemetry = data
            dev.telemetry_history.append(data)
            if len(dev.telemetry_history) > 60:
                dev.telemetry_history = dev.telemetry_history[-60:]
            await self.broadcast_to_browsers({
                "type": "telemetry_update",
                "telemetry": data,
                "status": dev.get_status()
            }, device_id=device_id)

        elif msg_type == "processes":
            dev.processes = data
            await self.broadcast_to_browsers({
                "type": "processes_update",
                "processes": data[:150],
                "risk": dev.get_risk()
            }, device_id=device_id)

        elif msg_type == "network":
            dev.network_conns = data
            await self.broadcast_to_browsers({
                "type": "network_update",
                "network": data[:150]
            }, device_id=device_id)

        elif msg_type == "protection_status":
            dev.defender_status = data.get("defender", {})
            dev.firewall_status = data.get("firewall", {})
            risk = dev.get_risk()
            await self.broadcast_to_browsers({
                "type": "protection_update",
                "protection": data,
                "risk": risk
            }, device_id=device_id)

        elif msg_type == "software_inventory":
            dev.software_inventory = data
            await self.broadcast_to_browsers({"type": "software_update", "count": len(data)}, device_id=device_id)

        elif msg_type == "services_inventory":
            dev.services_inventory = data
            await self.broadcast_to_browsers({"type": "services_update", "count": len(data)}, device_id=device_id)

        elif msg_type == "startup_inventory":
            dev.startup_inventory = data
            await self.broadcast_to_browsers({
                "type": "startup_update",
                "items": data,
                "risk": dev.get_risk()
            }, device_id=device_id)

        elif msg_type == "tracked_files":
            dev.tracked_files = data

        elif msg_type == "file_events":
            dev.file_events = data + dev.file_events
            dev.file_events = dev.file_events[:100]
            await self.broadcast_to_browsers({"type": "file_events_update", "events": dev.file_events[:20]}, device_id=device_id)

        elif msg_type == "windows_events":
            dev.security_events = data + dev.security_events
            dev.security_events = dev.security_events[:100]
            self._save_security_events(data, device_id)
            await self.broadcast_to_browsers({"type": "security_events_update", "events": dev.security_events[:30]}, device_id=device_id)

        elif msg_type == "threat_alerts":
            dev.threat_alerts = data
            self._save_threat_alerts(data, device_id)
            await self.broadcast_to_browsers({
                "type": "threats_update",
                "threats": data,
                "risk": dev.get_risk()
            }, device_id=device_id)

        elif msg_type == "scan_status":
            self._update_scan_status(data, device_id)
            await self.broadcast_to_browsers({"type": "scan_update", "scan": data}, device_id=device_id)

    def _save_device_record(self, data: Dict[str, Any]):
        try:
            device_id = data.get("device_id")
            with SessionLocal() as db:
                dev = db.query(EndpointDevice).filter(EndpointDevice.device_id == device_id).first()
                if not dev:
                    dev = EndpointDevice(
                        device_id=device_id,
                        hostname=data.get("hostname", "Unknown"),
                        os_name=data.get("os_name"),
                        os_version=data.get("os_version"),
                        agent_version=data.get("agent_version"),
                        status="ONLINE",
                        registered_at=datetime.datetime.utcnow()
                    )
                    db.add(dev)
                else:
                    dev.hostname = data.get("hostname", dev.hostname)
                    dev.os_name = data.get("os_name", dev.os_name)
                    dev.os_version = data.get("os_version", dev.os_version)
                    dev.status = "ONLINE"
                    dev.last_heartbeat = datetime.datetime.utcnow()
                db.commit()
        except Exception as e:
            logger.warning(f"Error saving device record: {e}")

    def _save_threat_alerts(self, alerts: List[Dict[str, Any]], device_id: str):
        try:
            with SessionLocal() as db:
                for a in alerts[:5]:
                    alert_id = a.get("id") or str(uuid.uuid4())
                    existing = db.query(EndpointThreatAlert).filter(EndpointThreatAlert.alert_id == alert_id).first()
                    if not existing:
                        db.add(EndpointThreatAlert(
                            alert_id=alert_id,
                            device_id=device_id,
                            severity=a.get("severity", "MEDIUM"),
                            category=a.get("category", "General"),
                            title=a.get("title", "Threat Alert"),
                            detection_source=a.get("detection_source", "Agent"),
                            evidence_json=json.dumps(a.get("evidence", [])),
                            explanation=a.get("explanation", ""),
                            affected_object=a.get("affected_object"),
                            recommended_action=a.get("recommended_action", ""),
                            status="ACTIVE"
                        ))
                db.commit()
        except Exception as e:
            logger.warning(f"Error saving threat alerts: {e}")

    def _save_security_events(self, events: List[Dict[str, Any]], device_id: str):
        try:
            with SessionLocal() as db:
                for ev in events[:5]:
                    db.add(EndpointSecurityEvent(
                        device_id=device_id,
                        severity=ev.get("severity", "LOW"),
                        event_type=ev.get("event_type", "event"),
                        source=ev.get("source", "system"),
                        description=ev.get("description", ""),
                        user=ev.get("user"),
                        process=ev.get("process"),
                        metadata_json=json.dumps(ev.get("metadata", {}))
                    ))
                db.commit()
        except Exception as e:
            logger.warning(f"Error saving security events: {e}")

    def _update_scan_status(self, scan_data: Dict[str, Any], device_id: str):
        scan_id = scan_data.get("scan_id")
        dev = self.get_device(device_id)
        for s in dev.scans:
            if s.get("scan_id") == scan_id:
                s.update(scan_data)
                break
        else:
            dev.scans.insert(0, scan_data)

        try:
            with SessionLocal() as db:
                rec = db.query(EndpointScan).filter(EndpointScan.scan_id == scan_id).first()
                if rec:
                    rec.status = scan_data.get("status", rec.status)
                    rec.findings_count = scan_data.get("findings_count", rec.findings_count)
                    if scan_data.get("summary"):
                        rec.summary_json = json.dumps(scan_data.get("summary"))
                    if scan_data.get("status") == "COMPLETED":
                        rec.completed_at = datetime.datetime.utcnow()
                    db.commit()
        except Exception as e:
            logger.warning(f"Error updating scan in DB: {e}")

    async def trigger_scan(self, scan_type: str, device_id: Optional[str] = None) -> Dict[str, Any]:
        """Trigger a real scan on an endpoint via the connected agent."""
        dev = self.get_device(device_id)
        agent_status = dev.get_status()
        target_ws = self.agent_sockets.get(dev.device_id) or self.agent_ws

        if agent_status["status"] == "OFFLINE" and not target_ws:
            return {
                "scan_id": str(uuid.uuid4())[:8],
                "scan_type": scan_type,
                "status": "UNAVAILABLE",
                "findings_count": 0,
                "started_at": datetime.datetime.utcnow().isoformat(),
                "summary": {"error": f"Agent for {dev.device_id} is offline."}
            }

        scan_id = f"scn-{uuid.uuid4().hex[:8]}"
        scan_record = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "status": "QUEUED",
            "findings_count": 0,
            "started_at": datetime.datetime.utcnow().isoformat(),
            "completed_at": None,
            "summary": None
        }

        dev.scans.insert(0, scan_record)

        # Record in DB
        try:
            with SessionLocal() as db:
                db.add(EndpointScan(
                    scan_id=scan_id,
                    device_id=dev.device_id,
                    scan_type=scan_type,
                    status="QUEUED",
                    started_at=datetime.datetime.utcnow()
                ))
                db.commit()
        except Exception as e:
            logger.warning(f"Error creating scan record: {e}")

        # Send command to agent over WebSocket if available
        if target_ws:
            try:
                await target_ws.send_json({
                    "action": "run_scan",
                    "scan_id": scan_id,
                    "scan_type": scan_type
                })
            except Exception as e:
                logger.error(f"Error dispatching scan to agent: {e}")
                scan_record["status"] = "FAILED"
                scan_record["summary"] = {"error": f"Failed to dispatch to agent: {e}"}

        await self.broadcast_to_browsers({"type": "scan_update", "scan": scan_record}, device_id=dev.device_id)
        return scan_record


endpoint_security_mgr = EndpointSecurityManager()

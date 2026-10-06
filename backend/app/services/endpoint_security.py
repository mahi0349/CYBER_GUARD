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

class EndpointSecurityManager:
    def __init__(self):
        # Connected browser clients
        self.browser_clients: Set[WebSocket] = set()
        # Connected agent WebSocket
        self.agent_ws: Optional[WebSocket] = None
        self.agent_device_id: Optional[str] = None

        # Real-time state cache
        self.device_info: Dict[str, Any] = {
            "device_id": "unknown",
            "hostname": "Unknown Host",
            "os_name": "Windows",
            "os_version": "Unknown",
            "agent_version": "1.0.0",
            "status": "OFFLINE",
            "registered_at": None,
            "last_telemetry_at": None
        }

        self.last_telemetry_time: Optional[datetime.datetime] = None
        self.system_telemetry: Optional[Dict[str, Any]] = None
        self.telemetry_history: List[Dict[str, Any]] = [] # last 40 readings for charts

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

    def get_agent_status(self) -> Dict[str, Any]:
        """Determine agent connection health."""
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
            "device_id": self.device_info.get("device_id", "unknown"),
            "hostname": self.device_info.get("hostname", "Unknown Host"),
            "os_name": self.device_info.get("os_name", "Windows"),
            "os_version": self.device_info.get("os_version", "Unknown"),
            "agent_version": self.device_info.get("agent_version", "1.0.0"),
            "status": status,
            "last_telemetry_at": self.last_telemetry_time.isoformat() if self.last_telemetry_time else None,
            "telemetry_age_seconds": age,
            "registered_at": self.device_info.get("registered_at")
        }

    def get_current_risk(self) -> Dict[str, Any]:
        return endpoint_risk_engine.evaluate(
            defender_data=self.defender_status,
            firewall_data=self.firewall_status,
            processes=self.processes,
            network_conns=self.network_conns,
            startup_items=self.startup_inventory,
            file_events=self.file_events,
            security_events=self.security_events
        )

    # ---------------- Browser WebSockets ----------------
    async def register_browser(self, ws: WebSocket):
        await ws.accept()
        self.browser_clients.add(ws)
        # Send initial full state immediately
        await self.send_browser_init(ws)

    def unregister_browser(self, ws: WebSocket):
        self.browser_clients.discard(ws)

    async def broadcast_to_browsers(self, message: Dict[str, Any]):
        dead_clients = set()
        for ws in self.browser_clients:
            try:
                await ws.send_json(message)
            except Exception:
                dead_clients.add(ws)
        self.browser_clients -= dead_clients

    async def send_browser_init(self, ws: WebSocket):
        """Send complete baseline state to newly connected browser client."""
        try:
            payload = {
                "type": "init_state",
                "status": self.get_agent_status(),
                "telemetry": self.system_telemetry,
                "telemetry_history": self.telemetry_history[-30:],
                "risk": self.get_current_risk(),
                "protection": {
                    "defender": self.defender_status,
                    "firewall": self.firewall_status
                },
                "processes": self.processes[:100],
                "network": self.network_conns[:100],
                "threats": self.threat_alerts[:25],
                "events": self.security_events[:30],
                "file_events": self.file_events[:20],
                "software_count": len(self.software_inventory),
                "services_count": len(self.services_inventory),
                "startup_count": len(self.startup_inventory),
                "scans": self.scans[:10]
            }
            await ws.send_json(payload)
        except Exception as e:
            logger.warning(f"Error sending init state to browser: {e}")

    # ---------------- Agent Ingestion ----------------
    async def process_agent_message(self, msg_type: str, device_id: str, data: Any):
        self.last_telemetry_time = datetime.datetime.utcnow()
        self.agent_device_id = device_id

        if msg_type == "device_register":
            self.device_info.update(data)
            self.device_info["registered_at"] = datetime.datetime.utcnow().isoformat()
            self._save_device_record(data)
            await self.broadcast_to_browsers({"type": "status_update", "status": self.get_agent_status()})

        elif msg_type == "system_telemetry":
            self.system_telemetry = data
            self.telemetry_history.append(data)
            if len(self.telemetry_history) > 60:
                self.telemetry_history = self.telemetry_history[-60:]
            await self.broadcast_to_browsers({
                "type": "telemetry_update",
                "telemetry": data,
                "status": self.get_agent_status()
            })

        elif msg_type == "processes":
            self.processes = data
            await self.broadcast_to_browsers({
                "type": "processes_update",
                "processes": data[:150],
                "risk": self.get_current_risk()
            })

        elif msg_type == "network":
            self.network_conns = data
            await self.broadcast_to_browsers({
                "type": "network_update",
                "network": data[:150]
            })

        elif msg_type == "protection_status":
            self.defender_status = data.get("defender", {})
            self.firewall_status = data.get("firewall", {})
            risk = self.get_current_risk()
            await self.broadcast_to_browsers({
                "type": "protection_update",
                "protection": data,
                "risk": risk
            })

        elif msg_type == "software_inventory":
            self.software_inventory = data
            await self.broadcast_to_browsers({"type": "software_update", "count": len(data)})

        elif msg_type == "services_inventory":
            self.services_inventory = data
            await self.broadcast_to_browsers({"type": "services_update", "count": len(data)})

        elif msg_type == "startup_inventory":
            self.startup_inventory = data
            await self.broadcast_to_browsers({
                "type": "startup_update",
                "items": data,
                "risk": self.get_current_risk()
            })

        elif msg_type == "tracked_files":
            self.tracked_files = data

        elif msg_type == "file_events":
            self.file_events = data + self.file_events
            self.file_events = self.file_events[:100]
            await self.broadcast_to_browsers({"type": "file_events_update", "events": self.file_events[:20]})

        elif msg_type == "windows_events":
            self.security_events = data + self.security_events
            self.security_events = self.security_events[:100]
            self._save_security_events(data)
            await self.broadcast_to_browsers({"type": "security_events_update", "events": self.security_events[:30]})

        elif msg_type == "threat_alerts":
            self.threat_alerts = data
            self._save_threat_alerts(data)
            await self.broadcast_to_browsers({
                "type": "threats_update",
                "threats": data,
                "risk": self.get_current_risk()
            })

        elif msg_type == "scan_status":
            self._update_scan_status(data)
            await self.broadcast_to_browsers({"type": "scan_update", "scan": data})

    def _save_device_record(self, data: Dict[str, Any]):
        try:
            with SessionLocal() as db:
                dev = db.query(EndpointDevice).filter(EndpointDevice.device_id == data.get("device_id")).first()
                if not dev:
                    dev = EndpointDevice(
                        device_id=data.get("device_id"),
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

    def _save_threat_alerts(self, alerts: List[Dict[str, Any]]):
        try:
            with SessionLocal() as db:
                for a in alerts[:5]:
                    alert_id = a.get("id") or str(uuid.uuid4())
                    existing = db.query(EndpointThreatAlert).filter(EndpointThreatAlert.alert_id == alert_id).first()
                    if not existing:
                        db.add(EndpointThreatAlert(
                            alert_id=alert_id,
                            device_id=self.device_info.get("device_id", "local"),
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

    def _save_security_events(self, events: List[Dict[str, Any]]):
        try:
            with SessionLocal() as db:
                for ev in events[:5]:
                    db.add(EndpointSecurityEvent(
                        device_id=self.device_info.get("device_id", "local"),
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

    def _update_scan_status(self, scan_data: Dict[str, Any]):
        scan_id = scan_data.get("scan_id")
        for s in self.scans:
            if s.get("scan_id") == scan_id:
                s.update(scan_data)
                break
        else:
            self.scans.insert(0, scan_data)

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

    async def trigger_scan(self, scan_type: str) -> Dict[str, Any]:
        """Trigger a real scan on the Windows endpoint via the connected agent."""
        agent_status = self.get_agent_status()
        if agent_status["status"] == "OFFLINE" and not self.agent_ws:
            return {
                "scan_id": str(uuid.uuid4())[:8],
                "scan_type": scan_type,
                "status": "UNAVAILABLE",
                "findings_count": 0,
                "started_at": datetime.datetime.utcnow().isoformat(),
                "summary": {"error": "Agent is offline. Telemetry agent required to execute scan."}
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

        self.scans.insert(0, scan_record)

        # Record in DB
        try:
            with SessionLocal() as db:
                db.add(EndpointScan(
                    scan_id=scan_id,
                    device_id=self.device_info.get("device_id", "local"),
                    scan_type=scan_type,
                    status="QUEUED",
                    started_at=datetime.datetime.utcnow()
                ))
                db.commit()
        except Exception as e:
            logger.warning(f"Error creating scan record: {e}")

        # Send command to agent over WebSocket if available
        if self.agent_ws:
            try:
                await self.agent_ws.send_json({
                    "action": "run_scan",
                    "scan_id": scan_id,
                    "scan_type": scan_type
                })
            except Exception as e:
                logger.error(f"Error dispatching scan to agent: {e}")
                scan_record["status"] = "FAILED"
                scan_record["summary"] = {"error": f"Failed to dispatch to agent: {e}"}

        await self.broadcast_to_browsers({"type": "scan_update", "scan": scan_record})
        return scan_record

endpoint_security_mgr = EndpointSecurityManager()

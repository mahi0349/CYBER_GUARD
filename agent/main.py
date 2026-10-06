import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone

from agent.config import config
from agent.collectors.system import system_collector
from agent.collectors.processes import process_collector
from agent.collectors.network import network_collector
from agent.collectors.defender import defender_collector
from agent.collectors.firewall import firewall_collector
from agent.collectors.software import software_collector
from agent.collectors.services import services_collector
from agent.collectors.startup import startup_collector
from agent.collectors.files import file_collector
from agent.collectors.windows_events import windows_events_collector
from agent.detection.rules import detection_engine
from agent.transport import AgentTransport

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("quantumvault.agent")

class QuantumVaultAgent:
    def __init__(self):
        self.config = config
        file_collector.monitored_paths = self.config.monitored_paths
        self.transport = AgentTransport(
            http_url=config.backend_http_url,
            ws_url=config.backend_ws_url,
            token=config.api_token,
            device_id=config.device_id
        )
        self.transport.on_command_callback = self.handle_command
        self.running = True

        # Cache of latest states
        self.cached_defender = {}
        self.cached_firewall = {}
        self.cached_startup = []
        self.cached_software = []
        self.cached_services = []

    async def handle_command(self, cmd_data: dict):
        """Handle incoming command from backend (e.g. run a scan)."""
        action = cmd_data.get("action")
        scan_id = cmd_data.get("scan_id")
        scan_type = cmd_data.get("scan_type", "quick")

        logger.info(f"Received command: action={action}, scan_id={scan_id}, type={scan_type}")

        if action == "run_scan":
            await self.execute_scan(scan_id, scan_type)

    async def execute_scan(self, scan_id: str, scan_type: str):
        """Execute a genuine scan on the Windows endpoint and report real results."""
        logger.info(f"Executing scan: {scan_type} (ID: {scan_id})")
        # Notify backend scan is running
        await self.transport.send_payload("scan_status", {
            "scan_id": scan_id,
            "status": "RUNNING",
            "message": f"Executing real endpoint {scan_type} scan...",
            "started_at": datetime.now(timezone.utc).isoformat()
        })

        findings = []
        try:
            if scan_type in ["quick", "config"]:
                def_data = defender_collector.collect()
                fw_data = firewall_collector.collect()
                self.cached_defender = def_data
                self.cached_firewall = fw_data

                if not def_data.get("real_time_protection"):
                    findings.append("Microsoft Defender Real-Time Protection is not enabled.")
                if not fw_data.get("all_enabled"):
                    findings.append("One or more Windows Firewall profiles are inactive.")
                if def_data.get("signature_age_days", 0) > 3:
                    findings.append(f"Antivirus signatures are {def_data.get('signature_age_days')} days old.")

            if scan_type in ["quick", "process"]:
                procs = process_collector.collect(limit=100)
                for p in procs:
                    if p.get("risk_level") in ["HIGH", "CRITICAL"]:
                        findings.append(f"Suspicious process {p.get('name')} (PID {p.get('pid')}): {', '.join(p.get('risk_reasons', []))}")

            if scan_type in ["quick", "startup"]:
                startup = startup_collector.collect()
                self.cached_startup = startup
                for s in startup:
                    if s.get("suspicious"):
                        findings.append(f"Suspicious startup entry {s.get('name')}: {', '.join(s.get('reasons', []))}")

            if scan_type in ["quick", "network"]:
                conns = network_collector.collect(limit=100)
                for c in conns:
                    if c.get("risk_level") == "HIGH":
                        findings.append(f"Suspicious network connection {c.get('process_name')} ({c.get('local_port')} -> {c.get('remote_port')})")

            if scan_type in ["quick", "file"]:
                tracked_files = file_collector.get_tracked_files()
                for tf in tracked_files:
                    if tf.get("is_executable") and not tf.get("sha256"):
                        findings.append(f"Unverified executable in monitored directory: {tf.get('name')}")

            await asyncio.sleep(1.0) # Ensure realistic async progression

            # Send completion
            await self.transport.send_payload("scan_status", {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "findings_count": len(findings),
                "summary": {
                    "findings": findings,
                    "target": scan_type,
                    "host": config.hostname
                }
            })
            logger.info(f"Scan {scan_id} completed with {len(findings)} findings.")
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            await self.transport.send_payload("scan_status", {
                "scan_id": scan_id,
                "status": "FAILED",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "findings_count": 0,
                "summary": {"error": str(e)}
            })

    async def telemetry_loop(self):
        """Continuously collect and broadcast live telemetry."""
        while self.running:
            try:
                data = system_collector.collect()
                await self.transport.send_payload("system_telemetry", data)
            except Exception as e:
                logger.error(f"Error in telemetry loop: {e}")
            await asyncio.sleep(self.config.telemetry_interval)

    async def processes_and_network_loop(self):
        """Continuously collect processes and network connections."""
        while self.running:
            try:
                procs = process_collector.collect()
                conns = network_collector.collect()
                await self.transport.send_payload("processes", procs)
                await self.transport.send_payload("network", conns)
            except Exception as e:
                logger.error(f"Error in proc/net loop: {e}")
            await asyncio.sleep(self.config.process_interval)

    async def protection_status_loop(self):
        """Periodically collect Defender, Firewall, and compute threats."""
        while self.running:
            try:
                def_data = defender_collector.collect()
                fw_data = firewall_collector.collect()
                self.cached_defender = def_data
                self.cached_firewall = fw_data

                await self.transport.send_payload("protection_status", {
                    "defender": def_data,
                    "firewall": fw_data
                })

                # Evaluate detection engine alerts
                procs = process_collector.collect(limit=50)
                conns = network_collector.collect(limit=50)
                file_evts = file_collector.get_recent_events()
                
                alerts = detection_engine.evaluate_threats(
                    defender_data=def_data,
                    firewall_data=fw_data,
                    startup_items=self.cached_startup,
                    processes=procs,
                    network_conns=conns,
                    file_events=file_evts
                )
                if alerts:
                    await self.transport.send_payload("threat_alerts", alerts)

            except Exception as e:
                logger.error(f"Error in protection status loop: {e}")
            await asyncio.sleep(self.config.security_status_interval)

    async def events_and_files_loop(self):
        """Collect Windows events and check monitored directories."""
        while self.running:
            try:
                # Monitored files
                new_file_events = file_collector.scan_monitored_directories()
                if new_file_events:
                    await self.transport.send_payload("file_events", new_file_events)

                # Send file inventory
                tracked_files = file_collector.get_tracked_files()
                await self.transport.send_payload("tracked_files", tracked_files)

                # Windows events
                win_evts = windows_events_collector.collect()
                if win_evts:
                    await self.transport.send_payload("windows_events", win_evts)

            except Exception as e:
                logger.error(f"Error in events loop: {e}")
            await asyncio.sleep(self.config.events_interval)

    async def inventory_loop(self):
        """Collect heavier inventories less frequently: software, services, startup."""
        while self.running:
            try:
                sw = software_collector.collect()
                svcs = services_collector.collect()
                su = startup_collector.collect()

                self.cached_software = sw
                self.cached_services = svcs
                self.cached_startup = su

                await self.transport.send_payload("software_inventory", sw)
                await self.transport.send_payload("services_inventory", svcs)
                await self.transport.send_payload("startup_inventory", su)
            except Exception as e:
                logger.error(f"Error in inventory loop: {e}")
            await asyncio.sleep(self.config.software_interval)

    async def register_device(self):
        """Register endpoint device with backend."""
        reg_payload = {
            "device_id": config.device_id,
            "hostname": config.hostname,
            "os_name": config.os_name,
            "os_version": config.os_version,
            "agent_version": config.version,
            "monitored_paths": config.monitored_paths,
            "status": "ONLINE"
        }
        await self.transport.send_payload("device_register", reg_payload)

    async def start(self):
        logger.info(f"Starting {config.agent_name} v{config.version} on {config.hostname}...")
        await self.transport.connect_ws()
        await self.register_device()

        # Prime file collector
        file_collector.scan_monitored_directories()

        # Gather initial inventory immediately
        try:
            self.cached_startup = startup_collector.collect()
            self.cached_software = software_collector.collect()
            self.cached_services = services_collector.collect()
            self.cached_defender = defender_collector.collect()
            self.cached_firewall = firewall_collector.collect()

            await self.transport.send_payload("startup_inventory", self.cached_startup)
            await self.transport.send_payload("software_inventory", self.cached_software)
            await self.transport.send_payload("services_inventory", self.cached_services)
            await self.transport.send_payload("protection_status", {
                "defender": self.cached_defender,
                "firewall": self.cached_firewall
            })
        except Exception as e:
            logger.warning(f"Error during initial collection: {e}")

        # Run concurrent loops
        tasks = [
            asyncio.create_task(self.transport.listen_for_commands()),
            asyncio.create_task(self.telemetry_loop()),
            asyncio.create_task(self.processes_and_network_loop()),
            asyncio.create_task(self.protection_status_loop()),
            asyncio.create_task(self.events_and_files_loop()),
            asyncio.create_task(self.inventory_loop())
        ]

        logger.info("Agent loops active. Telemetry flowing.")
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Agent tasks cancelled.")

    def stop(self):
        self.running = False

def run_agent():
    agent = QuantumVaultAgent()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(agent.start())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
        agent.stop()

if __name__ == "__main__":
    run_agent()

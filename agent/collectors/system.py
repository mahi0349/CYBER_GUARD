import time
import platform
import socket
import psutil
from datetime import datetime, timezone
from typing import Dict, Any

class SystemCollector:
    def __init__(self):
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        self.boot_time = psutil.boot_time()

    def collect(self) -> Dict[str, Any]:
        now = time.time()
        dt = max(now - self.last_time, 0.1)
        current_net_io = psutil.net_io_counters()
        
        bytes_sent_per_sec = max(0.0, (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / dt)
        bytes_recv_per_sec = max(0.0, (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / dt)
        
        self.last_net_io = current_net_io
        self.last_time = now
        
        cpu_pct = psutil.cpu_percent(interval=None)
        cpu_count = psutil.cpu_count(logical=True)
        
        mem = psutil.virtual_memory()
        
        # Disk usage of primary system drive
        try:
            sys_drive = "C:\\" if platform.system() == "Windows" else "/"
            disk = psutil.disk_usage(sys_drive)
            disk_total_gb = round(disk.total / (1024 ** 3), 1)
            disk_used_gb = round(disk.used / (1024 ** 3), 1)
            disk_free_gb = round(disk.free / (1024 ** 3), 1)
            disk_pct = disk.percent
        except Exception:
            disk_total_gb = 0
            disk_used_gb = 0
            disk_free_gb = 0
            disk_pct = 0.0

        uptime_secs = int(now - self.boot_time)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "os_name": platform.system(),
            "os_version": platform.version(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "cpu_percent": cpu_pct,
            "cpu_cores": cpu_count,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / (1024 ** 2), 1),
            "memory_total_mb": round(mem.total / (1024 ** 2), 1),
            "memory_available_mb": round(mem.available / (1024 ** 2), 1),
            "disk_percent": disk_pct,
            "disk_used_gb": disk_used_gb,
            "disk_total_gb": disk_total_gb,
            "disk_free_gb": disk_free_gb,
            "net_bytes_sent_sec": round(bytes_sent_per_sec, 1),
            "net_bytes_recv_sec": round(bytes_recv_per_sec, 1),
            "total_bytes_sent": current_net_io.bytes_sent,
            "total_bytes_recv": current_net_io.bytes_recv,
            "uptime_seconds": uptime_secs,
            "boot_time": datetime.fromtimestamp(self.boot_time, tz=timezone.utc).isoformat()
        }

system_collector = SystemCollector()

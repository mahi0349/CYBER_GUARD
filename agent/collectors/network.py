import socket
import psutil
from typing import List, Dict, Any

class NetworkCollector:
    def __init__(self):
        pass

    def evaluate_connection_risk(self, laddr: str, lport: int, raddr: str, rport: int, status: str, proc_name: str) -> Dict[str, Any]:
        """
        Evaluate connection risk without making unfounded malicious claims.
        """
        risk_score = 0
        reasons = []

        # Common administrative or sensitive listening ports
        sensitive_ports = {
            4444: "Common reverse shell port",
            6667: "IRC protocol port",
            1337: "Common backdoor port",
            3389: "RDP port listening",
            5985: "WinRM HTTP port",
            5986: "WinRM HTTPS port"
        }

        if status == "LISTEN":
            if lport in sensitive_ports:
                risk_score += 25
                reasons.append(f"Listening on sensitive port {lport}: {sensitive_ports[lport]}")

        # Non-standard outgoing ports from system tools
        if rport in [4444, 1337, 6667, 31337]:
            risk_score += 40
            reasons.append(f"Outbound connection to known suspicious port {rport}")

        level = "SAFE"
        if risk_score >= 35:
            level = "HIGH"
        elif risk_score >= 15:
            level = "MEDIUM"
        elif risk_score > 0:
            level = "LOW"

        return {
            "score": risk_score,
            "level": level,
            "reasons": reasons
        }

    def collect(self, limit: int = 250) -> List[Dict[str, Any]]:
        # Map pids to process names for fast lookup
        proc_names = {}
        for p in psutil.process_iter(['pid', 'name']):
            try:
                proc_names[p.info['pid']] = p.info['name']
            except Exception:
                pass

        results = []
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            return []

        for c in conns:
            try:
                laddr_ip = c.laddr.ip if c.laddr else ""
                laddr_port = c.laddr.port if c.laddr else 0
                raddr_ip = c.raddr.ip if c.raddr else ""
                rport = c.raddr.port if c.raddr else 0
                
                # Protocol
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                status = c.status if c.status else ("LISTEN" if proto == "TCP" and not raddr_ip else "ACTIVE")
                
                pid = c.pid or 0
                pname = proc_names.get(pid, "System / Unknown" if pid else "System")

                risk = self.evaluate_connection_risk(laddr_ip, laddr_port, raddr_ip, rport, status, pname)

                results.append({
                    "pid": pid,
                    "process_name": pname,
                    "protocol": proto,
                    "local_ip": laddr_ip,
                    "local_port": laddr_port,
                    "remote_ip": raddr_ip or "-",
                    "remote_port": rport if rport else "-",
                    "state": status,
                    "risk_score": risk["score"],
                    "risk_level": risk["level"],
                    "risk_reasons": risk["reasons"]
                })
            except Exception:
                continue

        # Sort: suspicious first, then established connections, then listening ports
        results.sort(key=lambda x: (x["risk_score"], 1 if x["state"] == "ESTABLISHED" else 0), reverse=True)
        return results[:limit]

network_collector = NetworkCollector()

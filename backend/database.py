import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .config import DATABASE_PATH
from .models.enums import IncidentStatus, RiskLevel, ThreatCategory
from .models.schemas import ThreatDetectionResult

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            threat_classification TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            human_explanation TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            recommended_actions_json TEXT NOT NULL,
            mitre_techniques_json TEXT NOT NULL,
            target_identity TEXT,
            origin_ip TEXT,
            raw_content_summary TEXT,
            metadata_json TEXT NOT NULL,
            incident_status TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS remediation_actions (
            id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            action_key TEXT NOT NULL,
            action_title TEXT NOT NULL,
            category TEXT NOT NULL,
            simulated_command TEXT NOT NULL,
            status TEXT NOT NULL,
            operator TEXT NOT NULL,
            notes TEXT,
            executed_at TEXT NOT NULL,
            audit_verification TEXT NOT NULL,
            impact TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_threat_event(event: ThreatDetectionResult):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO threat_events (
            id, timestamp, source, category, threat_classification,
            risk_score, risk_level, human_explanation,
            indicators_json, recommended_actions_json, mitre_techniques_json,
            target_identity, origin_ip, raw_content_summary, metadata_json,
            incident_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.id,
        event.timestamp.isoformat(),
        event.source.value if hasattr(event.source, 'value') else str(event.source),
        event.category.value if hasattr(event.category, 'value') else str(event.category),
        event.threat_classification,
        event.risk_score,
        event.risk_level.value if hasattr(event.risk_level, 'value') else str(event.risk_level),
        event.human_explanation,
        json.dumps([ind.model_dump() for ind in event.indicators], default=str),
        json.dumps([act.model_dump() for act in event.recommended_actions], default=str),
        json.dumps(event.mitre_attack_techniques, default=str),
        event.target_identity,
        event.origin_ip,
        event.raw_content_summary,
        json.dumps(event.metadata, default=str),
        event.incident_status.value if hasattr(event.incident_status, 'value') else str(event.incident_status)
    ))
    conn.commit()
    conn.close()

def get_recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    events = []
    for row in rows:
        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source": row["source"],
            "category": row["category"],
            "threat_classification": row["threat_classification"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "human_explanation": row["human_explanation"],
            "indicators": json.loads(row["indicators_json"]),
            "recommended_actions": json.loads(row["recommended_actions_json"]),
            "mitre_attack_techniques": json.loads(row["mitre_techniques_json"]),
            "target_identity": row["target_identity"],
            "origin_ip": row["origin_ip"],
            "raw_content_summary": row["raw_content_summary"],
            "metadata": json.loads(row["metadata_json"]),
            "incident_status": row["incident_status"],
        })
    conn.close()
    return events

def get_event_by_id(event_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "category": row["category"],
        "threat_classification": row["threat_classification"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "human_explanation": row["human_explanation"],
        "indicators": json.loads(row["indicators_json"]),
        "recommended_actions": json.loads(row["recommended_actions_json"]),
        "mitre_attack_techniques": json.loads(row["mitre_techniques_json"]),
        "target_identity": row["target_identity"],
        "origin_ip": row["origin_ip"],
        "raw_content_summary": row["raw_content_summary"],
        "metadata": json.loads(row["metadata_json"]),
        "incident_status": row["incident_status"],
    }

def update_incident_status(event_id: str, new_status: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE threat_events SET incident_status = ? WHERE id = ?", (new_status, event_id))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0

def save_remediation_action(action: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO remediation_actions (
            id, event_id, action_key, action_title, category,
            simulated_command, status, operator, notes, executed_at,
            audit_verification, impact
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        action["id"],
        action["event_id"],
        action["action_key"],
        action["action_title"],
        action["category"],
        action["simulated_command"],
        action["status"],
        action["operator"],
        action.get("notes", ""),
        action["executed_at"],
        action["audit_verification"],
        action["impact"]
    ))
    # Automatically mark the event status as MITIGATED
    cursor.execute("UPDATE threat_events SET incident_status = ? WHERE id = ?", ("Mitigated", action["event_id"]))
    conn.commit()
    conn.close()

def get_actions_for_event(event_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM remediation_actions WHERE event_id = ? ORDER BY executed_at DESC", (event_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_all_remediation_actions(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM remediation_actions ORDER BY executed_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_dashboard_metrics() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM threat_events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_events WHERE risk_level IN ('High', 'Critical')")
    critical_high_threats = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM threat_events")
    avg_score_row = cursor.fetchone()[0]
    avg_risk_score = round(avg_score_row, 1) if avg_score_row is not None else 0.0

    cursor.execute("SELECT COUNT(*) FROM remediation_actions")
    total_remediations = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_events WHERE incident_status = 'Mitigated'")
    mitigated_count = cursor.fetchone()[0]

    conn.close()

    containment_rate = round((mitigated_count / critical_high_threats * 100), 1) if critical_high_threats > 0 else 100.0

    return {
        "total_events": total_events,
        "critical_high_threats": critical_high_threats,
        "avg_risk_score": avg_risk_score,
        "total_remediations": total_remediations,
        "mitigated_count": mitigated_count,
        "containment_rate": min(100.0, containment_rate),
    }

def get_category_distribution() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT category, COUNT(*) as count, AVG(risk_score) as avg_risk
        FROM threat_events
        GROUP BY category
        ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{"category": row["category"], "count": row["count"], "avg_risk": round(row["avg_risk"], 1)} for row in rows]

def get_risk_distribution() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT risk_level, COUNT(*) as count
        FROM threat_events
        GROUP BY risk_level
    """)
    rows = cursor.fetchall()
    conn.close()
    level_counts = {row["risk_level"]: row["count"] for row in rows}
    # Return in ordered severity
    return [
        {"level": "Safe", "count": level_counts.get("Safe", 0), "color": "#10b981"},
        {"level": "Low", "count": level_counts.get("Low", 0), "color": "#06b6d4"},
        {"level": "Medium", "count": level_counts.get("Medium", 0), "color": "#f59e0b"},
        {"level": "High", "count": level_counts.get("High", 0), "color": "#f97316"},
        {"level": "Critical", "count": level_counts.get("Critical", 0), "color": "#ef4444"},
    ]

def get_timeline_events(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, category, risk_score, risk_level, threat_classification
        FROM threat_events
        ORDER BY timestamp ASC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

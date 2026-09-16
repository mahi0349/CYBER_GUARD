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

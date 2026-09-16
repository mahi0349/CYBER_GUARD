from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional
from ..models.enums import RiskLevel, ThreatCategory
from ..models.schemas import ThreatDetectionResult

def normalize_risk_score(raw_score: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Normalizes any raw score into 0.0 - 100.0 with 2 decimal precision."""
    if math.isnan(raw_score) or math.isinf(raw_score):
        return 0.0
    
    # If the score is in 0.0 - 1.0 format (probability)
    if max_val <= 1.0 or raw_score <= 1.0 and raw_score > 0.0 and max_val == 100.0:
        # Check if raw_score is <= 1.0 probability
        # Note: if raw_score is e.g. 0.85, it's 85.0
        score = raw_score * 100.0
    else:
        score = ((raw_score - min_val) / (max_val - min_val)) * 100.0 if max_val > min_val else raw_score
        
    clamped = max(0.0, min(100.0, score))
    return round(clamped, 1)

def score_to_risk_level(score: float) -> RiskLevel:
    """Standardized mapping from 0-100 score to RiskLevel enum."""
    if score >= 85.0:
        return RiskLevel.CRITICAL
    elif score >= 70.0:
        return RiskLevel.HIGH
    elif score >= 40.0:
        return RiskLevel.MEDIUM
    elif score >= 20.0:
        return RiskLevel.LOW
    return RiskLevel.SAFE

def calculate_time_decay_factor(event_time: datetime, current_time: Optional[datetime] = None, half_life_hours: float = 24.0) -> float:
    """Computes an exponential decay weight: recent events have weight closer to 1.0."""
    if current_time is None:
        current_time = datetime.now(timezone.utc)
    
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)

    hours_diff = max(0.0, (current_time - event_time).total_seconds() / 3600.0)
    # Decay formula: e^(-ln(2) * t / half_life)
    decay = math.exp(-0.693147 * (hours_diff / half_life_hours))
    return max(0.05, min(1.0, decay))

def calculate_entity_risk(events: List[Dict[str, Any]], entity_type: str = "identity") -> List[Dict[str, Any]]:
    """
    Aggregates threat risk scores for identities (user email / username) or origin IPs.
    Returns ranked entities ordered by composite risk score descending.
    """
    key_field = "target_identity" if entity_type == "identity" else "origin_ip"
    groups: Dict[str, List[Dict[str, Any]]] = {}

    for event in events:
        key = event.get(key_field)
        if not key or key.strip() == "" or key.lower() in ("unknown", "none", "n/a"):
            continue
        key = key.strip()
        if key not in groups:
            groups[key] = []
        groups[key].append(event)

    results = []
    now = datetime.now(timezone.utc)

    for entity_name, entity_events in groups.items():
        total_events = len(entity_events)
        max_score = 0.0
        weighted_score_sum = 0.0
        weight_sum = 0.0
        categories_seen = set()
        recent_mitre = set()

        for ev in entity_events:
            score = float(ev.get("risk_score", 0.0))
            max_score = max(max_score, score)
            categories_seen.add(ev.get("category", "General"))
            
            for tech in ev.get("mitre_attack_techniques", []):
                recent_mitre.add(tech)

            # Timestamp parse
            ts_raw = ev.get("timestamp")
            if isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except Exception:
                    ts = now
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                ts = now

            decay = calculate_time_decay_factor(ts, now, half_life_hours=36.0)
            weighted_score_sum += score * decay
            weight_sum += decay

        # Composite score combines average decayed score (40%) and maximum peak score (60%)
        avg_decayed = (weighted_score_sum / weight_sum) if weight_sum > 0 else 0.0
        composite_score = round(0.6 * max_score + 0.4 * avg_decayed, 1)
        composite_score = max(0.0, min(100.0, composite_score))

        results.append({
            "entity": entity_name,
            "entity_type": entity_type,
            "total_incidents": total_events,
            "peak_risk_score": round(max_score, 1),
            "composite_risk_score": composite_score,
            "risk_level": score_to_risk_level(composite_score).value,
            "threat_categories": sorted(list(categories_seen)),
            "mitre_techniques": sorted(list(recent_mitre))[:5],
            "last_seen": max((ev.get("timestamp") for ev in entity_events), default=now.isoformat())
        })

    # Sort descending by composite_risk_score
    results.sort(key=lambda x: x["composite_risk_score"], reverse=True)
    return results

def correlate_threat_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects correlated multi-stage attack campaigns across different detection modules.
    For example:
      - Phishing lure targeting user X -> Followed by Account Takeover anomaly on user X.
      - Same Origin IP scanning / attempting brute force and domain look-alike attacks.
    """
    correlations = []
    
    # 1. Correlate by Target Identity across Categories
    identity_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        target = ev.get("target_identity")
        if target and target.lower() not in ("unknown", "none"):
            identity_map.setdefault(target, []).append(ev)

    for target, ev_list in identity_map.items():
        categories = {ev.get("category") for ev in ev_list}
        # Multi-vector check: e.g. Phishing / Impersonation AND Account Takeover
        has_social_eng = any("Phishing" in str(c) or "Impersonation" in str(c) for c in categories)
        has_ato = any("Account Takeover" in str(c) or "Anomaly" in str(c) for c in categories)

        if has_social_eng and has_ato:
            max_score = max(float(e.get("risk_score", 0)) for e in ev_list)
            elevated_score = min(100.0, round(max_score * 1.15, 1))
            correlations.append({
                "correlation_type": "Multi-Stage Identity Compromise",
                "target_identity": target,
                "correlated_categories": list(categories),
                "event_ids": [e.get("id") for e in ev_list[:5]],
                "composite_risk_score": elevated_score,
                "risk_level": score_to_risk_level(elevated_score).value,
                "summary": (
                    f"Correlated Multi-Stage Campaign detected against target '{target}'. "
                    f"Initial social engineering (Phishing/Impersonation) observed alongside "
                    f"subsequent authentication anomalies / Account Takeover indicators."
                ),
                "recommended_response": "Immediate forced session revocation and identity quarantine."
            })

    # 2. Correlate by Origin IP across Multiple Targets
    ip_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        ip = ev.get("origin_ip")
        if ip and ip.lower() not in ("unknown", "none", "127.0.0.1"):
            ip_map.setdefault(ip, []).append(ev)

    for ip, ev_list in ip_map.items():
        targets = {e.get("target_identity") for e in ev_list if e.get("target_identity")}
        if len(targets) >= 2 or len(ev_list) >= 3:
            max_score = max(float(e.get("risk_score", 0)) for e in ev_list)
            correlations.append({
                "correlation_type": "Coordinated Adversary IP Campaign",
                "origin_ip": ip,
                "targeted_count": len(targets),
                "event_ids": [e.get("id") for e in ev_list[:5]],
                "composite_risk_score": max_score,
                "risk_level": score_to_risk_level(max_score).value,
                "summary": (
                    f"Host {ip} identified conducting distributed reconnaissance or multi-target attacks "
                    f"targeting {len(targets)} separate identities across {len(ev_list)} telemetry events."
                ),
                "recommended_response": "Immediate perimeter IP blocking and network ACL enforcement."
            })

    return correlations

"""
Account Takeover Anomaly Model: Rule-Based & Isolation Forest Engine.

Combines physical geo-velocity (Haversine) checks, failed authentication burst detection,
device novelty heuristics, and an Isolation Forest ML model.
"""

from datetime import datetime
import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from ...models.schemas import AuthLogEntry, ThreatIndicator

COMMERCIAL_FLIGHT_MAX_SPEED_KMH = 850.0  # Boeing 787 / Airbus A350 cruising speed
SUPERSONIC_SPEED_KMH = 3000.0           # Physical impossibility threshold


def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Computes great-circle distance between two points in kilometers using Haversine formula.
    """
    R = 6371.0  # Earth radius in kilometers

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + \
        math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return R * c


def calculate_geo_velocity(
    lat1: float, lon1: float, t1: datetime,
    lat2: float, lon2: float, t2: datetime
) -> Dict[str, Any]:
    """
    Calculates distance and travel velocity in km/h between two events.
    """
    distance_km = calculate_haversine_distance(lat1, lon1, lat2, lon2)
    time_delta = abs((t2 - t1).total_seconds())

    if time_delta < 1.0:
        time_delta = 1.0  # prevent division by zero

    velocity_kmh = (distance_km / (time_delta / 3600.0))

    return {
        "distance_km": round(distance_km, 1),
        "time_delta_seconds": round(time_delta, 1),
        "time_delta_minutes": round(time_delta / 60.0, 1),
        "velocity_kmh": round(velocity_kmh, 1),
        "is_impossible": velocity_kmh > COMMERCIAL_FLIGHT_MAX_SPEED_KMH and distance_km > 100.0,
        "is_supersonic": velocity_kmh > SUPERSONIC_SPEED_KMH and distance_km > 300.0,
    }


class AnomalyModel:
    """
    Hybrid detection engine utilizing physical geo-velocity heuristics,
    brute-force detection windows, and an Isolation Forest model.
    """

    def __init__(self):
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self._is_fitted = False
        self._init_baseline_model()

    def _init_baseline_model(self):
        """Fit Isolation Forest on synthetic normal authentication baseline vectors."""
        np.random.seed(42)
        n_samples = 300
        # Normal features:
        # 1. failed_count_recent: 0 most of the time (Poisson/low int)
        # 2. log1p(velocity_kmh): low (commutes < 80 km/h)
        # 3. time_delta_hours: 1 to 24
        # 4. is_new_device: 0 (95% same device)
        # 5. mfa_missing: 0 (mostly MFA enabled)
        # 6. is_off_hours: 0 (mostly 8am - 7pm)
        failed = np.random.choice([0, 1], size=n_samples, p=[0.92, 0.08])
        velocity = np.random.exponential(scale=20.0, size=n_samples)  # average speed ~20 km/h
        time_delta = np.random.uniform(0.5, 12.0, size=n_samples)
        new_dev = np.random.choice([0, 1], size=n_samples, p=[0.95, 0.05])
        mfa_missing = np.random.choice([0, 1], size=n_samples, p=[0.85, 0.15])
        off_hours = np.random.choice([0, 1], size=n_samples, p=[0.85, 0.15])

        X_normal = np.column_stack([
            failed,
            np.log1p(velocity),
            time_delta,
            new_dev,
            mfa_missing,
            off_hours
        ])
        self.iso_forest.fit(X_normal)
        self._is_fitted = True

    def _extract_feature_vector(
        self,
        entry: AuthLogEntry,
        prev_entry: Optional[AuthLogEntry],
        recent_failures: int,
        known_devices: set
    ) -> np.ndarray:
        """Extracts a 6-dimensional feature vector for an authentication event."""
        failed_count = float(recent_failures)

        if prev_entry and prev_entry.latitude and prev_entry.longitude and entry.latitude and entry.longitude:
            geo_info = calculate_geo_velocity(
                prev_entry.latitude, prev_entry.longitude, prev_entry.timestamp,
                entry.latitude, entry.longitude, entry.timestamp
            )
            velocity = geo_info["velocity_kmh"]
            time_delta_hours = geo_info["time_delta_seconds"] / 3600.0
        else:
            velocity = 0.0
            time_delta_hours = 4.0

        is_new_device = 1.0 if entry.device_fingerprint not in known_devices else 0.0
        mfa_missing = 0.0 if entry.mfa_used else 1.0
        hour = entry.timestamp.hour
        is_off_hours = 1.0 if (hour < 6 or hour > 22) else 0.0

        return np.array([
            failed_count,
            np.log1p(velocity),
            time_delta_hours,
            is_new_device,
            mfa_missing,
            is_off_hours
        ])

    def analyze_logs(self, logs: List[AuthLogEntry]) -> Dict[str, Any]:
        """
        Runs comprehensive hybrid analysis across a sequence of authentication logs.
        Returns indicators, travel events, attack details, and composite scores.
        """
        if not logs:
            return {
                "indicators": [],
                "impossible_travel_events": [],
                "brute_force_events": [],
                "device_anomalies": [],
                "ml_anomaly_score": 0.0,
                "rule_anomaly_score": 0.0,
                "composite_score": 0.0,
                "summary": "No logs provided for analysis."
            }

        # Sort logs chronologically
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)

        indicators: List[ThreatIndicator] = []
        impossible_travel_events: List[Dict[str, Any]] = []
        brute_force_events: List[Dict[str, Any]] = []
        device_anomalies: List[Dict[str, Any]] = []

        known_devices = set()
        # Find baseline device (most frequent device in logs)
        device_counts: Dict[str, int] = {}
        for l in sorted_logs:
            device_counts[l.device_fingerprint] = device_counts.get(l.device_fingerprint, 0) + 1
        if device_counts:
            primary_device = max(device_counts, key=device_counts.get)
            known_devices.add(primary_device)

        # 1. Evaluate Geo-Velocity & Impossible Travel
        for i in range(1, len(sorted_logs)):
            prev = sorted_logs[i - 1]
            curr = sorted_logs[i]

            if (prev.latitude is not None and prev.longitude is not None and
                curr.latitude is not None and curr.longitude is not None):
                
                geo = calculate_geo_velocity(
                    prev.latitude, prev.longitude, prev.timestamp,
                    curr.latitude, curr.longitude, curr.timestamp
                )

                if geo["is_impossible"]:
                    travel_event = {
                        "origin_city": prev.city or "Unknown",
                        "origin_country": prev.country or "Unknown",
                        "origin_ip": prev.ip_address,
                        "origin_time": prev.timestamp.isoformat(),
                        "dest_city": curr.city or "Unknown",
                        "dest_country": curr.country or "Unknown",
                        "dest_ip": curr.ip_address,
                        "dest_time": curr.timestamp.isoformat(),
                        "distance_km": geo["distance_km"],
                        "time_delta_minutes": geo["time_delta_minutes"],
                        "velocity_kmh": geo["velocity_kmh"],
                        "is_supersonic": geo["is_supersonic"]
                    }
                    impossible_travel_events.append(travel_event)

                    severity = "CRITICAL" if geo["is_supersonic"] else "HIGH"
                    weight = 0.95 if geo["is_supersonic"] else 0.85

                    indicators.append(ThreatIndicator(
                        name="Impossible Travel Anomaly",
                        category="Geographic & Velocity Anomaly",
                        weight=weight,
                        value=f"{geo['velocity_kmh']:,.0f} km/h between {prev.city} and {curr.city}",
                        description=(
                            f"Authentication detected across {geo['distance_km']:,.0f} km in "
                            f"{geo['time_delta_minutes']} minutes ({geo['velocity_kmh']:,.0f} km/h). "
                            f"Exceeds commercial airliner limit ({COMMERCIAL_FLIGHT_MAX_SPEED_KMH} km/h)."
                            f"{' Physically impossible (supersonic velocity).' if geo['is_supersonic'] else ''}"
                        )
                    ))

        # 2. Evaluate Brute Force / Consecutive Failed Attempts
        consecutive_failures = 0
        failure_ips = set()
        first_failure_time = None
        last_failure_time = None

        for idx, entry in enumerate(sorted_logs):
            if entry.status.upper() == "FAILURE":
                consecutive_failures += 1
                failure_ips.add(entry.ip_address)
                if first_failure_time is None:
                    first_failure_time = entry.timestamp
                last_failure_time = entry.timestamp
            else:
                # If there was a burst of failures immediately followed by a SUCCESS:
                if consecutive_failures >= 3:
                    burst_duration = (last_failure_time - first_failure_time).total_seconds() if first_failure_time and last_failure_time else 0
                    bf_event = {
                        "failed_count": consecutive_failures,
                        "duration_seconds": round(burst_duration, 1),
                        "attacker_ips": list(failure_ips),
                        "compromised_at": entry.timestamp.isoformat(),
                        "targeted_user": entry.username,
                        "final_status": "SUCCESSFUL_COMPROMISE"
                    }
                    brute_force_events.append(bf_event)

                    indicators.append(ThreatIndicator(
                        name="Brute Force / Password Spray Attack",
                        category="Authentication Velocity & Failure Burst",
                        weight=min(0.95, 0.60 + (consecutive_failures * 0.03)),
                        value=f"{consecutive_failures} failed logins followed by successful access",
                        description=(
                            f"Detected {consecutive_failures} rapid failed authentication attempts within "
                            f"{round(burst_duration)} seconds from IP(s) {', '.join(failure_ips)}, "
                            f"immediately followed by a successful login."
                        )
                    ))
                consecutive_failures = 0
                failure_ips = set()
                first_failure_time = None

        # Check if the sequence concludes with an active ongoing failure burst
        if consecutive_failures >= 4:
            burst_duration = (last_failure_time - first_failure_time).total_seconds() if first_failure_time and last_failure_time else 0
            bf_event = {
                "failed_count": consecutive_failures,
                "duration_seconds": round(burst_duration, 1),
                "attacker_ips": list(failure_ips),
                "targeted_user": sorted_logs[-1].username,
                "final_status": "LOCKED_OUT_OR_ONGOING"
            }
            brute_force_events.append(bf_event)

            indicators.append(ThreatIndicator(
                name="Active Password Spraying / Brute Force",
                category="Authentication Velocity & Failure Burst",
                weight=0.80,
                value=f"{consecutive_failures} consecutive failed attempts",
                description=(
                    f"Ongoing high-frequency authentication failure streak ({consecutive_failures} attempts) "
                    f"from {', '.join(failure_ips)}."
                )
            ))

        # 3. Evaluate Device Fingerprint Novelty & MFA Posture
        for entry in sorted_logs:
            if entry.status.upper() == "SUCCESS":
                if entry.device_fingerprint not in known_devices:
                    device_anomalies.append({
                        "timestamp": entry.timestamp.isoformat(),
                        "fingerprint": entry.device_fingerprint,
                        "user_agent": entry.user_agent,
                        "ip": entry.ip_address,
                        "city": entry.city,
                        "mfa_used": entry.mfa_used
                    })

                    # If new device AND mfa was skipped / missing
                    if not entry.mfa_used:
                        indicators.append(ThreatIndicator(
                            name="Unrecognized Device Without MFA",
                            category="Device Novelty & Identity Verification",
                            weight=0.75,
                            value=f"New device {entry.device_fingerprint[:14]}... with MFA bypassed",
                            description=(
                                f"Successful login from an unrecognized device ({entry.user_agent[:45]}...) "
                                f"in {entry.city or 'Unknown'}, without Multi-Factor Authentication challenge."
                            )
                        ))

        # 4. Machine Learning Evaluation (Isolation Forest)
        feature_vectors = []
        recent_fails = 0
        for i, entry in enumerate(sorted_logs):
            prev = sorted_logs[i - 1] if i > 0 else None
            if entry.status.upper() == "FAILURE":
                recent_fails += 1
            else:
                pass
            vec = self._extract_feature_vector(entry, prev, recent_fails, known_devices)
            feature_vectors.append(vec)
            if entry.status.upper() == "SUCCESS":
                recent_fails = 0

        X = np.array(feature_vectors)
        # Decision function: smaller / negative values are anomalies
        decision_scores = self.iso_forest.decision_function(X)
        min_score = float(np.min(decision_scores))

        # Convert decision function score (typically -0.3 to +0.2) to normalized anomaly probability (0.0 to 1.0)
        # min_score < -0.05 is suspicious, < -0.15 is highly anomalous
        ml_anomaly_score = float(1.0 / (1.0 + np.exp(min_score * 8.0)))
        ml_anomaly_score = max(0.0, min(1.0, round(ml_anomaly_score, 3)))

        if ml_anomaly_score > 0.65:
            indicators.append(ThreatIndicator(
                name="Isolation Forest Anomaly Cluster",
                category="Machine Learning Behavioral Anomaly",
                weight=round(ml_anomaly_score, 2),
                value=f"ML Anomaly Score: {ml_anomaly_score:.1%}",
                description=(
                    f"Multivariate Isolation Forest model flagged statistical divergence across "
                    f"geo-velocity, device entropy, and failure rate (anomaly score {ml_anomaly_score:.1%})."
                )
            ))

        # 5. Compute Rule-Based Score
        rule_weights = [ind.weight for ind in indicators]
        if not rule_weights:
            rule_score = 0.05
        else:
            # Diminishing returns combination: 1 - prod(1 - w_i)
            prod_complement = 1.0
            for w in rule_weights:
                prod_complement *= (1.0 - (w * 0.85))
            rule_score = min(1.0, 1.0 - prod_complement)

        # Composite score: 65% rules (deterministic safety guarantees) + 35% ML
        composite = (rule_score * 0.65) + (ml_anomaly_score * 0.35)
        # If impossible travel is detected, minimum score is 0.80
        if impossible_travel_events:
            composite = max(composite, 0.88 if any(e["is_supersonic"] for e in impossible_travel_events) else 0.80)
        # If brute force with compromise detected, minimum score is 0.85
        if any(b.get("final_status") == "SUCCESSFUL_COMPROMISE" for b in brute_force_events):
            composite = max(composite, 0.85)

        composite_score = round(composite, 3)

        return {
            "indicators": indicators,
            "impossible_travel_events": impossible_travel_events,
            "brute_force_events": brute_force_events,
            "device_anomalies": device_anomalies,
            "ml_anomaly_score": ml_anomaly_score,
            "rule_anomaly_score": round(rule_score, 3),
            "composite_score": composite_score,
            "total_logs_analyzed": len(sorted_logs),
            "users_involved": list(set(l.username for l in sorted_logs)),
            "devices_involved": list(set(l.device_fingerprint for l in sorted_logs)),
            "ips_involved": list(set(l.ip_address for l in sorted_logs)),
        }
